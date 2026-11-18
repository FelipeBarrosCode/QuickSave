// SPDX-License-Identifier: GPL-3.0-only
//! Exact, native-held workspace requests. The webview can spend a ticket, but
//! cannot replace its action, provider, roots, selection, or credential inputs.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::{FileStamp, SafeRoot};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::approval::{APPROVAL_TTL, MAX_APPROVALS};

pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_SELECTED_FILES: usize = 512;
// Covers the tracker's 48 real application roots and native restore's bounded
// 64-layout contract. Confirmation/document byte limits still apply.
const MAX_ROOTS: usize = 64;
const MAX_IMPORT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ConnectProvider,
    ConnectOauth,
    DisconnectProvider,
    VerifyProvider,
    AuthorizeProviderWrites,
    ReauthorizeProvider,
    ExportRecoveryKey,
    DiscoverNolandImport,
    ImportNoland,
    EnableAppTracking,
    RefreshAppTracking,
    TrackSoftware,
    AddFiles,
    SetProvider,
    SetAutosave,
    Upload,
    PreviewUploadAll,
    UploadAll,
    PreviewRestore,
    Download,
    RecoverRestore,
    PreviewDelete,
    DeleteCloud,
    Cancel,
    Retry,
}

impl Action {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "connect_provider" => Self::ConnectProvider,
            "connect_oauth" => Self::ConnectOauth,
            "disconnect_provider" => Self::DisconnectProvider,
            "verify_provider" => Self::VerifyProvider,
            "authorize_provider_writes" => Self::AuthorizeProviderWrites,
            "reauthorize_provider" => Self::ReauthorizeProvider,
            "export_recovery_key" => Self::ExportRecoveryKey,
            "discover_noland_import" => Self::DiscoverNolandImport,
            "import_noland" => Self::ImportNoland,
            "enable_app_tracking" => Self::EnableAppTracking,
            "refresh_app_tracking" => Self::RefreshAppTracking,
            "track_software" => Self::TrackSoftware,
            "add_files" => Self::AddFiles,
            "set_provider" => Self::SetProvider,
            "set_autosave" => Self::SetAutosave,
            "upload" => Self::Upload,
            "preview_upload_all" => Self::PreviewUploadAll,
            "upload_all" => Self::UploadAll,
            "preview_restore" => Self::PreviewRestore,
            "download" => Self::Download,
            "recover_restore" => Self::RecoverRestore,
            "preview_delete" => Self::PreviewDelete,
            "delete_cloud" => Self::DeleteCloud,
            "cancel" => Self::Cancel,
            "retry" => Self::Retry,
            _ => bail!("Unknown QuickSave workspace action"),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ConnectProvider => "connect_provider",
            Self::ConnectOauth => "connect_oauth",
            Self::DisconnectProvider => "disconnect_provider",
            Self::VerifyProvider => "verify_provider",
            Self::AuthorizeProviderWrites => "authorize_provider_writes",
            Self::ReauthorizeProvider => "reauthorize_provider",
            Self::ExportRecoveryKey => "export_recovery_key",
            Self::DiscoverNolandImport => "discover_noland_import",
            Self::ImportNoland => "import_noland",
            Self::EnableAppTracking => "enable_app_tracking",
            Self::RefreshAppTracking => "refresh_app_tracking",
            Self::TrackSoftware => "track_software",
            Self::AddFiles => "add_files",
            Self::SetProvider => "set_provider",
            Self::SetAutosave => "set_autosave",
            Self::Upload => "upload",
            Self::PreviewUploadAll => "preview_upload_all",
            Self::UploadAll => "upload_all",
            Self::PreviewRestore => "preview_restore",
            Self::Download => "download",
            Self::RecoverRestore => "recover_restore",
            Self::PreviewDelete => "preview_delete",
            Self::DeleteCloud => "delete_cloud",
            Self::Cancel => "cancel",
            Self::Retry => "retry",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::ConnectProvider => "Connect this cloud storage account",
            Self::ConnectOauth => "Open this provider's sign-in flow",
            Self::DisconnectProvider => "Disconnect this provider (keep backups and recovery keys)",
            Self::VerifyProvider => {
                "Check this provider's connection and authenticate its cloud metadata (read only)"
            }
            Self::AuthorizeProviderWrites => "Allow uploads to this imported provider",
            Self::ReauthorizeProvider => "Reauthorize this exact provider without changing its repository or root; disable existing autosave grants",
            Self::ExportRecoveryKey => "Write this repository's recovery key to one NEW external private file",
            Self::DiscoverNolandImport => "Find No Land's state.json in its standard application-data locations (read only)",
            Self::ImportNoland => {
                "READ-ONLY import of storage profiles and repository keys into QuickSave's vault"
            }
            Self::TrackSoftware => "Track only the listed local software folders",
            Self::EnableAppTracking => "Change automatic native application tracking and real bundle indexing",
            Self::RefreshAppTracking => "Reconcile real application identities, approved roots and bundle file indices",
            Self::AddFiles => "Track only the listed individual local files",
            Self::SetProvider => "Change this software's backup provider",
            Self::SetAutosave => "Change background autosave for this software and provider",
            Self::Upload => "Read the approved software selection and append a cloud backup",
            Self::PreviewUploadAll => "Freeze an exact set of approved application bundles for upload",
            Self::UploadAll => "Upload only the applications and roots in the frozen plan",
            Self::PreviewRestore => "Inspect the selected bundle and native destination to prepare an exact restore/conflict plan",
            Self::Download => "Restore only the frozen, native-confirmed application/file plan",
            Self::RecoverRestore => "Verify and recover only the original authenticated restore operation",
            Self::PreviewDelete => "Read cloud metadata to prepare an exact deletion preview",
            Self::DeleteCloud => "PERMANENTLY delete the frozen cloud selection",
            Self::Cancel => "Request cancellation of this operation",
            Self::Retry => "Retry only this operation's original authorized selection",
        }
    }
}

/// No Debug/Serialize: provider credentials may exist temporarily in `params`.
pub struct Request {
    action: Action,
    params: Value,
    scope: Value,
}

impl Drop for Request {
    fn drop(&mut self) {
        // Remove stale secret values from reusable JSON allocations on ticket
        // expiry/cancellation. This is not a claim that the allocator, IPC
        // transport, or provider SDK can guarantee process-wide zeroization.
        scrub(&mut self.params);
    }
}

fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => {
            text.zeroize();
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(items) => items.values_mut().for_each(scrub),
        _ => {}
    }
}

struct PrivateInput(Value);

impl std::ops::Deref for PrivateInput {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for PrivateInput {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

impl Request {
    /// Pure lexical/size validation. Does not open a path or contact a vault.
    pub fn new(action: &str, params: Value) -> Result<Self> {
        // Validation failures must retire transient credential inputs too.
        let mut params = PrivateInput(params);
        let action = Action::parse(action)?;
        validate_document(&params)?;
        let allowed: &[&str] = match action {
            Action::ConnectProvider => {
                &["kind", "name", "bucket", "prefix", "fields", "credentials"]
            }
            Action::ConnectOauth => &["kind", "name", "clientId", "clientSecret", "fields"],
            Action::DisconnectProvider
            | Action::VerifyProvider
            | Action::AuthorizeProviderWrites => &["providerId"],
            Action::ReauthorizeProvider => &["providerId", "credentials"],
            Action::ExportRecoveryKey => &["providerId", "destination"],
            Action::DiscoverNolandImport | Action::RefreshAppTracking => &[],
            Action::ImportNoland => &["sourceId", "stateFile", "profileIds"],
            Action::EnableAppTracking => &["enabled", "defaultProviderId", "roles"],
            Action::TrackSoftware => &["appId", "name", "roots", "providerId"],
            Action::AddFiles => &["paths", "providerId"],
            Action::SetProvider => &["softwareId", "providerId"],
            Action::SetAutosave => &["softwareId", "providerId", "enabled"],
            Action::Upload => &["softwareId", "providerId", "fileIds"],
            Action::PreviewUploadAll => &["providerId", "softwareIds"],
            Action::UploadAll => &["planSetId"],
            Action::PreviewRestore => &[
                "providerId",
                "bundleId",
                "appId",
                "destination",
                "fileIds",
                "mode",
            ],
            Action::Download => &["restorePreviewId", "overwriteAcknowledgement"],
            Action::PreviewDelete => &["providerId", "bundleId", "appId"],
            Action::DeleteCloud => &["providerId", "previewId", "acknowledgeDependencies"],
            Action::Cancel | Action::Retry | Action::RecoverRestore => &["operationId"],
        };
        fields(&params, allowed)?;
        match action {
            Action::ConnectProvider | Action::ConnectOauth => {
                required_text(&params, "kind", 128)?;
                required_text(&params, "name", 512)?;
                if let Some(value) = params.get("fields") {
                    ensure!(value.is_object(), "Provider fields must be an object");
                }
                if let Some(value) = params.get("credentials") {
                    ensure!(value.is_object(), "Provider credentials must be an object");
                }
            }
            Action::ReauthorizeProvider => {
                if let Some(credentials) = params.get("credentials") {
                    ensure!(
                        credentials.is_object(),
                        "Provider credentials must be an object"
                    );
                }
            }
            Action::ExportRecoveryKey => {
                absolute_path(required_text(&params, "destination", 4096)?)?;
            }
            Action::ImportNoland => {
                ensure!(
                    params.get("sourceId").is_some() != params.get("stateFile").is_some(),
                    "Import must select one native-discovered source or one advanced source file"
                );
                if let Some(source) = params.get("sourceId") {
                    display_text(source.as_str().context("Invalid native source ID")?, 512)?;
                } else {
                    absolute_path(required_text(&params, "stateFile", 4096)?)?;
                }
                string_list(&params, "profileIds", 64, false)?;
            }
            Action::EnableAppTracking => {
                ensure!(
                    params["enabled"].is_boolean(),
                    "App tracking needs an explicit enabled setting"
                );
                optional_text(&params, "defaultProviderId", 512)?;
                for role in string_list(&params, "roles", 4, false)? {
                    ensure!(
                        ["installation", "save", "config", "runtime"].contains(&role),
                        "Unknown automatic application root role"
                    );
                }
            }
            Action::PreviewUploadAll => {
                string_list(&params, "softwareIds", MAX_SELECTED_FILES, false)?;
            }
            Action::TrackSoftware => {
                required_text(&params, "name", 512)?;
                let roots = params
                    .get("roots")
                    .and_then(Value::as_array)
                    .context("Software roots must be a nonempty list")?;
                ensure!(
                    !roots.is_empty() && roots.len() <= MAX_ROOTS,
                    "Software must have between 1 and 32 approved roots"
                );
                let mut seen = BTreeSet::new();
                for root in roots {
                    fields(root, &["path", "role"])?;
                    let path = absolute_path(required_text(root, "path", 4096)?)?;
                    ensure!(seen.insert(path), "Duplicate software root");
                    optional_text(root, "role", 128)?;
                }
            }
            Action::AddFiles => {
                let paths = string_list(&params, "paths", MAX_SELECTED_FILES, true)?;
                for path in paths {
                    absolute_path(path)?;
                }
            }
            Action::SetAutosave => {
                ensure!(
                    params.get("enabled").and_then(Value::as_bool).is_some(),
                    "Autosave requires an explicit enabled boolean"
                );
            }
            Action::Upload | Action::PreviewRestore => {
                string_list(&params, "fileIds", MAX_SELECTED_FILES, false)?;
                if action == Action::PreviewRestore {
                    absolute_path(required_text(&params, "destination", 4096)?)?;
                    ensure!(
                        matches!(
                            params["mode"].as_str(),
                            Some("create_new" | "merge" | "replace")
                        ),
                        "Unknown native restore mode"
                    );
                }
            }
            Action::Download => {
                ensure!(
                    params["overwriteAcknowledgement"].is_boolean(),
                    "A frozen restore needs an explicit overwrite acknowledgement"
                );
            }
            Action::DeleteCloud => {
                ensure!(
                    params
                        .get("acknowledgeDependencies")
                        .and_then(Value::as_bool)
                        .is_some(),
                    "Deletion requires explicit dependent-backup acknowledgement"
                );
            }
            _ => {}
        }
        for field in [
            "providerId",
            "softwareId",
            "bundleId",
            "appId",
            "previewId",
            "operationId",
            "planSetId",
            "restorePreviewId",
        ] {
            if allowed.contains(&field) {
                let optional = matches!(action, Action::TrackSoftware | Action::AddFiles);
                if optional {
                    optional_text(&params, field, 4096)?;
                } else {
                    required_text(&params, field, 4096)?;
                }
            }
        }
        // Every non-secret top-level label may appear in a native dialog.
        for field in ["bucket", "prefix", "clientId"] {
            optional_text(&params, field, 4096)?;
        }
        Ok(Self {
            action,
            params: params.0.take(),
            scope: Value::Null,
        })
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn params(&self) -> &Value {
        &self.params
    }

    pub fn take_params(&mut self) -> Value {
        self.params.take()
    }

    pub fn native_scope(&self) -> &Value {
        &self.scope
    }

    /// The service supplies this deterministic authority snapshot from its own
    /// sanitized state, never from webview-provided "approved" properties.
    pub fn bind_scope(&mut self, scope: Value) -> Result<()> {
        validate_document(&scope)?;
        ensure!(
            scope.is_object(),
            "Native authority scope must be an object"
        );
        if self.action == Action::DeleteCloud {
            let deletion = scope
                .get("deletion")
                .and_then(Value::as_object)
                .context("Native deletion confirmation requires the frozen preview")?;
            ensure!(
                deletion.get("previewId") == self.params.get("previewId"),
                "Native deletion preview does not match the approved request"
            );
            let summary = deletion
                .get("summary")
                .and_then(Value::as_str)
                .context("Native deletion confirmation requires an exact scope summary")?;
            display_text(summary, 8192)?;
        }
        if self.action == Action::Download {
            let restore = scope
                .get("restore")
                .context("Native restore needs its frozen preview")?;
            ensure!(
                restore["previewId"] == self.params["restorePreviewId"],
                "Native restore preview does not match this request"
            );
            display_text(required_text(restore, "summary", 8192)?, 8192)?;
            ensure!(
                restore["requiresOverwriteAcknowledgement"].is_boolean(),
                "Native restore preview is missing its conflict policy"
            );
            ensure!(
                restore["requiresOverwriteAcknowledgement"] != true
                    || self.params["overwriteAcknowledgement"] == true,
                "Existing file replacement requires separate explicit acknowledgement"
            );
        }
        if self.action == Action::RecoverRestore {
            let restore = scope
                .get("restore")
                .context("Native recovery needs the original frozen restore scope")?;
            ensure!(
                restore["requestedOperationId"] == self.params["operationId"],
                "Native recovery scope does not match the selected original operation"
            );
            required_text(restore, "operationId", 4096)?;
            required_text(restore, "frozenPlanFingerprint", 512)?;
            display_text(required_text(restore, "summary", 8192)?, 8192)?;
            ensure!(
                restore["roots"]
                    .as_array()
                    .is_some_and(|roots| !roots.is_empty() && roots.len() <= MAX_ROOTS),
                "Native recovery needs exact original destination roots"
            );
        }
        if self.action == Action::UploadAll {
            let batch = scope
                .get("batch")
                .context("All-app upload requires its frozen native plan set")?;
            ensure!(
                batch["planSetId"] == self.params["planSetId"],
                "The frozen native application set does not match this request"
            );
            ensure!(
                batch["softwareCount"]
                    .as_u64()
                    .is_some_and(|count| (1..=4096).contains(&count)),
                "The frozen native application count is invalid"
            );
            display_text(required_text(batch, "summary", 8192)?, 8192)?;
            let digest = required_text(batch, "rootDigest", 64)?;
            ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "The frozen native roots are missing their exact plan digest"
            );
        }
        self.scope = scope;
        Ok(())
    }

    pub fn confirmation_message(&self) -> Result<String> {
        let mut message = format!("{}\n\n", self.action.description());
        for (label, name) in [
            ("Provider type", "kind"),
            ("Connection / software name", "name"),
            ("Provider", "providerId"),
            (
                "Default provider (not upload permission)",
                "defaultProviderId",
            ),
            ("Software", "softwareId"),
            ("Bundle", "bundleId"),
            ("Application", "appId"),
            ("Operation", "operationId"),
            ("Native No Land source", "sourceId"),
            ("Frozen application plan set", "planSetId"),
            ("Frozen restore preview", "restorePreviewId"),
            ("Frozen deletion preview", "previewId"),
            ("Bucket", "bucket"),
            ("Cloud prefix", "prefix"),
            ("No Land state file (read only)", "stateFile"),
            ("EMPTY destination", "destination"),
        ] {
            if let Some(text) = self.params.get(name).and_then(Value::as_str) {
                display_text(text, 4096)?;
                message.push_str(&format!("{label}: {text}\n"));
            }
        }
        if let Some(source) = self.scope.get("source") {
            if let Some(path) = source.get("path").and_then(Value::as_str) {
                display_text(path, 4096)?;
                message.push_str(&format!(
                    "Discovered No Land state file (READ ONLY): {path}\n"
                ));
            }
        }
        for section in ["enrollment", "discovery", "restore", "batch"] {
            if let Some(summary) = self
                .scope
                .get(section)
                .and_then(|value| value.get("summary"))
                .and_then(Value::as_str)
            {
                display_text(summary, 8192)?;
                message.push_str(summary);
                message.push('\n');
            }
        }
        if let Some(bases) = self
            .scope
            .pointer("/enrollment/baseDirectories")
            .and_then(Value::as_array)
        {
            ensure!(bases.len() <= MAX_ROOTS, "Too many native enrollment bases");
            for base in bases {
                let path = base
                    .as_str()
                    .context("Native enrollment base must be a path")?;
                absolute_path(path)?;
                message.push_str(&format!(
                    "Native identity-policy base (not whole-folder backup permission): {path}\n"
                ));
            }
        }
        if self.action == Action::UploadAll {
            let batch = &self.scope["batch"];
            message.push_str(&format!(
                "Frozen approved-root digest: {}\n",
                required_text(batch, "rootDigest", 64)?
            ));
            if let Some(names) = batch["sampleNames"].as_array() {
                ensure!(names.len() <= 16, "Native application summary is too large");
                for name in names {
                    let name = name
                        .as_str()
                        .context("Invalid native application summary")?;
                    display_text(name, 512)?;
                    message.push_str(&format!("Included software (bounded sample): {name}\n"));
                }
            }
            message.push_str("Only this exact frozen set is authorized. Later-discovered applications cannot join it; file metadata is captured when each approved child starts.\n");
        }
        if self.action == Action::DiscoverNolandImport {
            message.push_str("Inspect only No Land's standard com.noland.connect application-data locations. Do not modify source files or read credential vaults during discovery.\n");
        }
        if self.action == Action::EnableAppTracking {
            if let Some(roles) = self.params.get("roles").and_then(Value::as_array) {
                message.push_str(&format!(
                    "Automatic root roles: {}\n",
                    roles
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            message.push_str(if self.params["enabled"] == true {
                "Create real application/root/file indices only within the approved native identity policy. No name-only bundles; no cloud uploads without a separate upload/autosave grant.\n"
            } else {
                "Stop automatic app enrollment and observation. Keep local data and existing backup history.\n"
            });
        }
        if self.action == Action::Download {
            message.push_str(if self.params["overwriteAcknowledgement"] == true {
                "Replacement of exactly the frozen conflicting files is explicitly acknowledged; authenticated rollback and native ownership checks remain required.\n"
            } else {
                "No replacement of existing different file contents is acknowledged.\n"
            });
        }
        for (label, scope) in [
            ("Connected provider", self.scope.get("provider")),
            ("Tracked software", self.scope.get("software")),
        ] {
            if let Some(name) = scope
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
            {
                display_text(name, 512)?;
                message.push_str(&format!("{label}: {name}\n"));
            }
        }
        if let Some(provider) = self.scope.get("provider") {
            for (key, label) in [
                ("kind", "Connected provider type"),
                ("bucket", "Connected bucket / container"),
                ("prefix", "Connected cloud prefix"),
            ] {
                if let Some(text) = provider
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    display_text(text, 4096)?;
                    message.push_str(&format!("{label}: {text}\n"));
                }
            }
            if let Some(fields) = provider.get("publicScope").and_then(Value::as_object) {
                append_destination_fields(&mut message, fields)?;
            }
        }
        if matches!(self.action, Action::ConnectProvider | Action::ConnectOauth) {
            // Endpoint/root fields determine where credentials and data will be
            // used. They must be visible in native consent, not merely hashed
            // into an opaque scope. Never render arbitrary provider fields.
            if let Some(fields) = self.params.get("fields").and_then(Value::as_object) {
                append_destination_fields(&mut message, fields)?;
            }
        }
        for path in self.directory_paths()? {
            message.push_str(&format!("Approved folder: {}\n", path.display()));
        }
        if let Some(paths) = self.params.get("paths").and_then(Value::as_array) {
            for path in paths {
                let path = path.as_str().context("Invalid selected file path")?;
                display_text(path, 4096)?;
                message.push_str(&format!("Selected file: {path}\n"));
            }
        }
        if let Some(ids) = self.params.get("fileIds").and_then(Value::as_array) {
            message.push_str(&format!(
                "Exact selection: {} individual files (not the whole software).\n",
                ids.len()
            ));
        } else if self.action == Action::Upload {
            message.push_str("Selection: the whole approved software scope.\n");
        }
        if self.action == Action::SetAutosave {
            message.push_str(if self.params["enabled"] == true {
                "Autosave: ON. Allow future background uploads only for this exact software, approved roots and provider. Keep local files.\n"
            } else {
                "Autosave: OFF. Stop scheduling new background uploads for this software.\n"
            });
        }
        if self.action == Action::Upload
            || self.action == Action::SetAutosave && self.params["enabled"] == true
        {
            message.push_str(
                "Capture validates stable files; it is not an application-wide atomic snapshot.\n",
            );
        }
        if self.action == Action::ImportNoland {
            message.push_str(
                "Copy storage credentials and repository keys into QuickSave's own native vault. \
                 Do not modify No Land's state or vault. Imported connections start read-only.\n",
            );
        }
        if self.action == Action::ExportRecoveryKey {
            message.push_str("Export the native-vault repository key directly into the exact NEW private file. Never display the key, overwrite an existing file, or write inside tracked software/QuickSave/No Land state. Store this file securely and separately from backups.\n");
        }
        if self.action == Action::ConnectProvider || self.action == Action::ConnectOauth {
            message.push_str(
                "Credential values stay native after submission and are not shown in this dialog. \
                 Connect only an account you intend to use with QuickSave.\n",
            );
        }
        if self.action == Action::DeleteCloud {
            if let Some(dependencies) = self
                .scope
                .pointer("/deletion/dependentBundles")
                .and_then(Value::as_array)
            {
                ensure!(
                    dependencies.len() <= 256,
                    "Too many exact deletion dependencies for native review"
                );
                for dependency in dependencies {
                    let id = required_text(dependency, "id", 4096)?;
                    message.push_str(&format!("Dependent backup to delete: {id}"));
                    for (field, label) in [("appId", "application"), ("commitId", "commit")] {
                        if let Some(value) = dependency.get(field).and_then(Value::as_str) {
                            display_text(value, 512)?;
                            message.push_str(&format!("; {label}: {value}"));
                        }
                    }
                    message.push('\n');
                }
            }
            message.push_str(if self.params["acknowledgeDependencies"] == true {
                "Dependent-backup deletion: explicitly acknowledged. The engine must still verify the frozen preview and all dependencies.\n"
            } else {
                "Dependent-backup deletion: NOT acknowledged. A preview requiring it must be rejected.\n"
            });
            if let Some(summary) = self
                .scope
                .pointer("/deletion/summary")
                .and_then(Value::as_str)
            {
                display_text(summary, 8192)?;
                message.push_str(summary);
                message.push('\n');
            }
        }
        ensure!(
            message.len() <= 24 * 1024,
            "This scope is too large for a native confirmation; select fewer files or roots"
        );
        message.push_str(
            "\nOK authorizes this exact request once, within 10 minutes. Cancel if any scope is unexpected. \
             No automatic local deletion or cloud-history retirement is authorized.",
        );
        Ok(message)
    }

    fn directory_paths(&self) -> Result<BTreeSet<PathBuf>> {
        let mut paths = BTreeSet::new();
        for roots in [
            self.params.get("roots"),
            self.scope.get("roots"),
            self.scope.pointer("/software/roots"),
        ]
        .into_iter()
        .flatten()
        {
            let roots = roots.as_array().context("Native roots must be a list")?;
            ensure!(roots.len() <= MAX_ROOTS, "Too many approved software roots");
            for root in roots {
                paths.insert(absolute_path(required_text(root, "path", 4096)?)?);
            }
        }
        if self.action == Action::PreviewRestore {
            paths.insert(absolute_path(required_text(
                &self.params,
                "destination",
                4096,
            )?)?);
        }
        if self.action == Action::ExportRecoveryKey {
            let destination = absolute_path(required_text(&self.params, "destination", 4096)?)?;
            paths.insert(
                destination
                    .parent()
                    .context("Recovery export needs a parent directory")?
                    .to_path_buf(),
            );
        }
        if let Some(roots) = self
            .scope
            .pointer("/restore/roots")
            .and_then(Value::as_array)
        {
            ensure!(roots.len() <= MAX_ROOTS, "Too many native restore roots");
            for root in roots {
                paths.insert(absolute_path(required_text(root, "path", 4096)?)?);
            }
        }
        ensure!(paths.len() <= MAX_ROOTS + 1, "Too many native root proofs");
        Ok(paths)
    }
}

fn fields(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("Workspace parameters must be an object")?;
    ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "Unexpected workspace parameter; the request does not match its action"
    );
    Ok(())
}

fn display_text(text: &str, max: usize) -> Result<()> {
    ensure!(
        !text.is_empty() && text.len() <= max,
        "Text input is empty or too long"
    );
    ensure!(
        !text.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        }),
        "Text contains unsupported display/control characters"
    );
    Ok(())
}

fn append_destination_fields(
    message: &mut String,
    fields: &serde_json::Map<String, Value>,
) -> Result<()> {
    for (key, label) in [
        ("endpoint", "HTTPS endpoint"),
        ("url", "WebDAV URL"),
        ("host", "SFTP host"),
        ("port", "SFTP port"),
        ("host_keys", "Trusted SSH host keys"),
        ("remote_path", "Remote path"),
        ("folder", "Cloud folder"),
        ("drive_id", "Drive ID"),
        ("drive_type", "Drive type"),
        ("region", "Region"),
        ("account_id", "Cloudflare account ID"),
        ("bucket", "Bucket"),
        ("space_name", "Space"),
        ("container", "Container"),
        ("prefix", "Cloud prefix"),
        ("force_path_style", "Force path style"),
    ] {
        if let Some(value) = fields.get(key) {
            let text = match value {
                Value::String(text)
                    if text.is_empty() && ["remote_path", "folder", "prefix"].contains(&key) =>
                {
                    "(provider root)".to_owned()
                }
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                _ => bail!("Destination fields must contain bounded text"),
            };
            display_text(&text, 4096)?;
            message.push_str(&format!("{label}: {text}\n"));
        }
    }
    Ok(())
}

fn required_text<'a>(value: &'a Value, name: &str, max: usize) -> Result<&'a str> {
    let text = value
        .get(name)
        .and_then(Value::as_str)
        .context("Missing required text input")?;
    display_text(text, max)?;
    Ok(text)
}

fn optional_text(value: &Value, name: &str, max: usize) -> Result<()> {
    if value.get(name).is_some() {
        required_text(value, name, max)?;
    }
    Ok(())
}

fn absolute_path(text: &str) -> Result<PathBuf> {
    display_text(text, 4096)?;
    let path = Path::new(text);
    ensure!(
        path.is_absolute(),
        "Selected paths must be absolute native paths"
    );
    let path = quicksave_client::literal_path(path)?;
    ensure!(
        path.file_name().is_some(),
        "A filesystem root cannot be selected as a software folder or file"
    );
    Ok(path)
}

fn string_list<'a>(
    value: &'a Value,
    name: &str,
    max: usize,
    required: bool,
) -> Result<Vec<&'a str>> {
    let Some(list) = value.get(name) else {
        ensure!(!required, "Missing required selection list");
        return Ok(Vec::new());
    };
    let list = list.as_array().context("Selection must be a list")?;
    ensure!(
        !list.is_empty() && list.len() <= max,
        "Selection must be nonempty and within its file limit"
    );
    let mut seen = BTreeSet::new();
    list.iter()
        .map(|item| {
            let text = item
                .as_str()
                .context("Selection identifiers must be text")?;
            display_text(text, 4096)?;
            ensure!(seen.insert(text), "Duplicate selection identifier");
            Ok(text)
        })
        .collect()
}

fn validate_document(value: &Value) -> Result<()> {
    fn size(value: &Value, depth: usize) -> Result<usize> {
        ensure!(depth <= 8, "Workspace input is too deeply nested");
        Ok(match value {
            Value::String(text) => {
                ensure!(
                    text.len() <= 32 * 1024 && !text.contains('\0'),
                    "Invalid workspace text"
                );
                // Conservative bound on JSON escaping, without making a second
                // complete serialization containing plaintext credentials.
                text.len()
                    .checked_mul(6)
                    .context("Workspace input is too large")?
            }
            Value::Array(items) => {
                ensure!(
                    items.len() <= MAX_SELECTED_FILES,
                    "Workspace list is too large"
                );
                items.iter().try_fold(2usize, |sum, item| {
                    sum.checked_add(size(item, depth + 1)? + 1)
                        .context("Workspace input is too large")
                })?
            }
            Value::Object(items) => {
                ensure!(items.len() <= 64, "Workspace object has too many fields");
                items.iter().try_fold(2usize, |sum, (key, item)| {
                    display_text(key, 256)?;
                    sum.checked_add(key.len() * 6 + size(item, depth + 1)? + 4)
                        .context("Workspace input is too large")
                })?
            }
            _ => 32,
        })
    }
    ensure!(
        size(value, 0)? <= MAX_REQUEST_BYTES,
        "Workspace input exceeds its bounded size"
    );
    Ok(())
}

pub fn validate_query(name: &str, params: &Value) -> Result<()> {
    validate_document(params)?;
    let allowed: &[&str] = match name {
        "dashboard"
        | "provider_types"
        | "software"
        | "activity"
        | "noland_import_preview"
        | "app_tracking" => &[],
        "software_files" => &["softwareId", "cursor", "limit"],
        "bundles" => &["providerId", "cursor", "limit"],
        "catalog_apps" | "pending_deletions" => &["providerId", "cursor", "limit"],
        "history" => &["providerId", "appId", "mode", "cursor", "limit"],
        "deletion_targets" => &["providerId", "planId", "cursor", "limit"],
        "batch_status" => &["planSetId"],
        "bundle_files" => &["providerId", "bundleId", "appId", "cursor", "limit"],
        "operation" => &["operationId"],
        _ => bail!("Unknown QuickSave workspace query"),
    };
    fields(params, allowed)?;
    for field in [
        "softwareId",
        "providerId",
        "bundleId",
        "appId",
        "operationId",
        "planId",
        "planSetId",
    ] {
        if allowed.contains(&field) {
            required_text(params, field, 4096)?;
        }
    }
    optional_text(params, "cursor", 4096)?;
    if let Some(mode) = params.get("mode") {
        ensure!(
            matches!(
                mode.as_str(),
                Some("complete_application" | "personal_state" | "custom")
            ),
            "Unknown native catalog backup mode"
        );
    }
    if let Some(limit) = params.get("limit") {
        ensure!(
            limit
                .as_u64()
                .is_some_and(|limit| (1..=200).contains(&limit)),
            "File pages must contain between 1 and 200 entries"
        );
    }
    Ok(())
}

struct DirectoryProof {
    path: PathBuf,
    root: SafeRoot,
}

impl DirectoryProof {
    fn pin(path: PathBuf) -> Result<Self> {
        let root = SafeRoot::open(&path)?;
        Ok(Self { path, root })
    }

    fn verify(&self) -> Result<()> {
        let current = SafeRoot::open(&self.path)?;
        ensure!(
            self.root.same_root(&current)?,
            "Approved folder identity changed"
        );
        Ok(())
    }
}

struct SelectedFileProof {
    parent: DirectoryProof,
    name: String,
    _handle: File,
    stamp: FileStamp,
    private_import: bool,
}

impl SelectedFileProof {
    fn pin(path: &Path, private_import: bool) -> Result<Self> {
        let parent = DirectoryProof::pin(
            path.parent()
                .context("Selected file needs a parent")?
                .to_owned(),
        )?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Selected file must have a UTF-8 name")?
            .to_owned();
        let (file, stamp) = parent.root.read_file(&name)?;
        if private_import {
            ensure!(
                stamp.size <= MAX_IMPORT_BYTES,
                "No Land state exceeds the import size limit"
            );
            quicksave_platform::verify_private_file(&file)?;
        }
        Ok(Self {
            parent,
            name,
            _handle: file,
            stamp,
            private_import,
        })
    }

    fn verify(&self) -> Result<()> {
        self.parent.verify()?;
        self.parent.root.verify_file(&self.name, &self.stamp)?;
        if self.private_import {
            let (file, _) = self.parent.root.read_file(&self.name)?;
            quicksave_platform::verify_private_file(&file)?;
        }
        Ok(())
    }
}

/// Pins real roots/files only AFTER native confirmation. Engine workers must
/// also own their source proofs through capture; submission is not capture.
pub struct WorkspaceProofs {
    directories: Vec<DirectoryProof>,
    files: Vec<SelectedFileProof>,
}

impl WorkspaceProofs {
    pub fn pin(request: &Request) -> Result<Self> {
        let mut directories = request
            .directory_paths()?
            .into_iter()
            .map(DirectoryProof::pin)
            .collect::<Result<Vec<_>>>()?;
        if let Some(bases) = request
            .scope
            .pointer("/enrollment/baseDirectories")
            .and_then(Value::as_array)
        {
            ensure!(bases.len() <= MAX_ROOTS, "Too many native enrollment bases");
            for base in bases {
                let path = absolute_path(base.as_str().context("Invalid native enrollment base")?)?;
                // Missing/denied bases grant nothing. The worker may use only
                // identities present in this native-held handoff.
                if let Ok(proof) = DirectoryProof::pin(path) {
                    directories.push(proof);
                }
            }
            ensure!(
                !directories.is_empty(),
                "No eligible native enrollment bases are available"
            );
        }
        let mut files = Vec::new();
        if request.action == Action::ImportNoland {
            let path = match request.params.get("stateFile").and_then(Value::as_str) {
                Some(path) => absolute_path(path)?,
                None => absolute_path(required_text(
                    request
                        .scope
                        .get("source")
                        .context("The native-discovered source is unavailable")?,
                    "path",
                    4096,
                )?)?,
            };
            // Automatically discovered files have already passed the source's
            // read-only ownership policy (No Land may have written 0644).
            // The source registry verifies it again before import. Advanced
            // arbitrary selections retain the stricter private-file policy.
            let proof = SelectedFileProof::pin(&path, request.params.get("stateFile").is_some())?;
            ensure!(
                proof.stamp.size <= MAX_IMPORT_BYTES,
                "No Land state exceeds the import size limit"
            );
            files.push(proof);
        }
        if let Some(paths) = request.params.get("paths").and_then(Value::as_array) {
            for path in paths {
                files.push(SelectedFileProof::pin(
                    &absolute_path(path.as_str().context("Invalid selected path")?)?,
                    false,
                )?);
            }
        }
        Ok(Self { directories, files })
    }

    pub fn verify(&self) -> Result<()> {
        for directory in &self.directories {
            directory.verify()?;
        }
        for file in &self.files {
            file.verify()?;
        }
        Ok(())
    }

    /// Server-only, non-secret identity handoff. The receiving native worker
    /// must compare these IDs to its own pinned handles BEFORE granting tracking,
    /// reading an import, or accepting a download destination.
    pub fn worker_identities(&self) -> Result<Value> {
        self.verify()?;
        let mut items = Vec::with_capacity(self.directories.len() + self.files.len());
        for directory in &self.directories {
            items.push(serde_json::json!({
                "path":directory.path,
                "kind":"directory",
                "identity":directory.root.identity()?,
            }));
        }
        for file in &self.files {
            items.push(serde_json::json!({
                "path":file.parent.path.join(&file.name),
                "kind":"file",
                "identity":{"device":file.stamp.device,"fileId":file.stamp.file_id},
                "stamp":file.stamp,
                "parentIdentity":file.parent.root.identity()?,
            }));
        }
        Ok(Value::Array(items))
    }
}

pub struct Ticket<P> {
    pub request: Request,
    pub proof: P,
    issued_at: Instant,
}

impl<P> Ticket<P> {
    pub fn verify_lifetime(&self, now: Instant) -> Result<()> {
        ensure!(
            now.saturating_duration_since(self.issued_at) < APPROVAL_TTL,
            "Native workspace approval expired; request a new one"
        );
        Ok(())
    }
}

pub struct TicketStore<P> {
    tickets: BTreeMap<Uuid, Ticket<P>>,
}

impl<P> Default for TicketStore<P> {
    fn default() -> Self {
        Self {
            tickets: BTreeMap::new(),
        }
    }
}

impl<P> TicketStore<P> {
    pub fn check_capacity(&mut self, now: Instant) -> Result<()> {
        self.tickets
            .retain(|_, ticket| ticket.verify_lifetime(now).is_ok());
        ensure!(
            self.tickets.len() < MAX_APPROVALS,
            "Too many unused workspace approvals; use one or wait for expiry"
        );
        Ok(())
    }

    pub fn issue(&mut self, request: Request, proof: P, issued_at: Instant) -> Result<String> {
        let now = Instant::now();
        self.check_capacity(now)?;
        let ticket = Ticket {
            request,
            proof,
            issued_at,
        };
        ticket.verify_lifetime(now)?;
        let id = Uuid::new_v4();
        self.tickets.insert(id, ticket);
        Ok(id.to_string())
    }

    /// Remove before any filesystem IO. Even stale-scope/expired attempts spend
    /// the ticket; there is no parameter-bearing "execute" endpoint.
    pub fn consume(&mut self, id: Uuid, now: Instant) -> Result<Ticket<P>> {
        let ticket = self
            .tickets
            .remove(&id)
            .context("Unknown or already used workspace approval")?;
        ticket.verify_lifetime(now)?;
        Ok(ticket)
    }
}

impl Ticket<WorkspaceProofs> {
    pub fn verify(&self, current_scope: &Value) -> Result<()> {
        self.verify_lifetime(Instant::now())?;
        ensure!(
            &self.request.scope == current_scope,
            "Approved software, provider, or deletion scope changed; request a new approval"
        );
        self.proof.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Request {
        Request::new("upload", json!({"softwareId":"app-one","providerId":"provider-one","fileIds":["root-a/save.dat"]})).unwrap()
    }

    #[test]
    fn exact_action_schemas_reject_injected_authority_and_empty_selections() {
        assert!(Request::new(
            "upload",
            json!({"softwareId":"app","providerId":"p","approved":true})
        )
        .is_err());
        for field in ["_scopeFingerprint", "_approvedPaths"] {
            let mut params = json!({"softwareId":"app","providerId":"p"});
            params[field] = json!("forged-native-authority");
            assert!(Request::new("upload", params).is_err());
        }
        assert!(Request::new(
            "upload",
            json!({"softwareId":"app","providerId":"p","fileIds":[]})
        )
        .is_err());
        assert!(Request::new(
            "upload",
            json!({"softwareId":"app","providerId":"p","fileIds":["a","a"]})
        )
        .is_err());
        assert!(Request::new(
            "set_autosave",
            json!({"softwareId":"app","providerId":"p","enabled":"true"})
        )
        .is_err());
        assert!(
            Request::new("delete_cloud", json!({"providerId":"p","previewId":"plan"})).is_err()
        );
        assert!(Request::new("connect_unknown", json!({})).is_err());
        assert!(Request::new("track_software", json!({"name":"App","roots":[]})).is_err());
    }

    #[test]
    fn input_validation_is_bounded_and_rejects_deceptive_dialog_text() {
        for name in ["hidden\nline", "hidden\u{202e}text", ""] {
            assert!(Request::new("connect_provider", json!({"kind":"s3","name":name})).is_err());
        }
        assert!(Request::new(
            "upload",
            json!({"softwareId":"a","providerId":"p","fileIds":vec!["file";MAX_SELECTED_FILES+1]})
        )
        .is_err());
        assert!(Request::new("connect_provider", json!({"kind":"s3","name":"Test","credentials":{"secret":"x".repeat(MAX_REQUEST_BYTES)}})).is_err());
        let relative = json!({"name":"App","roots":[{"path":"../outside"}]});
        assert!(Request::new("track_software", relative).is_err());
    }

    #[test]
    fn credentials_never_appear_in_confirmation_and_import_is_read_only() {
        let request = Request::new(
            "connect_provider",
            json!({
                "kind":"s3","name":"Disposable test account","bucket":"fixture",
                "credentials":{"secretAccessKey":"DO_NOT_DISPLAY","accessKeyId":"ALSO_PRIVATE"},
            "fields":{"password":"HIDDEN_TOO","endpoint":"https://synthetic.invalid","folder":"approved-subfolder"}
            }),
        )
        .unwrap();
        let text = request.confirmation_message().unwrap();
        assert!(text.contains("Disposable test account"));
        assert!(text.contains("fixture"));
        assert!(text.contains("https://synthetic.invalid"));
        assert!(text.contains("approved-subfolder"));
        for secret in ["DO_NOT_DISPLAY", "ALSO_PRIVATE", "HIDDEN_TOO"] {
            assert!(!text.contains(secret));
        }
        #[cfg(unix)]
        let request = Request::new(
            "import_noland",
            json!({"stateFile":"/fixture/noland/state.json"}),
        )
        .unwrap();
        #[cfg(windows)]
        let request = Request::new(
            "import_noland",
            json!({"stateFile":r"C:\fixture\noland\state.json"}),
        )
        .unwrap();
        let text = request.confirmation_message().unwrap();
        assert!(text.contains("READ-ONLY"));
        assert!(text.contains("Do not modify No Land"));
    }

    #[test]
    fn single_use_tickets_retain_original_provider_and_selection_and_expire() {
        let now = Instant::now();
        let mut store = TicketStore::default();
        let id = Uuid::parse_str(&store.issue(request(), (), now).unwrap()).unwrap();
        let ticket = store.consume(id, now).unwrap();
        assert_eq!(ticket.request.params()["providerId"], "provider-one");
        assert_eq!(
            ticket.request.params()["fileIds"],
            json!(["root-a/save.dat"])
        );
        assert!(store.consume(id, now).is_err());
        let id = Uuid::parse_str(&store.issue(request(), (), now).unwrap()).unwrap();
        assert!(store.consume(id, now + APPROVAL_TTL).is_err());
        assert!(store.consume(id, now).is_err());
    }

    #[test]
    fn deletion_confirmation_requires_matching_frozen_scope_and_no_hidden_text() {
        let mut request = Request::new(
            "delete_cloud",
            json!({"providerId":"fixture","previewId":"frozen-one","acknowledgeDependencies":true}),
        )
        .unwrap();
        assert!(request.bind_scope(json!({})).is_err());
        assert!(request
            .bind_scope(json!({"deletion":{"previewId":"other","summary":"3 files"}}))
            .is_err());
        assert!(request
            .bind_scope(
                json!({"deletion":{"previewId":"frozen-one","summary":"3 files\nhidden scope"}})
            )
            .is_err());
        request
            .bind_scope(json!({"deletion":{"previewId":"frozen-one","summary":"3 files; 4096 bytes; 2 dependent bundles"}}))
            .unwrap();
        let message = request.confirmation_message().unwrap();
        assert!(message.contains("3 files; 4096 bytes; 2 dependent bundles"));
        assert!(message.contains("explicitly acknowledged"));
    }

    #[test]
    fn automatic_import_and_restore_use_registered_native_handles_not_editable_paths() {
        assert!(Request::new("discover_noland_import", json!({})).is_ok());
        assert!(Request::new("discover_noland_import", json!({"searchRoot":"/"})).is_err());
        assert!(Request::new("import_noland", json!({})).is_err());
        assert!(Request::new(
            "import_noland",
            json!({"sourceId":"native-one","stateFile":"/other/state.json"})
        )
        .is_err());
        assert!(Request::new("import_noland", json!({"sourceId":"native-one"})).is_ok());
        assert!(Request::new(
            "download",
            json!({"providerId":"p","bundleId":"b","appId":"a","destination":"/arbitrary"})
        )
        .is_err());
        let mut restore = Request::new(
            "download",
            json!({"restorePreviewId":"frozen-one","overwriteAcknowledgement":false}),
        )
        .unwrap();
        assert!(restore.bind_scope(json!({"restore":{"previewId":"frozen-one","summary":"1 conflicting file","requiresOverwriteAcknowledgement":true}})).is_err());
        assert!(restore.bind_scope(json!({"restore":{"previewId":"different","summary":"No conflicts","requiresOverwriteAcknowledgement":false}})).is_err());
        restore.bind_scope(json!({"restore":{"previewId":"frozen-one","summary":"No conflicts","requiresOverwriteAcknowledgement":false}})).unwrap();
        assert!(restore
            .confirmation_message()
            .unwrap()
            .contains("No replacement"));
    }

    #[cfg(unix)]
    #[test]
    fn external_recovery_export_pins_parent_not_a_new_file_and_never_renders_key_material() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        let destination = directory.join("new-recovery.key");
        let request = Request::new(
            "export_recovery_key",
            serde_json::json!({
                "providerId":"p","destination":destination,
            }),
        )
        .unwrap();
        let proof = WorkspaceProofs::pin(&request).unwrap();
        assert_eq!(
            proof.worker_identities().unwrap()[0]["path"],
            serde_json::json!(directory)
        );
        assert!(!destination.exists());
        assert!(request
            .confirmation_message()
            .unwrap()
            .contains("NEW external private file"));
        assert!(Request::new(
            "export_recovery_key",
            serde_json::json!({
                "providerId":"p","destination":destination,"key":"not-authority",
            })
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_ticket_pins_only_real_native_bases_and_rejects_replacements() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary
            .path()
            .canonicalize()
            .unwrap()
            .join("Applications");
        std::fs::create_dir(&base).unwrap();
        let missing = base.join("not-present");
        let mut request = Request::new("enable_app_tracking", json!({"enabled":true})).unwrap();
        request.bind_scope(json!({"enrollment":{"baseDirectories":[base,missing],"summary":"Exact verified identities only"}})).unwrap();
        let proof = WorkspaceProofs::pin(&request).unwrap();
        let identities = proof.worker_identities().unwrap();
        assert_eq!(identities.as_array().unwrap().len(), 1);
        assert_eq!(identities[0]["path"], json!(base));
        std::fs::rename(&base, base.with_file_name("retained-Applications")).unwrap();
        std::fs::create_dir(&base).unwrap();
        assert!(proof.verify().is_err());
    }

    #[test]
    fn workspace_ticket_capacity_and_query_pages_are_bounded() {
        let now = Instant::now();
        let mut store = TicketStore::default();
        for _ in 0..MAX_APPROVALS {
            store.issue(request(), (), now).unwrap();
        }
        assert!(store.issue(request(), (), now).is_err());
        store.check_capacity(now + APPROVAL_TTL).unwrap();
        assert!(store.tickets.is_empty());
        assert!(validate_query("software_files", &json!({"softwareId":"app","limit":200})).is_ok());
        assert!(
            validate_query("software_files", &json!({"softwareId":"app","limit":201})).is_err()
        );
        assert!(validate_query("dashboard", &json!({"stateFile":"/unapproved"})).is_err());
        assert!(validate_query("query_anything", &json!({})).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn real_root_and_individual_file_replacements_invalidate_workspace_proofs() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("quicksave-workspace-proof-")
            .tempdir_in(parent)
            .unwrap();
        let root = temp.path().join("approved");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("save.dat");
        std::fs::write(&file, b"first save").unwrap();
        let request = Request::new("add_files", json!({"paths":[file]})).unwrap();
        let proof = WorkspaceProofs::pin(&request).unwrap();
        proof.verify().unwrap();
        let identities = proof.worker_identities().unwrap();
        assert_eq!(identities[0]["kind"], "file");
        assert_eq!(identities[0]["path"], json!(file));
        assert!(identities[0]["stamp"]["file_id"].is_array());
        assert!(identities[0]["parentIdentity"]["fileId"].is_array());
        std::fs::rename(&file, root.join("kept.dat")).unwrap();
        std::fs::write(&file, b"first save").unwrap();
        assert!(proof.verify().is_err());
        let request = Request::new(
            "track_software",
            json!({"name":"Fixture","roots":[{"path":root}]}),
        )
        .unwrap();
        let proof = WorkspaceProofs::pin(&request).unwrap();
        let identities = proof.worker_identities().unwrap();
        assert_eq!(identities[0]["kind"], "directory");
        assert!(identities[0]["identity"]["fileId"].is_array());
        std::fs::rename(&root, temp.path().join("kept-root")).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(proof.verify().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn changed_native_scope_spends_ticket_and_cannot_reuse_provider_authority() {
        let mut request = request();
        request
            .bind_scope(json!({"provider":{"id":"provider-one","generation":1}}))
            .unwrap();
        let proof = WorkspaceProofs::pin(&request).unwrap();
        let now = Instant::now();
        let mut store = TicketStore::default();
        let id = Uuid::parse_str(&store.issue(request, proof, now).unwrap()).unwrap();
        let ticket = store.consume(id, now).unwrap();
        assert!(ticket
            .verify(&json!({"provider":{"id":"provider-one","generation":2}}))
            .is_err());
        assert!(store.consume(id, now).is_err());
    }
}
