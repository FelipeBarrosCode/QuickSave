// SPDX-License-Identifier: GPL-3.0-only
//! Portable frozen-plan validation. Wire/storage protocol remains in No Land.
//! The logical ID algorithm is derived from native_host.rs in the audited fork
//! (upstream e81238a7536aae201540956ce76981364fd36595); notices are preserved there.

use anyhow::{bail, ensure, Context, Result};
use hmac::{Hmac, Mac};
use noland_crypto::{derive_keys, MasterKey};
use noland_state_core::{
    AppId, AppIdentity, BundleManifest, LogicalRoot, PersistenceClass, SemanticRole,
};
use quicksave_platform::{FileStamp, NativeLinkStamp, RootIdentity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{collections::BTreeSet, path::PathBuf};
use uuid::Uuid;

pub(super) const MAX_FILES: usize = 250_000;
pub(super) const MAX_CHUNKS: usize = 1_000_000;
pub(super) const MAX_PLAN_BYTES: usize = 128 * 1024 * 1024;
const PLAN_AAD: &[u8] = b"quicksave-native-windows-frozen-plan-v1";
const PLAN_MAC: &[u8] = b"QuickSave Windows native operation binding v1\0";

/// Portable equivalent of the audited agent's NativeRootRole. No Linux agent
/// dependency is introduced merely to reuse this classification contract.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum NativeRootRole {
    Installation,
    Installer,
    Save,
    Config,
    Runtime,
    Container,
    GroupContainer,
    Data,
    Manual,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum NativeCoverage {
    #[default]
    LegacyExactSelection,
    FullApprovedScope,
    SelectedNodes,
}
pub(super) fn capture_coverage(selection: &Value) -> Result<NativeCoverage> {
    Ok(
        match selection
            .pointer("/captureSource/selectionKind")
            .and_then(Value::as_str)
        {
            Some("full_scope") => NativeCoverage::FullApprovedScope,
            Some("selected_nodes") | None => NativeCoverage::SelectedNodes,
            Some(_) => bail!("unknown authenticated native capture coverage"),
        },
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureScope {
    pub version: u32,
    pub work_id: String,
    pub metadata_identity: String,
    pub node_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_scope: Option<super::full_scope::FullScopeBinding>,
}
impl CaptureScope {
    pub fn full_scope_from_evidence(
        evidence: &Value,
    ) -> Result<super::full_scope::FullScopeBinding> {
        super::full_scope::FullScopeBinding::from_evidence(evidence)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.node_count <= MAX_FILES
                && (self.node_count > 0 || self.full_scope.is_some()),
            "native metadata capture scope version/count is invalid"
        );
        bounded_text(&self.work_id, 128)?;
        bounded_text(&self.metadata_identity, 512)?;
        if let Some(full) = &self.full_scope {
            full.validate()?;
            ensure!(
                self.node_count.saturating_add(full.deleted_count) <= MAX_FILES,
                "native live/deleted capture node bound exceeded"
            );
        }
        Ok(())
    }
}
impl NativeRootRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installation => "installation",
            Self::Installer => "installer",
            Self::Save => "save",
            Self::Config => "config",
            Self::Runtime => "runtime",
            Self::Container => "container",
            Self::GroupContainer => "group_container",
            Self::Data => "data",
            Self::Manual => "manual",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "installation" => Self::Installation,
            "installer" => Self::Installer,
            "save" => Self::Save,
            "config" => Self::Config,
            "runtime" => Self::Runtime,
            "container" => Self::Container,
            "group_container" => Self::GroupContainer,
            "data" => Self::Data,
            "manual" => Self::Manual,
            _ => bail!("unknown native application root role"),
        })
    }
    pub fn classification(self) -> (PersistenceClass, SemanticRole) {
        match self {
            Self::Installation | Self::Installer => (
                PersistenceClass::ReconstructableApp,
                SemanticRole::AppContent,
            ),
            Self::Runtime => (PersistenceClass::SharedState, SemanticRole::SharedRuntime),
            Self::GroupContainer => (PersistenceClass::SharedState, SemanticRole::UserState),
            Self::Save | Self::Config | Self::Container | Self::Data | Self::Manual => {
                (PersistenceClass::PersistentState, SemanticRole::UserState)
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RootSpec {
    pub id: String,
    pub logical: String,
    pub path: PathBuf,
    pub identity: RootIdentity,
    pub allowed_files: Option<BTreeSet<String>>,
    pub role: NativeRootRole,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ExpectedFile {
    pub id: String,
    pub root: String,
    pub relative: String,
    pub stamp: FileStamp,
    pub size: u64,
    pub hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct FrozenMetadata {
    pub root: String,
    pub relative: String,
    pub directory: bool,
    pub stamp: FileStamp,
    pub link: Option<NativeLinkStamp>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CaptureOrigin {
    pub generation: u64,
    pub automatic: bool,
    pub authorization: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Work {
    Upload {
        software: String,
        software_instance_id: String,
        app: AppId,
        name: String,
        source_identity: AppIdentity,
        roots: Vec<RootSpec>,
        snapshot: String,
        files: Vec<ExpectedFile>,
        metadata: Vec<FrozenMetadata>,
        complete_approved_scope: bool,
        #[serde(default)]
        coverage: NativeCoverage,
        #[serde(default)]
        capture_scope: Option<CaptureScope>,
        #[serde(default)]
        capture_origin: Option<CaptureOrigin>,
        #[serde(default)]
        full_snapshot: Option<super::full_scope::FullSnapshot>,
        #[serde(default)]
        reuse_epoch: Option<String>,
        bundle: Uuid,
        commit: Uuid,
    },
    Download {
        app: AppId,
        bundle: Uuid,
        commit: Uuid,
        manifest_hash: String,
        preview_id: Uuid,
        frozen_plan_fingerprint: String,
        files: Option<BTreeSet<(String, String)>>,
        destination: PathBuf,
        identity: RootIdentity,
    },
    Delete {
        plan: noland_storage::FullDeletionPlan,
        dependency_ack: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct FrozenPlan {
    pub version: u32,
    pub api: u32,
    pub operation: Uuid,
    pub instance: Uuid,
    pub provider: String,
    pub storage: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub work: Work,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPlan {
    plan: FrozenPlan,
    mac: Vec<u8>,
}

impl FrozenPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.api == 22,
            "native frozen-plan version/API mismatch"
        );
        ensure!(
            !self.operation.is_nil() && !self.instance.is_nil(),
            "native frozen-plan identity is invalid"
        );
        validate_id(&self.provider)?;
        bounded_text(&self.storage, 4096)?;
        match &self.work {
            Work::Upload {
                software,
                software_instance_id,
                app,
                name,
                source_identity,
                roots,
                snapshot,
                files,
                metadata,
                complete_approved_scope,
                coverage,
                capture_scope,
                capture_origin,
                full_snapshot,
                reuse_epoch,
                bundle,
                commit,
            } => {
                validate_id(software)?;
                bounded_text(software_instance_id, 512)?;
                validate_id(app.as_str())?;
                bounded_text(name, 256)?;
                ensure!(
                    &source_identity.app_id == app,
                    "frozen source application identity changed"
                );
                ensure!(
                    files.len().saturating_add(metadata.len()) <= MAX_FILES,
                    "frozen file/metadata entry bound exceeded"
                );
                ensure!(
                    *complete_approved_scope == (*coverage == NativeCoverage::FullApprovedScope),
                    "native complete mode differs from its authenticated coverage"
                );
                if let Some(steam) = source_identity.steam_app_id {
                    ensure!(
                        *app == AppId::steam(steam),
                        "frozen Steam application identity mismatch"
                    );
                }
                bounded_text(snapshot, 512)?;
                ensure!(
                    !bundle.is_nil() && !commit.is_nil(),
                    "invalid frozen revision"
                );
                ensure!(
                    !roots.is_empty()
                        && roots.len() <= 128
                        && (!files.is_empty()
                            || capture_scope.is_some()
                                && (!metadata.is_empty() || full_snapshot.is_some()))
                        && files.len() <= MAX_FILES,
                    "frozen capture is outside its bounds"
                );
                let mut roots_seen = BTreeSet::new();
                if let Some(scope) = capture_scope {
                    scope.validate()?;
                    ensure!(
                        scope.node_count == files.len().saturating_add(metadata.len())
                            && scope.metadata_identity == *snapshot,
                        "native capture scope changed its frozen nodes/metadata identity"
                    );
                }
                if let Some(origin) = capture_origin {
                    let tracking = &origin.authorization["trackingScope"];
                    ensure!(
                        capture_scope.is_some()
                            && origin.authorization.is_object()
                            && tracking.is_object()
                            && origin.authorization["trackingGrant"].is_object(),
                        "native capture completion lost its original generation/authorization"
                    );
                    ensure!(
                        tracking["softwareId"] == *software
                            && tracking["appId"] == *software_instance_id
                            && tracking["sourceIdentity"]["app_id"].as_str() == Some(app.as_str()),
                        "native capture confused workspace, installation or canonical identity"
                    );
                    let approved = tracking["roots"]
                        .as_array()
                        .context("original signed tracking roots are missing")?;
                    ensure!(
                        approved.len() == roots.len(),
                        "native capture root scope changed"
                    );
                    for (given, root) in approved.iter().zip(roots) {
                        ensure!(given["id"] == root.id && given["path"] == json!(root.path)
                            && given["role"] == root.role.as_str()
                            && given["identity"] == json!(root.identity)
                            && given["allowedFiles"] == json!(root.allowed_files)
                            && given["directory"] != false,
                            "original native capture role/kind/path/allowlist/full-ID root scope changed");
                    }
                }
                ensure!((*coverage == NativeCoverage::FullApprovedScope) == full_snapshot.is_some(),
                    "full native coverage requires the actual frozen Rust proof, never a selection marker");
                if let Some(full) = full_snapshot {
                    let scope = capture_scope
                        .as_ref()
                        .context("full native snapshot has no original capture scope")?;
                    full.validate_scope(
                        app,
                        software,
                        software_instance_id,
                        &self.provider,
                        scope,
                        roots,
                    )?;
                    if let Some(origin) = capture_origin {
                        ensure!(
                            full.evidence["generation"].as_u64() == Some(origin.generation)
                                && full.evidence["authorization"]["trackingScope"]
                                    == origin.authorization["trackingScope"],
                            "native full-scope generation differs from its original captured work"
                        );
                    }
                    full.verify_ids(
                        &files
                            .iter()
                            .map(|file| file.id.clone())
                            .chain(
                                metadata
                                    .iter()
                                    .map(|entry| file_id(&entry.root, &entry.relative)),
                            )
                            .collect::<BTreeSet<_>>(),
                    )?;
                } else {
                    ensure!(
                        capture_scope
                            .as_ref()
                            .is_none_or(|scope| scope.full_scope.is_none()),
                        "full-scope header cannot authorize a selected-node capture"
                    );
                }
                if let Some(epoch) = reuse_epoch {
                    ensure!(
                        capture_scope.is_some(),
                        "native reuse epoch requires a Rust capture controller"
                    );
                    bounded_text(epoch, 512)?;
                }
                for root in roots {
                    validate_id(&root.id)?;
                    ensure!(
                        root.logical == logical_token(app.as_str(), &root.id),
                        "frozen root token differs from its native identity"
                    );
                    ensure!(
                        roots_seen.insert(root.logical.as_str()),
                        "duplicate frozen root"
                    );
                    ensure!(
                        root.path.is_absolute()
                            && root.path.to_str().is_some_and(|p| p.len() <= 32768),
                        "invalid frozen absolute root"
                    );
                    ensure!(
                        root.identity.file_id != [0; 2],
                        "missing native 128-bit root ID"
                    );
                    if let Some(allowed) = &root.allowed_files {
                        ensure!(
                            !allowed.is_empty() && allowed.len() <= MAX_FILES,
                            "invalid leaf scope"
                        );
                        for leaf in allowed {
                            validate_relative(leaf)?;
                            ensure!(
                                !leaf.contains('/'),
                                "manual leaf scope cannot expand a directory"
                            );
                        }
                    }
                }
                let mut seen = BTreeSet::new();
                let mut path_bytes = 0usize;
                for file in files {
                    validate_relative(&file.relative)?;
                    mtime_ns_from_stamp(&file.stamp)?;
                    if capture_scope.is_some() {
                        ensure!(
                            file.hash.is_empty(),
                            "metadata-only capture cannot predict source hashes"
                        );
                    } else {
                        ensure!(
                            file.hash == canonical_hash(&file.hash)?,
                            "noncanonical capture hash"
                        );
                    }
                    ensure!(
                        file.size == file.stamp.size
                            && file.stamp.modified_nanoseconds < 1_000_000_000
                            && file.stamp.changed_nanoseconds < 1_000_000_000,
                        "frozen size and native stamp disagree"
                    );
                    ensure!(
                        file.stamp.file_id != [0; 2],
                        "missing native 128-bit source ID"
                    );
                    ensure!(
                        file.id == file_id(&file.root, &file.relative),
                        "frozen file ID mismatch"
                    );
                    ensure!(seen.insert(file.id.clone()), "duplicate frozen file");
                    let root = roots
                        .iter()
                        .find(|r| r.logical == file.root)
                        .context("frozen file is outside approved roots")?;
                    ensure!(
                        root.allowed_files
                            .as_ref()
                            .is_none_or(|leaves| leaves.contains(&file.relative)),
                        "frozen file is outside the manual leaf scope"
                    );
                    path_bytes = path_bytes
                        .checked_add(file.relative.len())
                        .context("frozen path byte overflow")?;
                    ensure!(
                        path_bytes <= 32 * 1024 * 1024,
                        "frozen path memory bound exceeded"
                    );
                }
                for entry in metadata {
                    validate_relative(&entry.relative)?;
                    mtime_ns_from_stamp(&entry.stamp)?;
                    let root = roots
                        .iter()
                        .find(|root| root.logical == entry.root)
                        .context("frozen metadata is outside approved roots")?;
                    ensure!(
                        root.allowed_files.is_none(),
                        "a manual regular-file leaf cannot become a directory or link scope"
                    );
                    ensure!(
                        seen.insert(file_id(&entry.root, &entry.relative)),
                        "duplicate frozen metadata entry"
                    );
                    ensure!(
                        entry.stamp.file_id != [0; 2]
                            && entry.stamp.modified_nanoseconds < 1_000_000_000
                            && entry.stamp.changed_nanoseconds < 1_000_000_000,
                        "missing native metadata 128-bit ID"
                    );
                    match (&entry.link, entry.directory) {
                        (None, true) => {}
                        (Some(link), false)
                            if link.stamp == entry.stamp && link.target_is_directory.is_some() =>
                        {
                            noland_state_core::validate_relative_symlink_target_within_root(
                                &entry.relative,
                                &link.target,
                            )
                            .map_err(super::source_error)?;
                        }
                        _ => bail!("frozen metadata kind/identity mismatch"),
                    }
                    path_bytes = path_bytes
                        .checked_add(entry.relative.len())
                        .context("frozen metadata path byte overflow")?;
                    ensure!(
                        path_bytes <= 32 * 1024 * 1024,
                        "frozen metadata path byte bound exceeded"
                    );
                }
            }
            Work::Download {
                app,
                bundle,
                commit,
                manifest_hash,
                preview_id,
                frozen_plan_fingerprint,
                files,
                destination,
                identity,
            } => {
                validate_id(app.as_str())?;
                ensure!(
                    !bundle.is_nil()
                        && !commit.is_nil()
                        && !preview_id.is_nil()
                        && frozen_plan_fingerprint.len() == 64
                        && frozen_plan_fingerprint
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit()),
                    "invalid restore revision"
                );
                canonical_hash(manifest_hash)?;
                ensure!(
                    destination.is_absolute()
                        && destination.to_str().is_some_and(|p| p.len() <= 32768)
                        && identity.file_id != [0; 2],
                    "invalid native restore destination"
                );
                if let Some(files) = files {
                    ensure!(
                        !files.is_empty() && files.len() <= MAX_FILES,
                        "invalid restore selection"
                    );
                    for (root, relative) in files {
                        ensure!(
                            LogicalRoot::parse(root).is_some(),
                            "unknown restore logical root"
                        );
                        validate_relative(relative)?;
                    }
                }
            }
            Work::Delete {
                plan,
                dependency_ack,
            } => {
                ensure!(
                    plan.plan_id == self.operation
                        && plan.operation_id == self.operation
                        && !plan.automatic
                        && !plan.targets.is_empty()
                        && plan.targets.len() <= 10_000
                        && plan.packs.len() <= 200_000,
                    "deletion plan identity or bounds changed"
                );
                ensure!(
                    plan.requested_count > 0
                        && plan.requested_count <= plan.targets.len()
                        && (plan.requested_count == plan.targets.len() || *dependency_ack),
                    "dependent backups lack the original explicit acknowledgement"
                );
            }
        }
        Ok(())
    }

    pub fn kind(&self) -> &'static str {
        match self.work {
            Work::Upload { .. } => "backup",
            Work::Download { .. } => "restore",
            Work::Delete { .. } => "delete",
        }
    }

    pub fn app(&self) -> Option<AppId> {
        match &self.work {
            Work::Upload { app, .. } | Work::Download { app, .. } => Some(app.clone()),
            Work::Delete { .. } => None,
        }
    }

    pub fn seal(&self, master: &MasterKey) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_PLAN_BYTES,
            "native frozen plan exceeds its document bound"
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derive_keys(master).manifest)?;
        mac.update(PLAN_MAC);
        mac.update(&bytes);
        bytes.fill(0);
        let envelope = AuthenticatedPlan {
            plan: self.clone(),
            mac: mac.finalize().into_bytes().to_vec(),
        };
        Ok(
            noland_storage::seal_metadata(&derive_keys(master).manifest, PLAN_AAD, &envelope)?
                .envelope,
        )
    }

    pub fn open(bytes: Vec<u8>, master: &MasterKey) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PLAN_BYTES + 1024 * 1024,
            "native frozen envelope exceeds its bound"
        );
        let envelope: AuthenticatedPlan = noland_storage::open_metadata_with_limit(
            &derive_keys(master).manifest,
            PLAN_AAD,
            bytes,
            MAX_PLAN_BYTES as u64,
        )?;
        let mut bytes = serde_json::to_vec(&envelope.plan)?;
        ensure!(
            bytes.len() <= MAX_PLAN_BYTES,
            "native frozen plan exceeds its bound"
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derive_keys(master).manifest)?;
        mac.update(PLAN_MAC);
        mac.update(&bytes);
        bytes.fill(0);
        mac.verify_slice(&envelope.mac)
            .map_err(|_| anyhow::anyhow!("native frozen-plan HMAC failed"))?;
        envelope.plan.validate()?;
        Ok(envelope.plan)
    }
}

pub(super) fn logical_token(app: &str, root: &str) -> String {
    fn hex(text: &str) -> String {
        text.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    LogicalRoot::NolandCustomRoot {
        id: format!("quicksave-v1-{}-{}", hex(app), hex(root)),
    }
    .as_token()
}

fn tracking_root(token: &str) -> Option<String> {
    let LogicalRoot::NolandCustomRoot { id } = LogicalRoot::parse(token)? else {
        return None;
    };
    let (_, root) = id.strip_prefix("quicksave-v1-")?.split_once('-')?;
    if root.is_empty() || root.len() > 1024 || !root.len().is_multiple_of(2) || !root.is_ascii() {
        return None;
    }
    let bytes = (0..root.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&root[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    let root = String::from_utf8(bytes).ok()?;
    (!root.chars().any(char::is_control)).then_some(root)
}

pub(super) fn file_id(root: &str, relative: &str) -> String {
    let root = tracking_root(root).unwrap_or_else(|| root.to_owned());
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave logical file v1\0");
    hash.update(&(root.len() as u64).to_le_bytes());
    hash.update(root.as_bytes());
    hash.update(relative.as_bytes());
    format!("file-{}", hash.finalize().to_hex())
}

/// Shared v3 native-root contract: actual root kind, conservative original leaf,
/// role and complete native identity are part of both receipts and publication.
pub(super) fn root_leaf(root: &RootSpec) -> Result<&str> {
    let leaf = root
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .context("native root must have a real original basename")?;
    noland_state_core::native_layout::validate_native_layout_leaf(leaf)
        .map_err(super::source_error)?;
    Ok(leaf)
}

pub(super) fn native_root_layouts_value(
    app: &AppId,
    instance: &str,
    roots: &[RootSpec],
    selected: Option<&BTreeSet<&str>>,
) -> Result<Value> {
    for root in roots
        .iter()
        .filter(|root| selected.is_none_or(|tokens| tokens.contains(root.logical.as_str())))
    {
        ensure!(
            quicksave_platform::SafeRoot::open(&root.path)?.identity()? == root.identity,
            "native root layout identity changed"
        );
    }
    frozen_root_layouts_value(app, instance, roots, selected)
}

/// Pure projection of the already device-authenticated frozen native roots.
/// Completion never reopens/scans live software to reconstruct old capture.
pub(super) fn frozen_root_layouts_value(
    app: &AppId,
    instance: &str,
    roots: &[RootSpec],
    selected: Option<&BTreeSet<&str>>,
) -> Result<Value> {
    bounded_text(instance, 256)?;
    let layouts = roots
        .iter()
        .filter(|root| selected.is_none_or(|tokens| tokens.contains(root.logical.as_str())))
        .map(|root| {
            // Every currently registered Windows root is a real pinned directory.
            // A manual file allowlist does not fabricate an approved file-root ID.
            Ok(
                json!({"logical_root":root.logical,"root_id":root.id,"role":root.role,
                "source_kind":"directory","leaf_name":root_leaf(root)?}),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !layouts.is_empty() && layouts.len() <= 64,
        "native root layout count is invalid"
    );
    Ok(
        json!({"version":1,"platform":"windows","app_id":app.as_str(),
        "software_instance_id":instance,"roots":layouts}),
    )
}

pub(super) fn native_roots_fingerprint(app: &AppId, roots: &[RootSpec]) -> Result<String> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"quicksave-native-roots-v3\0");
    hash.update(app.as_str().as_bytes());
    for root in roots {
        hash.update(&(root.id.len() as u64).to_le_bytes());
        hash.update(root.id.as_bytes());
        hash.update(root.role.as_str().as_bytes());
        hash.update(&[0]);
        hash.update(b"directory\0");
        let leaf = root_leaf(root)?;
        hash.update(&(leaf.len() as u64).to_le_bytes());
        hash.update(leaf.as_bytes());
        hash.update(
            root.path
                .to_str()
                .context("native root path must be Unicode")?
                .as_bytes(),
        );
        hash.update(&root.identity.device.to_le_bytes());
        for word in root.identity.file_id {
            hash.update(&word.to_le_bytes());
        }
        if let Some(leaves) = &root.allowed_files {
            hash.update(b"allowed-files\0");
            for leaf in leaves {
                hash.update(&(leaf.len() as u64).to_le_bytes());
                hash.update(leaf.as_bytes());
            }
        } else {
            hash.update(b"whole-root\0");
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

pub(super) fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 256
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:.-@".contains(&byte)),
        "invalid native metadata identifier"
    );
    Ok(())
}

pub(super) fn identifier(value: &Value, key: &str) -> Result<String> {
    let id = value[key]
        .as_str()
        .with_context(|| format!("{key} is required"))?;
    validate_id(id)?;
    Ok(id.into())
}

pub(super) fn bounded_text(text: &str, limit: usize) -> Result<String> {
    ensure!(
        !text.is_empty() && text.len() <= limit && !text.chars().any(char::is_control),
        "untrusted metadata text is invalid"
    );
    Ok(text.into())
}

pub(super) fn canonical_hash(hash: &str) -> Result<String> {
    let hash = hash.strip_prefix("blake3:").unwrap_or(hash);
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected BLAKE3 hash is invalid"
    );
    Ok(format!("blake3:{}", hash.to_ascii_lowercase()))
}

pub(super) fn mtime_ns_from_stamp(stamp: &FileStamp) -> Result<i64> {
    ensure!(
        stamp.modified_nanoseconds < 1_000_000_000,
        "native mtime has an invalid nanosecond component"
    );
    i64::try_from(
        stamp.modified_seconds as i128 * 1_000_000_000 + i128::from(stamp.modified_nanoseconds),
    )
    .context("native mtime is outside the exact signed No Land nanosecond range")
}

pub(super) fn validate_relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 32768
            && !path.contains(['\\', '\0', ':'])
            && path.split('/').count() <= 128,
        "invalid native relative path"
    );
    for part in path.split('/') {
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && !part.ends_with(['.', ' '])
                && !part
                    .chars()
                    .any(|c| c < ' ' || matches!(c, '<' | '>' | '"' | '|' | '?' | '*')),
            "invalid Windows path component"
        );
        let stem = part.split('.').next().unwrap().to_ascii_uppercase();
        ensure!(
            !matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) && !(stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "reserved Windows device path"
        );
    }
    Ok(())
}

pub(super) fn file_item(root: &str, relative: &str, kind: &str, size: u64) -> Result<Value> {
    ensure!(
        LogicalRoot::parse(root).is_some(),
        "unknown authenticated logical root"
    );
    validate_relative(relative)?;
    ensure!(
        matches!(kind, "file" | "directory" | "symlink"),
        "unknown native file type"
    );
    Ok(json!({
        "id":file_id(root, relative), "name":relative.rsplit('/').next().unwrap(),
        "path":relative,"directory":kind == "directory","size":size,
        "rootId":root,"fileType":kind,
    }))
}

pub(super) fn page(mut files: Vec<Value>, params: &Value) -> Result<Value> {
    files.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let offset = match params.get("cursor") {
        None | Some(Value::Null) => 0,
        Some(Value::String(text)) if text.len() <= 16 => text.parse::<usize>()?,
        _ => bail!("invalid file cursor"),
    };
    ensure!(
        offset <= files.len(),
        "file cursor is outside the current inventory"
    );
    let limit = params
        .get("limit")
        .map(|v| v.as_u64().context("invalid page limit"))
        .transpose()?
        .unwrap_or(200)
        .min(1000) as usize;
    ensure!(limit > 0, "file page limit must be positive");
    let end = offset.saturating_add(limit).min(files.len());
    Ok(json!({
        "files":files.drain(offset..end).collect::<Vec<_>>(),
        "nextCursor":(end < files.len()).then(|| end.to_string()),
    }))
}

/// The caller's index is already sorted and immutable. Clone only the requested
/// page, not a 250k-entry native inventory on every UI request.
pub(super) fn indexed_page(files: &[Value], params: &Value, revision: &str) -> Result<Value> {
    let offset = match params.get("cursor") {
        None | Some(Value::Null) => 0,
        Some(Value::String(cursor)) if cursor.len() <= 128 => {
            let (bound, offset) = cursor
                .rsplit_once('.')
                .context("invalid revision-bound cursor")?;
            ensure!(
                bound == revision,
                "native file index revision changed; restart pagination"
            );
            offset.parse::<usize>()?
        }
        _ => bail!("invalid revision-bound cursor"),
    };
    ensure!(offset <= files.len(), "cursor is outside the native index");
    let limit = params
        .get("limit")
        .map(|v| v.as_u64().context("invalid page limit"))
        .transpose()?
        .unwrap_or(200)
        .clamp(1, 1000) as usize;
    let end = offset.saturating_add(limit).min(files.len());
    Ok(json!({
        "files":&files[offset..end],"indexRevision":revision,
        "nextCursor":(end < files.len()).then(|| format!("{revision}.{end}")),
    }))
}

pub(super) fn selected_manifest(
    manifest: &BundleManifest,
    selection: &Value,
) -> Result<Option<BTreeSet<(String, String)>>> {
    let Some(ids) = selection.get("fileIds") else {
        return Ok(None);
    };
    let ids = ids.as_array().context("fileIds must be an exact array")?;
    ensure!(
        !ids.is_empty() && ids.len() <= MAX_FILES,
        "select 1–250000 exact files"
    );
    let lookup = manifest
        .files
        .iter()
        .map(|file| (file_id(&file.logical_root, &file.relative_path), file))
        .collect::<std::collections::BTreeMap<_, _>>();
    ensure!(
        lookup.len() == manifest.files.len(),
        "ambiguous authenticated manifest selection"
    );
    let mut selected = BTreeSet::new();
    for id in ids {
        let file = lookup
            .get(id.as_str().context("selected file ID must be text")?)
            .context("selected file is outside the authenticated manifest")?;
        ensure!(
            file.file_type != "directory",
            "directory expansion is not authorized"
        );
        ensure!(
            selected.insert((file.logical_root.clone(), file.relative_path.clone())),
            "duplicate selected file"
        );
    }
    Ok(Some(selected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ids_are_lossless_and_match_tracker_root_names() {
        let token = logical_token("quicksave:game", "save-root");
        assert_eq!(tracking_root(&token).as_deref(), Some("save-root"));
        assert_eq!(file_id(&token, "a/b"), file_id("save-root", "a/b"));
        assert_ne!(file_id(&token, "a/b"), file_id(&token, "ab"));
        let id = RootIdentity {
            device: 7,
            file_id: [11, u64::MAX],
        };
        assert_eq!(
            serde_json::from_value::<RootIdentity>(serde_json::to_value(&id).unwrap()).unwrap(),
            id
        );
    }

    #[test]
    fn windows_path_aliases_and_ads_are_not_canonical_files() {
        for invalid in [
            "a/../b",
            "a//b",
            "a\\b",
            "a:stream",
            "a.",
            "a ",
            "CON",
            "nul.txt",
            "LPT1",
            "/absolute",
        ] {
            assert!(validate_relative(invalid).is_err(), "{invalid}");
        }
        assert!(validate_relative("Saves/game-1.dat").is_ok());
    }

    #[test]
    fn authenticated_plan_rejects_wrong_key_tampering_and_identity_changes() {
        let master = MasterKey::from_bytes([7; 32]);
        // Use a restore plan so this portable test needs no filesystem or account.
        let plan = FrozenPlan {
            version: 1,
            api: 22,
            operation: Uuid::new_v4(),
            instance: Uuid::new_v4(),
            provider: "fixture".into(),
            storage: "fixture-root".into(),
            created_at: chrono::Utc::now(),
            work: Work::Download {
                app: AppId("fixture".into()),
                bundle: Uuid::new_v4(),
                commit: Uuid::new_v4(),
                manifest_hash: format!("blake3:{}", "a".repeat(64)),
                preview_id: Uuid::new_v4(),
                frozen_plan_fingerprint: "b".repeat(64),
                files: None,
                // Host absolute path only for portable plan validation; never opened.
                destination: std::env::temp_dir(),
                identity: RootIdentity {
                    device: 2,
                    file_id: [3, 1 << 63],
                },
            },
        };
        let bytes = plan.seal(&master).unwrap();
        let opened = FrozenPlan::open(bytes.clone(), &master).unwrap();
        assert_eq!(opened.operation, plan.operation);
        assert!(FrozenPlan::open(bytes.clone(), &MasterKey::from_bytes([8; 32])).is_err());
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(FrozenPlan::open(corrupt, &master).is_err());
        let mut foreign = plan;
        foreign.api = 21;
        assert!(foreign.seal(&master).is_err());
    }

    #[test]
    fn metadata_capture_binds_coverage_instance_and_no_predicted_hashes() {
        let app = AppId::steam(480);
        let root = logical_token(app.as_str(), "actual-native-root");
        let stamp = FileStamp {
            device: 7,
            file_id: [11, 1 << 63],
            size: 0,
            modified_seconds: 1,
            modified_nanoseconds: 100,
            changed_seconds: 2,
            changed_nanoseconds: 200,
        };
        let mut plan = FrozenPlan {
            version: 1,
            api: 22,
            operation: Uuid::new_v4(),
            instance: Uuid::new_v4(),
            provider: "fixture".into(),
            storage: "fixture".into(),
            created_at: chrono::Utc::now(),
            work: Work::Upload {
                software: "software-fixture".into(),
                software_instance_id: "steam:480@native-fixture".into(),
                app: app.clone(),
                name: "Fixture".into(),
                source_identity: AppIdentity::new(app, "Fixture"),
                roots: vec![RootSpec {
                    id: "actual-native-root".into(),
                    logical: root.clone(),
                    path: std::env::temp_dir(),
                    identity: RootIdentity {
                        device: 7,
                        file_id: [12, 1 << 63],
                    },
                    allowed_files: None,
                    role: NativeRootRole::Save,
                }],
                snapshot: "metadata-fixture".into(),
                files: vec![ExpectedFile {
                    id: file_id(&root, "empty.dat"),
                    root,
                    relative: "empty.dat".into(),
                    stamp,
                    size: 0,
                    hash: String::new(),
                }],
                metadata: Vec::new(),
                complete_approved_scope: false,
                coverage: NativeCoverage::SelectedNodes,
                capture_scope: Some(CaptureScope {
                    version: 1,
                    work_id: "work-fixture".into(),
                    metadata_identity: "metadata-fixture".into(),
                    node_count: 1,
                    full_scope: None,
                }),
                capture_origin: None,
                full_snapshot: None,
                reuse_epoch: None,
                bundle: Uuid::new_v4(),
                commit: Uuid::new_v4(),
            },
        };
        plan.validate().unwrap();
        let key = MasterKey::from_bytes([8; 32]);
        let opened = FrozenPlan::open(plan.seal(&key).unwrap(), &key).unwrap();
        let Work::Upload {
            app,
            software_instance_id,
            files,
            ..
        } = opened.work
        else {
            panic!("wrong plan kind")
        };
        assert_eq!(app, AppId::steam(480));
        assert_eq!(software_instance_id, "steam:480@native-fixture");
        assert_eq!(files[0].stamp.file_id, [11, 1 << 63]);
        let Work::Upload {
            complete_approved_scope,
            ..
        } = &mut plan.work
        else {
            unreachable!()
        };
        *complete_approved_scope = true;
        assert!(
            plan.validate().is_err(),
            "selecting nodes cannot silently become complete mode"
        );
        let Work::Upload { coverage, .. } = &mut plan.work else {
            unreachable!()
        };
        *coverage = NativeCoverage::FullApprovedScope;
        assert!(
            plan.validate().is_err(),
            "an unauthenticated full-scope marker cannot authorize complete/empty capture"
        );
        let Work::Upload { capture_scope, .. } = &mut plan.work else {
            unreachable!()
        };
        *capture_scope = None;
        assert!(
            plan.validate().is_err(),
            "legacy expected-file work must provide its canonical hash"
        );
        assert!(matches!(
            capture_coverage(&json!({})).unwrap(),
            NativeCoverage::SelectedNodes
        ));
        assert!(capture_coverage(&json!({"captureSource":{"selectionKind":"unknown"}})).is_err());
    }

    #[test]
    fn native_mtime_is_exact_at_negative_boundaries_and_never_silently_omitted() {
        let mut stamp = FileStamp {
            device: 7,
            file_id: [11, 19],
            size: 0,
            modified_seconds: -9_223_372_037,
            modified_nanoseconds: 145_224_200,
            changed_seconds: 1,
            changed_nanoseconds: 0,
        };
        assert_eq!(mtime_ns_from_stamp(&stamp).unwrap(), i64::MIN + 8);
        stamp.modified_seconds = i64::MAX;
        assert!(mtime_ns_from_stamp(&stamp).is_err());
        stamp.modified_seconds = 0;
        stamp.modified_nanoseconds = 1_000_000_000;
        assert!(mtime_ns_from_stamp(&stamp).is_err());
    }
}
