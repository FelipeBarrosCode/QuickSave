// SPDX-License-Identifier: GPL-3.0-only
//! Native-library authority adapter. Capture, hashing, packing, admission and
//! publication remain in the source engine. Explicit roots replace discovery,
//! not the source engine's generation, stable-file or authenticated-retry guards.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use noland_snapshot::SourcePath;
use noland_state_core::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::StateAgent;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct NativeFileKey {
    pub logical_root: String,
    pub relative_path: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeSelection {
    pub version: u32,
    /// Uploads always freeze exact keys. Some(empty) is valid only with an
    /// installed native full-scope capability; it never means "all files".
    pub file_keys: Option<Vec<NativeFileKey>>,
    pub roots_fingerprint: String,
    pub destination: Option<PathBuf>,
    pub destination_identity: Option<(u64, u64)>,
    #[serde(default)]
    pub snapshot_identity: Option<String>,
    #[serde(default)]
    pub expected_files: Option<Vec<NativeExpectedFile>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_scope: Option<crate::native_capture::NativeCaptureScope>,
    #[serde(default)]
    pub coverage: NativeCoverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_instance_id: Option<String>,
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeCoverage {
    /// Old native records froze exact keys but did not authenticate completeness.
    #[default]
    LegacyExactSelection,
    /// Every node in the approved, evidenced roots, not all possible app data.
    FullApprovedScope,
    SelectedNodes,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExpectedFile {
    pub id: String,
    pub size: u64,
    pub file_hash: String,
}

pub type NativePublicationGuard = Arc<dyn Fn() -> Result<()> + Send + Sync>;

impl NativeSelection {
    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let mut selected: Self = serde_json::from_value(value.clone())?;
        if selected.version != 1 || selected.roots_fingerprint.len() != 64 {
            return Err(StateError::Invalid(
                "invalid native selection binding".into(),
            ));
        }
        if selected
            .software_instance_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            return Err(StateError::Invalid(
                "invalid native software-instance identity".into(),
            ));
        }
        if let Some(keys) = &selected.file_keys {
            if keys.len() > 250_000
                || (keys.is_empty()
                    && (selected.coverage != NativeCoverage::FullApprovedScope
                        || selected
                            .capture_scope
                            .as_ref()
                            .is_none_or(|scope| scope.full_scope.is_none())
                        || selected.destination.is_some()))
            {
                return Err(StateError::Invalid("select 1–250000 files".into()));
            }
            let mut unique = BTreeSet::new();
            for key in keys {
                if LogicalRoot::parse(&key.logical_root).is_none()
                    || !unique.insert(key)
                    || key.relative_path.len() > 32_768
                {
                    return Err(StateError::UnsafePath(
                        "invalid or duplicate native file key".into(),
                    ));
                }
                validate_native_relative(&key.relative_path)?;
            }
        }
        if let Some(keys) = &mut selected.file_keys {
            keys.sort();
        }
        if selected.destination.is_none() {
            let keys = selected.file_keys.as_ref().ok_or_else(|| {
                StateError::Invalid("native upload requires frozen exact file keys".into())
            })?;
            if let Some(scope) = &selected.capture_scope {
                scope.validate()?;
                if selected.expected_files.is_some()
                    || selected.software_instance_id.is_none()
                    || scope.node_count != keys.len()
                    || selected.snapshot_identity.as_deref()
                        != Some(scope.metadata_identity.as_str())
                    || (scope.full_scope.is_some()
                        != (selected.coverage == NativeCoverage::FullApprovedScope))
                    || (scope.full_scope.is_some() && selected.software_instance_id.is_none())
                {
                    return Err(StateError::Invalid("native metadata capture cannot carry predicted hashes or a different scope".into()));
                }
                return Ok(selected);
            }
            if selected.coverage == NativeCoverage::FullApprovedScope {
                return Err(StateError::Invalid(
                    "full native coverage requires a frozen Rust full-scope capability".into(),
                ));
            }
            let expected = selected.expected_files.as_mut().ok_or_else(|| {
                StateError::Invalid("native upload requires expected hash/size evidence".into())
            })?;
            expected.sort_by(|left, right| left.id.cmp(&right.id));
            let expected_ids = keys
                .iter()
                .map(|key| native_file_id(&key.logical_root, &key.relative_path))
                .collect::<BTreeSet<_>>();
            if selected
                .snapshot_identity
                .as_ref()
                .is_none_or(|id| id.is_empty() || id.len() > 512)
                || expected.len() != keys.len()
                || expected
                    .iter()
                    .map(|file| file.id.clone())
                    .collect::<BTreeSet<_>>()
                    != expected_ids
                || expected.iter().any(|file| {
                    file.file_hash
                        .strip_prefix("blake3:")
                        .is_none_or(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
                })
            {
                return Err(StateError::Invalid(
                    "native upload expected-file evidence does not match exact selection".into(),
                ));
            }
        }
        Ok(selected)
    }

    pub fn contains(&self, root: &str, relative: &str) -> bool {
        self.file_keys.as_ref().is_none_or(|keys| {
            keys.binary_search_by(|key| {
                key.logical_root
                    .as_str()
                    .cmp(root)
                    .then_with(|| key.relative_path.as_str().cmp(relative))
            })
            .is_ok()
        })
    }
}

pub fn validate_native_relative(relative: &str) -> Result<()> {
    validate_native_relative_path(relative)
}

/// Hash identities are opaque browse handles, never authority or absolute paths.
pub fn native_file_id(root: &str, relative: &str) -> String {
    let tracking_root = native_tracking_root_id(root).unwrap_or_else(|| root.to_owned());
    let mut hash = blake3::Hasher::new();
    // Exact shared UI identity contract with quicksave_tracking::file_id. The
    // custom logical token retains the stable approved root ID, not host paths.
    hash.update(b"QuickSave logical file v1\0");
    hash.update(&(tracking_root.len() as u64).to_le_bytes());
    hash.update(tracking_root.as_bytes());
    hash.update(relative.as_bytes());
    format!("file-{}", hash.finalize().to_hex())
}

fn hex_text(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Lossless logical mapping only; constructing a token does not authorize the
/// corresponding root. Registration and native capture still pin real handles.
pub fn native_root_token(app: &AppId, root: &str) -> String {
    LogicalRoot::NolandCustomRoot {
        id: format!("quicksave-v1-{}-{}", hex_text(app.as_str()), hex_text(root)),
    }
    .as_token()
}

pub fn native_tracking_root_id(token: &str) -> Option<String> {
    let LogicalRoot::NolandCustomRoot { id } = LogicalRoot::parse(token)? else {
        return None;
    };
    let (_, root) = id.strip_prefix("quicksave-v1-")?.split_once('-')?;
    if root.is_empty() || root.len() > 1024 || root.len() % 2 != 0 || !root.is_ascii() {
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

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeRootRole {
    Installation,
    /// Approved installer *files* only; this role never executes an installer.
    Installer,
    Save,
    Config,
    Runtime,
    Container,
    GroupContainer,
    Data,
    #[default]
    Manual,
}

impl NativeRootRole {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "installation" => Ok(Self::Installation),
            "installer" => Ok(Self::Installer),
            "save" => Ok(Self::Save),
            "config" => Ok(Self::Config),
            "runtime" => Ok(Self::Runtime),
            "container" => Ok(Self::Container),
            "group_container" => Ok(Self::GroupContainer),
            "data" => Ok(Self::Data),
            "manual" => Ok(Self::Manual),
            _ => Err(StateError::Invalid(
                "unknown native application root role".into(),
            )),
        }
    }

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

pub struct ApprovedNativeRoot {
    pub id: String,
    pub path: PathBuf,
    /// Parent-directory manual-file authority. Never enumerate that parent.
    pub allowed_files: Option<BTreeSet<String>>,
    pub expected_identity: Option<(u64, u64)>,
    pub role: NativeRootRole,
}

struct RootBinding {
    id: String,
    path: PathBuf,
    logical: LogicalRoot,
    base: PathBuf,
    handle: File,
    device: u64,
    inode: u64,
    parent: (u64, u64),
    directory: bool,
    allowed_files: Option<BTreeSet<String>>,
    role: NativeRootRole,
}

/// A source-owned clone of a registered root, not authority constructed from
/// JSON. Receipts retain it even for an empty scope or a direct file approval.
pub(crate) struct NativeApprovedPin {
    pub id: String,
    pub path: PathBuf,
    pub logical_root: String,
    pub directory: bool,
    pub allowed_files: Option<BTreeSet<String>>,
    pub role: NativeRootRole,
    pub identity: (u64, u64),
    parent: (u64, u64),
    pub handle: File,
}

fn native_root_leaf_name(path: &Path) -> Result<&str> {
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            StateError::UnsafePath("approved native root has no UTF-8 leaf name".into())
        })?;
    noland_state_core::native_layout::validate_native_layout_leaf(leaf)?;
    Ok(leaf)
}

/// Exact native reconstruction metadata from actual pinned bindings, not source
/// path hints, UI labels or guesses about a host's HOME/Applications directories.
pub(crate) fn root_layouts_from_pins(
    app: &AppId,
    instance: &str,
    pins: &[Arc<NativeApprovedPin>],
    selected_roots: Option<&BTreeSet<&str>>,
) -> Result<serde_json::Value> {
    if app.as_str().is_empty()
        || app.as_str().len() > 512
        || instance.is_empty()
        || instance.len() > 256
        || instance.chars().any(char::is_control)
        || pins.is_empty()
        || pins.len() > 128
    {
        return Err(StateError::Invalid(
            "invalid native root-layout identity/count".into(),
        ));
    }
    let platform = match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        _ => {
            return Err(StateError::Invalid(
                "native root-layout platform is unsupported".into(),
            ))
        }
    };
    let mut roots = Vec::with_capacity(pins.len());
    let mut logical_roots = BTreeSet::new();
    for pin in pins {
        pin.check()?;
        if selected_roots.is_some_and(|selected| !selected.contains(pin.logical_root.as_str())) {
            continue;
        }
        if !logical_roots.insert(pin.logical_root.as_str()) {
            return Err(StateError::Integrity(
                "duplicate native reconstruction logical root".into(),
            ));
        }
        if pin.logical_root.len() > 4096
            || LogicalRoot::parse(&pin.logical_root)
                .is_none_or(|root| root.as_token() != pin.logical_root)
        {
            return Err(StateError::Integrity(
                "noncanonical native source layout token".into(),
            ));
        }
        roots.push(serde_json::json!({
            "logical_root":pin.logical_root,"root_id":pin.id,"role":pin.role.as_str(),
            "source_kind":if pin.directory { "directory" } else { "file" },
            "leaf_name":native_root_leaf_name(&pin.path)?,
        }));
    }
    if roots.is_empty()
        || roots.len() > noland_state_core::native_layout::MAX_NATIVE_LAYOUT_ROOTS
        || selected_roots.is_some_and(|selected| selected.len() != logical_roots.len())
    {
        return Err(StateError::Invalid(
            "native root-layout selection/count is unsupported".into(),
        ));
    }
    Ok(serde_json::json!({
        "version":1,"platform":platform,"app_id":app.as_str(),
        "software_instance_id":instance,"roots":roots,
    }))
}

impl NativeApprovedPin {
    pub fn check(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let source = SourcePath::new(&self.path)?;
        let current = source.metadata()?;
        let held = self.handle.metadata()?;
        if current.is_symlink()
            || current.is_dir() != self.directory
            || !(current.is_dir() || current.is_file())
            || (current.dev(), current.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
            || source.parent_identity()? != self.parent
        {
            return Err(StateError::Conflict(
                "approved native root authority changed".into(),
            ));
        }
        Ok(())
    }
}

impl RootBinding {
    fn validate(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let source = SourcePath::new(&self.path)?;
        let current = source.metadata()?;
        let held = self.handle.metadata()?;
        if current.is_symlink()
            || current.is_dir() != self.directory
            || current.dev() != self.device
            || current.ino() != self.inode
            || held.dev() != self.device
            || held.ino() != self.inode
            || source.parent_identity()? != self.parent
        {
            return Err(StateError::Conflict(
                "approved native root identity changed".into(),
            ));
        }
        Ok(())
    }

    fn contains(&self, path: &Path) -> bool {
        if let Some(leaves) = &self.allowed_files {
            return path.parent() == Some(self.path.as_path())
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| leaves.contains(name));
        }
        if self.directory {
            path.starts_with(&self.path)
        } else {
            path == self.path
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        if let Some(leaves) = &self.allowed_files {
            return leaves
                .iter()
                .any(|leaf| other.contains(&self.path.join(leaf)));
        }
        other.contains(&self.path) || self.contains(&other.path)
    }
}

#[derive(Default)]
pub(crate) struct NativeBindings {
    apps: BTreeMap<AppId, Vec<RootBinding>>,
    publication_guards: BTreeMap<Uuid, NativePublicationGuard>,
    pub(crate) captures: crate::native_capture::NativeCaptures,
}

impl StateAgent {
    pub fn native_set_publication_guard(
        &self,
        id: Uuid,
        guard: NativePublicationGuard,
    ) -> Result<()> {
        if !self.config.native_host || self.operations.is_running(id) {
            return Err(StateError::Conflict(
                "native publication guard cannot change during execution".into(),
            ));
        }
        let mut bindings = self.native_bindings.lock();
        if bindings.publication_guards.len() >= 256
            && !bindings.publication_guards.contains_key(&id)
        {
            bindings.publication_guards.retain(|id, _| {
                self.db
                    .get_operation(*id)
                    .ok()
                    .flatten()
                    .is_none_or(|op| op.state != "COMPLETED")
            });
        }
        if bindings.publication_guards.len() >= 256
            && !bindings.publication_guards.contains_key(&id)
        {
            return Err(StateError::Conflict(
                "native publication guard capacity reached".into(),
            ));
        }
        bindings.publication_guards.insert(id, guard);
        Ok(())
    }

    pub fn native_check_publication(&self, id: Uuid, manifest: &BundleManifest) -> Result<()> {
        if !self.config.native_host {
            return Ok(());
        }
        let selection = self
            .native_selection_for_operation(id)?
            .ok_or_else(|| StateError::Invalid("native selection missing".into()))?;
        let captured_selection =
            NativeSelection::parse(&manifest.environment["quicksave_native"]["selection"])?;
        if captured_selection != selection {
            return Err(StateError::Conflict(
                "prepared native revision belongs to a different approved capture selection".into(),
            ));
        }
        if selection.software_instance_id.is_some() {
            if manifest.environment["quicksave_native_root_layouts"]
                != self.native_selection_layouts(&manifest.app.app_id, &selection)?
            {
                return Err(StateError::Conflict(
                    "prepared native root-layout descriptor differs from actual held roots".into(),
                ));
            }
        } else if !manifest.environment["quicksave_native_root_layouts"].is_null() {
            return Err(StateError::Conflict(
                "legacy native capture cannot supply an unbound root-layout descriptor".into(),
            ));
        }
        if selection.capture_scope.is_some() {
            crate::native_capture::verify_prepared(self, id, manifest)?;
            return self.native_check_publication_guard(id);
        }
        let expected = selection.expected_files.as_ref().ok_or_else(|| {
            StateError::Invalid("expected native capture evidence missing".into())
        })?;
        if manifest.files.len() != expected.len() {
            return Err(StateError::Conflict(
                "prepared native manifest has a different file selection than the approved capture"
                    .into(),
            ));
        }
        let files = manifest
            .files
            .iter()
            .map(|file| {
                (
                    native_file_id(&file.logical_root, &file.relative_path),
                    file,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if files.len() != expected.len() {
            return Err(StateError::Integrity(
                "prepared manifest has duplicate logical file identities".into(),
            ));
        }
        for expected in expected {
            let file = files.get(&expected.id).ok_or_else(|| {
                StateError::Conflict("prepared manifest omitted an expected native file".into())
            })?;
            if file.file_type != "file"
                || file.size != expected.size
                || file.file_hash != expected.file_hash
            {
                return Err(StateError::Conflict(
                    "actual native captured hash/size differs from the approved tracker capture"
                        .into(),
                ));
            }
        }
        self.native_check_publication_guard(id)
    }

    pub fn native_check_publication_guard(&self, id: Uuid) -> Result<()> {
        if !self.config.native_host {
            return Ok(());
        }
        let guard = self
            .native_bindings
            .lock()
            .publication_guards
            .get(&id)
            .cloned()
            .ok_or_else(|| {
                StateError::Conflict(
                    "native publication requires a fresh operation-bound authorization guard"
                        .into(),
                )
            })?;
        // Never hold the binding mutex while the service revalidates vault/state
        // grants, root handles, provider scope and autosave authority.
        guard().map_err(|_| {
            StateError::Conflict(
                "native publication authorization was revoked or changed after capture".into(),
            )
        })
    }

    pub(crate) fn native_has_publication_guard(&self, id: Uuid) -> bool {
        self.native_bindings
            .lock()
            .publication_guards
            .contains_key(&id)
    }

    pub fn native_register(
        &self,
        identity: AppIdentity,
        approved: Vec<ApprovedNativeRoot>,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        if !self.config.native_host || approved.is_empty() || approved.len() > 128 {
            return Err(StateError::Invalid(
                "native registration requires 1–128 approved roots".into(),
            ));
        }
        if !self.operations.running_snapshots().is_empty() {
            return Err(StateError::Conflict(
                "cannot change native roots during a storage operation".into(),
            ));
        }
        let mut roots = Vec::<RootBinding>::new();
        let mut ids = BTreeSet::new();
        let mut leaf_count = 0usize;
        let mut leaf_bytes = 0usize;
        for root in approved {
            if !ids.insert(root.id.clone())
                || root.id.is_empty()
                || root.id.len() > 128
                || !is_valid_index_path(&root.path)
                || self.config.paths.is_internal(&root.path)
                || self.config.capture_exclusions.iter().any(|excluded| {
                    root.path.starts_with(excluded) || excluded.starts_with(&root.path)
                })
            {
                return Err(StateError::UnsafePath(
                    "invalid, duplicate or internal native capture root".into(),
                ));
            }
            let source = SourcePath::new(&root.path)?;
            let metadata = source.metadata()?;
            if metadata.is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
                return Err(StateError::UnsafePath(
                    "native roots must be regular files or directories".into(),
                ));
            }
            let directory = metadata.is_dir();
            if let Some(expected) = root.expected_identity {
                if expected != (metadata.dev(), metadata.ino()) {
                    return Err(StateError::Conflict(
                        "approved native root no longer matches its persistent identity".into(),
                    ));
                }
            }
            if let Some(leaves) = &root.allowed_files {
                leaf_count = leaf_count.saturating_add(leaves.len());
                leaf_bytes = leaves
                    .iter()
                    .fold(leaf_bytes, |sum, leaf| sum.saturating_add(leaf.len()));
                if !directory
                    || leaves.is_empty()
                    || leaf_count > 250_000
                    || leaf_bytes > 32 * 1024 * 1024
                {
                    return Err(StateError::Invalid(
                        "manual native roots require a bounded nonempty file allowlist".into(),
                    ));
                }
                for leaf in leaves {
                    validate_native_relative(leaf)?;
                    if leaf.contains('/') {
                        return Err(StateError::UnsafePath(
                            "manual allowlist requires exact leaves".into(),
                        ));
                    }
                }
            }
            let handle = if directory {
                source.open_directory()?
            } else {
                source.open_regular()?
            };
            let held = handle.metadata()?;
            if held.dev() != metadata.dev() || held.ino() != metadata.ino() {
                return Err(StateError::Conflict(
                    "native root changed during approval binding".into(),
                ));
            }
            let logical = LogicalRoot::NolandCustomRoot {
                id: format!(
                    "quicksave-v1-{}-{}",
                    hex_text(identity.app_id.as_str()),
                    hex_text(&root.id)
                ),
            };
            let base = if directory {
                root.path.clone()
            } else {
                root.path
                    .parent()
                    .ok_or_else(|| StateError::UnsafePath("file root has no parent".into()))?
                    .to_path_buf()
            };
            let binding = RootBinding {
                id: root.id,
                path: root.path,
                logical,
                base,
                handle,
                device: metadata.dev(),
                inode: metadata.ino(),
                parent: source.parent_identity()?,
                directory,
                allowed_files: root.allowed_files,
                role: root.role,
            };
            binding.validate()?;
            if roots
                .iter()
                .any(|other| other.overlaps(&binding) || binding.overlaps(other))
            {
                return Err(StateError::Invalid(
                    "overlapping native roots must be approved as one root".into(),
                ));
            }
            roots.push(binding);
        }
        roots.sort_by(|left, right| left.id.cmp(&right.id));
        self.db.upsert_app(&identity)?;
        // DB roots remain provenance/index hints. Only the pinned bindings above
        // authorize native capture; historical DB roots can never widen a scan.
        for root in &roots {
            self.db.add_known_root(
                &identity.app_id,
                root.role.as_str(),
                root.path.to_str().unwrap(),
            )?;
        }
        self.db.mark_dirty(&identity.app_id, None, true)?;
        let mut bindings = self.native_bindings.lock();
        bindings.apps.insert(identity.app_id, roots);
        let mut map = LogicalRootMap::default();
        for root in bindings.apps.values().flatten() {
            if let LogicalRoot::NolandCustomRoot { id } = &root.logical {
                map.custom_roots.insert(id.clone(), root.base.clone());
            }
        }
        *self.roots.lock() = map;
        Ok(())
    }

    pub fn native_validate_all(&self) -> Result<()> {
        for root in self.native_bindings.lock().apps.values().flatten() {
            root.validate()?;
        }
        Ok(())
    }

    pub fn native_binding_fingerprint(&self, app: &AppId) -> Result<String> {
        let bindings = self.native_bindings.lock();
        let roots = bindings
            .apps
            .get(app)
            .ok_or_else(|| StateError::Invalid("software has no approved native roots".into()))?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"quicksave-native-roots-v3\0");
        hash.update(app.as_str().as_bytes());
        for root in roots {
            root.validate()?;
            hash.update(&(root.id.len() as u64).to_le_bytes());
            hash.update(root.id.as_bytes());
            hash.update(root.role.as_str().as_bytes());
            hash.update(&[0]);
            let leaf = native_root_leaf_name(&root.path)?;
            hash.update(if root.directory {
                b"directory\0"
            } else {
                b"file\0"
            });
            hash.update(&(leaf.len() as u64).to_le_bytes());
            hash.update(leaf.as_bytes());
            hash.update(root.path.to_str().unwrap().as_bytes());
            hash.update(&root.device.to_le_bytes());
            hash.update(&root.inode.to_le_bytes());
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

    pub(crate) fn native_capture_root_pins(
        &self,
        app: &AppId,
    ) -> Result<Vec<Arc<NativeApprovedPin>>> {
        let bindings = self.native_bindings.lock();
        let roots = bindings
            .apps
            .get(app)
            .ok_or_else(|| StateError::Invalid("software has no approved native roots".into()))?;
        let mut pins = Vec::with_capacity(roots.len());
        for root in roots {
            root.validate()?;
            let pin = Arc::new(NativeApprovedPin {
                id: root.id.clone(),
                path: root.path.clone(),
                logical_root: root.logical.as_token(),
                directory: root.directory,
                allowed_files: root.allowed_files.clone(),
                role: root.role,
                identity: (root.device, root.inode),
                parent: root.parent,
                handle: root.handle.try_clone()?,
            });
            pin.check()?;
            pins.push(pin);
        }
        Ok(pins)
    }

    pub fn native_root_layouts(&self, app: &AppId, instance: &str) -> Result<serde_json::Value> {
        root_layouts_from_pins(app, instance, &self.native_capture_root_pins(app)?, None)
    }

    pub(crate) fn native_selection_layouts(
        &self,
        app: &AppId,
        selection: &NativeSelection,
    ) -> Result<serde_json::Value> {
        let instance = selection.software_instance_id.as_deref().ok_or_else(|| {
            StateError::Invalid("native root layouts require a software instance".into())
        })?;
        let selected = selection.file_keys.as_ref().map(|keys| {
            keys.iter()
                .map(|key| key.logical_root.as_str())
                .collect::<BTreeSet<_>>()
        });
        root_layouts_from_pins(
            app,
            instance,
            &self.native_capture_root_pins(app)?,
            if selection.coverage == NativeCoverage::FullApprovedScope {
                None
            } else {
                selected.as_ref()
            },
        )
    }

    pub fn native_approved_roots(&self, app: &AppId) -> Result<Vec<PathBuf>> {
        let bindings = self.native_bindings.lock();
        let roots = bindings
            .apps
            .get(app)
            .ok_or_else(|| StateError::Invalid("software has no approved native roots".into()))?;
        let mut scan_roots = Vec::new();
        for root in roots {
            root.validate()?;
            if let Some(leaves) = &root.allowed_files {
                scan_roots.extend(leaves.iter().map(|leaf| root.path.join(leaf)));
            } else {
                scan_roots.push(root.path.clone());
            }
        }
        Ok(scan_roots)
    }

    pub(crate) fn native_permits(&self, app: &AppId, path: &Path) -> bool {
        !self.config.paths.is_internal(path)
            && !self
                .config
                .capture_exclusions
                .iter()
                .any(|excluded| path.starts_with(excluded))
            && self
                .native_bindings
                .lock()
                .apps
                .get(app)
                .is_some_and(|roots| roots.iter().any(|root| root.contains(path)))
    }

    pub fn native_path_classification(
        &self,
        app: &AppId,
        path: &Path,
    ) -> Result<(PersistenceClass, SemanticRole)> {
        let bindings = self.native_bindings.lock();
        let binding = bindings
            .apps
            .get(app)
            .and_then(|roots| roots.iter().find(|root| root.contains(path)))
            .ok_or_else(|| StateError::UnsafePath("path has no approved native role".into()))?;
        binding.validate()?;
        Ok(binding.role.classification())
    }

    pub fn native_logical_path(&self, app: &AppId, path: &Path) -> Result<LogicalPath> {
        let bindings = self.native_bindings.lock();
        let root = bindings
            .apps
            .get(app)
            .and_then(|roots| roots.iter().find(|root| root.contains(path)))
            .ok_or_else(|| {
                StateError::UnsafePath("file is outside approved native roots".into())
            })?;
        let relative = path
            .strip_prefix(&root.base)
            .map_err(|_| StateError::UnsafePath("native mapping escaped root".into()))?
            .to_str()
            .ok_or_else(|| StateError::UnsafePath("non-UTF8 native path".into()))?;
        if relative.is_empty() {
            return Err(StateError::UnsafePath(
                "native root directory is not a file".into(),
            ));
        }
        LogicalPath::new_native(root.logical.clone(), relative)
    }

    pub(crate) fn native_selection_for_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<NativeSelection>> {
        if !self.config.native_host {
            return Ok(None);
        }
        let op = self
            .db
            .get_operation(id)?
            .ok_or_else(|| StateError::NotFound(id.to_string()))?;
        let selection = NativeSelection::parse(&op.detail_json["native_selection"])?;
        if let Some(scope) = &selection.capture_scope {
            crate::native_capture::validate_selection(
                self,
                id,
                scope,
                selection
                    .file_keys
                    .as_deref()
                    .ok_or_else(|| StateError::Invalid("native capture keys missing".into()))?,
                &selection.roots_fingerprint,
                selection.coverage,
                selection.software_instance_id.as_deref(),
            )?;
        }
        Ok(Some(selection))
    }
}

/// Fresh download mapping. Original Linux absolute hints, host HOME, launch
/// prerequisites and source executable paths are deliberately not consulted.
pub fn native_restore_roots(
    destination: &Path,
    manifest: &BundleManifest,
) -> Result<LogicalRootMap> {
    let layout = noland_state_core::native_layout::native_restore_layout(manifest, destination)?;
    noland_state_core::native_layout::logical_root_map(&layout.roots)
}
