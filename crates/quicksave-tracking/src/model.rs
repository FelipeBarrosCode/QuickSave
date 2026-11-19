// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{ensure, Context, Result};
use quicksave_platform::{FileStamp, NativeLinkStamp};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub const MAX_SOFTWARE: usize = 4096;
pub const MAX_ROOTS: usize = 48;
pub const MAX_FILES: usize = 250_000;
pub const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BASELINE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_PAGE: usize = 500;
pub const MAX_SELECTION: usize = MAX_FILES;

/// Native lifecycle dependency, never deserialized from settings/IPC. Values
/// must be monotonic elapsed milliseconds. Production uses Instant by default;
/// isolated fixtures may inject a manually advanced/frozen clock.
pub trait TrackingClock: std::fmt::Debug + Send + Sync + 'static {
    fn now_millis(&self) -> u64;
}

#[derive(Clone, Debug)]
pub struct TrackingPolicy {
    pub(crate) data_dir: PathBuf,
    pub excluded_paths: Vec<PathBuf>,
    pub audit_interval: Duration,
    pub supports_deletion_snapshots: bool,
    /// Set only when the native writer and publication guard support directory
    /// and confined link evidence, including genuinely empty full-root captures.
    pub supports_metadata_snapshots: bool,
    pub max_file_bytes: u64,
    pub(crate) clock: Option<Arc<dyn TrackingClock>>,
    #[cfg(test)]
    pub(crate) faults: crate::diagnostics::Faults,
}

impl TrackingPolicy {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            excluded_paths: Vec::new(),
            data_dir,
            audit_interval: Duration::from_secs(60),
            supports_deletion_snapshots: false,
            supports_metadata_snapshots: false,
            max_file_bytes: 1024 * 1024 * 1024 * 1024,
            clock: None,
            #[cfg(test)]
            faults: crate::diagnostics::Faults::default(),
        }
    }

    /// Native-only test/host clock injection. Does not disable watchers, discard
    /// hints, change production quiet/audit intervals, or imply clean data.
    pub fn with_clock(mut self, clock: Arc<dyn TrackingClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_absolute(&self.data_dir)?;
        ensure!(
            self.audit_interval >= Duration::from_secs(5)
                && self.audit_interval <= Duration::from_secs(60 * 60),
            "audit interval must be between five seconds and one hour"
        );
        ensure!(self.max_file_bytes > 0, "invalid streaming file bound");
        ensure!(self.excluded_paths.len() <= 128, "too many excluded roots");
        for path in &self.excluded_paths {
            validate_absolute(path)?;
        }
        Ok(())
    }

    pub(crate) fn baseline_dir(&self) -> PathBuf {
        self.data_dir.join("tracking-baselines")
    }

    pub(crate) fn bundle_dir(&self) -> PathBuf {
        self.data_dir.join("tracking-bundles")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootIdentity {
    pub device: u64,
    pub file_id: [u64; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedRoot {
    pub id: String,
    pub path: PathBuf,
    pub role: String,
    pub identity: RootIdentity,
    /// None is an approved tree; Some is a fixed set of parent-directory leaves.
    pub allowed_files: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

impl ApprovedRoot {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        validate_absolute(&self.path)?;
        ensure!(
            matches!(
                self.role.as_str(),
                "installation"
                    | "save"
                    | "config"
                    | "manual"
                    | "runtime"
                    | "container"
                    | "group_container"
                    | "data"
                    | "installer"
            ),
            "unsupported tracking root role (cache roots are excluded)"
        );
        if let Some(leaves) = &self.allowed_files {
            ensure!(
                !leaves.is_empty() && leaves.len() <= 4096,
                "invalid manual-file scope"
            );
            for leaf in leaves {
                validate_relative(leaf)?;
                ensure!(
                    !leaf.contains('/'),
                    "manual file allowlists contain leaves only"
                );
                ensure!(
                    !is_secret_component(leaf),
                    "key material is excluded from tracking"
                );
            }
        }
        if let Some(source) = &self.source {
            bounded_json(source, 64 * 1024)?;
        }
        Ok(())
    }

    pub(crate) fn authority(&self) -> Value {
        // Source/display metadata is deliberately not filesystem authority.
        json!({
            "id": self.id, "path": self.path, "role": self.role,
            "identity": self.identity, "allowedFiles": self.allowed_files
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Node {
    pub root_id: String,
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub stamp: Option<FileStamp>,
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<NativeLinkStamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<NativeMetadata>,
}

/// Native metadata is platform-specific. Windows never receives Unix UID/GID
/// placeholders or a truncated standard-library file index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum NativeMetadata {
    Unix(UnixMetadata),
    Windows(WindowsMetadata),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UnixMetadata {
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
    pub link_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WindowsMetadataPlatform {
    Windows,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowsMetadata {
    pub platform: WindowsMetadataPlatform,
    pub identity: RootIdentity,
    pub kind: quicksave_platform::EntryKind,
    pub size: u64,
    /// Raw 100 ns FILETIME ticks since 1601, retained without pretending they
    /// are Unix timestamps. FileStamp separately carries the checked conversion.
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
    pub link_count: u32,
    pub reparse_tag: u32,
}

impl PartialEq for WindowsMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.platform == other.platform
            && self.identity == other.identity
            && self.kind == other.kind
            && self.size == other.size
            && self.creation_time == other.creation_time
            && self.last_write_time == other.last_write_time
            && self.change_time == other.change_time
            && self.attributes == other.attributes
            && self.link_count == other.link_count
            && self.reparse_tag == other.reparse_tag
    }
}
impl Eq for WindowsMetadata {}

impl WindowsMetadata {
    pub(crate) fn stamp(&self) -> Result<FileStamp> {
        let native_time = |ticks: i64| -> Result<(i64, u32)> {
            Ok((
                ticks
                    .div_euclid(10_000_000)
                    .checked_sub(11_644_473_600)
                    .context("Windows native timestamp exceeds representable range")?,
                ticks.rem_euclid(10_000_000) as u32 * 100,
            ))
        };
        let modified = native_time(self.last_write_time)?;
        let changed = native_time(self.change_time)?;
        Ok(FileStamp {
            device: self.identity.device,
            file_id: self.identity.file_id,
            size: self.size,
            modified_seconds: modified.0,
            modified_nanoseconds: modified.1,
            changed_seconds: changed.0,
            changed_nanoseconds: changed.1,
        })
    }
}

impl NativeMetadata {
    /// Atime-only observations are not changes and must not churn native
    /// index revisions. The retained atime is still a real prior observation.
    pub(crate) fn retain_read_time(&mut self, previous: Option<&Self>) {
        if let (Self::Windows(current), Some(Self::Windows(old))) = (self, previous) {
            if &*current == old {
                current.last_access_time = old.last_access_time;
            }
        }
    }

    pub(crate) fn validate(&self, kind: &str, stamp: Option<&FileStamp>) -> Result<()> {
        match self {
            Self::Unix(metadata) => {
                let expected = match kind {
                    "file" => 0o100000,
                    "directory" => 0o040000,
                    "symlink" => 0o120000,
                    _ => anyhow::bail!("unknown native metadata kind"),
                };
                ensure!(
                    metadata.mode & 0o170000 == expected && metadata.link_count > 0,
                    "Unix native metadata kind/link count is invalid"
                );
            }
            Self::Windows(metadata) => {
                let expected = match kind {
                    "file" => quicksave_platform::EntryKind::File,
                    "directory" => quicksave_platform::EntryKind::Directory,
                    "symlink" => quicksave_platform::EntryKind::Symlink,
                    _ => anyhow::bail!("unknown Windows metadata kind"),
                };
                ensure!(
                    metadata.kind == expected
                        && metadata.link_count > 0
                        && metadata.identity.file_id != [0, 0],
                    "Windows metadata lacks a real kind/full native identity"
                );
                ensure!(
                    if kind == "symlink" {
                        metadata.reparse_tag == 0xa000000c && metadata.attributes & 0x400 != 0
                    } else {
                        metadata.reparse_tag == 0
                            && metadata.attributes & 0x400 == 0
                            && (metadata.attributes & 0x10 != 0) == (kind == "directory")
                    },
                    "Windows metadata has an unsupported reparse/attribute combination"
                );
                if let Some(stamp) = stamp {
                    ensure!(
                        &metadata.stamp()? == stamp,
                        "Windows metadata differs from complete native identity/length/time stamp"
                    );
                }
            }
        }
        Ok(())
    }
}

impl Node {
    pub(crate) fn id(&self) -> String {
        file_id(&self.root_id, &self.path)
    }

    pub(crate) fn item(&self, status: &str) -> Value {
        json!({
            "id": self.id(), "name": self.path.rsplit('/').next().unwrap_or(&self.path),
            "path": self.path, "directory": self.directory, "size": self.size,
            "status": status, "rootId": self.root_id, "kind": self.kind()
        })
    }

    pub(crate) fn kind(&self) -> &'static str {
        if self.directory {
            "directory"
        } else if self.link.is_some() {
            "symlink"
        } else {
            "file"
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub nodes: BTreeMap<String, Node>,
    #[serde(default)]
    pub content_captured: bool,
    /// Full-tree root metadata is retained even for a genuinely empty root.
    /// Manual file scopes never read or depend on unselected sibling metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_metadata: BTreeMap<String, NativeMetadata>,
    /// Exact directory ID/length/write/change stamp, including genuine empty
    /// roots. Never used for unselected parents of manual leaf scopes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_stamps: BTreeMap<String, FileStamp>,
}

impl Snapshot {
    pub(crate) fn validate(&self, roots: &[ApprovedRoot]) -> Result<()> {
        ensure!(
            self.nodes.len() <= MAX_FILES,
            "baseline exceeds entry limit"
        );
        let mut path_bytes = 0_usize;
        for (id, node) in &self.nodes {
            validate_relative(&node.path)?;
            path_bytes = path_bytes
                .checked_add(node.path.len())
                .and_then(|bytes| {
                    bytes.checked_add(node.link.as_ref().map_or(0, |link| link.target.len()))
                })
                .context("path size overflow")?;
            ensure!(
                path_bytes <= MAX_PATH_BYTES,
                "baseline exceeds path-memory bound"
            );
            let root = roots
                .iter()
                .find(|r| r.id == node.root_id)
                .context("unknown baseline root")?;
            ensure!(
                root.allowed_files
                    .as_ref()
                    .is_none_or(|leaves| leaves.contains(&node.path)),
                "baseline file exceeds the approved leaf scope"
            );
            ensure!(id == &node.id(), "invalid baseline logical file identity");
            if let Some(metadata) = &node.metadata {
                metadata.validate(node.kind(), node.stamp.as_ref())?;
            }
            if node.directory {
                ensure!(
                    node.size == 0 && node.hash.is_none() && node.link.is_none(),
                    "invalid directory baseline"
                );
            } else if let Some(link) = &node.link {
                validate_link_target(&node.path, &link.target)?;
                ensure!(
                    node.size == 0
                        && node.hash.is_none()
                        && node.stamp.as_ref() == Some(&link.stamp),
                    "invalid link baseline"
                );
            } else {
                ensure!(node.stamp.is_some(), "file baseline has no native stamp");
                ensure!(
                    node.stamp.as_ref().unwrap().size == node.size,
                    "baseline size mismatch"
                );
                if let Some(hash) = node.hash.as_deref() {
                    ensure!(
                        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                        "invalid hash"
                    );
                }
            }
        }
        for id in self.root_metadata.keys() {
            ensure!(
                roots
                    .iter()
                    .any(|root| &root.id == id && root.allowed_files.is_none()),
                "unknown or unselected root metadata"
            );
            self.root_metadata[id].validate("directory", self.root_stamps.get(id))?;
        }
        for (id, stamp) in &self.root_stamps {
            let root = roots
                .iter()
                .find(|root| &root.id == id && root.allowed_files.is_none())
                .context("unknown or unselected root stamp")?;
            ensure!(
                self.root_metadata.contains_key(id)
                    && stamp.device == root.identity.device
                    && stamp.file_id == root.identity.file_id,
                "native root stamp does not match approved identity/metadata"
            );
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> Result<String> {
        Ok(self.identity_and_size()?.0)
    }

    /// The index's existing serialized metadata identity, not a file-content
    /// read/hash. Count bytes in the same bounded pass for native Arc retention.
    pub(crate) fn identity_and_size(&self) -> Result<(String, u64)> {
        // A bounded streaming writer avoids another whole serialized index.
        let mut hash = blake3::Hasher::new();
        let written = {
            let mut writer = HashWriter {
                hash: &mut hash,
                written: 0,
            };
            serde_json::to_writer(&mut writer, self)?;
            writer.written
        };
        Ok((hash.finalize().to_hex().to_string(), written))
    }

    pub(crate) fn validate_content(&self, roots: &[ApprovedRoot]) -> Result<()> {
        self.validate(roots)?;
        ensure!(
            self.content_captured,
            "metadata-only inventory is not a content capture"
        );
        ensure!(
            self.nodes
                .values()
                .all(|node| node.directory || node.link.is_some() || node.hash.is_some()),
            "content snapshot has unhashed regular files"
        );
        Ok(())
    }

    pub(crate) fn content_verified(&self) -> bool {
        self.content_captured
            && self
                .nodes
                .values()
                .all(|node| node.directory || node.link.is_some() || node.hash.is_some())
    }

    pub(crate) fn same_metadata(&self, other: &Self) -> bool {
        self.root_metadata == other.root_metadata
            && self.root_stamps == other.root_stamps
            && self.nodes.len() == other.nodes.len()
            && self.nodes.iter().all(|(id, node)| {
                other.nodes.get(id).is_some_and(|other| {
                    node.root_id == other.root_id
                        && node.path == other.path
                        && node.directory == other.directory
                        && node.size == other.size
                        && node.stamp == other.stamp
                        && node.link == other.link
                        && node.metadata == other.metadata
                })
            })
    }

    pub(crate) fn counts(&self) -> Result<(u64, u64)> {
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        for node in self
            .nodes
            .values()
            .filter(|node| !node.directory && node.link.is_none())
        {
            count = count.checked_add(1).context("file count overflow")?;
            bytes = bytes
                .checked_add(node.size)
                .context("logical size overflow")?;
        }
        Ok((count, bytes))
    }

    pub(crate) fn path_bytes(&self) -> Result<usize> {
        self.nodes.values().try_fold(0_usize, |bytes, node| {
            bytes
                .checked_add(node.path.len())
                .and_then(|bytes| {
                    bytes.checked_add(node.link.as_ref().map_or(0, |link| link.target.len()))
                })
                .context("native path/link memory count overflow")
        })
    }

    pub(crate) fn changed_ids(&self, baseline: &Self) -> BTreeSet<String> {
        self.nodes
            .iter()
            .filter(|(id, node)| baseline.nodes.get(*id) != Some(*node))
            .map(|(id, _)| id.clone())
            .chain(
                baseline
                    .nodes
                    .keys()
                    .filter(|id| !self.nodes.contains_key(*id))
                    .cloned(),
            )
            .collect()
    }
}

struct HashWriter<'a> {
    hash: &'a mut blake3::Hasher,
    written: u64,
}
impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("tracking metadata size overflow"))?;
        if next > MAX_BASELINE_BYTES {
            return Err(std::io::Error::other(
                "tracking snapshot exceeds metadata guard",
            ));
        }
        self.hash.update(bytes);
        self.written = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BaselineReference {
    pub name: String,
    pub hash: String,
    pub grant: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedSoftware {
    pub id: String,
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<Value>,
    pub name: String,
    pub tracked: bool,
    pub provider_id: Option<String>,
    pub autosave: bool,
    /// A denial-only recovery latch. Never grants authority or changes opt-in.
    #[serde(default)]
    pub(crate) authorization_pending: bool,
    pub dirty: bool,
    pub status: String,
    pub last_saved_at: Option<String>,
    pub file_count: Option<u64>,
    pub logical_bytes: Option<u64>,
    pub error: Option<String>,
    pub roots: Vec<ApprovedRoot>,
    pub dirty_generation: u64,
    /// Native recovery/gap partition. This can only invalidate cached proofs;
    /// it is never plaintext authorization to track or write a source.
    #[serde(default)]
    pub(crate) unknown_generation: u64,
    pub last_confirmed_uploaded_generation: u64,
    pub(crate) tracking_grant: Value,
    pub(crate) autosave_grant: Option<Value>,
    pub(crate) baseline: Option<BaselineReference>,
    #[serde(default)]
    pub(crate) baseline_full_scope: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bundle_index_source: Option<crate::bundle::BundleIndexSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) previous_bundle_manifest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) auto_enrollment: Option<crate::bundle::AutoEnrollment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) app_running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capture_receipt: Option<Value>,
    /// Non-secret authenticated reference only; never exposed in UI DTOs.
    #[serde(default)]
    pub(crate) pending_work: Option<Value>,
}

impl TrackedSoftware {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        validate_name(&self.name)?;
        if let Some(id) = &self.app_id {
            validate_id(id)?;
        }
        if let Some(id) = &self.provider_id {
            validate_id(id)?;
        }
        if let Some(identity) = &self.source_identity {
            bounded_json(identity, 16 * 1024)?;
            validate_id(
                identity["app_id"]
                    .as_str()
                    .context("native source AppIdentity lacks app_id")?,
            )?;
        }
        // A native-approved scope can be persisted pending its first real index.
        // A plaintext flag alone is never materialization or tracking authority.
        ensure!(
            !self.roots.is_empty() && self.roots.len() <= MAX_ROOTS,
            "invalid root count"
        );
        let mut seen = BTreeSet::new();
        for root in &self.roots {
            root.validate()?;
            ensure!(seen.insert(&root.id), "duplicate logical root ID");
        }
        ensure!(
            self.dirty_generation >= self.last_confirmed_uploaded_generation,
            "invalid persisted generation ordering"
        );
        bounded_json(&self.tracking_grant, 16_384)?;
        if let Some(reference) = &self.pending_work {
            bounded_json(reference, 64 * 1024)?;
        }
        if let Some(grant) = &self.autosave_grant {
            bounded_json(grant, 16_384)?;
        }
        Ok(())
    }

    pub(crate) fn tracking_scope(&self) -> Value {
        let mut scope = json!({
            "version": 1, "softwareId": self.id, "appId": self.app_id,
            "roots": self.roots.iter().map(ApprovedRoot::authority).collect::<Vec<_>>()
        });
        if let Some(enrollment) = &self.auto_enrollment {
            scope["autoEnrollment"] = enrollment.binding();
        }
        if let Some(identity) = &self.source_identity {
            scope["sourceIdentity"] = identity.clone();
        }
        scope
    }

    pub(crate) fn autosave_scope(&self) -> Value {
        json!({"version": 1, "tracking": self.tracking_scope(), "providerId": self.provider_id})
    }

    pub(crate) fn baseline_scope(&self, name: &str, hash: &str) -> Value {
        json!({
            "version": 1, "tracking": self.tracking_scope(), "providerId": self.provider_id,
            "name": name, "hash": hash, "fullScope": self.baseline_full_scope
        })
    }

    pub(crate) fn sanitized(&self) -> Value {
        let tracked = self.tracked && self.bundle_index_source.is_some();
        // Callers validate tracking/policy grants before projecting cached
        // records. Invalid/unmaterialized records must not advertise raw roots.
        // The approved record bounds this list to MAX_ROOTS (48), paths to
        // 32 KiB, and primary roles to the validated native/manual role enum.
        let roots = if tracked {
            self.roots
                .iter()
                .map(|root| {
                    let mut value = json!({
                        "id": root.id, "path": root.path, "role": root.role
                    });
                    // Manual source/display JSON is not MAC-bound authority.
                    // Only automatic app-evidence binds normalized extra roles.
                    if self.auto_enrollment.is_some() {
                        if let Some(roles) = root
                            .source
                            .as_ref()
                            .and_then(|source| source.get("roles"))
                            .and_then(Value::as_array)
                            .filter(|roles| {
                                !roles.is_empty()
                                    && roles.len() <= 4
                                    && roles.iter().all(|role| {
                                        matches!(
                                            role.as_str(),
                                            Some("installation" | "save" | "config" | "runtime")
                                        )
                                    })
                            })
                        {
                            value["roles"] = json!(roles);
                        }
                    }
                    value
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        json!({
            "id": self.id, "appId": self.app_id, "name": self.name,
            "tracked": tracked, "roots": roots,
            "providerId": self.provider_id, "autosave": self.autosave, "dirty": self.dirty,
            "status": self.status, "lastSavedAt": self.last_saved_at,
            "fileCount": self.file_count, "logicalBytes": self.logical_bytes, "error": self.error,
            "dirtyGeneration": self.dirty_generation,
            "unknownGeneration": self.unknown_generation,
            "lastConfirmedUploadedGeneration": self.last_confirmed_uploaded_generation,
            "appRunning": self.app_running,
            "payloadReadability": "not_established",
            "fullScopeCaptureBlocked": self.auto_enrollment.as_ref()
                .is_some_and(crate::bundle::AutoEnrollment::has_failed_roots),
            "bundle": self.bundle_index_source.as_ref().map(|source| source.sanitized())
        })
    }
}

pub fn file_id(root_id: &str, relative_path: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"QuickSave logical file v1\0");
    h.update(&(root_id.len() as u64).to_le_bytes());
    h.update(root_id.as_bytes());
    h.update(relative_path.as_bytes());
    format!("file-{}", h.finalize().to_hex())
}

pub(crate) fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
        "invalid logical ID"
    );
    Ok(())
}

pub(crate) fn validate_name(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
        "invalid software name"
    );
    Ok(())
}

pub(crate) fn validate_absolute(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "source roots must be absolute");
    let text = path.to_str().context("root path must be UTF-8")?;
    ensure!(
        text.len() <= 32_768 && !text.contains('\0'),
        "invalid source path length"
    );
    ensure!(
        !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "source path cannot contain dot components"
    );
    ensure!(
        path.parent().is_some(),
        "the filesystem root cannot be tracked"
    );
    Ok(())
}

pub(crate) fn validate_relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 32_768,
        "invalid relative path length"
    );
    ensure!(!path.contains('\0'), "invalid relative path");
    #[cfg(not(unix))]
    ensure!(!path.contains(['\\', ':']), "invalid Windows relative path");
    ensure!(
        path.split('/').count() <= 128,
        "relative path exceeds depth bound"
    );
    for component in path.split('/') {
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= 255
                && !component.chars().any(char::is_control),
            "invalid relative path component"
        );
    }
    Ok(())
}

/// Revalidate persisted link text without resolving or opening its target.
pub(crate) fn validate_link_target(relative: &str, target: &str) -> Result<()> {
    validate_relative(relative)?;
    ensure!(
        !target.is_empty()
            && target.len() <= 32_768
            && !target.starts_with('/')
            && !target.contains('\0'),
        "invalid confined relative link target"
    );
    #[cfg(not(unix))]
    ensure!(
        !target.contains(['\\', ':']),
        "invalid Windows relative link target"
    );
    let mut depth = relative.split('/').count() - 1;
    for (index, component) in target.split('/').enumerate() {
        ensure!(index < 128, "link target exceeds depth bound");
        match component {
            "." => {}
            ".." => {
                depth = depth
                    .checked_sub(1)
                    .context("link target escapes approved root")?
            }
            component => {
                validate_relative(component)?;
                depth = depth.checked_add(1).context("link depth overflow")?;
                ensure!(depth <= 128, "link target exceeds depth bound");
            }
        }
    }
    Ok(())
}

pub(crate) fn is_secret_component(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        ".git"
            | ".ssh"
            | ".gnupg"
            | ".aws"
            | ".azure"
            | ".cache"
            | "caches"
            | "logs"
            | "keychains"
            | "credentials"
            | "credentials.json"
            | ".env"
            | "id_rsa"
            | "id_ed25519"
            | "recovery.key"
            | "master.key"
            | ".noland"
            | ".no-land"
            | "no-land"
            | "noland-state"
            | "com.noland.connect"
            | "quicksave"
            | "vault"
            | "vaults"
    ) || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
}

/// Conservative, allocation-free JSON size/depth/node guard for native callers.
pub(crate) fn bounded_json(value: &Value, max: usize) -> Result<()> {
    fn walk(value: &Value, depth: usize, remaining: &mut usize, nodes: &mut usize) -> Result<()> {
        ensure!(
            depth <= 24 && *nodes > 0,
            "JSON exceeds the structure bound"
        );
        *nodes -= 1;
        let charge = match value {
            Value::String(text) => text.len().saturating_mul(6).saturating_add(2),
            Value::Array(items) => items.len().saturating_add(2),
            Value::Object(fields) => fields.iter().fold(2_usize, |size, (key, _)| {
                size.saturating_add(key.len().saturating_mul(6).saturating_add(4))
            }),
            Value::Number(_) => 32,
            Value::Null | Value::Bool(_) => 5,
        };
        *remaining = remaining
            .checked_sub(charge)
            .context("JSON exceeds the byte bound")?;
        match value {
            Value::Array(items) => {
                for item in items {
                    walk(item, depth + 1, remaining, nodes)?;
                }
            }
            Value::Object(fields) => {
                for item in fields.values() {
                    walk(item, depth + 1, remaining, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut remaining = max;
    let mut nodes = 100_000;
    walk(value, 0, &mut remaining, &mut nodes)
}

/// Exact serialized native-metadata bound, without allocating another copy.
pub(crate) fn bounded_serialized<T: Serialize + ?Sized>(value: &T, max: u64) -> Result<()> {
    serialized_size(value, max).map(|_| ())
}

pub(crate) fn serialized_size<T: Serialize + ?Sized>(value: &T, max: u64) -> Result<u64> {
    struct Counter {
        written: u64,
        max: u64,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .written
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("native metadata size overflow"))?;
            if next > self.max {
                return Err(std::io::Error::other("native work exceeds metadata guard"));
            }
            self.written = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { written: 0, max };
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.written)
}

#[cfg(test)]
mod relative_path_tests {
    use super::*;

    #[test]
    fn native_relative_paths_still_reject_traversal_and_invalid_components() {
        for bad in [
            "",
            "/absolute",
            "../up",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "a\0b",
            "a\nb",
        ] {
            assert!(validate_relative(bad).is_err(), "accepted {bad:?}");
        }
        assert!(validate_link_target("link", "/absolute").is_err());
        assert!(validate_link_target("link", "../outside").is_err());
        assert!(validate_link_target("dir/link", "../../outside").is_err());
        assert!(validate_link_target("dir/link", "../inside").is_ok());
    }

    #[test]
    fn native_punctuation_is_not_normalized_into_other_logical_paths() {
        for path in ["literal:leaf", "literal\\leaf", "dir:one/literal\\leaf"] {
            #[cfg(unix)]
            {
                assert!(validate_relative(path).is_ok(), "{path}");
                assert!(validate_link_target("dir/link", path).is_ok(), "{path}");
            }
            #[cfg(not(unix))]
            {
                assert!(validate_relative(path).is_err(), "{path}");
                assert!(validate_link_target("dir/link", path).is_err(), "{path}");
            }
        }
        assert_ne!(
            file_id("root", "literal\\leaf"),
            file_id("root", "literal/leaf")
        );
        assert_ne!(
            file_id("root", "literal:leaf"),
            file_id("root", "literal/leaf")
        );
    }
}
