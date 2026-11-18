// SPDX-License-Identifier: GPL-3.0-only
// Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! Native-only, metadata-frozen capture coordination. A JSON scope is a binding,
//! never authority: its operation must own an installed Rust sink. Only the real
//! capture pipeline can mint file proofs. There are no content reads here.

#[path = "native_capture_resume.rs"]
pub mod resume;

use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use noland_crypto::MasterKey;
use noland_snapshot::{SourceMetadata, SourcePath};
use noland_state_core::{
    AppId, BackupMode, BundleManifest, ConsistencyKind, LogicalRoot, ManifestFile,
    ManifestTombstone, Result, StateError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    native_host::{
        native_file_id, native_tracking_root_id, root_layouts_from_pins, validate_native_relative,
        NativeApprovedPin, NativeCoverage, NativeFileKey,
    },
    StateAgent,
};

pub const MAX_CAPTURE_NODES: usize = 250_000;
pub const NATIVE_CAPTURE_PAGE: usize = 500;
const MAX_CAPTURE_PATH_BYTES: usize = 64 * 1024 * 1024;
// Reuse, never raise, the source's existing authenticated metadata ceiling.
const MAX_CAPTURE_DOCUMENT: usize = noland_storage::MAX_METADATA_BYTES as usize;
const MAX_CAPTURE_OPERATIONS: usize = 64;
const MAX_CAPTURE_ROOT_HANDLES: usize = 256;

#[derive(Default)]
struct Counters {
    frozen_pages: AtomicU64,
    metadata_file_opens: AtomicU64,
    directory_pin_validations: AtomicU64,
    source_proofs_recorded: AtomicU64,
    reused_file_proofs: AtomicU64,
    checkpoint_read_bytes: AtomicU64,
    accepted_receipts: AtomicU64,
    inventory_nodes: AtomicU64,
}

/// Actual coordinator counters, not physical OS syscall/RSS measurements.
/// Content hashing is exclusively counted by the source OperationMetrics.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeCaptureCounters {
    pub frozen_pages: u64,
    pub metadata_file_opens: u64,
    pub directory_pin_validations: u64,
    pub source_proofs_recorded: u64,
    pub reused_file_proofs: u64,
    pub checkpoint_read_bytes: u64,
    pub accepted_receipts: u64,
    pub inventory_nodes: u64,
}

impl Counters {
    fn snapshot(&self) -> NativeCaptureCounters {
        NativeCaptureCounters {
            frozen_pages: self.frozen_pages.load(Ordering::Relaxed),
            metadata_file_opens: self.metadata_file_opens.load(Ordering::Relaxed),
            directory_pin_validations: self.directory_pin_validations.load(Ordering::Relaxed),
            source_proofs_recorded: self.source_proofs_recorded.load(Ordering::Relaxed),
            reused_file_proofs: self.reused_file_proofs.load(Ordering::Relaxed),
            checkpoint_read_bytes: self.checkpoint_read_bytes.load(Ordering::Relaxed),
            accepted_receipts: self.accepted_receipts.load(Ordering::Relaxed),
            inventory_nodes: self.inventory_nodes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCaptureScope {
    pub version: u32,
    pub work_id: String,
    pub metadata_identity: String,
    pub node_count: usize,
    /// A compact binding only. A matching installed Rust authority, signed full
    /// snapshot and independent source root/inventory checks are still required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_scope: Option<NativeFullScopeBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFullScopeBinding {
    pub version: u32,
    /// Raw lowercase 64-hex metadata digest, matching Tracker's digest domain.
    /// This is not a tagged source content/manifest hash and grants no authority.
    pub evidence_hash: String,
    pub root_count: usize,
    pub deleted_count: usize,
}

impl NativeFullScopeBinding {
    /// Call only on evidence obtained from the original native tracker owner,
    /// never incoming UI/IPC data. This digest itself grants no authority.
    pub fn from_evidence(evidence: &Value) -> Result<Self> {
        let roots = evidence["roots"]
            .as_array()
            .ok_or_else(|| StateError::Invalid("native full scope has no root evidence".into()))?;
        let deleted = evidence["deletedNodes"].as_array().ok_or_else(|| {
            StateError::Invalid("native full scope has no exact deleted-node list".into())
        })?;
        validate_tracker_digest_fields(evidence)?;
        let binding = Self {
            version: 1,
            evidence_hash: metadata_digest(evidence)?,
            root_count: roots.len(),
            deleted_count: deleted.len(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !canonical_raw_hash(&self.evidence_hash)
            || !(1..=128).contains(&self.root_count)
            || self.deleted_count > MAX_CAPTURE_NODES
        {
            return Err(StateError::Invalid(
                "invalid native full-scope binding".into(),
            ));
        }
        Ok(())
    }
}

/// Validate the actual Tracker::full_scope_evidence digest schema. Signed
/// metadata is never normalized, prefix-stripped or reissued by this module.
fn validate_tracker_digest_fields(evidence: &Value) -> Result<()> {
    let proof = &evidence["expectedFullScope"]["scope"];
    for value in [
        &evidence["metadataIdentity"],
        &proof["metadataIdentity"],
        &proof["trackingScopeHash"],
        &proof["expectedNodeIdsHash"],
        &proof["deletedNodeIdsHash"],
    ] {
        if !value.as_str().is_some_and(canonical_raw_hash) {
            return Err(StateError::Invalid(
                "native tracker metadata digests require exact lowercase 64-hex, without a content-hash prefix".into(),
            ));
        }
    }
    if proof["metadataIdentity"] != evidence["metadataIdentity"]
        || proof["baselineIdentity"] != evidence["baseline"]["snapshotIdentity"]
    {
        return Err(StateError::Conflict(
            "native full-scope metadata/baseline identities differ from the signed scope".into(),
        ));
    }
    match evidence["baseline"]["kind"].as_str() {
        Some("none")
            if proof["baselineIdentity"].is_null()
                && evidence["baseline"]["reference"].is_null()
                && evidence["baseline"]["scope"].is_null() => {}
        Some("full" | "partial") => {
            for value in [
                &proof["baselineIdentity"],
                &evidence["baseline"]["reference"]["hash"],
                &evidence["baseline"]["scope"]["hash"],
            ] {
                if !value.as_str().is_some_and(canonical_raw_hash) {
                    return Err(StateError::Invalid(
                        "native tracker baseline digests require exact lowercase 64-hex".into(),
                    ));
                }
            }
            if evidence["baseline"]["reference"]["hash"] != evidence["baseline"]["scope"]["hash"]
                || evidence["baseline"]["reference"]["name"]
                    != evidence["baseline"]["scope"]["name"]
            {
                return Err(StateError::Conflict(
                    "native original baseline reference differs from its signed scope".into(),
                ));
            }
        }
        _ => {
            return Err(StateError::Invalid(
                "invalid native tracker baseline digest schema".into(),
            ))
        }
    }
    Ok(())
}

impl NativeCaptureScope {
    /// Compact header from native-only frozen tracker evidence. The resulting
    /// value grants nothing without the matching installed Rust authority.
    pub fn full_scope_from_evidence(evidence: &Value) -> Result<NativeFullScopeBinding> {
        NativeFullScopeBinding::from_evidence(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.work_id.is_empty()
            || self.work_id.len() > 128
            || self.work_id.chars().any(char::is_control)
            || self.metadata_identity.is_empty()
            || self.metadata_identity.len() > 512
            || self.metadata_identity.chars().any(char::is_control)
            || self.node_count > MAX_CAPTURE_NODES
            || (self.node_count == 0 && self.full_scope.is_none())
        {
            return Err(StateError::Invalid(
                "invalid frozen native capture scope".into(),
            ));
        }
        if let Some(full) = &self.full_scope {
            full.validate()?;
            if self.node_count.saturating_add(full.deleted_count) > MAX_CAPTURE_NODES {
                return Err(StateError::Invalid(
                    "native live/deleted node bound exceeded".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Wire-compatible with QuickSave's complete FileStamp, including change time.
/// Access time is intentionally excluded: reads can legitimately change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCaptureStamp {
    pub device: u64,
    pub file_id: [u64; 2],
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u32,
    pub changed_seconds: i64,
    pub changed_nanoseconds: u32,
}

impl NativeCaptureStamp {
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !(metadata.is_file() || metadata.is_dir() || metadata.file_type().is_symlink())
                || !(0..1_000_000_000).contains(&metadata.mtime_nsec())
                || !(0..1_000_000_000).contains(&metadata.ctime_nsec())
            {
                return Err(StateError::UnsafePath(
                    "native capture receipt requires a supported entry with exact timestamps"
                        .into(),
                ));
            }
            return Ok(Self {
                device: metadata.dev(),
                file_id: [metadata.ino(), 0],
                size: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec() as u32,
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec() as u32,
            });
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(StateError::Invalid(
                "source native capture receipt stamps are unsupported on this platform".into(),
            ))
        }
    }

    /// Complete stamp of an anchored, no-follow observation, including the
    /// entry's native length even when its logical metadata-node size is zero.
    pub fn from_source_metadata(metadata: &SourceMetadata) -> Result<Self> {
        #[cfg(unix)]
        {
            let modified = metadata.mtime_ns().ok_or_else(|| {
                StateError::Invalid("native metadata mtime is not exactly representable".into())
            })?;
            let changed = metadata.ctime_ns().ok_or_else(|| {
                StateError::Invalid("native metadata ctime is not exactly representable".into())
            })?;
            return Ok(Self {
                device: metadata.dev(),
                file_id: [metadata.ino(), 0],
                size: metadata.len(),
                modified_seconds: modified.div_euclid(1_000_000_000),
                modified_nanoseconds: modified.rem_euclid(1_000_000_000) as u32,
                changed_seconds: changed.div_euclid(1_000_000_000),
                changed_nanoseconds: changed.rem_euclid(1_000_000_000) as u32,
            });
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(StateError::Invalid(
                "native no-follow metadata stamps are unsupported on this platform".into(),
            ))
        }
    }
}

/// Metadata-only node read from the trusted native frozen index. No predicted
/// content hash is accepted. `logical_root` is assigned by the native bridge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCaptureNode {
    pub id: String,
    pub root_id: String,
    pub logical_root: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub stamp: NativeCaptureStamp,
    #[serde(default)]
    pub link_target_hash: Option<String>,
}

/// In-process capability. Do not implement this from an incoming IPC document.
/// Neither method may reenter StateAgent while its native-binding lock is held;
/// this module never holds that lock across callbacks.
pub trait NativeCaptureSink: Send + Sync + 'static {
    fn node_page(
        &self,
        scope: &NativeCaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<NativeCaptureNode>>;
    /// Native-only restart/uncertainty-generation binding. None disables reuse.
    /// This token must change after observer loss, overflow or tracker restart.
    fn reuse_epoch(&self, _scope: &NativeCaptureScope) -> Result<Option<String>> {
        Ok(None)
    }
    /// Default None is explicitly NOT full-snapshot/empty/deletion authority.
    fn full_scope_authority(
        &self,
        _scope: &NativeCaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        Ok(None)
    }
    fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> Result<()>;
}

/// Native-only owner of the tracker's signed expectedFullScope, exact frozen
/// baseline/deleted nodes and original grants. No Deserialize constructor.
/// Revalidation must verify those grants and original root/provider scope.
/// Called only while preparing capture, never by source receipt revalidation.
pub trait NativeFullScopeAuthority: Send + Sync + 'static {
    fn evidence(&self) -> Result<Value>;
    fn revalidate(&self) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootCapture {
    id: String,
    logical_root: String,
    stamp: NativeCaptureStamp,
    mode: u32,
    owner: u32,
    group: u32,
    link_count: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletedNode {
    key: NativeFileKey,
    id: String,
    kind: String,
    size: u64,
    file_hash: Option<String>,
    link_target_hash: Option<String>,
    stamp: NativeCaptureStamp,
    metadata: NodeMetadata,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NodeMetadata {
    mode: u32,
    owner: u32,
    group: u32,
    link_count: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NativeHistory {
    parent_bundle_id: Option<Uuid>,
    parent_manifest_hash: Option<String>,
    deleted: Vec<DeletedNode>,
}

struct FullSnapshot {
    authority: Arc<dyn NativeFullScopeAuthority>,
    evidence: Value,
    /// Installation identity from the original authorization.trackingScope.appId,
    /// never the private workspace softwareId or canonical source AppId.
    software_instance_id: String,
    deleted: BTreeMap<NativeFileKey, DeletedNode>,
    roots: Vec<RootCapture>,
}

fn root_capture(pin: &NativeApprovedPin) -> Result<RootCapture> {
    pin.check()?;
    let metadata = pin.handle.metadata()?;
    let stamp = NativeCaptureStamp::from_metadata(&metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(RootCapture {
            id: pin.id.clone(),
            logical_root: pin.logical_root.clone(),
            stamp,
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            link_count: metadata.nlink(),
        });
    }
    #[cfg(not(unix))]
    Err(StateError::Invalid(
        "full native root metadata is unsupported on this platform".into(),
    ))
}

fn full_snapshot(
    scope: &NativeCaptureScope,
    app: &AppId,
    sink: &dyn NativeCaptureSink,
    pins: &[Arc<NativeApprovedPin>],
) -> Result<Option<FullSnapshot>> {
    let Some(binding) = &scope.full_scope else {
        return Ok(None);
    };
    let authority = sink.full_scope_authority(scope)?.ok_or_else(|| {
        StateError::Conflict("full/empty/deleted capture has no installed native authority".into())
    })?;
    authority.revalidate()?;
    let evidence = authority.evidence()?;
    if NativeFullScopeBinding::from_evidence(&evidence)? != *binding {
        return Err(StateError::Conflict(
            "native full snapshot evidence changed after freezing".into(),
        ));
    }
    let proof = &evidence["expectedFullScope"]["scope"];
    // Three separate identities: the private workspace record authorizes the
    // work; trackingScope.appId names its installation; `app` is the canonical
    // source identity that owns the pinned roots and logical-root namespace.
    // Never substitute one for another or rewrite the original signed scope.
    let private_software_id = evidence["softwareId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
        .ok_or_else(|| StateError::Invalid("full native private software ID is missing".into()))?;
    let tracking_scope = &evidence["authorization"]["trackingScope"];
    let instance = tracking_scope["appId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
        .ok_or_else(|| StateError::Invalid("full native software-instance ID is missing".into()))?;
    if evidence["version"] != 1
        || evidence["workId"] != scope.work_id
        || evidence["metadataIdentity"] != scope.metadata_identity
        || evidence["sourceIdentity"]["app_id"].as_str() != Some(app.as_str())
        || evidence["fullScope"] != true
        || evidence["completeFileList"] != true
        || evidence["keepsVersionHistory"] != true
        || evidence["coverageScope"] != "approved_evidenced_roots_only"
        || proof["version"] != 1
        || proof["workId"] != scope.work_id
        || proof["metadataIdentity"] != scope.metadata_identity
        || proof["softwareId"].as_str() != Some(private_software_id)
        || tracking_scope["softwareId"].as_str() != Some(private_software_id)
        || tracking_scope["sourceIdentity"] != evidence["sourceIdentity"]
        || proof["providerId"] != evidence["providerId"]
        || proof["generation"] != evidence["generation"]
        || proof["snapshotMode"] != "additive_full_scope"
        || proof["keepsHistory"] != true
        || !evidence["expectedFullScope"]["grant"].is_object()
        || proof["baselineKind"] != evidence["baseline"]["kind"]
        || proof["baselineIdentity"] != evidence["baseline"]["snapshotIdentity"]
        || !tracking_scope.is_object()
        || proof["trackingScopeHash"] != metadata_digest(tracking_scope)?
    {
        return Err(StateError::Conflict(
            "signed native full snapshot does not bind this exact source scope".into(),
        ));
    }
    let root_evidence = evidence["roots"]
        .as_array()
        .ok_or_else(|| StateError::Integrity("full scope roots are missing".into()))?;
    let root_ids = root_evidence
        .iter()
        .map(|root| {
            root["id"]
                .as_str()
                .ok_or_else(|| StateError::Integrity("full scope root has no ID".into()))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let proof_roots = proof["rootIds"]
        .as_array()
        .ok_or_else(|| StateError::Integrity("signed full-scope root IDs are missing".into()))?;
    if root_ids.len() != pins.len()
        || root_ids.len() != root_evidence.len()
        || proof_roots.len() != root_ids.len()
        || proof_roots
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            != root_ids
    {
        return Err(StateError::Conflict(
            "full native snapshot omitted/duplicated approved roots".into(),
        ));
    }
    let mut roots = Vec::with_capacity(pins.len());
    for pin in pins {
        let root = root_evidence
            .iter()
            .find(|root| root["id"] == pin.id)
            .ok_or_else(|| {
                StateError::Conflict("approved root omitted from full snapshot".into())
            })?;
        let actual = root_capture(pin)?;
        if root["path"] != json!(pin.path)
            || root["role"] != pin.role.as_str()
            || root["identity"] != json!({"device":pin.identity.0,"fileId":[pin.identity.1,0]})
            || root["allowedFiles"] != json!(pin.allowed_files)
        {
            return Err(StateError::Conflict(
                "full snapshot root is not the actual approved native identity".into(),
            ));
        }
        // A manual leaf allowlist never claims its unrelated parent metadata as
        // app content. Whole-root snapshots must carry the frozen native stamp.
        if pin.allowed_files.is_none() {
            let stamp: NativeCaptureStamp =
                serde_json::from_value(evidence["rootStamps"][&pin.id].clone())?;
            let metadata: NodeMetadata =
                serde_json::from_value(evidence["rootMetadata"][&pin.id].clone())?;
            if stamp != actual.stamp
                || metadata.mode != actual.mode
                || metadata.owner != actual.owner
                || metadata.group != actual.group
                || metadata.link_count != actual.link_count
            {
                return Err(StateError::Conflict(
                    "full snapshot root metadata changed before source capture".into(),
                ));
            }
        }
        roots.push(actual);
    }
    let mut deleted = BTreeMap::new();
    let mut deleted_ids = BTreeSet::new();
    let mut path_bytes = 0usize;
    for node in evidence["deletedNodes"]
        .as_array()
        .expect("binding checked deleted list")
    {
        let root_id = node["rootId"]
            .as_str()
            .ok_or_else(|| StateError::Integrity("deleted native node has no root ID".into()))?;
        let pin = pins.iter().find(|pin| pin.id == root_id).ok_or_else(|| {
            StateError::UnsafePath("deleted node is outside approved roots".into())
        })?;
        let path = node["path"]
            .as_str()
            .ok_or_else(|| StateError::Integrity("deleted native node has no path".into()))?;
        validate_native_relative(path)?;
        path_bytes = path_bytes.saturating_add(path.len());
        if path_bytes > MAX_CAPTURE_PATH_BYTES
            || !pin.directory
            || pin
                .allowed_files
                .as_ref()
                .is_some_and(|leaves| !leaves.contains(path))
        {
            return Err(StateError::UnsafePath(
                "native deletion exceeds frozen root/file authority".into(),
            ));
        }
        let id = native_file_id(&pin.logical_root, path);
        let kind = node["kind"].as_str().unwrap_or("");
        let size = node["size"].as_u64().ok_or_else(|| {
            StateError::Integrity("deleted native logical size is missing".into())
        })?;
        // Tracker's captured file digest is raw; the source ManifestFile wire
        // hash is tagged. Convert only the private source comparison value, not
        // the original evidence or MAC-signed grant.
        let file_hash = match &node["fileHash"] {
            Value::Null => None,
            Value::String(hash) if canonical_raw_hash(hash) => Some(format!("blake3:{hash}")),
            _ => {
                return Err(StateError::Invalid(
                    "native tracker captured file digest requires exact lowercase 64-hex".into(),
                ))
            }
        };
        let link_target_hash = node["linkTargetHash"].as_str().map(str::to_owned);
        if node["id"] != id
            || !deleted_ids.insert(id.clone())
            || match kind {
                "file" => {
                    file_hash.as_ref().is_none_or(|hash| !canonical_hash(hash))
                        || link_target_hash.is_some()
                }
                "directory" => size != 0 || file_hash.is_some() || link_target_hash.is_some(),
                "symlink" => {
                    size != 0
                        || file_hash.is_some()
                        || link_target_hash
                            .as_ref()
                            .is_none_or(|hash| !canonical_raw_hash(hash))
                }
                _ => true,
            }
        {
            return Err(StateError::Integrity(
                "invalid, duplicate or unauthenticated native deletion identity".into(),
            ));
        }
        let key = NativeFileKey {
            logical_root: pin.logical_root.clone(),
            relative_path: path.into(),
        };
        let stamp: NativeCaptureStamp = serde_json::from_value(node["stamp"].clone())?;
        let metadata: NodeMetadata = serde_json::from_value(node["metadata"].clone())?;
        if (kind == "file" && stamp.size != size)
            || stamp.modified_nanoseconds >= 1_000_000_000
            || stamp.changed_nanoseconds >= 1_000_000_000
        {
            return Err(StateError::Integrity(
                "deleted native complete stamp is invalid".into(),
            ));
        }
        deleted.insert(
            key.clone(),
            DeletedNode {
                key,
                id,
                kind: kind.into(),
                size,
                file_hash,
                link_target_hash,
                stamp,
                metadata,
            },
        );
    }
    let exact_deleted = deleted_ids.iter().collect::<Vec<_>>();
    if evidence["deletedFileIds"] != json!(exact_deleted)
        || proof["deletedNodeIdsHash"] != metadata_digest(&exact_deleted)?
        || (!deleted.is_empty()
            && (!matches!(
                evidence["baseline"]["kind"].as_str(),
                Some("full" | "partial")
            ) || !evidence["baseline"]["reference"].is_object()
                || !evidence["baseline"]["scope"].is_object()))
    {
        return Err(StateError::Conflict(
            "native full snapshot deletion list/baseline is not exact".into(),
        ));
    }
    authority.revalidate()?;
    let software_instance_id = instance.to_owned();
    Ok(Some(FullSnapshot {
        authority,
        evidence,
        software_instance_id,
        deleted,
        roots,
    }))
}

/// One bounded, descriptor-anchored completeness check before capture. Errors,
/// including unreadable roots, are never converted to absent/empty authority.
fn verify_full_inventory(
    pins: &[Arc<NativeApprovedPin>],
    full: &FullSnapshot,
    nodes: &BTreeMap<NativeFileKey, NativeCaptureNode>,
    counters: &Counters,
) -> Result<()> {
    fn visit(
        source: &SourcePath,
        pin: &NativeApprovedPin,
        relative: &str,
        nodes: &BTreeMap<NativeFileKey, NativeCaptureNode>,
        seen: &mut BTreeSet<NativeFileKey>,
        counters: &Counters,
    ) -> Result<()> {
        validate_native_relative(relative)?;
        let before = source.metadata()?;
        let key = NativeFileKey {
            logical_root: pin.logical_root.clone(),
            relative_path: relative.into(),
        };
        let expected = nodes.get(&key).ok_or_else(|| {
            StateError::Conflict("full native inventory contains an unfrozen node".into())
        })?;
        if !seen.insert(key)
            || metadata_kind(&before)? != expected.kind
            || NativeCaptureStamp::from_source_metadata(&before)? != expected.stamp
        {
            return Err(StateError::Conflict(
                "full native inventory changed after metadata freeze".into(),
            ));
        }
        counters.inventory_nodes.fetch_add(1, Ordering::Relaxed);
        if before.is_dir() {
            let directory = source.open_directory()?;
            if SourceMetadata::from(&directory.metadata()?) != before {
                return Err(StateError::Conflict(
                    "native inventory directory changed while opening".into(),
                ));
            }
            let names = noland_snapshot::native_metadata::directory_names(&directory)?;
            if names.len() > MAX_CAPTURE_NODES.saturating_sub(seen.len()) {
                return Err(StateError::Invalid(
                    "full native inventory exceeds its node bound".into(),
                ));
            }
            for name in names {
                let leaf = name
                    .to_str()
                    .ok_or_else(|| StateError::UnsafePath("non-UTF8 full-scope name".into()))?;
                let child_relative = format!("{relative}/{leaf}");
                visit(
                    &SourcePath::child(&directory, name)?,
                    pin,
                    &child_relative,
                    nodes,
                    seen,
                    counters,
                )?;
            }
            if SourceMetadata::from(&directory.metadata()?) != before {
                return Err(StateError::Conflict(
                    "native inventory changed during directory enumeration".into(),
                ));
            }
        } else if before.is_symlink() {
            let target = source.read_link()?;
            let target = target
                .to_str()
                .ok_or_else(|| StateError::UnsafePath("non-UTF8 native link".into()))?;
            noland_state_core::validate_relative_symlink_target_within_root(relative, target)?;
            if expected.link_target_hash.as_deref()
                != Some(blake3::hash(target.as_bytes()).to_hex().as_str())
            {
                return Err(StateError::Conflict(
                    "full inventory confined link changed".into(),
                ));
            }
        }
        if source.metadata()? != before {
            return Err(StateError::Conflict(
                "full native node changed during inventory validation".into(),
            ));
        }
        Ok(())
    }
    let mut seen = BTreeSet::new();
    for pin in pins {
        pin.check()?;
        let frozen = full
            .roots
            .iter()
            .find(|root| root.id == pin.id)
            .ok_or_else(|| StateError::Integrity("native root proof missing".into()))?;
        if root_capture(pin)? != *frozen {
            return Err(StateError::Conflict(
                "approved root metadata changed while installing full capture".into(),
            ));
        }
        if let Some(leaves) = &pin.allowed_files {
            for leaf in leaves {
                let child = SourcePath::child(&pin.handle, leaf.into())?;
                match child.metadata() {
                    Ok(metadata) => {
                        if !metadata.is_file() {
                            return Err(StateError::UnsafePath(
                                "manual leaf is not an approved regular file".into(),
                            ));
                        }
                        visit(&child, pin, leaf, nodes, &mut seen, counters)?;
                    }
                    Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        } else if pin.directory {
            let names = noland_snapshot::native_metadata::directory_names(&pin.handle)?;
            if names.len() > MAX_CAPTURE_NODES.saturating_sub(seen.len()) {
                return Err(StateError::Invalid(
                    "native root inventory exceeds its node bound".into(),
                ));
            }
            for name in names {
                let relative = name
                    .to_str()
                    .ok_or_else(|| StateError::UnsafePath("non-UTF8 native name".into()))?
                    .to_owned();
                visit(
                    &SourcePath::child(&pin.handle, name)?,
                    pin,
                    &relative,
                    nodes,
                    &mut seen,
                    counters,
                )?;
            }
        } else {
            let relative = pin
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| StateError::UnsafePath("file approval has no native name".into()))?;
            visit(
                &SourcePath::new(&pin.path)?,
                pin,
                relative,
                nodes,
                &mut seen,
                counters,
            )?;
        }
        if root_capture(pin)? != *frozen {
            return Err(StateError::Conflict(
                "full approved root changed during inventory capture".into(),
            ));
        }
    }
    let ids = nodes.values().map(|node| &node.id).collect::<BTreeSet<_>>();
    if seen.len() != nodes.len()
        || full.deleted.keys().any(|key| seen.contains(key))
        || full.evidence["expectedFullScope"]["scope"]["expectedNodeIdsHash"]
            != metadata_digest(&ids.iter().collect::<Vec<_>>())?
    {
        return Err(StateError::Conflict(
            "full snapshot has missing nodes or an inexact signed live/deleted partition".into(),
        ));
    }
    Ok(())
}

struct RootPin {
    path: PathBuf,
    handle: File,
    identity: (u64, u64),
    counters: Arc<Counters>,
}

impl RootPin {
    fn open(path: PathBuf, counters: Arc<Counters>) -> Result<Self> {
        let handle = SourcePath::new(&path)?.open_directory()?;
        let identity = directory_identity(&handle)?;
        let pin = Self {
            path,
            handle,
            identity,
            counters,
        };
        pin.check()?;
        Ok(pin)
    }

    fn check(&self) -> Result<()> {
        self.counters
            .directory_pin_validations
            .fetch_add(1, Ordering::Relaxed);
        if directory_identity(&self.handle)? != self.identity
            || directory_identity(&SourcePath::new(&self.path)?.open_directory()?)? != self.identity
        {
            return Err(StateError::Conflict(
                "native capture root identity changed".into(),
            ));
        }
        Ok(())
    }

    fn check_node(&self, node: &NativeCaptureNode) -> Result<()> {
        self.check()?;
        let source =
            SourcePath::new_beneath(&self.path.join(&node.path), &self.path, self.identity)?;
        let before = source.metadata()?;
        if metadata_kind(&before)? != node.kind
            || NativeCaptureStamp::from_source_metadata(&before)? != node.stamp
        {
            return Err(StateError::Conflict(
                "native source no longer matches its captured full file stamp".into(),
            ));
        }
        match node.kind.as_str() {
            "file" => {
                let opened = source.open_regular()?;
                self.counters
                    .metadata_file_opens
                    .fetch_add(1, Ordering::Relaxed);
                if NativeCaptureStamp::from_metadata(&opened.metadata()?)? != node.stamp {
                    return Err(StateError::Conflict(
                        "native file changed while opening its metadata proof".into(),
                    ));
                }
            }
            "directory" => {
                // Never enumerate/follow children here; the frozen native index
                // already supplies the exact nodes and directory change stamp.
                let opened = source.open_directory()?;
                let held = SourceMetadata::from(&opened.metadata()?);
                if held != before {
                    return Err(StateError::Conflict(
                        "native directory changed while validating".into(),
                    ));
                }
            }
            "symlink" => {
                let target = source.read_link()?;
                let target = target.to_str().ok_or_else(|| {
                    StateError::UnsafePath("native link target is not UTF-8".into())
                })?;
                noland_state_core::validate_relative_symlink_target_within_root(
                    &node.path, target,
                )?;
                if node.link_target_hash.as_deref()
                    != Some(blake3::hash(target.as_bytes()).to_hex().as_str())
                {
                    return Err(StateError::Conflict(
                        "native confined link target changed".into(),
                    ));
                }
            }
            _ => {
                return Err(StateError::UnsafePath(
                    "unsupported native capture node kind".into(),
                ))
            }
        }
        if source.metadata()? != before {
            return Err(StateError::Conflict(
                "native metadata node changed while validating".into(),
            ));
        }
        Ok(())
    }
}

fn metadata_kind(metadata: &SourceMetadata) -> Result<&'static str> {
    if metadata.is_file() {
        Ok("file")
    } else if metadata.is_dir() {
        Ok("directory")
    } else if metadata.is_symlink() {
        Ok("symlink")
    } else {
        Err(StateError::UnsafePath(
            "native capture refuses special entries/reparse kinds".into(),
        ))
    }
}

fn directory_identity(file: &File) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(StateError::UnsafePath(
                "capture boundary is not a directory".into(),
            ));
        }
        return Ok((metadata.dev(), metadata.ino()));
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(StateError::Invalid(
            "source capture directory pins are unsupported".into(),
        ))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapturedFile {
    key: NativeFileKey,
    stamp: NativeCaptureStamp,
    #[serde(default = "regular_kind")]
    kind: String,
    file_hash: Option<String>,
    size: u64,
    chunks_hash: Option<String>,
    #[serde(default)]
    link_target_hash: Option<String>,
}

fn regular_kind() -> String {
    "file".into()
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CaptureProof {
    version: u32,
    operation: Uuid,
    app: AppId,
    scope: NativeCaptureScope,
    roots_fingerprint: String,
    #[serde(default)]
    software_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_layouts: Option<Value>,
    #[serde(default)]
    reuse_epoch: Option<String>,
    #[serde(default)]
    source_loss_generation: u64,
    files: Vec<CapturedFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    full_scope_evidence: Option<Value>,
    #[serde(default)]
    root_captures: Vec<RootCapture>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history: Option<NativeHistory>,
}

struct Session {
    operation: Uuid,
    app: AppId,
    scope: NativeCaptureScope,
    roots_fingerprint: String,
    software_instance_id: Mutex<Option<String>>,
    reuse_epoch: Option<String>,
    source_loss_generation: u64,
    nodes: Arc<BTreeMap<NativeFileKey, NativeCaptureNode>>,
    roots: BTreeMap<String, Arc<RootPin>>,
    approved: Vec<Arc<NativeApprovedPin>>,
    full: Option<FullSnapshot>,
    history: Mutex<Option<NativeHistory>>,
    workspace: Arc<RootPin>,
    sink: Arc<dyn NativeCaptureSink>,
    captured: Mutex<BTreeMap<NativeFileKey, CapturedFile>>,
    accepted: Mutex<Option<Arc<NativeCaptureReceipt>>>,
    accepting: std::sync::atomic::AtomicBool,
    counters: Arc<Counters>,
}

#[derive(Clone)]
struct ReuseProof {
    stamp: NativeCaptureStamp,
    file_hash: String,
    size: u64,
    epoch: String,
    source_loss_generation: u64,
    chunks_hash: String,
}

/// Add one `captures: NativeCaptures` field to NativeBindings. All mutation is
/// behind the existing native-bindings mutex; callbacks use cloned Arc sessions.
#[derive(Default)]
pub struct NativeCaptures {
    sessions: BTreeMap<Uuid, Arc<Session>>,
    reuse: BTreeMap<(AppId, String, String, NativeFileKey), ReuseProof>,
}

impl NativeCaptures {
    pub fn contains(&self, operation: Uuid) -> bool {
        self.sessions.contains_key(&operation)
    }
}

fn session(agent: &StateAgent, operation: Uuid) -> Result<Option<Arc<Session>>> {
    Ok(agent
        .native_bindings
        .lock()
        .captures
        .sessions
        .get(&operation)
        .cloned())
}

pub fn is_installed(agent: &StateAgent, operation: Uuid) -> bool {
    agent.native_bindings.lock().captures.contains(operation)
}

/// Cheap status diagnostics: no source walk, file opens, receipt revalidation,
/// provider access, key lookup or serialization of the frozen node inventory.
pub fn counters(agent: &StateAgent, operation: Uuid) -> Result<Option<NativeCaptureCounters>> {
    Ok(session(agent, operation)?.map(|session| session.counters.snapshot()))
}

/// Install before admitting execution. This consumes metadata pages once and
/// returns the exact source logical keys, avoiding local_files()/a second walk.
pub fn install(
    agent: &StateAgent,
    operation: Uuid,
    app: &AppId,
    scope: NativeCaptureScope,
    sink: Arc<dyn NativeCaptureSink>,
) -> Result<Vec<NativeFileKey>> {
    scope.validate()?;
    if !agent.config.native_host || operation.is_nil() || agent.operations.is_running(operation) {
        return Err(StateError::Conflict(
            "native capture sink cannot change during execution".into(),
        ));
    }
    let fingerprint = agent.native_binding_fingerprint(app)?;
    let source_loss_generation = agent.observer.loss_generation();
    let approved = agent.native_capture_root_pins(app)?;
    let full = full_snapshot(&scope, app, sink.as_ref(), &approved)?;
    let counters = Arc::new(Counters::default());
    let workspace = Arc::new(RootPin::open(
        agent.config.paths.packs.clone(),
        counters.clone(),
    )?);
    let reuse_epoch = sink.reuse_epoch(&scope)?;
    if reuse_epoch.as_ref().is_some_and(|epoch| {
        epoch.is_empty() || epoch.len() > 1024 || epoch.chars().any(char::is_control)
    }) {
        return Err(StateError::Invalid(
            "invalid native-only reuse epoch".into(),
        ));
    }
    let root_map = agent.roots.lock().clone();
    let mut nodes = BTreeMap::new();
    let mut roots = BTreeMap::new();
    let mut path_bytes = full.as_ref().map_or(0, |full| {
        full.deleted
            .keys()
            .map(|key| key.relative_path.len())
            .sum::<usize>()
    });
    while nodes.len() < scope.node_count {
        let offset = nodes.len();
        let count = NATIVE_CAPTURE_PAGE.min(scope.node_count - offset);
        let page = sink.node_page(&scope, offset, count)?;
        counters.frozen_pages.fetch_add(1, Ordering::Relaxed);
        if page.len() != count {
            return Err(StateError::Integrity(
                "native frozen node page added/omitted nodes".into(),
            ));
        }
        for node in page {
            validate_native_relative(&node.path)?;
            let valid_kind = match node.kind.as_str() {
                "file" => node.size == node.stamp.size && node.link_target_hash.is_none(),
                "directory" => node.size == 0 && node.link_target_hash.is_none(),
                "symlink" => {
                    node.size == 0
                        && node
                            .link_target_hash
                            .as_ref()
                            .is_some_and(|hash| canonical_raw_hash(hash))
                }
                _ => false,
            };
            if !valid_kind
                || node.id != native_file_id(&node.logical_root, &node.path)
                || native_tracking_root_id(&node.logical_root).as_deref()
                    != Some(node.root_id.as_str())
            {
                return Err(StateError::Integrity(
                    "native node metadata/logical identity mismatch".into(),
                ));
            }
            // Root tokens repeat per node but are independently bounded by the
            // 128-root native registration and metadata document ceiling.
            path_bytes = path_bytes.saturating_add(node.path.len());
            if path_bytes > MAX_CAPTURE_PATH_BYTES {
                return Err(StateError::Invalid(
                    "frozen native capture paths exceed their aggregate bound".into(),
                ));
            }
            let logical = LogicalRoot::parse(&node.logical_root).ok_or_else(|| {
                StateError::UnsafePath("unknown native capture logical root".into())
            })?;
            let root = root_map.resolve(&logical).ok_or_else(|| {
                StateError::UnsafePath("native frozen node has no approved root".into())
            })?;
            let path = root.join(&node.path);
            let actual = agent.native_logical_path(app, &path)?;
            if !agent.native_permits(app, &path)
                || actual.logical_root.as_token() != node.logical_root
                || actual.relative_path != node.path
            {
                return Err(StateError::UnsafePath(
                    "native frozen node escaped approved selection".into(),
                ));
            }
            if !roots.contains_key(&node.logical_root) {
                if roots.len() >= 128 {
                    return Err(StateError::Invalid("native capture root ceiling".into()));
                }
                roots.insert(
                    node.logical_root.clone(),
                    Arc::new(RootPin::open(root, counters.clone())?),
                );
            }
            if full.is_none() {
                roots[&node.logical_root].check_node(&node)?;
            }
            let key = NativeFileKey {
                logical_root: node.logical_root.clone(),
                relative_path: node.path.clone(),
            };
            if nodes.insert(key, node).is_some() {
                return Err(StateError::Integrity("duplicate frozen native node".into()));
            }
        }
    }
    if let Some(full) = &full {
        verify_full_inventory(&approved, full, &nodes, &counters)?;
    }
    hash_value(&nodes.values().collect::<Vec<_>>())?;
    let keys = nodes.keys().cloned().collect::<Vec<_>>();
    let prepared = Arc::new(Session {
        operation,
        app: app.clone(),
        scope,
        roots_fingerprint: fingerprint,
        reuse_epoch,
        source_loss_generation,
        software_instance_id: Mutex::new(
            full.as_ref().map(|full| full.software_instance_id.clone()),
        ),
        nodes: Arc::new(nodes),
        roots,
        approved,
        full,
        history: Mutex::new(None),
        workspace,
        sink,
        captured: Mutex::new(BTreeMap::new()),
        accepted: Mutex::new(None),
        accepting: std::sync::atomic::AtomicBool::new(false),
        counters,
    });
    let mut bindings = agent.native_bindings.lock();
    let captures = &mut bindings.captures;
    let total = captures
        .sessions
        .values()
        .map(|session| {
            session.nodes.len() + session.full.as_ref().map_or(0, |full| full.deleted.len())
        })
        .sum::<usize>();
    let added = prepared.nodes.len() + prepared.full.as_ref().map_or(0, |full| full.deleted.len());
    let retained_paths = captures
        .sessions
        .values()
        .map(|session| {
            session
                .nodes
                .keys()
                .map(|key| key.relative_path.len())
                .sum::<usize>()
                + session.full.as_ref().map_or(0, |full| {
                    full.deleted
                        .keys()
                        .map(|key| key.relative_path.len())
                        .sum::<usize>()
                })
        })
        .sum::<usize>();
    let root_handles = captures
        .sessions
        .values()
        .map(|session| session.roots.len() + session.approved.len() + 1)
        .sum::<usize>();
    if captures.sessions.contains_key(&operation)
        || captures.sessions.len() >= MAX_CAPTURE_OPERATIONS
        || total.saturating_add(added) > MAX_CAPTURE_NODES
        || retained_paths.saturating_add(path_bytes) > MAX_CAPTURE_PATH_BYTES
        || root_handles.saturating_add(prepared.roots.len() + prepared.approved.len() + 1)
            > MAX_CAPTURE_ROOT_HANDLES
    {
        return Err(StateError::Conflict(
            "native capture registration exists or bounded capacity is exhausted".into(),
        ));
    }
    captures.sessions.insert(operation, prepared);
    Ok(keys)
}

pub fn validate_selection(
    agent: &StateAgent,
    operation: Uuid,
    scope: &NativeCaptureScope,
    keys: &[NativeFileKey],
    roots_fingerprint: &str,
    coverage: NativeCoverage,
    software_instance_id: Option<&str>,
) -> Result<()> {
    let session = session(agent, operation)?.ok_or_else(|| {
        StateError::Conflict("native metadata scope has no installed Rust capture sink".into())
    })?;
    if session.scope != *scope
        || session.roots_fingerprint != roots_fingerprint
        || session.roots_fingerprint != agent.native_binding_fingerprint(&session.app)?
        || keys.len() != session.nodes.len()
        || !keys.iter().eq(session.nodes.keys())
        || (session.full.is_some() != (coverage == NativeCoverage::FullApprovedScope))
        || session
            .full
            .as_ref()
            .is_some_and(|full| Some(full.software_instance_id.as_str()) != software_instance_id)
    {
        return Err(StateError::Conflict(
            "native frozen capture selection/binding changed".into(),
        ));
    }
    let instance = software_instance_id.ok_or_else(|| {
        StateError::Conflict("native metadata selection lacks a software-instance binding".into())
    })?;
    let mut bound = session
        .software_instance_id
        .lock()
        .map_err(|_| StateError::Invalid("native instance binding lock failed".into()))?;
    if bound.as_ref().is_some_and(|previous| previous != instance) {
        return Err(StateError::Conflict(
            "native software-instance binding changed".into(),
        ));
    }
    *bound = Some(instance.to_owned());
    Ok(())
}

/// Bind omission authority to the *actual authenticated source parent* before
/// filtering inherited files. Watcher delete hints never create this plan.
/// Selected/legacy scopes cannot authorize omissions or empty full snapshots.
pub(crate) fn prepare_history(
    agent: &StateAgent,
    operation: Uuid,
    parent: Option<&BundleManifest>,
) -> Result<Vec<ManifestTombstone>> {
    let Some(session) = session(agent, operation)? else {
        return Ok(Vec::new());
    };
    let mut history = NativeHistory {
        parent_bundle_id: parent.map(|manifest| manifest.bundle_id),
        parent_manifest_hash: parent.map(hash_value).transpose()?,
        deleted: Vec::new(),
    };
    if let Some(full) = &session.full {
        full.authority.revalidate()?;
        for pin in &session.approved {
            pin.check()?;
            let original = full
                .roots
                .iter()
                .find(|root| root.id == pin.id)
                .ok_or_else(|| StateError::Integrity("frozen native root proof missing".into()))?;
            if root_capture(pin)? != *original {
                return Err(StateError::Conflict(
                    "full native root metadata changed before capture began".into(),
                ));
            }
        }
        if let Some(parent) = parent {
            if parent.app.app_id != session.app
                || parent.environment["quicksave_native"]["software_instance_id"]
                    != full.software_instance_id
                || parent.environment["quicksave_native"]["selection"]["roots_fingerprint"]
                    != session.roots_fingerprint
            {
                return Err(StateError::Conflict(
                    "source parent is not the same canonical app/instance/approved roots".into(),
                ));
            }
            let mut prior = BTreeMap::new();
            for file in &parent.files {
                let key = NativeFileKey {
                    logical_root: file.logical_root.clone(),
                    relative_path: file.relative_path.clone(),
                };
                if prior.insert(key.clone(), file).is_some()
                    || (!session.nodes.contains_key(&key) && !full.deleted.contains_key(&key))
                {
                    return Err(StateError::Conflict(
                        "full native snapshot silently omits a prior source key".into(),
                    ));
                }
            }
            for (key, deleted) in &full.deleted {
                let file = prior.get(key).ok_or_else(|| {
                    StateError::Conflict(
                        "frozen deletion is absent from the actual source parent baseline".into(),
                    )
                })?;
                let mtime = deleted
                    .stamp
                    .modified_seconds
                    .checked_mul(1_000_000_000)
                    .and_then(|seconds| {
                        seconds.checked_add(i64::from(deleted.stamp.modified_nanoseconds))
                    });
                if file.file_type != deleted.kind
                    || file.mode != Some(deleted.metadata.mode)
                    || file.uid != Some(deleted.metadata.owner)
                    || file.gid != Some(deleted.metadata.group)
                    || mtime.is_none()
                    || file.mtime_ns != mtime
                    || match deleted.kind.as_str() {
                        "file" => {
                            file.size != deleted.size
                                || deleted.file_hash.as_ref() != Some(&file.file_hash)
                        }
                        "directory" => {
                            file.size != 0 || !file.file_hash.is_empty() || !file.chunks.is_empty()
                        }
                        "symlink" => file.symlink_target.as_ref().is_none_or(|target| {
                            deleted.link_target_hash.as_deref()
                                != Some(blake3::hash(target.as_bytes()).to_hex().as_str())
                        }),
                        _ => true,
                    }
                {
                    return Err(StateError::Conflict("frozen deletion differs from the authenticated source parent's captured entry".into()));
                }
            }
            if let Some(source_baseline) = full
                .evidence
                .get("sourceBaseline")
                .filter(|value| !value.is_null())
            {
                if source_baseline["sourceSnapshotId"] != parent.bundle_id.to_string()
                    || source_baseline["manifestHash"].as_str()
                        != history.parent_manifest_hash.as_deref()
                {
                    return Err(StateError::Conflict(
                        "full scope names a different actual source baseline".into(),
                    ));
                }
            }
        } else if !full.deleted.is_empty()
            || full
                .evidence
                .get("sourceBaseline")
                .is_some_and(|value| !value.is_null())
        {
            return Err(StateError::Conflict(
                "native deletion has no authenticated source parent".into(),
            ));
        }
        history.deleted = full.deleted.values().cloned().collect();
    }
    let tombstones = history
        .deleted
        .iter()
        .map(|deleted| ManifestTombstone {
            logical_root: deleted.key.logical_root.clone(),
            relative_path: deleted.key.relative_path.clone(),
            reason: "authenticated native full-scope omission; additive history retained".into(),
        })
        .collect();
    let mut stored = session
        .history
        .lock()
        .map_err(|_| StateError::Invalid("native history lock failed".into()))?;
    if stored.as_ref().is_some_and(|previous| previous != &history) {
        return Err(StateError::Conflict(
            "native capture parent/deletion baseline changed".into(),
        ));
    }
    *stored = Some(history);
    Ok(tombstones)
}

/// Freeze actual source root metadata in the source-format manifest environment.
/// Empty roots are evidence, never placeholder ManifestFile entries.
pub(crate) fn bind_manifest_history(
    agent: &StateAgent,
    operation: Uuid,
    manifest: &mut BundleManifest,
) -> Result<()> {
    let Some(session) = session(agent, operation)? else {
        return Ok(());
    };
    let Some(full) = &session.full else {
        return Ok(());
    };
    let history = session
        .history
        .lock()
        .map_err(|_| StateError::Invalid("native history lock failed".into()))?
        .clone()
        .ok_or_else(|| {
            StateError::Conflict("full native capture lacks its source parent plan".into())
        })?;
    manifest.environment["quicksave_native"]["full_scope"] = json!({
        "version":1,"binding":session.scope.full_scope,
        "rootCaptures":full.roots,"sourceParent":history.parent_bundle_id,
        "sourceParentManifestHash":history.parent_manifest_hash,
        "deletedNodeIdsHash":full.evidence["expectedFullScope"]["scope"]["deletedNodeIdsHash"],
        "keepsVersionHistory":true,
    });
    Ok(())
}

fn validate_history(
    session: &Session,
    manifest: &BundleManifest,
    proof: &CaptureProof,
) -> Result<()> {
    let Some(full) = &session.full else {
        if !manifest.tombstones.is_empty() || proof.full_scope_evidence.is_some() {
            return Err(StateError::Conflict(
                "selected native scope cannot authorize source deletions".into(),
            ));
        }
        return Ok(());
    };
    let binding = session
        .scope
        .full_scope
        .as_ref()
        .expect("full capability has a scope binding");
    let history = proof.history.as_ref().ok_or_else(|| {
        StateError::Conflict("native proof lacks its authenticated source history binding".into())
    })?;
    if proof.full_scope_evidence.as_ref() != Some(&full.evidence)
        || proof.root_captures != full.roots
        || history.deleted != full.deleted.values().cloned().collect::<Vec<_>>()
        || manifest.parent_bundle_id != history.parent_bundle_id
        || manifest.environment["quicksave_native"]["full_scope"]["binding"] != json!(binding)
        || manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"]
            != json!(proof.root_captures)
        || manifest.environment["quicksave_native"]["full_scope"]["sourceParentManifestHash"]
            != json!(history.parent_manifest_hash)
        || manifest.environment["quicksave_native"]["software_instance_id"]
            != full.software_instance_id
        || manifest.environment["quicksave_native"]["coverage"] != "full_approved_scope"
    {
        return Err(StateError::Conflict(
            "native source history/full-root proof changed after preparation".into(),
        ));
    }
    let actual = manifest
        .tombstones
        .iter()
        .map(|entry| NativeFileKey {
            logical_root: entry.logical_root.clone(),
            relative_path: entry.relative_path.clone(),
        })
        .collect::<BTreeSet<_>>();
    if actual.len() != manifest.tombstones.len() || !actual.iter().eq(full.deleted.keys()) {
        return Err(StateError::Conflict(
            "source tombstones do not exactly equal authenticated frozen deletions".into(),
        ));
    }
    Ok(())
}

/// Keep legacy empty-complete rejection everywhere; only a live native full
/// capability with proven actual roots and its exact source plan may bypass it.
pub(crate) fn validate_empty_complete(
    agent: &StateAgent,
    operation: Uuid,
    manifest: &BundleManifest,
) -> Result<()> {
    if manifest.mode != BackupMode::CompleteApplication || !manifest.files.is_empty() {
        return Ok(());
    }
    let session = session(agent, operation)?.ok_or_else(|| {
        StateError::Invalid("complete backup contains no application files".into())
    })?;
    if session.scope.node_count != 0 || session.full.is_none() {
        return Err(StateError::Invalid(
            "empty complete backup requires actual full-scope/root evidence".into(),
        ));
    }
    validate_history(&session, manifest, &make_proof(&session)?)
}

/// Called only by the actual source pipeline after its before/after checks.
/// `stamp` is the pre-read frozen identity, NEVER newly queried post-hash metadata.
pub(crate) fn record_file(
    agent: &StateAgent,
    operation: Uuid,
    file: &ManifestFile,
    stamp: Option<&NativeCaptureStamp>,
    stable: bool,
) -> Result<()> {
    if !agent.config.native_host {
        return Ok(());
    }
    let Some(session) = session(agent, operation)? else {
        return Ok(());
    };
    let stamp = stamp.ok_or_else(|| {
        StateError::Conflict(
            "capture lacks an authenticated pre-read complete stamp; recapture explicitly".into(),
        )
    })?;
    let key = NativeFileKey {
        logical_root: file.logical_root.clone(),
        relative_path: file.relative_path.clone(),
    };
    let expected = session
        .nodes
        .get(&key)
        .ok_or_else(|| StateError::Conflict("source captured an unselected native file".into()))?;
    if !stable
        || expected.kind != "file"
        || file.file_type != "file"
        || file.size != expected.size
        || *stamp != expected.stamp
        || !canonical_hash(&file.file_hash)
    {
        return Err(StateError::Conflict(
            "actual source capture does not match frozen metadata/stability".into(),
        ));
    }
    let proof = CapturedFile {
        key: key.clone(),
        stamp: stamp.clone(),
        kind: "file".into(),
        file_hash: Some(file.file_hash.clone()),
        size: file.size,
        chunks_hash: Some(hash_value(&file.chunks)?),
        link_target_hash: None,
    };
    store_proof(&session, key, proof)
}

fn store_proof(session: &Session, key: NativeFileKey, proof: CapturedFile) -> Result<()> {
    let mut captured = session
        .captured
        .lock()
        .map_err(|_| StateError::Invalid("native capture proof lock failed".into()))?;
    if captured
        .get(&key)
        .is_some_and(|previous| previous != &proof)
    {
        return Err(StateError::Integrity(
            "conflicting native file capture receipts".into(),
        ));
    }
    if captured.insert(key, proof).is_none() {
        session
            .counters
            .source_proofs_recorded
            .fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Parent calls from actual capture_directory/capture_symlink after its anchored
/// before/after checks. These nodes have no FastCDC/file-content payload.
pub fn record_metadata(
    agent: &StateAgent,
    operation: Uuid,
    file: &ManifestFile,
    before: &SourceMetadata,
    after: &SourceMetadata,
) -> Result<()> {
    if !agent.config.native_host {
        return Ok(());
    }
    let Some(session) = session(agent, operation)? else {
        return Ok(());
    };
    let kind = metadata_kind(before)?;
    if before != after || !matches!(kind, "directory" | "symlink") || file.file_type != kind {
        return Err(StateError::Conflict(
            "native metadata node changed during actual source capture".into(),
        ));
    }
    let key = NativeFileKey {
        logical_root: file.logical_root.clone(),
        relative_path: file.relative_path.clone(),
    };
    let expected = session
        .nodes
        .get(&key)
        .ok_or_else(|| StateError::Conflict("source captured unselected metadata".into()))?;
    let stamp = NativeCaptureStamp::from_source_metadata(before)?;
    if expected.kind != kind
        || expected.size != 0
        || expected.stamp != stamp
        || file.mtime_ns != before.mtime_ns()
    {
        return Err(StateError::Conflict(
            "actual metadata capture differs from frozen native metadata".into(),
        ));
    }
    #[cfg(unix)]
    if file.mode != Some(before.mode())
        || file.uid != Some(before.uid())
        || file.gid != Some(before.gid())
    {
        return Err(StateError::Conflict(
            "native metadata capture omitted/differed in actual mode or ownership".into(),
        ));
    }
    let link_target_hash = if kind == "symlink" {
        let target = file
            .symlink_target
            .as_deref()
            .ok_or_else(|| StateError::Integrity("captured symlink target missing".into()))?;
        noland_state_core::validate_relative_symlink_target_within_root(
            &file.relative_path,
            target,
        )?;
        let hash = blake3::hash(target.as_bytes()).to_hex().to_string();
        if expected.link_target_hash.as_ref() != Some(&hash) {
            return Err(StateError::Conflict(
                "actual source captured a different confined link target".into(),
            ));
        }
        Some(hash)
    } else {
        None
    };
    let proof = CapturedFile {
        key: key.clone(),
        stamp,
        kind: kind.into(),
        file_hash: None,
        size: 0,
        chunks_hash: None,
        link_target_hash,
    };
    if !manifest_matches_proof(file, &proof)? {
        return Err(StateError::Integrity(
            "native metadata manifest carries a payload or wrong link identity".into(),
        ));
    }
    session.roots[&expected.logical_root].check_node(expected)?;
    store_proof(&session, key, proof)
}

fn manifest_matches_proof(file: &ManifestFile, proof: &CapturedFile) -> Result<bool> {
    if file.file_type != proof.kind {
        return Ok(false);
    }
    Ok(match proof.kind.as_str() {
        "file" => {
            file.size == proof.size
                && proof.file_hash.as_deref() == Some(file.file_hash.as_str())
                && proof.chunks_hash.as_deref() == Some(hash_value(&file.chunks)?.as_str())
                && proof.link_target_hash.is_none()
                && file.symlink_target.is_none()
        }
        "directory" => {
            proof.size == 0
                && file.size == 0
                && file.chunks.is_empty()
                && proof.file_hash.is_none()
                && proof.chunks_hash.is_none()
                && proof.link_target_hash.is_none()
                && file.symlink_target.is_none()
                && file.file_hash.is_empty()
        }
        "symlink" => {
            let Some(target) = file.symlink_target.as_deref() else {
                return Ok(false);
            };
            noland_state_core::validate_relative_symlink_target_within_root(
                &file.relative_path,
                target,
            )?;
            let hash = blake3::hash(target.as_bytes()).to_hex().to_string();
            proof.size == 0
                && file.size == target.len() as u64
                && file.chunks.is_empty()
                && proof.file_hash.is_none()
                && proof.chunks_hash.is_none()
                && proof.link_target_hash.as_ref() == Some(&hash)
                && file.file_hash == format!("blake3:{hash}")
        }
        _ => false,
    })
}

/// Safe optimization for a parent-authenticated inherited ManifestFile. The
/// reusable hash was minted by a previous actual source capture in this process,
/// not by event silence or the DB's size/mtime-only fast-identity row.
pub fn prove_reuse(agent: &StateAgent, operation: Uuid, file: &ManifestFile) -> Result<bool> {
    let Some(session) = session(agent, operation)? else {
        return Ok(false);
    };
    let key = NativeFileKey {
        logical_root: file.logical_root.clone(),
        relative_path: file.relative_path.clone(),
    };
    let Some(node) = session.nodes.get(&key) else {
        return Ok(false);
    };
    if node.kind != "file" {
        return Ok(false);
    }
    // An independently observed source overflow/loss also fences reuse. A stale
    // controller token must not override the source engine's own uncertainty.
    // This does not revoke already completed stable captures or old payloads.
    if session.source_loss_generation != agent.observer.loss_generation() {
        return Ok(false);
    }
    let instance = session
        .software_instance_id
        .lock()
        .map_err(|_| StateError::Invalid("native instance binding lock failed".into()))?
        .clone()
        .ok_or_else(|| StateError::Conflict("native capture instance is not bound".into()))?;
    let previous = agent
        .native_bindings
        .lock()
        .captures
        .reuse
        .get(&(
            session.app.clone(),
            session.roots_fingerprint.clone(),
            instance,
            key,
        ))
        .cloned();
    let Some(previous) = previous else {
        return Ok(false);
    };
    if session.reuse_epoch.as_deref() != Some(previous.epoch.as_str())
        || previous.source_loss_generation != session.source_loss_generation
        || previous.stamp != node.stamp
        || previous.file_hash != file.file_hash
        || previous.size != file.size
        || previous.chunks_hash != hash_value(&file.chunks)?
        || file.file_type != "file"
    {
        return Ok(false);
    }
    session.roots[&node.logical_root].check_node(node)?;
    record_file(agent, operation, file, Some(&previous.stamp), true)?;
    session
        .counters
        .reused_file_proofs
        .fetch_add(1, Ordering::Relaxed);
    Ok(true)
}

fn make_proof(session: &Session) -> Result<CaptureProof> {
    let files = session
        .captured
        .lock()
        .map_err(|_| StateError::Invalid("native proof lock failed".into()))?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let history = session
        .history
        .lock()
        .map_err(|_| StateError::Invalid("native history lock failed".into()))?
        .clone();
    if files.len() != session.nodes.len() || (session.full.is_some() && history.is_none()) {
        return Err(StateError::Conflict(
            "native capture has unproved/omitted selected files".into(),
        ));
    }
    let software_instance_id = session
        .software_instance_id
        .lock()
        .map_err(|_| StateError::Invalid("native instance binding lock failed".into()))?
        .clone();
    let selected_roots = session
        .nodes
        .keys()
        .map(|key| key.logical_root.as_str())
        .collect::<BTreeSet<_>>();
    let root_layouts = software_instance_id
        .as_deref()
        .map(|instance| {
            root_layouts_from_pins(
                &session.app,
                instance,
                &session.approved,
                if session.full.is_some() {
                    None
                } else {
                    Some(&selected_roots)
                },
            )
        })
        .transpose()?;
    Ok(CaptureProof {
        version: 1,
        operation: session.operation,
        app: session.app.clone(),
        scope: session.scope.clone(),
        roots_fingerprint: session.roots_fingerprint.clone(),
        reuse_epoch: session.reuse_epoch.clone(),
        source_loss_generation: session.source_loss_generation,
        files,
        software_instance_id,
        root_layouts,
        full_scope_evidence: session.full.as_ref().map(|full| full.evidence.clone()),
        root_captures: session
            .full
            .as_ref()
            .map_or_else(Vec::new, |full| full.roots.clone()),
        history,
    })
}

fn checkpoint(agent: &StateAgent, operation: Uuid) -> PathBuf {
    agent
        .config
        .paths
        .packs
        .join(format!("{operation}.native-capture.enc"))
}

fn aad(operation: Uuid) -> String {
    format!("quicksave-native-source-capture-v1:{operation}")
}

/// Persist actual pipeline provenance once, before its retry receipts are
/// cleaned. A resumed prepared revision cannot replace missing proofs with a
/// fresh metadata query. Existing evidence must be byte/semantically identical.
pub(crate) fn seal_captured(agent: &StateAgent, operation: Uuid, master: &MasterKey) -> Result<()> {
    let Some(session) = session(agent, operation)? else {
        return Ok(());
    };
    write_proof(
        &session.workspace,
        &checkpoint(agent, operation),
        operation,
        master,
        &make_proof(&session)?,
    )
}

fn read_proof(
    workspace: &RootPin,
    path: &Path,
    operation: Uuid,
    master: &MasterKey,
) -> Result<Option<CaptureProof>> {
    workspace.check()?;
    let file = match SourcePath::new_beneath(path, &workspace.path, workspace.identity)
        .and_then(|path| path.open_regular())
    {
        Ok(file) => file,
        Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take((MAX_CAPTURE_DOCUMENT + 1024) as u64 + 1)
        .read_to_end(&mut bytes)?;
    workspace
        .counters
        .checkpoint_read_bytes
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if bytes.len() > MAX_CAPTURE_DOCUMENT + 1024 {
        return Err(StateError::Integrity(
            "native capture checkpoint exceeds its bound".into(),
        ));
    }
    let proof: CaptureProof = noland_storage::open_metadata_with_limit(
        &noland_crypto::derive_keys(master).manifest,
        aad(operation).as_bytes(),
        bytes,
        MAX_CAPTURE_DOCUMENT as u64,
    )?;
    if proof.version != 1 || proof.operation != operation || proof.files.len() > MAX_CAPTURE_NODES {
        return Err(StateError::Integrity(
            "native capture checkpoint identity/bound mismatch".into(),
        ));
    }
    workspace.check()?;
    Ok(Some(proof))
}

fn write_proof(
    workspace: &RootPin,
    path: &Path,
    operation: Uuid,
    master: &MasterKey,
    proof: &CaptureProof,
) -> Result<()> {
    hash_value(proof)?;
    if let Some(existing) = read_proof(workspace, path, operation, master)? {
        return if existing == *proof {
            Ok(())
        } else {
            Err(StateError::Integrity(
                "native capture checkpoint changed for this operation".into(),
            ))
        };
    }
    #[cfg(unix)]
    {
        let sealed = noland_storage::seal_metadata(
            &noland_crypto::derive_keys(master).manifest,
            aad(operation).as_bytes(),
            proof,
        )?;
        if sealed.envelope.len() > MAX_CAPTURE_DOCUMENT + 1024 {
            return Err(StateError::Invalid(
                "native capture sealed metadata bound".into(),
            ));
        }
        noland_state_core::disk::ensure_space(
            path.parent()
                .ok_or_else(|| StateError::UnsafePath("native checkpoint parent missing".into()))?,
            sealed.envelope.len() as u64,
        )?;
        let temporary = path.with_extension(format!("native-partial-{}", Uuid::new_v4()));
        let source = SourcePath::new_beneath(&temporary, &workspace.path, workspace.identity)?;
        let mut file = source.open_partial_private(true)?;
        file.write_all(&sealed.envelope)?;
        file.sync_all()?;
        source.publish_new_to(&SourcePath::new_beneath(
            path,
            &workspace.path,
            workspace.identity,
        )?)?;
        workspace.check()?;
        return Ok(());
    }
    #[cfg(not(unix))]
    Err(StateError::Invalid(
        "native source capture checkpoint publication is unsupported".into(),
    ))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestAuthentication {
    version: u32,
    operation: Uuid,
    app: AppId,
    scope: NativeCaptureScope,
    roots_fingerprint: String,
    source_snapshot_id: Uuid,
    manifest_hash: String,
    captured_files_hash: String,
    capture_proof_hash: String,
    root_layouts_hash: String,
}

/// Source-owned capability. Fields are private and constructors are not public.
/// `revalidate` has NO service/Tracker/publication-guard callback, avoiding the
/// Tracker -> receipt -> publication guard -> Tracker recursion trap.
pub struct NativeCaptureReceipt {
    binding: ManifestAuthentication,
    authentication: Vec<u8>,
    master: MasterKey,
    proof: CaptureProof,
    proof_hash: String,
    nodes: Arc<BTreeMap<NativeFileKey, NativeCaptureNode>>,
    roots: BTreeMap<String, Arc<RootPin>>,
    approved: Vec<Arc<NativeApprovedPin>>,
    workspace: Arc<RootPin>,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl NativeCaptureReceipt {
    pub fn revalidate(&self) -> Result<()> {
        if (self.cancelled)() {
            return Err(StateError::Conflict("native capture was cancelled".into()));
        }
        self.workspace.check()?;
        let binding: ManifestAuthentication = noland_storage::open_metadata(
            &noland_crypto::derive_keys(&self.master).manifest,
            b"quicksave-native-expected-manifest-v1",
            self.authentication.clone(),
        )?;
        // `proof` is privately owned immutable captured provenance. Its digest
        // was computed after exact manifest/proof validation, not from live
        // post-capture data. No 250k-node stat/hash walk belongs at this barrier.
        if binding != self.binding || binding.capture_proof_hash != self.proof_hash {
            return Err(StateError::Integrity(
                "actual native expected-manifest authentication failed".into(),
            ));
        }
        for root in self.roots.values() {
            root.check()?;
        }
        for pin in &self.approved {
            pin.check()?;
        }
        Ok(())
    }

    pub fn evidence(&self) -> Result<Value> {
        let files = self
            .proof
            .files
            .iter()
            .map(|file| {
                let node = &self.nodes[&file.key];
                let mut evidence = json!({
                    "id":node.id,"rootId":node.root_id,"path":node.path,"kind":node.kind,
                    "size":file.size,"stamp":file.stamp,
                });
                if let Some(hash) = &file.file_hash {
                    evidence["fileHash"] = json!(hash);
                }
                if let Some(hash) = &file.link_target_hash {
                    evidence["linkTargetHash"] = json!(hash);
                }
                evidence
            })
            .collect::<Vec<_>>();
        let mut evidence = json!({
            "workId":self.binding.scope.work_id,
            "metadataIdentity":self.binding.scope.metadata_identity,
            "sourceSnapshotId":self.binding.source_snapshot_id.to_string(),
            "sourceExpectedManifestAuth":{
                "version":1,"algorithm":"source-xchacha20poly1305-metadata",
                "manifestHash":self.binding.manifest_hash,
                "capturedFilesHash":self.binding.captured_files_hash,
                "capturedProofHash":self.binding.capture_proof_hash,
                "rootLayoutsHash":self.binding.root_layouts_hash,
                "operationId":self.binding.operation,
                "aad":"quicksave-native-expected-manifest-v1",
                "envelopeHex":hex::encode(&self.authentication),
            },
            "nodes":files,
            "rootLayouts":self.proof.root_layouts,
        });
        if let Some(full) = &self.proof.full_scope_evidence {
            evidence["fullScope"] = json!(true);
            evidence["expectedFullScope"] = full["expectedFullScope"].clone();
            evidence["deletedFileIds"] = full["deletedFileIds"].clone();
            evidence["deletedNodes"] = full["deletedNodes"].clone();
            evidence["rootCaptures"] = json!(self.proof.root_captures);
            evidence["sourceParent"] = json!(self.proof.history);
        }
        hash_value(&evidence)?;
        Ok(evidence)
    }
}

/// Called after source capture/sealing/upload and BEFORE any first COMMITTED or
/// LATEST publication. No installed sink is the legacy expected-hash path.
pub fn accept_prepared(
    agent: &StateAgent,
    operation: Uuid,
    manifest: &BundleManifest,
    master: &MasterKey,
) -> Result<()> {
    let Some(session) = session(agent, operation)? else {
        // A request-local JSON binding can only make this gate stricter. It can
        // never manufacture the missing Rust capability or enable the fallback.
        if agent.config.native_host
            && agent.db.get_operation(operation)?.is_some_and(|record| {
                record.detail_json["native_selection"]
                    .get("capture_scope")
                    .is_some_and(|scope| !scope.is_null())
            })
        {
            return Err(StateError::Conflict(
                "metadata-frozen source capture lost its native Rust sink before publication"
                    .into(),
            ));
        }
        return Ok(());
    };
    if let Some(receipt) = session
        .accepted
        .lock()
        .map_err(|_| StateError::Invalid("native receipt lock failed".into()))?
        .clone()
    {
        if receipt.binding.manifest_hash != hash_value(manifest)? {
            return Err(StateError::Conflict(
                "native operation prepared a different manifest after receipt acceptance".into(),
            ));
        }
        return receipt.revalidate();
    }
    if session
        .accepting
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return Err(StateError::Conflict(
            "native receipt acceptance is already running".into(),
        ));
    }
    let result = (|| {
        let current = make_proof(&session);
        let proof = match current {
            Ok(proof) => {
                write_proof(
                    &session.workspace,
                    &checkpoint(agent, operation),
                    operation,
                    master,
                    &proof,
                )?;
                proof
            }
            Err(StateError::Conflict(_)) => read_proof(
                &session.workspace,
                &checkpoint(agent, operation),
                operation,
                master,
            )?
            .ok_or_else(|| {
                StateError::Conflict(
                    "prepared native revision lacks actual captured-stamp provenance".into(),
                )
            })?,
            Err(error) => return Err(error),
        };
        if proof.scope != session.scope
            || proof.app != session.app
            || proof.software_instance_id
                != *session.software_instance_id.lock().map_err(|_| {
                    StateError::Invalid("native instance binding lock failed".into())
                })?
            || proof.roots_fingerprint != session.roots_fingerprint
            || proof.roots_fingerprint != agent.native_binding_fingerprint(&session.app)?
            || manifest.app.app_id != session.app
            || manifest.consistency == ConsistencyKind::BestEffort
            || manifest.files.len() != session.nodes.len()
            || proof.files.len() != session.nodes.len()
            || !proof
                .files
                .iter()
                .map(|file| &file.key)
                .eq(session.nodes.keys())
        {
            return Err(StateError::Conflict(
                "prepared source manifest/frozen scope is not exact and stable".into(),
            ));
        }
        validate_history(&session, manifest, &proof)?;
        let instance = proof.software_instance_id.as_deref().ok_or_else(|| {
            StateError::Conflict("actual source capture has no software-instance identity".into())
        })?;
        let selected_roots = session
            .nodes
            .keys()
            .map(|key| key.logical_root.as_str())
            .collect::<BTreeSet<_>>();
        let filter = if session.full.is_some() {
            None
        } else {
            Some(&selected_roots)
        };
        let root_layouts =
            root_layouts_from_pins(&session.app, instance, &session.approved, filter)?;
        if proof.root_layouts.as_ref() != Some(&root_layouts)
            || manifest.environment["quicksave_native_root_layouts"] != root_layouts
            || root_layouts_from_pins(
                &session.app,
                instance,
                &agent.native_capture_root_pins(&session.app)?,
                filter,
            )? != root_layouts
        {
            return Err(StateError::Conflict(
                "native reconstruction descriptor is not the actual held source layout".into(),
            ));
        }
        let actual = manifest
            .files
            .iter()
            .map(|file| {
                (
                    NativeFileKey {
                        logical_root: file.logical_root.clone(),
                        relative_path: file.relative_path.clone(),
                    },
                    file,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if actual.len() != manifest.files.len() {
            return Err(StateError::Integrity(
                "duplicate source manifest files".into(),
            ));
        }
        for file in &proof.files {
            let expected = session.nodes.get(&file.key).ok_or_else(|| {
                StateError::Conflict("captured checkpoint includes an unselected node".into())
            })?;
            let actual = actual.get(&file.key).ok_or_else(|| {
                StateError::Conflict("source manifest omitted a captured file".into())
            })?;
            if file.stamp != expected.stamp
                || file.size != expected.size
                || file.kind != expected.kind
                || !manifest_matches_proof(actual, file)?
            {
                return Err(StateError::Conflict(
                    "actual source manifest/stamp differs from frozen native selection".into(),
                ));
            }
        }
        let binding = ManifestAuthentication {
            version: 1,
            operation,
            app: session.app.clone(),
            scope: session.scope.clone(),
            roots_fingerprint: session.roots_fingerprint.clone(),
            source_snapshot_id: manifest.bundle_id,
            manifest_hash: hash_value(manifest)?,
            captured_files_hash: hash_value(&proof.files)?,
            capture_proof_hash: hash_value(&proof)?,
            root_layouts_hash: hash_value(&root_layouts)?,
        };
        let authentication = noland_storage::seal_metadata(
            &noland_crypto::derive_keys(master).manifest,
            b"quicksave-native-expected-manifest-v1",
            &binding,
        )?
        .envelope;
        let operations = agent.operations.clone();
        let receipt = Arc::new(NativeCaptureReceipt {
            proof_hash: binding.capture_proof_hash.clone(),
            binding,
            authentication,
            master: master.clone(),
            proof,
            nodes: session.nodes.clone(),
            roots: session.roots.clone(),
            approved: session.approved.clone(),
            workspace: session.workspace.clone(),
            cancelled: Arc::new(move || operations.cancel_requested(operation)),
        });
        receipt.revalidate()?;
        session.sink.accept(Arc::clone(&receipt))?;
        receipt.revalidate()?;
        session
            .counters
            .accepted_receipts
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut bindings = agent.native_bindings.lock();
            if let (Some(epoch), Some(instance)) = (
                session
                    .reuse_epoch
                    .as_ref()
                    .filter(|epoch| receipt.proof.reuse_epoch.as_ref() == Some(*epoch)),
                receipt.proof.software_instance_id.as_ref(),
            ) {
                for file in receipt
                    .proof
                    .files
                    .iter()
                    .filter(|file| file.kind == "file")
                {
                    bindings.captures.reuse.insert(
                        (
                            session.app.clone(),
                            session.roots_fingerprint.clone(),
                            instance.clone(),
                            file.key.clone(),
                        ),
                        ReuseProof {
                            stamp: file.stamp.clone(),
                            file_hash: file.file_hash.clone().expect("validated regular hash"),
                            size: file.size,
                            epoch: epoch.clone(),
                            source_loss_generation: receipt.proof.source_loss_generation,
                            chunks_hash: file
                                .chunks_hash
                                .clone()
                                .expect("validated regular chunks"),
                        },
                    );
                }
            }
            while bindings.captures.reuse.len() > MAX_CAPTURE_NODES {
                bindings.captures.reuse.pop_first();
            }
        }
        *session
            .accepted
            .lock()
            .map_err(|_| StateError::Invalid("native receipt lock failed".into()))? = Some(receipt);
        Ok(())
    })();
    session
        .accepting
        .store(false, std::sync::atomic::Ordering::Release);
    result
}

pub fn verify_prepared(
    agent: &StateAgent,
    operation: Uuid,
    manifest: &BundleManifest,
) -> Result<()> {
    let session = session(agent, operation)?
        .ok_or_else(|| StateError::Conflict("native capture sink is unavailable".into()))?;
    if session.roots_fingerprint != agent.native_binding_fingerprint(&session.app)? {
        return Err(StateError::Conflict(
            "native capture root binding changed".into(),
        ));
    }
    let receipt = session
        .accepted
        .lock()
        .map_err(|_| StateError::Invalid("native receipt lock failed".into()))?
        .clone()
        .ok_or_else(|| {
            StateError::Conflict(
                "actual source capture receipt was not accepted before publication".into(),
            )
        })?;
    if receipt.binding.manifest_hash != hash_value(manifest)? {
        return Err(StateError::Conflict(
            "native published manifest differs from accepted actual capture".into(),
        ));
    }
    receipt.revalidate()
}

pub fn remove(agent: &StateAgent, operation: Uuid) -> Result<()> {
    if agent.operations.is_running(operation) {
        return Err(StateError::Conflict(
            "native capture is still executing".into(),
        ));
    }
    agent
        .native_bindings
        .lock()
        .captures
        .sessions
        .remove(&operation);
    Ok(())
}

fn canonical_hash(hash: &str) -> bool {
    hash.strip_prefix("blake3:").is_some_and(canonical_raw_hash)
}

fn canonical_raw_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hash_value<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    // Existing source wire hashes remain tagged. Do not use this domain for
    // Tracker metadata identities or MAC-signed node-ID-set digests.
    Ok(format!("blake3:{}", metadata_digest(value)?))
}

/// Matches Tracker::bundle::digest: bounded serde JSON -> raw BLAKE3 64-hex.
/// Keep distinct from source wire content/manifest/proof hashes.
fn metadata_digest<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    struct BoundedHash {
        hash: blake3::Hasher,
        bytes: usize,
    }
    impl Write for BoundedHash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_CAPTURE_DOCUMENT)
                .ok_or_else(|| {
                    std::io::Error::other("native capture metadata exceeds bounded document size")
                })?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedHash {
        hash: blake3::Hasher::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.hash.finalize().to_hex().to_string())
}

#[cfg(all(test, unix))]
#[path = "native_capture_tests.rs"]
mod tests;
