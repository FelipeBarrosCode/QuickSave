// SPDX-License-Identifier: GPL-3.0-only
//! Windows adapter for the native full-scope proof contract. The tracker owner
//! verifies its original grants; this engine independently checks exact native
//! roots, inventory and the CAS-produced manifest. A digest/empty list is never
//! authority. Derived contract: No Land e81238a7536aae201540956ce76981364fd36595
//! native_capture.rs; no StateAgent or collector is linked here.
use super::*;
use capture::{FrozenCaptureNode, NativeCaptureController, NativeFullScopeAuthority};
use noland_snapshot::{NativeEntryKind, WindowsMetadata};
use noland_state_core::{ManifestFile, ManifestTombstone};
use serde::{Deserialize, Serialize};
#[cfg(test)]
#[path = "full_scope_tests.rs"]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FullScopeBinding {
    pub version: u32,
    pub evidence_hash: String,
    pub root_count: usize,
    pub deleted_count: usize,
}

impl FullScopeBinding {
    /// Native-only evidence from the original tracker owner. No grant is
    /// verified by constructing this compact header alone.
    pub fn from_evidence(evidence: &Value) -> Result<Self> {
        validate_tracker_digests(evidence)?;
        let binding = Self {
            version: 1,
            evidence_hash: metadata_digest(evidence)?,
            root_count: evidence["roots"]
                .as_array()
                .context("full scope root evidence is missing")?
                .len(),
            deleted_count: evidence["deletedNodes"]
                .as_array()
                .context("full scope deleted evidence is missing")?
                .len(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && raw_hash(&self.evidence_hash)
                && (1..=128).contains(&self.root_count)
                && self.deleted_count <= MAX_FILES,
            "invalid native full-scope binding"
        );
        Ok(())
    }
}

pub(super) fn raw_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Tracker metadata hashes are RAW lowercase hex. Content hashes elsewhere in
/// the No Land format remain blake3:...; never normalize a signed metadata field.
pub(super) fn metadata_digest<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    struct LimitedHash {
        hash: blake3::Hasher,
        bytes: usize,
    }
    impl Write for LimitedHash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= MAX_PLAN_BYTES)
                .ok_or_else(|| {
                    std::io::Error::other("native full-scope metadata exceeds its bound")
                })?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = LimitedHash {
        hash: blake3::Hasher::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.hash.finalize().to_hex().to_string())
}

fn validate_tracker_digests(evidence: &Value) -> Result<()> {
    let proof = &evidence["expectedFullScope"]["scope"];
    for value in [
        &evidence["metadataIdentity"],
        &proof["metadataIdentity"],
        &proof["trackingScopeHash"],
        &proof["expectedNodeIdsHash"],
        &proof["deletedNodeIdsHash"],
    ] {
        ensure!(value.as_str().is_some_and(raw_hash),
            "native tracker metadata digests require exact lowercase 64-hex without content prefixes");
    }
    ensure!(
        proof["metadataIdentity"] == evidence["metadataIdentity"]
            && proof["baselineIdentity"] == evidence["baseline"]["snapshotIdentity"],
        "signed full-scope metadata/baseline identities differ"
    );
    match evidence["baseline"]["kind"].as_str() {
        Some("none") => ensure!(
            proof["baselineIdentity"].is_null()
                && evidence["baseline"]["reference"].is_null()
                && evidence["baseline"]["scope"].is_null(),
            "a missing baseline cannot authorize signed prior omissions"
        ),
        Some("full" | "partial") => {
            for value in [
                &proof["baselineIdentity"],
                &evidence["baseline"]["reference"]["hash"],
                &evidence["baseline"]["scope"]["hash"],
            ] {
                ensure!(
                    value.as_str().is_some_and(raw_hash),
                    "native baseline digests require exact lowercase 64-hex"
                );
            }
            ensure!(
                evidence["baseline"]["reference"]["hash"] == evidence["baseline"]["scope"]["hash"]
                    && evidence["baseline"]["reference"]["name"]
                        == evidence["baseline"]["scope"]["name"],
                "native original baseline reference differs from its signed scope"
            );
        }
        _ => bail!("invalid native tracker baseline schema"),
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Windows,
}

/// Actual tracker Windows metadata, not fabricated mode/owner/group values.
/// Atime is preserved but deliberately excluded from stable-state equality.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NativeMetadata {
    platform: Platform,
    identity: RootIdentity,
    kind: EntryKind,
    size: u64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
    link_count: u32,
    reparse_tag: u32,
}

impl NativeMetadata {
    fn from_native(native: &WindowsMetadata) -> Self {
        Self {
            platform: Platform::Windows,
            identity: RootIdentity {
                device: native.identity.volume,
                file_id: native.identity.file_id,
            },
            kind: match native.kind {
                NativeEntryKind::File => EntryKind::File,
                NativeEntryKind::Directory => EntryKind::Directory,
                NativeEntryKind::Symlink => EntryKind::Symlink,
            },
            size: native.size,
            creation_time: native.creation_time,
            last_access_time: native.last_access_time,
            last_write_time: native.last_write_time,
            change_time: native.change_time,
            attributes: native.attributes,
            link_count: native.number_of_links,
            reparse_tag: native.reparse_tag,
        }
    }

    fn same_state(&self, other: &Self) -> bool {
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

    fn stamp(&self) -> Result<FileStamp> {
        let time = |ticks: i64| -> Result<(i64, u32)> {
            Ok((
                ticks
                    .div_euclid(10_000_000)
                    .checked_sub(11_644_473_600)
                    .context("native Windows timestamp is out of range")?,
                ticks.rem_euclid(10_000_000) as u32 * 100,
            ))
        };
        let modified = time(self.last_write_time)?;
        let changed = time(self.change_time)?;
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

    fn validate(&self, stamp: &FileStamp, kind: EntryKind) -> Result<()> {
        ensure!(
            self.identity.file_id != [0; 2]
                && self.link_count > 0
                && self.kind == kind
                && &self.stamp()? == stamp
                && self.attributes & 0x40 == 0
                && if kind == EntryKind::Symlink {
                    self.reparse_tag == 0xa000000c && self.attributes & 0x400 != 0
                } else {
                    self.reparse_tag == 0
                        && self.attributes & 0x400 == 0
                        && (self.attributes & 0x10 != 0) == (kind == EntryKind::Directory)
                },
            "full-scope metadata lacks its exact real native kind/128-bit identity/stamp"
        );
        mtime_ns_from_stamp(stamp)?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RootCapture {
    pub id: String,
    pub logical_root: String,
    pub kind: String,
    pub stamp: FileStamp,
    pub metadata: Option<NativeMetadata>,
    pub allowed_files: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_scope: Option<RootMetadataScope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetadataScopeKind {
    ManualLeavesOnly,
}

/// Signed provenance for a directory used ONLY as an exact manual-leaf anchor.
/// It supplies no permissions, timestamps or whole/empty-directory authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RootMetadataScope {
    version: u32,
    kind: MetadataScopeKind,
    source_root_id: String,
    source_root_identity: RootIdentity,
    allowed_files_digest: String,
}

impl RootMetadataScope {
    fn for_root(root: &RootSpec) -> Result<Option<Self>> {
        let Some(allowed) = &root.allowed_files else {
            return Ok(None);
        };
        ensure!(
            !allowed.is_empty() && allowed.len() <= MAX_FILES,
            "manual root metadata scope requires exact nonempty leaves"
        );
        for leaf in allowed {
            validate_relative(leaf)?;
        }
        Ok(Some(Self {
            version: 1,
            kind: MetadataScopeKind::ManualLeavesOnly,
            source_root_id: root.id.clone(),
            source_root_identity: root.identity.clone(),
            // BTreeSet serializes as the original sorted, duplicate-free JSON
            // array; this is RAW BLAKE3, not a tagged content/manifest hash.
            allowed_files_digest: metadata_digest(allowed)?,
        }))
    }
}

impl RootCapture {
    fn validate_metadata_scope(&self, root: &RootSpec) -> Result<()> {
        ensure!(
            self.id == root.id
                && self.logical_root == root.logical
                && self.kind == "directory"
                && self.allowed_files == root.allowed_files
                && self.stamp.device == root.identity.device
                && self.stamp.file_id == root.identity.file_id
                && self.metadata_scope == RootMetadataScope::for_root(root)?,
            "root metadata scope lost its original logical/root/full-ID/leaf binding"
        );
        if root.allowed_files.is_some() {
            ensure!(
                self.metadata.is_none(),
                "manual leaves cannot claim parent metadata"
            );
        } else {
            self.metadata
                .as_ref()
                .context("whole-directory capture requires actual native metadata")?
                .validate(&self.stamp, EntryKind::Directory)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeletedNode {
    pub id: String,
    pub logical_root: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub stamp: FileStamp,
    metadata: NativeMetadata,
    file_hash: Option<String>,
    link_target_hash: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FullSnapshot {
    pub evidence: Value,
    pub roots: Vec<RootCapture>,
    pub deleted: Vec<DeletedNode>,
}

fn root_capture(root: &RootSpec) -> Result<RootCapture> {
    let handle = SafeRoot::open(&root.path)?;
    ensure!(
        handle.identity()? == root.identity,
        "native root changed before full-scope capture"
    );
    let native =
        WindowsMetadata::from_file(&handle.clone_root_directory_handle()?).map_err(source_error)?;
    let metadata = NativeMetadata::from_native(&native);
    let stamp = metadata.stamp()?;
    metadata.validate(&stamp, EntryKind::Directory)?;
    ensure!(
        metadata.identity == root.identity,
        "root metadata changed its actual complete native identity"
    );
    Ok(RootCapture {
        id: root.id.clone(),
        logical_root: root.logical.clone(),
        kind: "directory".into(),
        stamp,
        metadata: root.allowed_files.is_none().then_some(metadata),
        allowed_files: root.allowed_files.clone(),
        metadata_scope: RootMetadataScope::for_root(root)?,
    })
}

impl FullSnapshot {
    pub(super) fn prepare(
        binding: &SoftwareBinding,
        scope: &CaptureScope,
        controller: &dyn NativeCaptureController,
        provider: &str,
    ) -> Result<Option<Self>> {
        let Some(header) = &scope.full_scope else {
            return Ok(None);
        };
        let authority = controller
            .full_scope_authority(scope)?
            .context("full/empty/deleted capture has no installed native Rust authority")?;
        authority.revalidate()?;
        let evidence = authority.evidence()?;
        ensure!(
            FullScopeBinding::from_evidence(&evidence)? == *header,
            "native full-scope evidence changed after freezing"
        );
        let roots = binding
            .roots
            .iter()
            .map(|root| root_capture(&root.spec))
            .collect::<Result<Vec<_>>>()?;
        let mut deleted = Vec::new();
        let mut ids = BTreeSet::new();
        let mut path_bytes = 0usize;
        for node in evidence["deletedNodes"]
            .as_array()
            .context("exact deleted nodes are missing")?
        {
            let root_id = node["rootId"]
                .as_str()
                .context("deleted node root ID is missing")?;
            let root = binding
                .roots
                .iter()
                .find(|root| root.spec.id == root_id)
                .context("deleted node exceeds original approved roots")?;
            let path = node["path"]
                .as_str()
                .context("deleted node path is missing")?;
            validate_relative(path)?;
            path_bytes = path_bytes
                .checked_add(path.len())
                .filter(|total| *total <= 32 * 1024 * 1024)
                .context("native deleted path memory bound exceeded")?;
            ensure!(
                root.spec
                    .allowed_files
                    .as_ref()
                    .is_none_or(|leaves| leaves.contains(path)),
                "deleted node exceeds original manual-file authority"
            );
            let id = file_id(&root.spec.logical, path);
            ensure!(
                node["id"] == id && ids.insert(id.clone()),
                "invalid duplicate deleted identity"
            );
            let kind = node["kind"]
                .as_str()
                .context("deleted node kind is missing")?;
            let stamp: FileStamp = serde_json::from_value(node["stamp"].clone())?;
            let metadata: NativeMetadata = serde_json::from_value(node["metadata"].clone())?;
            let size = node["size"]
                .as_u64()
                .context("deleted node size is missing")?;
            let file_hash = node["fileHash"].as_str().map(str::to_owned);
            let link_target_hash = node["linkTargetHash"].as_str().map(str::to_owned);
            match kind {
                "file" => {
                    metadata.validate(&stamp, EntryKind::File)?;
                    ensure!(
                        stamp.size == size
                            && file_hash.as_deref().is_some_and(raw_hash)
                            && node["linkTargetHash"].is_null(),
                        "invalid deleted regular-file evidence"
                    );
                }
                "directory" => {
                    metadata.validate(&stamp, EntryKind::Directory)?;
                    ensure!(
                        size == 0 && node["fileHash"].is_null() && node["linkTargetHash"].is_null(),
                        "invalid deleted directory evidence"
                    );
                }
                "symlink" => {
                    metadata.validate(&stamp, EntryKind::Symlink)?;
                    ensure!(
                        size == 0
                            && node["fileHash"].is_null()
                            && link_target_hash.as_deref().is_some_and(raw_hash),
                        "invalid deleted symbolic-link evidence"
                    );
                }
                _ => bail!("unsupported deleted native entry kind"),
            }
            deleted.push(DeletedNode {
                id,
                logical_root: root.spec.logical.clone(),
                path: path.into(),
                kind: kind.into(),
                size,
                stamp,
                metadata,
                file_hash,
                link_target_hash,
            });
        }
        deleted.sort_by(|a, b| a.id.cmp(&b.id));
        let snapshot = Self {
            evidence,
            roots,
            deleted,
        };
        snapshot.validate_scope(
            &binding.app,
            &binding.id,
            &binding.instance,
            provider,
            scope,
            &binding
                .roots
                .iter()
                .map(|root| root.spec.clone())
                .collect::<Vec<_>>(),
        )?;
        snapshot.revalidate_roots(
            &binding
                .roots
                .iter()
                .map(|root| root.spec.clone())
                .collect::<Vec<_>>(),
        )?;
        authority.revalidate()?;
        Ok(Some(snapshot))
    }

    pub(super) fn validate_scope(
        &self,
        app: &AppId,
        software: &str,
        instance: &str,
        provider: &str,
        scope: &CaptureScope,
        roots: &[RootSpec],
    ) -> Result<()> {
        let header = scope
            .full_scope
            .as_ref()
            .context("full snapshot lacks its compact native binding")?;
        ensure!(
            FullScopeBinding::from_evidence(&self.evidence)? == *header
                && self.deleted.len() == header.deleted_count
                && self.roots.len() == roots.len(),
            "full snapshot differs from original root/deletion binding"
        );
        let evidence = &self.evidence;
        let proof = &evidence["expectedFullScope"]["scope"];
        ensure!(
            evidence["version"] == 1
                && evidence["workId"] == scope.work_id
                && evidence["metadataIdentity"] == scope.metadata_identity
                && evidence["softwareId"] == software
                && evidence["providerId"] == provider
                && evidence["sourceIdentity"]["app_id"].as_str() == Some(app.as_str())
                && evidence["fullScope"] == true
                && evidence["completeFileList"] == true
                && evidence["keepsVersionHistory"] == true
                && evidence["coverageScope"] == "approved_evidenced_roots_only"
                && proof["version"] == 1
                && proof["workId"] == scope.work_id
                && proof["softwareId"] == software
                && proof["metadataIdentity"] == scope.metadata_identity
                && proof["providerId"] == provider
                && proof["generation"] == evidence["generation"]
                && proof["snapshotMode"] == "additive_full_scope"
                && proof["keepsHistory"] == true
                && evidence["expectedFullScope"]["grant"].is_object()
                && proof["baselineKind"] == evidence["baseline"]["kind"]
                && evidence["authorization"]["trackingScope"].is_object()
                && evidence["authorization"]["trackingScope"]["softwareId"] == software
                && evidence["authorization"]["trackingScope"]["appId"] == instance
                && proof["trackingScopeHash"]
                    == metadata_digest(&evidence["authorization"]["trackingScope"])?,
            "signed native full snapshot does not bind this exact source scope"
        );
        let root_evidence = evidence["roots"]
            .as_array()
            .context("native full snapshot roots are missing")?;
        let ids = root_evidence
            .iter()
            .map(|root| {
                root["id"]
                    .as_str()
                    .context("native full root ID is missing")
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let proof_roots = proof["rootIds"]
            .as_array()
            .context("signed native full root IDs are missing")?;
        ensure!(
            ids.len() == roots.len()
                && ids.len() == root_evidence.len()
                && proof_roots.len() == ids.len()
                && proof_roots
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    == ids,
            "native full snapshot omitted or duplicated approved roots"
        );
        for root in roots {
            let evidence = root_evidence
                .iter()
                .find(|evidence| evidence["id"] == root.id)
                .context("native full snapshot omitted an approved root")?;
            ensure!(
                evidence["path"] == json!(root.path)
                    && evidence["identity"] == json!(root.identity)
                    && evidence["role"] == root.role.as_str()
                    && evidence["allowedFiles"] == json!(root.allowed_files),
                "native full snapshot root path/kind/identity/role/allowlist changed"
            );
            let captures = self
                .roots
                .iter()
                .filter(|capture| capture.id == root.id)
                .collect::<Vec<_>>();
            ensure!(
                captures.len() == 1,
                "full root capture lacks the original complete native identity"
            );
            captures[0].validate_metadata_scope(root)?;
            if root.allowed_files.is_none() {
                let stamp: FileStamp =
                    serde_json::from_value(self.evidence["rootStamps"][&root.id].clone())?;
                let metadata: NativeMetadata =
                    serde_json::from_value(self.evidence["rootMetadata"][&root.id].clone())?;
                metadata.validate(&stamp, EntryKind::Directory)?;
                ensure!(
                    captures[0].stamp == stamp
                        && captures[0]
                            .metadata
                            .as_ref()
                            .is_some_and(|actual| actual.same_state(&metadata)),
                    "full native root metadata/stamp changed before capture"
                );
            }
        }
        let deleted_ids = self.deleted.iter().map(|node| &node.id).collect::<Vec<_>>();
        ensure!(
            evidence["deletedFileIds"] == json!(deleted_ids)
                && proof["deletedNodeIdsHash"] == metadata_digest(&deleted_ids)?
                && (self.deleted.is_empty()
                    || matches!(
                        evidence["baseline"]["kind"].as_str(),
                        Some("full" | "partial")
                    ) && evidence["baseline"]["reference"].is_object()
                        && evidence["baseline"]["scope"].is_object()),
            "full snapshot deleted IDs/baseline are not exact"
        );
        let original = evidence["deletedNodes"]
            .as_array()
            .context("original deleted-node evidence is missing")?;
        let original_by_id = original
            .iter()
            .map(|row| {
                row["id"]
                    .as_str()
                    .map(|id| (id, row))
                    .context("original deleted-node ID is missing")
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(
            original_by_id.len() == original.len(),
            "original signed deleted-node evidence contains duplicates"
        );
        let mut deleted_seen = BTreeSet::new();
        for node in &self.deleted {
            validate_relative(&node.path)?;
            ensure!(
                deleted_seen.insert(&node.id),
                "duplicate native deleted proof"
            );
            let root = roots
                .iter()
                .find(|root| root.logical == node.logical_root)
                .context("native deleted proof exceeds the original roots")?;
            ensure!(
                root.allowed_files
                    .as_ref()
                    .is_none_or(|leaves| leaves.contains(&node.path))
                    && node.id == file_id(&root.logical, &node.path),
                "native deleted proof exceeds its exact original root/leaf identities"
            );
            let row = original_by_id
                .get(node.id.as_str())
                .context("native deleted proof is absent from original signed evidence")?;
            ensure!(
                row["rootId"] == root.id
                    && row["path"] == node.path
                    && row["kind"] == node.kind
                    && row["size"] == node.size
                    && row["stamp"] == json!(node.stamp)
                    && row["metadata"] == json!(node.metadata)
                    && row["fileHash"] == json!(node.file_hash)
                    && row["linkTargetHash"] == json!(node.link_target_hash),
                "native deleted proof differs from original signed evidence"
            );
            let kind = match node.kind.as_str() {
                "file" => EntryKind::File,
                "directory" => EntryKind::Directory,
                "symlink" => EntryKind::Symlink,
                _ => bail!("invalid native deleted kind"),
            };
            node.metadata.validate(&node.stamp, kind)?;
        }
        Ok(())
    }

    pub(super) fn verify_nodes(
        &self,
        roots: &[RootSpec],
        nodes: &BTreeMap<String, FrozenCaptureNode>,
    ) -> Result<()> {
        self.verify_ids(&nodes.keys().cloned().collect())?;
        ensure!(
            self.deleted
                .iter()
                .all(|deleted| !nodes.contains_key(&deleted.id)),
            "deleted native node is also present in frozen scope"
        );
        let mut seen = BTreeSet::new();
        for root in roots {
            let handle = SafeRoot::open(&root.path)?;
            ensure!(
                handle.identity()? == root.identity,
                "full native inventory root changed"
            );
            if let Some(leaves) = &root.allowed_files {
                for leaf in leaves {
                    let id = file_id(&root.logical, leaf);
                    let (_, stamp) = match handle.read_file(leaf) {
                        Ok(file) => file,
                        Err(error)
                            if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                                error.kind() == std::io::ErrorKind::NotFound
                            }) =>
                        {
                            ensure!(
                                !nodes.contains_key(&id),
                                "missing manual leaf is still present in the frozen inventory"
                            );
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let expected = nodes
                        .get(&id)
                        .context("manual full scope contains an unfrozen leaf")?;
                    ensure!(
                        expected.kind == "file" && expected.stamp == stamp && seen.insert(id),
                        "native full manual file identity/stamp changed"
                    );
                }
            } else {
                for entry in handle.metadata_entries()? {
                    let id = file_id(&root.logical, &entry.relative_path);
                    let node = nodes
                        .get(&id)
                        .context("full native inventory contains an unfrozen node")?;
                    let kind = match entry.kind {
                        EntryKind::File => "file",
                        EntryKind::Directory => "directory",
                        EntryKind::Symlink => "symlink",
                    };
                    ensure!(
                        node.kind == kind && node.stamp == entry.stamp && seen.insert(id),
                        "full native inventory kind/identity/stamp changed"
                    );
                    if let Some(link) = &entry.link {
                        ensure!(
                            node.link_target_hash.as_deref()
                                == Some(blake3::hash(link.target.as_bytes()).to_hex().as_str()),
                            "full native inventory link target changed"
                        );
                    }
                }
            }
        }
        ensure!(
            seen.len() == nodes.len(),
            "full native source omitted or duplicated frozen entries"
        );
        self.revalidate_roots(roots)
    }

    pub(super) fn verify_ids(&self, ids: &BTreeSet<String>) -> Result<()> {
        let proof = &self.evidence["expectedFullScope"]["scope"];
        ensure!(
            proof["expectedNodeIdsHash"] == metadata_digest(&ids.iter().collect::<Vec<_>>())?
                && self.deleted.iter().all(|node| !ids.contains(&node.id)),
            "full capture node IDs differ from original signed complete scope"
        );
        Ok(())
    }

    pub(super) fn revalidate_roots(&self, roots: &[RootSpec]) -> Result<()> {
        for root in roots {
            let expected = self
                .roots
                .iter()
                .find(|capture| capture.id == root.id)
                .context("full native root capture disappeared")?;
            if root.allowed_files.is_some() {
                ensure!(
                    SafeRoot::open(&root.path)?.identity()? == root.identity,
                    "manual-file parent native identity changed"
                );
            } else {
                let actual = root_capture(root)?;
                ensure!(
                    actual.stamp == expected.stamp
                        && actual
                            .metadata
                            .as_ref()
                            .zip(expected.metadata.as_ref())
                            .is_some_and(|(a, b)| a.same_state(b)),
                    "full native root metadata/stamp changed during source capture"
                );
            }
        }
        Ok(())
    }

    pub(super) fn revalidate_authority(
        &self,
        scope: &CaptureScope,
        controller: &dyn NativeCaptureController,
    ) -> Result<Arc<dyn NativeFullScopeAuthority>> {
        let authority = controller
            .full_scope_authority(scope)?
            .context("full native capture lost its original Rust authority")?;
        authority.revalidate()?;
        ensure!(
            FullScopeBinding::from_evidence(&authority.evidence()?)?
                == *scope
                    .full_scope
                    .as_ref()
                    .context("full native scope binding is missing")?,
            "native full-scope evidence changed during capture"
        );
        Ok(authority)
    }

    pub(super) fn apply_manifest(
        &self,
        manifest: &mut BundleManifest,
        parent: Option<&BundleManifest>,
        approved_roots: &[RootSpec],
    ) -> Result<()> {
        let roots_fingerprint = native_roots_fingerprint(&manifest.app.app_id, approved_roots)?;
        ensure!(
            self.roots.len() == approved_roots.len(),
            "native root captures differ from the frozen source layout"
        );
        for root in approved_roots {
            let captures = self
                .roots
                .iter()
                .filter(|capture| capture.id == root.id)
                .collect::<Vec<_>>();
            ensure!(
                captures.len() == 1,
                "native root capture is missing or duplicated"
            );
            captures[0].validate_metadata_scope(root)?;
        }
        ensure!(
            manifest.mode == noland_state_core::BackupMode::CompleteApplication
                && manifest.environment["quicksave_native"]["coverage"] == "full_approved_scope"
                && manifest.environment["quicksave_native"]["software_instance_id"]
                    == self.evidence["authorization"]["trackingScope"]["appId"]
                && self.evidence["softwareId"]
                    == self.evidence["authorization"]["trackingScope"]["softwareId"]
                && manifest.environment["quicksave_native"]["rootsFingerprint"]
                    == roots_fingerprint
                && self.evidence["sourceIdentity"]["app_id"].as_str()
                    == Some(manifest.app.app_id.as_str()),
            "native full-scope history lost its original source context"
        );
        let actual = manifest
            .files
            .iter()
            .map(|file| (file_id(&file.logical_root, &file.relative_path), file))
            .collect::<BTreeMap<_, _>>();
        let proof = &self.evidence["expectedFullScope"]["scope"];
        ensure!(
            actual.len() == manifest.files.len()
                && proof["expectedNodeIdsHash"]
                    == metadata_digest(&actual.keys().collect::<Vec<_>>())?,
            "actual CAS capture did not produce every signed full-scope entry"
        );
        let deleted = self
            .deleted
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        let mut tombstones = Vec::new();
        let mut prior_entries = Vec::new();
        // This is the No Land source manifest hash domain (tagged), not the
        // tracker's raw metadata/node-ID-set digest domain.
        let parent_manifest_hash = parent
            .map(noland_storage::compact_json_hash)
            .transpose()
            .map_err(source_error)?;
        if let Some(parent) = parent {
            let parent_root_fingerprints = [
                &parent.environment["quicksave_native"]["selection"]["roots_fingerprint"],
                &parent.environment["quicksave_native"]["rootsFingerprint"],
            ];
            ensure!(
                manifest.parent_bundle_id == Some(parent.bundle_id)
                    && parent.app.app_id == manifest.app.app_id
                    && parent.source.instance_id == manifest.source.instance_id
                    && parent.environment["quicksave_native"]["software_instance_id"]
                        == self.evidence["authorization"]["trackingScope"]["appId"]
                    && parent_root_fingerprints
                        .iter()
                        .any(|value| !value.is_null())
                    && parent_root_fingerprints.iter().all(|value| value.is_null()
                        || value.as_str() == Some(roots_fingerprint.as_str())),
                "authenticated parent is not the original source instance/app/approved roots"
            );
            if let Some(baseline) = self
                .evidence
                .get("sourceBaseline")
                .filter(|value| !value.is_null())
            {
                ensure!(
                    baseline["sourceSnapshotId"] == parent.bundle_id.to_string()
                        && baseline["manifestHash"].as_str() == parent_manifest_hash.as_deref(),
                    "signed full scope names another actual source parent baseline"
                );
            }
            let roots = approved_roots
                .iter()
                .map(|root| (root.logical.as_str(), root))
                .collect::<BTreeMap<_, _>>();
            let mut prior_ids = BTreeSet::new();
            for file in &parent.files {
                validate_relative(&file.relative_path)?;
                let id = file_id(&file.logical_root, &file.relative_path);
                let root = roots
                    .get(file.logical_root.as_str())
                    .context("authenticated source parent contains an unapproved root")?;
                let (persistence_class, semantic_role) = root.role.classification();
                ensure!(
                    prior_ids.insert(id.clone())
                        && root
                            .allowed_files
                            .as_ref()
                            .is_none_or(|leaves| leaves.contains(&file.relative_path))
                        && file.persistence_class == persistence_class
                        && file.semantic_role == semantic_role,
                    "authenticated parent entry changed its exact root/leaf/classification context"
                );
                if actual.contains_key(&id) {
                    continue;
                }
                let prior = deleted.get(id.as_str()).context(
                    "authenticated parent omission lacks original signed frozen baseline evidence",
                )?;
                compare_deleted(file, prior)?;
                // Preserve actual prior hash/size/classification in the AEAD-
                // authenticated environment, not invented tombstone wire fields.
                prior_entries.push(json!({
                    "logicalRoot":file.logical_root,"path":file.relative_path,
                    "fileType":file.file_type,"fileHash":file.file_hash,"size":file.size,
                    "mtimeNs":file.mtime_ns,"persistenceClass":file.persistence_class,
                    "semanticRole":file.semantic_role,
                }));
                tombstones.push(ManifestTombstone {
                    logical_root: file.logical_root.clone(),
                    relative_path: file.relative_path.clone(),
                    reason: "authenticated native full-scope omission; additive history retained"
                        .into(),
                });
            }
        } else {
            ensure!(
                manifest.parent_bundle_id.is_none()
                    && self.deleted.is_empty()
                    && self
                        .evidence
                        .get("sourceBaseline")
                        .is_none_or(Value::is_null),
                "native deletion/source baseline has no authenticated source parent"
            );
        }
        ensure!(
            tombstones.len() == self.deleted.len(),
            "signed deleted-node baseline differs from the authenticated original parent"
        );
        tombstones.sort_by(|a, b| {
            (&a.logical_root, &a.relative_path).cmp(&(&b.logical_root, &b.relative_path))
        });
        for root in approved_roots
            .iter()
            .filter(|root| root.allowed_files.is_some())
        {
            ensure!(
                manifest
                    .files
                    .iter()
                    .any(|file| file.logical_root == root.logical)
                    || tombstones
                        .iter()
                        .any(|node| node.logical_root == root.logical),
                "manual leaves cannot publish an empty whole-directory parent capture"
            );
        }
        manifest.tombstones = tombstones;
        manifest.environment["quicksave_native"]["full_scope"] = json!({
            "version":1,"evidenceHash":metadata_digest(&self.evidence)?,
            "originalTrackerEvidence":self.evidence,"deletedNodes":self.deleted,
            "rootCaptures":self.roots,"baselineReference":self.evidence["baseline"]["reference"],
            "baselineScope":self.evidence["baseline"]["scope"],
            "baselineIdentity":self.evidence["baseline"]["snapshotIdentity"],
            "baselineKind":self.evidence["baseline"]["kind"],
            "operationId":self.evidence["workId"],"tombstoneCount":manifest.tombstones.len(),
            "sourceParent":parent.map(|parent| parent.bundle_id),
            "sourceParentManifestHash":parent_manifest_hash,
            "sourceParentInstanceId":parent.map(|parent| parent.source.instance_id),
            "sourceParentMode":parent.map(|parent| parent.mode),
            "sourcePriorEntries":prior_entries,
            "keepsVersionHistory":true,
        });
        Ok(())
    }
}

fn compare_deleted(file: &ManifestFile, prior: &DeletedNode) -> Result<()> {
    let hash = prior.file_hash.as_ref().map(|raw| format!("blake3:{raw}"));
    ensure!(
        file.file_type == prior.kind
            && file.size == prior.size
            && file.mtime_ns == Some(mtime_ns_from_stamp(&prior.stamp)?)
            && file.mode.is_none()
            && file.uid.is_none()
            && file.gid.is_none()
            && (file.file_type != "file" || hash.as_deref() == Some(file.file_hash.as_str()))
            && (file.file_type != "symlink"
                || file
                    .symlink_target
                    .as_ref()
                    .map(|target| blake3::hash(target.as_bytes()).to_hex().to_string())
                    == prior.link_target_hash),
        "signed deleted node differs from its authenticated native parent"
    );
    Ok(())
}
