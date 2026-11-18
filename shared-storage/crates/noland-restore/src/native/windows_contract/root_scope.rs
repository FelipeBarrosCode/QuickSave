// SPDX-License-Identifier: GPL-3.0-only
//! Source-only Windows root scope validation; never probes an OS or resolves a
//! source path. Mirrors the active Windows full_scope.rs/plan.rs contracts in
//! the audited No Land e81238a7536aae201540956ce76981364fd36595 integration.
use std::collections::{BTreeMap, BTreeSet};

use noland_state_core::{
    native_layout::{NativeRootLayout, NativeRootLayouts},
    BundleManifest, Result, StateError,
};
use serde::Deserialize;
use serde_json::Value;

use super::super::{bounded_digest, MAX_ENTRIES};
use super::{SourceIdentity, SourceMetadata, SourceStamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootMetadata {
    Captured(i64),
    ManualLeavesOnly,
    UnknownFilesOnly,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScopeKind {
    ManualLeavesOnly,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MetadataScope {
    version: u32,
    kind: ScopeKind,
    source_root_id: String,
    source_root_identity: SourceIdentity,
    allowed_files_digest: String,
}

fn invalid(message: &str) -> StateError {
    StateError::Integrity(message.into())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn raw_digest(value: &Value) -> Option<&str> {
    value.as_str().filter(|hash| canonical_digest(hash))
}

fn canonical_digest(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn rows_by_id<'a>(value: &'a Value, bound: usize) -> Result<BTreeMap<&'a str, &'a Value>> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= bound)
        .ok_or_else(|| invalid("native source proof rows exceed their bound or are missing"))?;
    let mut indexed = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
            .ok_or_else(|| invalid("native source proof row has an invalid identity"))?;
        require(
            indexed.insert(id, row).is_none(),
            "duplicate native source proof identity",
        )?;
    }
    Ok(indexed)
}

fn leaves(value: &Value) -> Result<BTreeSet<&str>> {
    let rows = value
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= MAX_ENTRIES)
        .ok_or_else(|| {
            invalid("manual leaf authority requires a nonempty bounded exact allowlist")
        })?;
    let mut selected = BTreeSet::new();
    let mut bytes = 0usize;
    let mut previous = None;
    for row in rows {
        let path = row
            .as_str()
            .ok_or_else(|| invalid("manual leaf path is not a string"))?;
        noland_state_core::validate_windows_relative_path(path)?;
        bytes = bytes
            .checked_add(path.len())
            .filter(|bytes| *bytes <= 32 * 1024 * 1024)
            .ok_or_else(|| invalid("manual leaf path budget exceeded"))?;
        require(
            previous.is_none_or(|previous: &str| previous < path) && selected.insert(path),
            "manual leaf allowlist must be sorted and duplicate-free",
        )?;
        previous = Some(path);
    }
    Ok(selected)
}

// Exact producer logical-file-ID domain. The original root ID, not an absolute
// path or a truncated native inode, is the input to this metadata identifier.
fn file_id(root_id: &str, path: &str) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave logical file v1\0");
    hash.update(&(root_id.len() as u64).to_le_bytes());
    hash.update(root_id.as_bytes());
    hash.update(path.as_bytes());
    format!("file-{}", hash.finalize().to_hex())
}

struct ManualProof<'a> {
    full: &'a Value,
    evidence: &'a Value,
    roots: BTreeMap<&'a str, &'a Value>,
    tracking_roots: BTreeMap<&'a str, &'a Value>,
    deleted: BTreeMap<&'a str, &'a Value>,
    original_deleted: BTreeMap<&'a str, &'a Value>,
}

impl<'a> ManualProof<'a> {
    fn new(manifest: &'a BundleManifest, layout: &NativeRootLayouts) -> Result<Self> {
        let full = &manifest.environment["quicksave_native"]["full_scope"];
        let evidence = &full["originalTrackerEvidence"];
        let scope = &evidence["expectedFullScope"]["scope"];
        let tracking = &evidence["authorization"]["trackingScope"];
        require(
            full["version"] == 1
                && evidence["version"] == 1
                && scope["version"] == 1
                && evidence["fullScope"] == true
                && evidence["completeFileList"] == true
                && evidence["keepsVersionHistory"] == true
                && evidence["coverageScope"] == "approved_evidenced_roots_only"
                && scope["snapshotMode"] == "additive_full_scope"
                && scope["keepsHistory"] == true
                && evidence["sourceIdentity"]["app_id"].as_str()
                    == Some(manifest.app.app_id.as_str())
                // Canonical app, software instance and private workspace
                // software IDs are distinct namespaces in the source schema.
                && tracking["appId"].as_str() == Some(layout.software_instance_id.as_str())
                && evidence["softwareId"].as_str().is_some_and(|id| !id.is_empty())
                && scope["softwareId"] == evidence["softwareId"]
                && tracking["softwareId"] == evidence["softwareId"]
                // Tracking grants are provider-independent. Only the original
                // full-scope/work proof binds the source provider.
                && evidence["providerId"].as_str().is_some_and(|id| !id.is_empty())
                && scope["providerId"] == evidence["providerId"]
                && scope["workId"] == evidence["workId"]
                && full["operationId"] == evidence["workId"]
                && scope["metadataIdentity"] == evidence["metadataIdentity"]
                && evidence["expectedFullScope"]["grant"].is_object()
                && evidence["authorization"]["trackingGrant"].is_object()
                && scope["baselineKind"] == evidence["baseline"]["kind"]
                && scope["baselineIdentity"] == evidence["baseline"]["snapshotIdentity"],
            "manual leaf metadata scope is detached from its original native source proof",
        )?;
        require(
            raw_digest(&full["evidenceHash"]) == Some(bounded_digest(evidence)?.as_str())
                && raw_digest(&scope["trackingScopeHash"])
                    == Some(bounded_digest(tracking)?.as_str())
                && raw_digest(&scope["expectedNodeIdsHash"]).is_some()
                && raw_digest(&scope["deletedNodeIdsHash"]).is_some()
                && raw_digest(&scope["metadataIdentity"]).is_some(),
            "manual leaf source proof digest changed",
        )?;
        let roots = rows_by_id(&evidence["roots"], 128)?;
        let tracking_roots = rows_by_id(&tracking["roots"], 128)?;
        let root_ids = scope["rootIds"]
            .as_array()
            .filter(|ids| ids.len() == roots.len())
            .ok_or_else(|| invalid("manual leaf source proof root coverage changed"))?;
        let root_ids = root_ids
            .iter()
            .map(|id| {
                id.as_str()
                    .ok_or_else(|| invalid("invalid source proof root ID"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            root_ids.len() == roots.len()
                && root_ids.iter().copied().eq(roots.keys().copied())
                && tracking_roots.keys().eq(roots.keys()),
            "manual leaf tracker root scope is inconsistent",
        )?;
        let deleted = rows_by_id(&full["deletedNodes"], MAX_ENTRIES)?;
        let original_deleted = rows_by_id(&evidence["deletedNodes"], MAX_ENTRIES)?;
        require(
            deleted.keys().eq(original_deleted.keys())
                && evidence["deletedFileIds"]
                    == serde_json::to_value(deleted.keys().copied().collect::<Vec<_>>())?
                && raw_digest(&scope["deletedNodeIdsHash"])
                    == Some(bounded_digest(&deleted.keys().copied().collect::<Vec<_>>())?.as_str()),
            "manual leaf source deletion identities changed",
        )?;
        Ok(Self {
            full,
            evidence,
            roots,
            tracking_roots,
            deleted,
            original_deleted,
        })
    }

    fn validate_root(
        &self,
        manifest: &BundleManifest,
        root: &NativeRootLayout,
        capture: &Value,
        scope: &MetadataScope,
        allowed: &BTreeSet<&str>,
    ) -> Result<()> {
        let original = self
            .roots
            .get(root.root_id.as_str())
            .ok_or_else(|| invalid("manual leaf source root is absent from original proof"))?;
        let tracking = self
            .tracking_roots
            .get(root.root_id.as_str())
            .ok_or_else(|| invalid("manual leaf source root lacks original tracking scope"))?;
        let stamp = SourceStamp::deserialize(&capture["stamp"])?;
        let _kind = &scope.kind;
        require(
            scope.version == 1
                && scope.source_root_id == root.root_id
                && capture["id"] == root.root_id
                && capture["logicalRoot"] == root.logical_root
                && capture["kind"] == "directory"
                && scope.source_root_identity.file_id != [0; 2]
                && scope.source_root_identity.device == stamp.device
                && scope.source_root_identity.file_id == stamp.file_id
                && canonical_digest(&scope.allowed_files_digest)
                && scope.allowed_files_digest == bounded_digest(allowed)?,
            "manual leaf metadata scope lacks its exact source root identity/leaf digest",
        )?;
        let identity = serde_json::json!({"device":scope.source_root_identity.device,
            "fileId":scope.source_root_identity.file_id});
        for row in [*original, *tracking] {
            require(
                row["identity"] == identity
                    && row["role"] == root.role.as_str()
                    && leaves(&row["allowedFiles"])? == *allowed,
                "manual leaf allowlist/root identity differs from original signed tracking scope",
            )?;
        }
        let mut count = 0usize;
        for file in manifest
            .files
            .iter()
            .filter(|file| file.logical_root == root.logical_root)
        {
            require(file.file_type == "file"
                    && file.mode.is_none() && file.uid.is_none() && file.gid.is_none()
                    && allowed.contains(file.relative_path.as_str()),
                "manual leaf restore attempted a sibling, directory or link outside its exact files")?;
            count += 1;
        }
        for tombstone in manifest
            .tombstones
            .iter()
            .filter(|entry| entry.logical_root == root.logical_root)
        {
            require(
                allowed.contains(tombstone.relative_path.as_str()),
                "manual leaf tombstone widened its original exact allowlist",
            )?;
            self.validate_deleted(manifest, root, &tombstone.relative_path)?;
            count += 1;
        }
        require(
            count != 0,
            "manual leaves cannot authorize an empty parent-directory capture",
        )
    }

    fn validate_captured_directory(&self, root: &NativeRootLayout, capture: &Value) -> Result<()> {
        let original = self
            .roots
            .get(root.root_id.as_str())
            .ok_or_else(|| invalid("captured directory lacks original native root evidence"))?;
        let tracking = self
            .tracking_roots
            .get(root.root_id.as_str())
            .ok_or_else(|| invalid("captured directory lacks original tracking scope"))?;
        let metadata = SourceMetadata::deserialize(&capture["metadata"])?;
        let expected = SourceMetadata::deserialize(&self.evidence["rootMetadata"][&root.root_id])?;
        let stamp = SourceStamp::deserialize(&capture["stamp"])?;
        let expected_stamp = SourceStamp::deserialize(&self.evidence["rootStamps"][&root.root_id])?;
        require(
            stamp == expected_stamp && metadata.same_state(&expected),
            "whole-directory capture lacks its actual original native metadata/stamp proof",
        )?;
        let identity = serde_json::json!({"device":stamp.device,"fileId":stamp.file_id});
        for row in [*original, *tracking] {
            require(
                row["identity"] == identity
                    && row["role"] == root.role.as_str()
                    && row.get("allowedFiles").is_some_and(Value::is_null),
                "manual leaf authority cannot be promoted to whole-directory metadata",
            )?;
        }
        Ok(())
    }

    fn validate_deleted(
        &self,
        manifest: &BundleManifest,
        root: &NativeRootLayout,
        path: &str,
    ) -> Result<()> {
        let id = file_id(&root.root_id, path);
        let deleted = self.deleted.get(id.as_str()).ok_or_else(|| {
            invalid("manual leaf tombstone lacks its prior authenticated deleted ID")
        })?;
        let original = self
            .original_deleted
            .get(id.as_str())
            .ok_or_else(|| invalid("manual leaf deletion lost its original tracker evidence"))?;
        super::captured_file_mtime(&deleted["metadata"], &deleted["stamp"])?;
        require(
            deleted["size"] == deleted["stamp"]["size"],
            "manual deleted leaf lost its actual prior byte length",
        )?;
        require(
            deleted["logicalRoot"] == root.logical_root
                && deleted["path"] == path
                && deleted["kind"] == "file"
                && original["rootId"] == root.root_id
                && original["path"] == path
                && original["kind"] == "file"
                && ["stamp", "metadata", "size", "fileHash", "linkTargetHash"]
                    .iter()
                    .all(|key| deleted[*key] == original[*key])
                && raw_digest(&deleted["fileHash"]).is_some()
                && matches!(
                    self.evidence["baseline"]["kind"].as_str(),
                    Some("full" | "partial")
                )
                && self.full["keepsVersionHistory"] == true
                && manifest.parent_bundle_id.is_some()
                && self.full["sourceParent"] == serde_json::to_value(manifest.parent_bundle_id)?
                && self.full["sourceParentManifestHash"]
                    .as_str()
                    .is_some_and(|hash| {
                        hash.strip_prefix("blake3:").is_some_and(|raw| {
                            raw.len() == 64
                                && raw.bytes().all(|byte| {
                                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                })
                        })
                    })
                && self.evidence["baseline"]["reference"].is_object()
                && self.evidence["baseline"]["scope"].is_object(),
            "manual leaf deletion cannot become an unauthenticated empty-root/application claim",
        )
    }
}

pub(crate) struct WindowsRootMetadata<'a> {
    manifest: &'a BundleManifest,
    captures: BTreeMap<&'a str, &'a Value>,
    proof: Option<ManualProof<'a>>,
}

impl<'a> WindowsRootMetadata<'a> {
    pub(crate) fn new(manifest: &'a BundleManifest, layout: &NativeRootLayouts) -> Result<Self> {
        require(
            manifest
                .files
                .iter()
                .all(|file| file.mode.is_none() && file.uid.is_none() && file.gid.is_none()),
            "Windows source files cannot claim unsupported legacy POSIX permissions",
        )?;
        let full = &manifest.environment["quicksave_native"]["full_scope"];
        let captures = if full.get("rootCaptures").is_none() {
            BTreeMap::new()
        } else {
            require(
                full["version"] == 1,
                "unsupported Windows source root-capture version",
            )?;
            rows_by_id(&full["rootCaptures"], 128)?
        };
        let needs_proof = full["originalTrackerEvidence"].is_object()
            || layout.roots.iter().any(|root| {
                captures.get(root.root_id.as_str()).is_some_and(|capture| {
                    capture
                        .get("metadataScope")
                        .is_some_and(|value| !value.is_null())
                })
            });
        for root in &layout.roots {
            if captures.get(root.root_id.as_str()).is_some_and(|capture| {
                capture
                    .get("metadataScope")
                    .is_some_and(|scope| !scope.is_null())
            }) {
                require(
                    root.source_kind
                        == noland_state_core::native_layout::NativeLayoutSourceKind::Directory,
                    "manual leaf scope cannot invent a native single-file root identity",
                )?;
            }
        }
        let proof = if needs_proof {
            Some(ManualProof::new(manifest, layout)?)
        } else {
            None
        };
        if manifest.environment["quicksave_native_download"]["whole_bundle"].as_bool()
            != Some(false)
        {
            if let Some(proof) = &proof {
                let root_ids = layout
                    .roots
                    .iter()
                    .map(|root| (root.logical_root.as_str(), root.root_id.as_str()))
                    .collect::<BTreeMap<_, _>>();
                let mut ids = BTreeSet::new();
                for file in &manifest.files {
                    let root = root_ids
                        .get(file.logical_root.as_str())
                        .ok_or_else(|| invalid("source proof file has no original root layout"))?;
                    require(
                        ids.insert(file_id(root, &file.relative_path)),
                        "source proof contains duplicate actual file identities",
                    )?;
                }
                require(raw_digest(&proof.evidence["expectedFullScope"]["scope"]["expectedNodeIdsHash"])
                    == Some(bounded_digest(&ids)?.as_str()),
                    "actual source manifest differs from the original complete native file-ID proof")?;
            }
        }
        Ok(Self {
            manifest,
            captures,
            proof,
        })
    }

    pub(crate) fn root(&self, root: &NativeRootLayout) -> Result<RootMetadata> {
        let Some(capture) = self.captures.get(root.root_id.as_str()).copied() else {
            return self.unknown(root);
        };
        require(
            capture["logicalRoot"] == root.logical_root,
            "Windows root capture changed its original logical identity",
        )?;
        require(
            ["mode", "uid", "gid", "owner", "group"].iter().all(|key| {
                capture.get(*key).is_none_or(Value::is_null)
                    && capture["metadata"].get(*key).is_none_or(Value::is_null)
            }),
            "unsupported legacy POSIX root permissions cannot be invented on Windows",
        )?;
        if let Some(value) = capture
            .get("metadataScope")
            .filter(|value| !value.is_null())
        {
            require(
                capture.get("metadata").is_some_and(Value::is_null),
                "manual leaves must not claim source parent-directory metadata",
            )?;
            require(
                value["sourceRootId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 256)
                    && raw_digest(&value["allowedFilesDigest"]).is_some(),
                "manual leaf metadata-scope string bounds are invalid",
            )?;
            let scope = MetadataScope::deserialize(value)?;
            let allowed = leaves(&capture["allowedFiles"])?;
            self.proof
                .as_ref()
                .ok_or_else(|| invalid("manual leaf scope has no original source proof"))?
                .validate_root(self.manifest, root, capture, &scope, &allowed)?;
            return Ok(RootMetadata::ManualLeavesOnly);
        }
        require(
            capture.get("allowedFiles").is_none_or(Value::is_null),
            "manual leaf metadata:null requires explicit versioned metadataScope proof",
        )?;
        require(
            self.proof
                .as_ref()
                .and_then(|proof| proof.roots.get(root.root_id.as_str()))
                .is_none_or(|row| row.get("allowedFiles").is_none_or(Value::is_null)),
            "original manual leaf authority lost its explicit metadataScope discriminator",
        )?;
        if capture["metadata"]["platform"] == "windows" {
            let time = super::captured_root_mtime(capture)?;
            if let Some(proof) = &self.proof {
                proof.validate_captured_directory(root, capture)?;
                return Ok(RootMetadata::Captured(time));
            }
            // A recognizable stat frame is not original whole-root authority.
            // Legacy manifests can still provide explicit files, never a new
            // empty directory or guessed parent permissions.
            return self.unknown(root);
        }
        self.unknown(root)
    }

    fn unknown(&self, root: &NativeRootLayout) -> Result<RootMetadata> {
        require(
            self.proof
                .as_ref()
                .and_then(|proof| proof.roots.get(root.root_id.as_str()))
                .is_none_or(|row| row.get("allowedFiles").is_none_or(Value::is_null)),
            "original manual root needs its explicit leaf-only metadata-scope proof",
        )?;
        require(
            self.manifest
                .files
                .iter()
                .any(|file| file.logical_root == root.logical_root),
            "an empty Windows directory root requires actual captured native metadata proof",
        )?;
        Ok(RootMetadata::UnknownFilesOnly)
    }
}
