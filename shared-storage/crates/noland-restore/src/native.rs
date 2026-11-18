// SPDX-License-Identifier: GPL-3.0-only
//! Authenticated native publication and recovery. This is not the legacy
//! checksummed, path-authorized rollback journal.
//!
//! Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! New control/journal code is GPL-3.0-only; original notices remain unchanged.
pub(super) mod filesystem;
mod journal;
mod reconstruction;
pub(crate) mod windows_contract;
pub use reconstruction::{
    NativeApplicationAssessment, NativeReconstructionReport, NativeRestoreReadiness,
};
#[cfg(test)]
mod observation_tests;
#[cfg(all(test, unix))]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use noland_state_core::native_layout::{
    logical_root_map, native_root_layout_mappings, native_root_layouts,
    validate_native_restore_names, validate_native_root_mappings, NativeRootLayouts,
};
use noland_state_core::{
    AppId, BundleManifest, LogicalRootMap, ManifestFile, RestoreMode, Result, StateError,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use self::filesystem::NativeRoot;
use self::journal::{
    DirectoryMetadataRollback, Event, NativeJournal, OwnershipRole, Publication, RollbackCapture,
};

pub const MAX_NATIVE_RESTORE_METADATA: usize = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 250_000;
#[cfg(unix)]
const NATIVE_CONTROL_VERSION: u32 = 1;
#[cfg(windows)]
const NATIVE_CONTROL_VERSION: u32 = 2;

/// Opaque, native filesystem identity. Windows IDs must not be narrowed to ino64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeObjectId {
    pub device: u64,
    pub file_id: [u64; 2],
}

#[cfg(unix)]
impl From<(u64, u64)> for NativeObjectId {
    fn from((device, inode): (u64, u64)) -> Self {
        Self {
            device,
            file_id: [inode, 0],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEntryKind {
    File,
    Directory,
    Symlink,
}

/// A stable observation of the entry itself, never the target of a symlink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEntryObservation {
    pub id: NativeObjectId,
    pub kind: NativeEntryKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub links: u64,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub symlink_target: Option<String>,
    pub target_is_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<NativeWindowsObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWindowsSecurity {
    pub current_user_sid: [u8; 32],
    pub owner_sid: [u8; 32],
    pub dacl: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWindowsObservation {
    pub version: u32,
    pub attributes: u32,
    pub creation_time: i64,
    pub reparse_tag: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_data: Option<[u8; 32]>,
    pub security: NativeWindowsSecurity,
}

impl NativeEntryObservation {
    fn validate_platform(&self) -> Result<()> {
        #[cfg(unix)]
        if self.windows.is_some() || self.mode.is_none() || self.uid.is_none() || self.gid.is_none()
        {
            return Err(StateError::Integrity(
                "native Unix observation has missing or foreign ownership semantics".into(),
            ));
        }
        #[cfg(windows)]
        {
            let win = self.windows.as_ref().ok_or_else(|| StateError::Integrity(
                "legacy/unbound Windows restore receipt has no authenticated native ownership frame".into()))?;
            if self.mode.is_some()
                || self.uid.is_some()
                || self.gid.is_some()
                || win.version != 1
                || win.security.owner_sid != win.security.current_user_sid
                || win.security.owner_sid == [0; 32]
                || win.security.dacl == [0; 32]
                || self.id.file_id == [0; 2]
                || self.links == 0
                || self.mtime_ns % 100 != 0
                || self.ctime_ns % 100 != 0
                || win.creation_time <= 0
                || win.attributes & 0x40 != 0
                || match self.kind {
                    NativeEntryKind::File => {
                        win.attributes & (0x10 | 0x400) != 0
                            || win.reparse_tag != 0
                            || self.symlink_target.is_some()
                            || self.target_is_directory.is_some()
                            || win.reparse_data.is_some()
                    }
                    NativeEntryKind::Directory => {
                        win.attributes & (0x10 | 0x400) != 0x10
                            || win.reparse_tag != 0
                            || self.symlink_target.is_some()
                            || self.target_is_directory.is_some()
                            || win.reparse_data.is_some()
                    }
                    NativeEntryKind::Symlink => {
                        win.attributes & 0x400 == 0
                            || win.reparse_tag != 0xa000000c
                            || self.symlink_target.is_none()
                            || self.target_is_directory != Some(win.attributes & 0x10 != 0)
                            || win.reparse_data.is_none()
                    }
                }
            {
                return Err(StateError::Integrity("Windows restore receipt has fabricated POSIX or invalid native ownership fields".into()));
            }
        }
        Ok(())
    }

    fn metadata_matches(
        &self,
        mode: Option<u32>,
        time: Option<i64>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> bool {
        mode.is_none_or(|mode| {
            self.mode
                .is_some_and(|actual| actual & 0o7777 == mode & 0o7777)
        }) && time.is_none_or(|time| self.mtime_ns == time)
            && uid.is_none_or(|uid| self.uid == Some(uid))
            && gid.is_none_or(|gid| self.gid == Some(gid))
    }

    fn same_security(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.windows == other.windows
    }
    fn after_move_matches(&self, other: &Self) -> bool {
        // Moving an entry changes ctime, not its content, kind, ownership or ID.
        let mut expected = self.clone();
        expected.ctime_ns = other.ctime_ns;
        expected == *other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConflictMode {
    /// No existing entry is authorized except real ancestor directories.
    CreateOnly,
    /// Existing directories and byte/metadata-identical files can be reused.
    Merge,
    /// Replacements listed in this exact preview are explicitly approvable.
    Overwrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRestoreAction {
    Create,
    Reuse,
    Replace,
    Remove,
    Conflict,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRestoreEntry {
    pub logical_root: String,
    pub relative_path: String,
    pub destination_relative: String,
    pub kind: NativeEntryKind,
    pub size: u64,
    pub file_hash: String,
    pub symlink_target: Option<String>,
    pub target_is_directory: Option<bool>,
    pub mode: Option<u32>,
    pub mtime_ns: Option<i64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub expected: Option<NativeEntryObservation>,
    pub action: NativeRestoreAction,
}

impl NativeRestoreEntry {
    /// A frozen destination ancestor, not captured source directory metadata.
    /// Input manifests can produce this only after the root-scope parser has
    /// validated an exact manual allowlist or a nonempty files-only legacy root.
    fn is_scaffold_root(&self) -> bool {
        self.relative_path.is_empty()
            && self.kind == NativeEntryKind::Directory
            && self.mode.is_none()
            && self.mtime_ns.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
    }
}

fn destination_observation_matches(
    entry: &NativeRestoreEntry,
    expected: Option<&NativeEntryObservation>,
    current: Option<&NativeEntryObservation>,
) -> bool {
    if !entry.is_scaffold_root() {
        return expected == current;
    }
    match (expected, current) {
        (None, None) => true,
        (Some(expected), Some(current)) => {
            expected.kind == NativeEntryKind::Directory
                && current.kind == NativeEntryKind::Directory
                && expected.id == current.id
                && expected.same_security(current)
        }
        _ => false,
    }
}

/// Fresh native preview and exact expected-payload gate. The host must build
/// this from an authenticated manifest, display replacements, and freeze it
/// only after native consent. A UI JSON document is not an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRestorePreview {
    pub version: u32,
    pub job_id: Uuid,
    pub bundle_id: Uuid,
    pub app_id: AppId,
    pub destination: PathBuf,
    pub destination_identity: NativeObjectId,
    pub conflict_mode: NativeConflictMode,
    pub mode: RestoreMode,
    pub expected_payload: String,
    /// Existing ancestors are identities too: replacing a real directory with
    /// another real directory must not redirect a previously approved plan.
    pub parents: BTreeMap<String, NativeObjectId>,
    pub entries: Vec<NativeRestoreEntry>,
    pub tombstones: Vec<NativeRestoreEntry>,
    /// Frozen exact placement, included in the device MAC and journal scope.
    /// Empty only for legacy private plans created before layout frames existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_mappings: BTreeMap<String, PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_layout: Option<NativeRootLayouts>,
    #[serde(default = "true_value", skip_serializing_if = "is_true")]
    pub entire_manifest: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_full_scope: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_app_name: String,
    /// Actual captured directory-root metadata, not fabricated bundle contents
    /// or extra manifest files. Kept outside file/pack/accounting inventories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_entries: Vec<NativeRestoreEntry>,
}

fn true_value() -> bool {
    true
}
fn is_true(value: &bool) -> bool {
    *value
}
fn is_false(value: &bool) -> bool {
    !*value
}

impl NativeRestorePreview {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        job_id: Uuid,
        manifest: &BundleManifest,
        roots: &LogicalRootMap,
        destination: &Path,
        destination_identity: impl Into<NativeObjectId>,
        conflict_mode: NativeConflictMode,
    ) -> Result<Self> {
        Self::prepare_for_mode(
            job_id,
            manifest,
            roots,
            destination,
            destination_identity,
            conflict_mode,
            RestoreMode::CompleteApplication,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_for_mode(
        job_id: Uuid,
        manifest: &BundleManifest,
        roots: &LogicalRootMap,
        destination: &Path,
        destination_identity: impl Into<NativeObjectId>,
        conflict_mode: NativeConflictMode,
        mode: RestoreMode,
    ) -> Result<Self> {
        validate_native_restore_names(manifest)?;
        #[cfg(windows)]
        if manifest
            .files
            .iter()
            .any(|file| file.mode.is_some() || file.uid.is_some() || file.gid.is_some())
        {
            return Err(StateError::Invalid(
                "Windows restore cannot apply Unix mode/UID/GID metadata".into(),
            ));
        }
        if manifest
            .files
            .len()
            .saturating_add(manifest.tombstones.len())
            > MAX_ENTRIES
        {
            return Err(StateError::Invalid(
                "native restore exceeds its 250000-entry bound".into(),
            ));
        }
        if !manifest.environment.is_object() && !manifest.environment.is_null() {
            return Err(StateError::Integrity(
                "native restore manifest environment must be an object".into(),
            ));
        }
        let destination_identity = destination_identity.into();
        let root_layout = native_root_layouts(manifest)?;
        let mut tokens = manifest
            .files
            .iter()
            .filter(|file| crate::include_file(mode, file))
            .map(|file| file.logical_root.as_str())
            .chain(
                manifest
                    .tombstones
                    .iter()
                    .map(|entry| entry.logical_root.as_str()),
            )
            .collect::<BTreeSet<_>>();
        if let Some(layout) = &root_layout {
            tokens.extend(layout.roots.iter().map(|root| root.logical_root.as_str()));
        }
        let root_mappings = tokens
            .into_iter()
            .map(|token| {
                let logical = noland_state_core::LogicalRoot::parse(token).ok_or_else(|| {
                    StateError::Integrity("native preview has an unknown logical root".into())
                })?;
                let path = roots.resolve(&logical).ok_or_else(|| {
                    StateError::UnsafePath(
                        "native preview is missing a selected root mapping".into(),
                    )
                })?;
                Ok((token.to_owned(), path))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        validate_native_root_mappings(destination, &root_mappings)?;
        if let Some(layout) = &root_layout {
            if native_root_layout_mappings(layout, destination)? != root_mappings {
                return Err(StateError::Conflict(
                    "native preview mappings differ from the authenticated root layout".into(),
                ));
            }
        }
        let windows_metadata = root_layout
            .as_ref()
            .filter(|layout| {
                layout.platform == noland_state_core::native_layout::NativeLayoutPlatform::Windows
            })
            .map(|layout| windows_contract::WindowsRootMetadata::new(manifest, layout))
            .transpose()?;
        let root = NativeRoot::open(destination, destination_identity)?;
        let mut preview = Self {
            version: NATIVE_CONTROL_VERSION,
            job_id,
            app_id: manifest.app.app_id.clone(),
            bundle_id: manifest.bundle_id,
            destination: destination.into(),
            destination_identity,
            conflict_mode,
            mode,
            expected_payload: payload_digest(manifest, mode)?,
            parents: BTreeMap::new(),
            entries: Vec::new(),
            tombstones: Vec::new(),
            root_mappings,
            root_layout,
            entire_manifest: manifest.environment["quicksave_native_download"]["whole_bundle"]
                .as_bool()
                .unwrap_or(true),
            source_full_scope: manifest.mode == noland_state_core::BackupMode::CompleteApplication
                && manifest.environment["quicksave_native"]["coverage"] == "full_approved_scope",
            source_app_name: manifest
                .app
                .display_name
                .chars()
                .filter(|c| !c.is_control())
                .take(1024)
                .collect(),
            root_entries: Vec::new(),
        };
        let mut seen = BTreeSet::new();
        #[cfg(windows)]
        let link_hints = windows_contract::link_hints(&manifest.environment)?;
        for file in &manifest.files {
            if !crate::include_file(mode, file) {
                continue;
            }
            let (logical_root, destination_path) = resolve_destination(roots, file)?;
            if !logical_root.starts_with(destination) || logical_root == destination {
                return Err(StateError::UnsafePath(
                    "native logical root is outside the approved destination".into(),
                ));
            }
            let relative = relative_to(destination, &destination_path)?;
            if !seen.insert(relative.clone()) {
                return Err(StateError::Integrity(
                    "native manifest has duplicate resolved destinations".into(),
                ));
            }
            root.collect_parents(&relative, &mut preview.parents)?;
            let expected = root.observe_if_present(&relative)?;
            if let Some(prior) = &expected {
                if prior.kind == NativeEntryKind::Directory {
                    preview.parents.insert(relative.clone(), prior.id);
                }
            }
            let kind = match file.file_type.as_str() {
                "file" => NativeEntryKind::File,
                "directory" => NativeEntryKind::Directory,
                "symlink" => {
                    noland_state_core::validate_relative_symlink_target_within_root(
                        &file.relative_path,
                        file.symlink_target.as_deref().ok_or_else(|| {
                            StateError::Integrity("native symlink target missing".into())
                        })?,
                    )?;
                    NativeEntryKind::Symlink
                }
                _ => {
                    return Err(StateError::UnsafePath(
                        "native restore supports only regular files, directories and confined relative links".into(),
                    ));
                }
            };
            #[cfg(windows)]
            let target_is_directory = native_link_directory_hint(&link_hints, file)?;
            #[cfg(not(windows))]
            let target_is_directory = None;
            // Type-changing directory replacement would delete an unbounded
            // tree. It is never implicit in an overwrite-file approval.
            let compatible = expected.as_ref().is_none_or(|prior| {
                (kind == NativeEntryKind::Directory) == (prior.kind == NativeEntryKind::Directory)
            });
            let identical = match &expected {
                Some(prior) if compatible && prior.kind == kind => match kind {
                    NativeEntryKind::Directory => {
                        prior.metadata_matches(file.mode, file.mtime_ns, file.uid, file.gid)
                    }
                    NativeEntryKind::Symlink => {
                        prior.symlink_target == file.symlink_target
                            && prior.target_is_directory == target_is_directory
                    }
                    NativeEntryKind::File => root.matches_manifest_file(&relative, file)?,
                },
                _ => false,
            };
            let action = if expected.is_some()
                && compatible
                && !identical
                && kind == NativeEntryKind::Directory
                && conflict_mode != NativeConflictMode::CreateOnly
            {
                NativeRestoreAction::Metadata
            } else {
                match (expected.is_some(), identical, compatible, conflict_mode) {
                    (false, _, _, _) => NativeRestoreAction::Create,
                    (_, _, false, _) => NativeRestoreAction::Conflict,
                    (true, _, _, NativeConflictMode::CreateOnly) => NativeRestoreAction::Conflict,
                    (true, true, _, _) => NativeRestoreAction::Reuse,
                    (true, false, _, NativeConflictMode::Merge) => NativeRestoreAction::Conflict,
                    (true, false, _, NativeConflictMode::Overwrite) => NativeRestoreAction::Replace,
                }
            };
            preview.entries.push(NativeRestoreEntry {
                logical_root: file.logical_root.clone(),
                relative_path: file.relative_path.clone(),
                destination_relative: relative,
                kind,
                size: file.size,
                file_hash: file.file_hash.clone(),
                symlink_target: file.symlink_target.clone(),
                target_is_directory,
                mode: file.mode,
                mtime_ns: file.mtime_ns,
                uid: file.uid,
                gid: file.gid,
                expected,
                action,
            });
        }
        for tombstone in &manifest.tombstones {
            let logical = noland_state_core::LogicalRoot::parse(&tombstone.logical_root)
                .ok_or_else(|| StateError::UnsafePath("native tombstone root unknown".into()))?;
            let logical_root = roots
                .resolve(&logical)
                .ok_or_else(|| StateError::UnsafePath("native tombstone root unapproved".into()))?;
            if !logical_root.starts_with(destination) || logical_root == destination {
                return Err(StateError::UnsafePath(
                    "native tombstone is outside its approved destination".into(),
                ));
            }
            let path =
                noland_state_core::join_native_relative(&logical_root, &tombstone.relative_path)?;
            let relative = relative_to(destination, &path)?;
            if !seen.insert(relative.clone()) {
                return Err(StateError::Integrity(
                    "native entry and tombstone resolve to the same destination".into(),
                ));
            }
            root.collect_parents(&relative, &mut preview.parents)?;
            let expected = root.observe_if_present(&relative)?;
            let kind = expected
                .as_ref()
                .map_or(NativeEntryKind::File, |entry| entry.kind);
            let action = match (&expected, kind, conflict_mode) {
                (None, _, _) => NativeRestoreAction::Reuse,
                (_, NativeEntryKind::Directory, _) => NativeRestoreAction::Conflict,
                (_, _, NativeConflictMode::Overwrite) => NativeRestoreAction::Remove,
                _ => NativeRestoreAction::Conflict,
            };
            preview.tombstones.push(NativeRestoreEntry {
                logical_root: tombstone.logical_root.clone(),
                relative_path: tombstone.relative_path.clone(),
                destination_relative: relative,
                kind,
                size: 0,
                file_hash: String::new(),
                symlink_target: None,
                target_is_directory: None,
                mode: None,
                mtime_ns: None,
                uid: None,
                gid: None,
                expected,
                action,
            });
        }
        preview.entries.sort_by(|a, b| {
            (&a.logical_root, &a.relative_path).cmp(&(&b.logical_root, &b.relative_path))
        });
        preview.tombstones.sort_by(|a, b| {
            (&a.logical_root, &a.relative_path).cmp(&(&b.logical_root, &b.relative_path))
        });
        if let Some(layout) = &preview.root_layout {
            for declared in &layout.roots {
                if declared.source_kind
                    != noland_state_core::native_layout::NativeLayoutSourceKind::Directory
                {
                    continue;
                }
                let mapped = &preview.root_mappings[&declared.logical_root];
                let relative = relative_to(destination, mapped)?;
                root.collect_parents(&relative, &mut preview.parents)?;
                let expected = root.observe_if_present(&relative)?;
                let (mode, mtime_ns, uid, gid) = if let Some(metadata) = &windows_metadata {
                    match metadata.root(declared)? {
                        windows_contract::RootMetadata::Captured(time) => {
                            (None, Some(time), None, None)
                        }
                        windows_contract::RootMetadata::ManualLeavesOnly
                        | windows_contract::RootMetadata::UnknownFilesOnly => {
                            (None, None, None, None)
                        }
                    }
                } else {
                    captured_root_metadata(manifest, declared)?
                };
                let scaffold_only =
                    mode.is_none() && mtime_ns.is_none() && uid.is_none() && gid.is_none();
                let same = expected.as_ref().is_some_and(|prior| {
                    prior.kind == NativeEntryKind::Directory
                        && prior.metadata_matches(mode, mtime_ns, uid, gid)
                });
                let action = match (&expected, conflict_mode, same) {
                    (None, _, _) => NativeRestoreAction::Create,
                    (Some(prior), _, _)
                        if scaffold_only && prior.kind == NativeEntryKind::Directory =>
                    {
                        NativeRestoreAction::Reuse
                    }
                    (Some(_), NativeConflictMode::CreateOnly, _) => NativeRestoreAction::Conflict,
                    (Some(prior), _, _) if prior.kind != NativeEntryKind::Directory => {
                        NativeRestoreAction::Conflict
                    }
                    (_, _, true) => NativeRestoreAction::Reuse,
                    _ => NativeRestoreAction::Metadata,
                };
                if let Some(prior) = &expected {
                    if prior.kind == NativeEntryKind::Directory {
                        preview.parents.insert(relative.clone(), prior.id);
                    }
                }
                preview.root_entries.push(NativeRestoreEntry {
                    logical_root: declared.logical_root.clone(),
                    relative_path: String::new(),
                    destination_relative: relative,
                    kind: NativeEntryKind::Directory,
                    size: 0,
                    file_hash: String::new(),
                    symlink_target: None,
                    target_is_directory: None,
                    mode,
                    mtime_ns,
                    uid,
                    gid,
                    expected,
                    action,
                });
            }
        }
        preview.validate_shape()?;
        Ok(preview)
    }

    pub fn digest(&self) -> Result<String> {
        bounded_digest(self)
    }

    pub fn digest_and_size(&self) -> Result<(String, usize)> {
        bounded_fingerprint(self)
    }

    pub fn has_conflicts(&self) -> bool {
        self.entries
            .iter()
            .chain(&self.tombstones)
            .chain(&self.root_entries)
            .any(|entry| entry.action == NativeRestoreAction::Conflict)
    }

    /// Native-private exact mapping for preview, execution and restart. It never
    /// reinterprets original absolute source hints or a later incoming UI map.
    pub fn logical_roots(&self) -> Result<LogicalRootMap> {
        logical_root_map(&self.frozen_root_mappings()?)
    }

    pub fn reconstruction_eligible(&self) -> bool {
        self.entire_manifest
            && self.source_full_scope
            && !self
                .root_entries
                .iter()
                .any(NativeRestoreEntry::is_scaffold_root)
            && self.root_layout.as_ref().is_some_and(|layout| {
                layout.platform.is_current()
                    && layout.roots.iter().any(|root| {
                        root.role
                            == noland_state_core::native_layout::NativeLayoutRole::Installation
                    })
            })
    }

    pub fn root_mapping_digest(&self) -> Result<String> {
        bounded_digest(&(
            &self.root_mappings,
            &self.root_layout,
            self.entire_manifest,
            self.source_full_scope,
            &self.root_entries,
        ))
    }

    fn frozen_root_mappings(&self) -> Result<BTreeMap<String, PathBuf>> {
        if !self.root_mappings.is_empty() {
            return Ok(self.root_mappings.clone());
        }
        // Legacy MAC documents have no explicit frame. Derive only from their
        // already-frozen destination-relative entries, never a manifest hint.
        let mut roots = BTreeMap::new();
        for entry in self.entries.iter().chain(&self.tombstones) {
            let suffix = format!("/{}", entry.relative_path);
            let base = entry
                .destination_relative
                .strip_suffix(&suffix)
                .ok_or_else(|| {
                    StateError::Integrity(
                        "legacy native preview lacks an exact root mapping".into(),
                    )
                })?;
            validate_relative(base)?;
            let mapped = self.destination.join(base);
            if roots
                .insert(entry.logical_root.clone(), mapped.clone())
                .is_some_and(|previous| previous != mapped)
            {
                return Err(StateError::Integrity(
                    "legacy native root mapping is inconsistent".into(),
                ));
            }
        }
        Ok(roots)
    }

    /// Consent/ticket validation without provider credentials, remote reads or
    /// content hashing. Every leaf/ancestor must still be the previewed native
    /// entry. A pathname or client-supplied fingerprint is never sufficient.
    pub fn validate_native_destination(&self) -> Result<()> {
        let root = NativeRoot::open(&self.destination, self.destination_identity)?;
        root.bind_parents(self.parents.clone())?;
        for entry in self
            .entries
            .iter()
            .chain(&self.tombstones)
            .chain(&self.root_entries)
        {
            let current = root.observe_if_present(&entry.destination_relative)?;
            if !destination_observation_matches(entry, entry.expected.as_ref(), current.as_ref()) {
                return Err(StateError::Conflict(
                    "native restore destination changed; obtain a fresh conflict preview".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.version != NATIVE_CONTROL_VERSION
            || self.job_id.is_nil()
            || self.entries.len().saturating_add(self.tombstones.len()) > MAX_ENTRIES
        {
            return Err(StateError::Invalid("invalid native restore preview".into()));
        }
        crate::validate_absolute_journal_path(&self.destination, "native destination")?;
        let mappings = self.frozen_root_mappings()?;
        validate_native_root_mappings(&self.destination, &mappings)?;
        let tokens = self
            .entries
            .iter()
            .chain(&self.tombstones)
            .chain(&self.root_entries)
            .map(|entry| entry.logical_root.as_str())
            .collect::<BTreeSet<_>>();
        if mappings.keys().map(String::as_str).collect::<BTreeSet<_>>() != tokens {
            return Err(StateError::Integrity(
                "native preview mapping/selection coverage changed".into(),
            ));
        }
        if let Some(layout) = &self.root_layout {
            if layout.app_id != self.app_id.as_str()
                || native_root_layout_mappings(layout, &self.destination)? != mappings
            {
                return Err(StateError::Integrity(
                    "native preview root-layout frame changed".into(),
                ));
            }
        }
        let mut paths = BTreeSet::new();
        for entry in self.entries.iter().chain(&self.tombstones) {
            if let Some(expected) = &entry.expected {
                expected.validate_platform()?;
            }
            #[cfg(windows)]
            if entry.mode.is_some() || entry.uid.is_some() || entry.gid.is_some() {
                return Err(StateError::Invalid(
                    "Windows native plan requests unsupported POSIX metadata".into(),
                ));
            }
            validate_relative(&entry.relative_path)?;
            validate_relative(&entry.destination_relative)?;
            let expected = noland_state_core::join_native_relative(
                mappings.get(&entry.logical_root).ok_or_else(|| {
                    StateError::Integrity("native preview root mapping missing".into())
                })?,
                &entry.relative_path,
            )?;
            if relative_to(&self.destination, &expected)? != entry.destination_relative {
                return Err(StateError::Integrity(
                    "native preview destination widened its frozen layout".into(),
                ));
            }
            if !paths.insert(&entry.destination_relative) {
                return Err(StateError::Integrity(
                    "duplicate native preview path".into(),
                ));
            }
        }
        if self.root_entries.len() > 64 {
            return Err(StateError::Integrity(
                "native root metadata bound exceeded".into(),
            ));
        }
        let expected_roots = self.root_layout.as_ref().map_or(0, |layout| {
            layout
                .roots
                .iter()
                .filter(|root| {
                    root.source_kind
                        == noland_state_core::native_layout::NativeLayoutSourceKind::Directory
                })
                .count()
        });
        if self.root_entries.len() != expected_roots {
            return Err(StateError::Integrity(
                "native root-directory inventory is incomplete".into(),
            ));
        }
        for entry in &self.root_entries {
            validate_relative(&entry.destination_relative)?;
            if entry.is_scaffold_root()
                && !self
                    .entries
                    .iter()
                    .chain(&self.tombstones)
                    .any(|leaf| leaf.logical_root == entry.logical_root)
            {
                return Err(StateError::Integrity(
                    "a scaffold-only root cannot authorize an empty directory/application capture"
                        .into(),
                ));
            }
            if let Some(expected) = &entry.expected {
                expected.validate_platform()?;
            }
            #[cfg(windows)]
            if entry.mode.is_some() || entry.uid.is_some() || entry.gid.is_some() {
                return Err(StateError::Invalid(
                    "Windows root plan requests unsupported POSIX metadata".into(),
                ));
            }
            let declared = self
                .root_layout
                .as_ref()
                .and_then(|layout| {
                    layout
                        .roots
                        .iter()
                        .find(|root| root.logical_root == entry.logical_root)
                })
                .ok_or_else(|| {
                    StateError::Integrity("native root metadata lacks its layout frame".into())
                })?;
            if declared.source_kind
                != noland_state_core::native_layout::NativeLayoutSourceKind::Directory
                || !entry.relative_path.is_empty()
                || entry.kind != NativeEntryKind::Directory
                || mappings.get(&entry.logical_root)
                    != Some(&self.destination.join(&entry.destination_relative))
                || !paths.insert(&entry.destination_relative)
            {
                return Err(StateError::Integrity(
                    "native root-directory metadata widened its mapping".into(),
                ));
            }
        }
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.kind == NativeEntryKind::Symlink)
        {
            noland_state_core::validate_relative_symlink_target_within_root(
                &entry.relative_path,
                entry.symlink_target.as_deref().ok_or_else(|| {
                    StateError::Integrity("native approved link target is missing".into())
                })?,
            )?;
            #[cfg(windows)]
            {
                if entry.target_is_directory.is_none() {
                    return Err(StateError::Integrity(
                        "Windows native plan lacks an authenticated symlink type".into(),
                    ));
                }
                for part in entry.symlink_target.as_deref().unwrap().split('/') {
                    if part != "." && part != ".." {
                        crate::windows::validate_component(part)?;
                    }
                }
            }
        }
        #[cfg(windows)]
        crate::windows::validate_namespace(
            self.entries
                .iter()
                .chain(&self.tombstones)
                .chain(&self.root_entries)
                .map(|entry| (entry.destination_relative.as_str(), entry.kind))
                .chain(
                    self.parents
                        .keys()
                        .map(|path| (path.as_str(), NativeEntryKind::Directory)),
                ),
        )?;
        // Also bounds all path strings and metadata, not just the entry count.
        self.digest()?;
        Ok(())
    }
}

fn captured_root_metadata(
    manifest: &BundleManifest,
    root: &noland_state_core::native_layout::NativeRootLayout,
) -> Result<(Option<u32>, Option<i64>, Option<u32>, Option<u32>)> {
    #[cfg(windows)]
    {
        let Some(captures) =
            manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"].as_array()
        else {
            return Ok((None, None, None, None));
        };
        if captures.len() > 128
            || manifest.environment["quicksave_native"]["full_scope"]["version"].as_u64() != Some(1)
        {
            return Err(StateError::Integrity(
                "native captured root metadata bound/version invalid".into(),
            ));
        }
        let mut matches = captures.iter().filter(|capture| {
            capture["id"].as_str() == Some(root.root_id.as_str())
                && capture["logicalRoot"].as_str() == Some(root.logical_root.as_str())
        });
        let Some(capture) = matches.next() else {
            return Ok((None, None, None, None));
        };
        if matches.next().is_some() {
            return Err(StateError::Integrity(
                "duplicate authenticated Windows root metadata".into(),
            ));
        }
        if ["mode", "uid", "gid", "owner", "group"]
            .iter()
            .any(|key| capture.get(*key).is_some_and(|value| !value.is_null()))
        {
            return Err(StateError::Invalid(
                "Unix source-root permissions are not supported by Windows native restore".into(),
            ));
        }
        return Ok((None, None, None, None));
    }
    #[cfg(unix)]
    {
        let Some(captures) =
            manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"].as_array()
        else {
            return Ok((None, None, None, None));
        };
        if captures.len() > 128
            || manifest.environment["quicksave_native"]["full_scope"]["version"].as_u64() != Some(1)
        {
            return Err(StateError::Integrity(
                "native captured root metadata bound exceeded".into(),
            ));
        }
        let mut matches = captures.iter().filter(|capture| {
            capture["id"].as_str() == Some(root.root_id.as_str())
                && capture["logicalRoot"].as_str() == Some(root.logical_root.as_str())
        });
        let Some(capture) = matches.next() else {
            return Ok((None, None, None, None));
        };
        if matches.next().is_some() {
            return Err(StateError::Integrity(
                "duplicate authenticated root metadata".into(),
            ));
        }
        let integer = |key: &str| {
            capture[key]
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(|| {
                    StateError::Integrity("invalid captured root metadata integer".into())
                })
        };
        let seconds = capture["stamp"]["modified_seconds"]
            .as_i64()
            .ok_or_else(|| StateError::Integrity("captured root mtime is missing".into()))?;
        let nanos = capture["stamp"]["modified_nanoseconds"]
            .as_i64()
            .filter(|nanos| (0..1_000_000_000).contains(nanos))
            .ok_or_else(|| StateError::Integrity("invalid captured root mtime precision".into()))?;
        let time = seconds
            .checked_mul(1_000_000_000)
            .and_then(|time| time.checked_add(nanos))
            .ok_or_else(|| StateError::Integrity("captured root mtime overflow".into()))?;
        Ok((
            Some(integer("mode")?),
            Some(time),
            Some(integer("owner")?),
            Some(integer("group")?),
        ))
    }
}

/// The native host retains its vault key. Every MAC includes domain separation,
/// job, destination identity, frozen expected payload and actual ownership IDs.
/// Implementations must not derive this key from the cloud repository key.
pub trait NativeRecoveryAuthority: Send + Sync {
    fn mac(&self, bytes: &[u8]) -> Result<[u8; 32]>;
}

pub type NativeExpectedGate = Arc<dyn Fn() -> Result<()> + Send + Sync>;
pub type NativeAttemptRecorder = Arc<dyn Fn(Uuid) -> Result<()> + Send + Sync>;
pub type NativeCredentialCheckpoint = Arc<dyn Fn() -> Result<()> + Send + Sync>;
pub type NativeCommitRecorder = Arc<dyn Fn(Uuid) -> Result<()> + Send + Sync>;

/// Not deserializable: possession of an RPC plan/string is not consent.
pub struct NativeRestoreControl {
    preview: Arc<NativeRestorePreview>,
    authority: Arc<dyn NativeRecoveryAuthority>,
    expected_gate: NativeExpectedGate,
    by_destination: BTreeMap<String, usize>,
    tombstone_destinations: BTreeSet<String>,
    recovered: Mutex<BTreeMap<String, NativeEntryObservation>>,
    completed_outputs: Mutex<BTreeMap<String, NativeEntryObservation>>,
    completed_parents: Mutex<BTreeMap<String, NativeObjectId>>,
    attempt_recorder: Mutex<Option<NativeAttemptRecorder>>,
    credential_checkpoint: Mutex<Option<NativeCredentialCheckpoint>>,
    commit_recorder: Mutex<Option<NativeCommitRecorder>>,
    require_committed: AtomicBool,
    metadata_bytes: usize,
}

impl std::fmt::Debug for NativeRestoreControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRestoreControl")
            .field("job_id", &self.preview.job_id)
            .field("bundle_id", &self.preview.bundle_id)
            .finish_non_exhaustive()
    }
}

impl NativeRestoreControl {
    pub fn approve(
        preview: NativeRestorePreview,
        authority: Arc<dyn NativeRecoveryAuthority>,
        expected_gate: NativeExpectedGate,
    ) -> Result<Self> {
        Self::approve_shared(Arc::new(preview), authority, expected_gate)
    }

    pub fn approve_shared(
        preview: Arc<NativeRestorePreview>,
        authority: Arc<dyn NativeRecoveryAuthority>,
        expected_gate: NativeExpectedGate,
    ) -> Result<Self> {
        preview.validate_shape()?;
        if preview.has_conflicts() {
            return Err(StateError::Conflict(
                "native restore preview has unresolved overwrite/type conflicts".into(),
            ));
        }
        expected_gate()?;
        let metadata_bytes = preview.digest_and_size()?.1;
        Ok(Self {
            by_destination: preview
                .entries
                .iter()
                .enumerate()
                .map(|(index, entry)| (entry.destination_relative.clone(), index))
                .collect(),
            tombstone_destinations: preview
                .tombstones
                .iter()
                .map(|entry| entry.destination_relative.clone())
                .collect(),
            preview,
            authority,
            expected_gate,
            recovered: Mutex::new(BTreeMap::new()),
            completed_outputs: Mutex::new(BTreeMap::new()),
            completed_parents: Mutex::new(BTreeMap::new()),
            attempt_recorder: Mutex::new(None),
            credential_checkpoint: Mutex::new(None),
            commit_recorder: Mutex::new(None),
            require_committed: AtomicBool::new(false),
            metadata_bytes,
        })
    }

    pub fn preview(&self) -> &NativeRestorePreview {
        &self.preview
    }

    pub fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }

    pub fn logical_roots(&self) -> Result<LogicalRootMap> {
        self.preview.logical_roots()
    }

    fn directory_entry(&self, destination: &str) -> Option<&NativeRestoreEntry> {
        self.by_destination
            .get(destination)
            .map(|index| &self.preview.entries[*index])
            .or_else(|| {
                self.preview
                    .root_entries
                    .iter()
                    .find(|entry| entry.destination_relative == destination)
            })
    }

    fn directory_entry_at(&self, index: usize) -> &NativeRestoreEntry {
        if index < self.preview.entries.len() {
            &self.preview.entries[index]
        } else {
            &self.preview.root_entries[index - self.preview.entries.len()]
        }
    }

    pub fn check_gate(&self) -> Result<()> {
        (self.expected_gate)().map_err(|_| {
            StateError::Conflict("native restore approval was revoked or changed".into())
        })
    }

    /// Installed by a native host before admission. The durable attempt hint is
    /// recorded only after its MAC scope/log exist and before target mutation.
    pub fn set_attempt_recorder(&self, recorder: NativeAttemptRecorder) -> Result<()> {
        *self.attempt_recorder.lock().map_err(|_| {
            StateError::Storage("native restore attempt recorder lock poisoned".into())
        })? = Some(recorder);
        Ok(())
    }

    pub fn set_credential_checkpoint(&self, checkpoint: NativeCredentialCheckpoint) -> Result<()> {
        *self.credential_checkpoint.lock().map_err(|_| {
            StateError::Storage("native restore credential checkpoint lock poisoned".into())
        })? = Some(checkpoint);
        Ok(())
    }

    pub fn set_commit_recorder(&self, recorder: NativeCommitRecorder) -> Result<()> {
        *self.commit_recorder.lock().map_err(|_| {
            StateError::Storage("native restore commit recorder lock poisoned".into())
        })? = Some(recorder);
        Ok(())
    }

    /// A host's durable completed decision may only restrict recovery. It never
    /// authorizes deletion or supplies file IDs from unauthenticated DB data.
    pub fn require_committed_recovery(&self) {
        self.require_committed.store(true, Ordering::Release);
    }

    fn checkpoint_credentials(&self) -> Result<()> {
        let checkpoint = self
            .credential_checkpoint
            .lock()
            .map_err(|_| {
                StateError::Storage("native restore credential checkpoint lock poisoned".into())
            })?
            .clone();
        checkpoint.map_or(Ok(()), |checkpoint| checkpoint())
    }

    fn expected(&self, entry: &NativeRestoreEntry) -> Result<Option<NativeEntryObservation>> {
        if let Some(observation) = self
            .completed_outputs
            .lock()
            .map_err(|_| {
                StateError::Storage("native committed output receipt lock poisoned".into())
            })?
            .get(&entry.destination_relative)
            .cloned()
        {
            return Ok(Some(observation));
        }
        Ok(self
            .recovered
            .lock()
            .map_err(|_| {
                StateError::Storage("native restore recovery receipt lock poisoned".into())
            })?
            .get(&entry.destination_relative)
            .cloned()
            .or_else(|| entry.expected.clone()))
    }

    fn binding_parents(&self) -> Result<BTreeMap<String, NativeObjectId>> {
        let mut parents = self.preview.parents.clone();
        parents.extend(
            self.completed_parents
                .lock()
                .map_err(|_| {
                    StateError::Storage("native committed parent receipt lock poisoned".into())
                })?
                .iter()
                .map(|(path, id)| (path.clone(), *id)),
        );
        Ok(parents)
    }

    fn completed(&self, destination: &str) -> Result<bool> {
        Ok(self
            .completed_outputs
            .lock()
            .map_err(|_| {
                StateError::Storage("native committed output receipt lock poisoned".into())
            })?
            .contains_key(destination))
    }

    pub fn validate_payload(&self, manifest: &BundleManifest, mode: RestoreMode) -> Result<()> {
        // This must precede journal/scaffold writes even on resumed execution.
        // Target compatibility is independent of the signed source platform.
        validate_native_restore_names(manifest)?;
        if manifest.app.app_id != self.preview.app_id
            || manifest.bundle_id != self.preview.bundle_id
            || mode != self.preview.mode
            || payload_digest(manifest, mode)? != self.preview.expected_payload
            || native_root_layouts(manifest)? != self.preview.root_layout
            || manifest.environment["quicksave_native_download"]["whole_bundle"]
                .as_bool()
                .unwrap_or(true)
                != self.preview.entire_manifest
        {
            return Err(StateError::Conflict(
                "native restore expected authenticated payload/selection changed".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_fresh(
        &self,
        manifest: &BundleManifest,
        mode: RestoreMode,
        roots: &LogicalRootMap,
    ) -> Result<()> {
        self.check_gate()?;
        self.validate_payload(manifest, mode)?;
        let root = NativeRoot::open(&self.preview.destination, self.preview.destination_identity)?;
        root.bind_parents(self.binding_parents()?)?;
        // Preview already verified reused-file bytes. Exact native IDs, ctime,
        // size, ownership and mtime are rechecked here; do not hash every reused
        // file a second time merely to reconstruct an identical preview.
        for entry in self
            .preview
            .entries
            .iter()
            .chain(&self.preview.tombstones)
            .chain(&self.preview.root_entries)
        {
            let logical = noland_state_core::LogicalRoot::parse(&entry.logical_root)
                .ok_or_else(|| StateError::UnsafePath("native preview root unknown".into()))?;
            let base = roots.resolve(&logical).ok_or_else(|| {
                StateError::UnsafePath("approved native logical root missing".into())
            })?;
            let destination = if entry.relative_path.is_empty() {
                base
            } else {
                noland_state_core::join_native_relative(&base, &entry.relative_path)?
            };
            let current = root.observe_if_present(&entry.destination_relative)?;
            let expected = self.expected(entry)?;
            if relative_to(&self.preview.destination, &destination)? != entry.destination_relative
                || !destination_observation_matches(entry, expected.as_ref(), current.as_ref())
            {
                return Err(StateError::Conflict(
                    "native destination changed after conflict preview; preview and approve again"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct NativeRestoreRecoveryReport {
    pub committed: bool,
    pub rolled_back: bool,
    pub removed_owned_entries: usize,
    pub restored_original_entries: usize,
    pub retained_artifacts: Vec<String>,
    pub completion: Option<NativeRestoreCompletionReceipt>,
    pub owned_artifacts_clean: bool,
    pub metadata_only_workspace: bool,
    pub reconstruction: Option<NativeReconstructionReport>,
}

/// A read-only result, never incoming authorization. Issued only after MAC
/// replay, artifact cleanup and native-handle auditing of the retained journal.
#[derive(Debug, Default, Clone, Serialize)]
pub struct NativeRestoreCompletionReceipt {
    pub version: u32,
    pub restore_id: Uuid,
    pub committed: bool,
    pub authenticated_journal: bool,
    pub owned_artifacts_clean: bool,
    pub metadata_only_workspace: bool,
    pub retained_metadata_files: u64,
    pub scaffold_directories: u64,
}

impl NativeRestoreCompletionReceipt {
    pub fn is_clean_committed(&self) -> bool {
        self.version == 1
            && self.committed
            && self.authenticated_journal
            && self.owned_artifacts_clean
            && self.metadata_only_workspace
            && self.retained_metadata_files == 2
    }
}

/// Independently verifies completion without cleaning, repairing a torn log,
/// invoking a provider, or trusting a directory's mere existence/emptiness.
pub fn verify_native_restore_completion(
    workspace: &Path,
    control: Arc<NativeRestoreControl>,
) -> Result<NativeRestoreCompletionReceipt> {
    let transaction = NativeTransaction::load_readonly(workspace, control)?;
    if !transaction.committed {
        return Err(StateError::Integrity(
            "native restore journal is not committed".into(),
        ));
    }
    transaction.completion_receipt()
}

impl NativeRestoreRecoveryReport {
    fn retain(&mut self, error: impl std::fmt::Display) {
        if self.retained_artifacts.len() < 128 {
            self.retained_artifacts
                .push(error.to_string().chars().take(1024).collect());
        } else if self.retained_artifacts.len() == 128 {
            self.retained_artifacts
                .push("additional retained-artifact diagnostics omitted".into());
        }
    }
}

/// Explicit, authority-bound recovery. Never scan/replay unsigned native paths.
pub fn recover_native_restore(
    workspace: &Path,
    control: Arc<NativeRestoreControl>,
) -> Result<NativeRestoreRecoveryReport> {
    control.check_gate()?;
    let mut transaction = NativeTransaction::load(workspace, control)?;
    transaction.recover_verified()
}

pub(super) struct NativeTransaction {
    control: Arc<NativeRestoreControl>,
    root: Arc<NativeRoot>,
    workspace_root: NativeRoot,
    journal: NativeJournal,
    owned: BTreeMap<String, (NativeEntryObservation, OwnershipRole)>,
    publications: BTreeMap<String, Publication>,
    captures: BTreeMap<String, RollbackCapture>,
    directory_metadata: BTreeMap<String, DirectoryMetadataRollback>,
    captured_bytes: u64,
    copied_original_bytes: u64,
    cow_original_bytes: u64,
    committed: bool,
    rolled_back: bool,
    dirty_parents: BTreeSet<String>,
}

impl NativeTransaction {
    fn optional_scaffold(&self, entry: &NativeRestoreEntry) -> bool {
        entry.is_scaffold_root()
            && entry.expected.is_none()
            && !self
                .control
                .preview
                .entries
                .iter()
                .any(|leaf| leaf.logical_root == entry.logical_root)
    }

    pub fn begin(
        workspace: &Path,
        restore_id: Uuid,
        control: Arc<NativeRestoreControl>,
        manifest: &BundleManifest,
        mode: RestoreMode,
        roots: &LogicalRootMap,
    ) -> Result<Self> {
        control.validate_fresh(manifest, mode, roots)?;
        let journal = NativeJournal::create(workspace, restore_id, Arc::clone(&control))?;
        let recorder = control
            .attempt_recorder
            .lock()
            .map_err(|_| {
                StateError::Storage("native restore attempt recorder lock poisoned".into())
            })?
            .clone();
        if let Some(recorder) = recorder {
            recorder(restore_id)?;
        }
        Self::from_journal(journal, control)
    }

    fn from_journal(journal: NativeJournal, control: Arc<NativeRestoreControl>) -> Result<Self> {
        let root = Arc::new(NativeRoot::open(
            &control.preview.destination,
            control.preview.destination_identity,
        )?);
        root.bind_parents(control.binding_parents()?)?;
        let workspace_root = NativeRoot::open(journal.workspace(), journal.workspace_identity())?;
        let transaction = Self {
            control,
            root,
            workspace_root,
            owned: BTreeMap::new(),
            publications: BTreeMap::new(),
            captures: BTreeMap::new(),
            directory_metadata: BTreeMap::new(),
            captured_bytes: 0,
            copied_original_bytes: 0,
            cow_original_bytes: 0,
            committed: false,
            rolled_back: false,
            dirty_parents: BTreeSet::new(),
            journal,
        };
        Ok(transaction)
    }

    fn load(workspace: &Path, control: Arc<NativeRestoreControl>) -> Result<Self> {
        Self::load_impl(workspace, control, false)
    }

    fn load_readonly(workspace: &Path, control: Arc<NativeRestoreControl>) -> Result<Self> {
        Self::load_impl(workspace, control, true)
    }

    fn load_impl(
        workspace: &Path,
        control: Arc<NativeRestoreControl>,
        readonly: bool,
    ) -> Result<Self> {
        let scope = NativeJournal::open_scope(workspace, Arc::clone(&control))?;
        let mut transaction = Self::from_journal(scope, Arc::clone(&control))?;
        let replayed = if readonly {
            NativeJournal::replay_readonly(workspace, control, |event| {
                transaction.apply_event(&event)
            })?
        } else {
            NativeJournal::replay(workspace, control, |event| transaction.apply_event(&event))?
        };
        transaction.journal = replayed;
        if !transaction.committed
            && !transaction.rolled_back
            && transaction
                .control
                .require_committed
                .load(Ordering::Acquire)
            && !transaction.publications.is_empty()
        {
            return Err(StateError::Conflict(
                "native restore has a completed filesystem decision but no matching committed journal; retaining data without rollback".into(),
            ));
        }
        if transaction.committed {
            transaction.adopt_committed_receipts()?;
        }
        Ok(transaction)
    }

    fn adopt_committed_receipts(&self) -> Result<()> {
        // A credential/lease finalization failure after the durable filesystem
        // decision must retry finalization, not download or overwrite outputs
        // again. Only this same job's authenticated IDs/stamps qualify.
        let mut parents = self.control.completed_parents.lock().map_err(|_| {
            StateError::Storage("native committed parent receipt lock poisoned".into())
        })?;
        for (path, (observation, role)) in &self.owned {
            if *role == OwnershipRole::Directory {
                let current = self.root.observe(path)?;
                if current.id != observation.id || current.kind != NativeEntryKind::Directory {
                    return Err(StateError::Conflict(
                        "committed native parent was replaced; retained without replay".into(),
                    ));
                }
                parents.insert(path.clone(), observation.id);
            }
        }
        drop(parents);
        let mut outputs = self.control.completed_outputs.lock().map_err(|_| {
            StateError::Storage("native committed output receipt lock poisoned".into())
        })?;
        for (path, publication) in &self.publications {
            if let Some(output) = &publication.output {
                if !publication.durable || self.root.observe(path)? != *output {
                    return Err(StateError::Conflict("committed native output was modified/replaced; refusing retry scope changes".into()));
                }
                outputs.insert(path.clone(), output.clone());
            }
        }
        for entry in self
            .control
            .preview
            .entries
            .iter()
            .chain(&self.control.preview.root_entries)
        {
            if entry.kind != NativeEntryKind::Directory {
                continue;
            }
            let expected_id = outputs
                .get(&entry.destination_relative)
                .map(|expected| expected.id)
                .or_else(|| entry.expected.as_ref().map(|expected| expected.id))
                .or_else(|| {
                    self.owned
                        .get(&entry.destination_relative)
                        .map(|(owned, _)| owned.id)
                });
            let Some(current) = self.root.observe_if_present(&entry.destination_relative)? else {
                if self.optional_scaffold(entry) {
                    continue;
                }
                return Err(StateError::Conflict(
                    "committed native directory is missing; obtain fresh approval".into(),
                ));
            };
            if expected_id != Some(current.id)
                || !current.metadata_matches(entry.mode, entry.mtime_ns, entry.uid, entry.gid)
            {
                return Err(StateError::Conflict(
                    "committed native directory metadata was modified; obtain fresh approval"
                        .into(),
                ));
            }
            outputs.insert(entry.destination_relative.clone(), current);
        }
        Ok(())
    }

    fn record(&mut self, event: Event) -> Result<()> {
        self.journal.append(&event)?;
        self.apply_event(&event)
    }

    fn apply_event(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Owned { observation, .. }
            | Event::Published { observation, .. }
            | Event::BackupStored { observation, .. }
            | Event::Restored { observation, .. }
            | Event::DirectoryMetadataRestored { observation, .. } => {
                self.root.validate_observation_scope(observation)?
            }
            Event::Publish(publication) => {
                for observation in publication.output.iter().chain(&publication.original) {
                    self.root.validate_observation_scope(observation)?;
                }
            }
            Event::CapturedOriginal { capture, .. } => {
                self.root.validate_observation_scope(&capture.observation)?
            }
            Event::DirectoryMetadata(rollback) => {
                self.root.validate_observation_scope(&rollback.original)?
            }
            _ => {}
        }
        if self.committed || self.rolled_back {
            return Err(StateError::Integrity(
                "native journal has mutation records after its terminal decision".into(),
            ));
        }
        match event {
            Event::Owned {
                path,
                observation,
                role,
            } => {
                validate_relative(path)?;
                self.owned
                    .insert(path.clone(), (observation.clone(), *role));
                if matches!(
                    role,
                    OwnershipRole::Directory | OwnershipRole::RollbackDirectory
                ) {
                    self.root.bind_created_directory(path, observation.id)?;
                }
            }
            Event::Publish(publication) => {
                if !self
                    .control
                    .by_destination
                    .contains_key(&publication.destination)
                    && !self
                        .control
                        .tombstone_destinations
                        .contains(&publication.destination)
                {
                    return Err(StateError::Integrity(
                        "native journal publication is outside approved scope".into(),
                    ));
                }
                self.publications
                    .insert(publication.destination.clone(), publication.clone());
            }
            Event::CapturedOriginal {
                destination,
                capture,
            } => {
                let approved = self
                    .control
                    .by_destination
                    .get(destination)
                    .map(|index| &self.control.preview.entries[*index])
                    .or_else(|| {
                        self.control
                            .preview
                            .tombstones
                            .iter()
                            .find(|entry| entry.destination_relative == *destination)
                    })
                    .ok_or_else(|| {
                        StateError::Integrity(
                            "native rollback capture widened the approved scope".into(),
                        )
                    })?;
                if !approved
                    .expected
                    .as_ref()
                    .is_some_and(|prior| prior.kind == NativeEntryKind::File)
                    || capture.observation.kind != NativeEntryKind::File
                    || !capture.artifact.starts_with("native-original-")
                    || capture.artifact.contains('/')
                {
                    return Err(StateError::Integrity(
                        "invalid native rollback capture identity".into(),
                    ));
                }
                self.captured_bytes = self
                    .captured_bytes
                    .checked_add(capture.observation.size)
                    .ok_or_else(|| {
                        StateError::Integrity("native rollback capture byte overflow".into())
                    })?;
                if capture.copied_bytes.checked_add(capture.cow_bytes)
                    != Some(capture.observation.size)
                {
                    return Err(StateError::Integrity(
                        "native rollback copy accounting is inconsistent".into(),
                    ));
                }
                self.copied_original_bytes = self
                    .copied_original_bytes
                    .checked_add(capture.copied_bytes)
                    .ok_or_else(|| {
                        StateError::Integrity("native rollback copy byte overflow".into())
                    })?;
                self.cow_original_bytes = self
                    .cow_original_bytes
                    .checked_add(capture.cow_bytes)
                    .ok_or_else(|| {
                        StateError::Integrity("native rollback CoW byte overflow".into())
                    })?;
                self.captures.insert(destination.clone(), capture.clone());
            }
            Event::DirectoryMetadata(rollback) => {
                let entry = self
                    .control
                    .directory_entry(&rollback.destination)
                    .ok_or_else(|| {
                        StateError::Integrity(
                            "native directory metadata widened approved scope".into(),
                        )
                    })?;
                if entry.kind != NativeEntryKind::Directory
                    || rollback.original.kind != NativeEntryKind::Directory
                    || rollback.requested_mode != entry.mode
                    || rollback.requested_mtime_ns != entry.mtime_ns
                    || rollback.requested_uid != entry.uid
                    || rollback.requested_gid != entry.gid
                {
                    return Err(StateError::Integrity(
                        "native directory metadata grant changed".into(),
                    ));
                }
                self.directory_metadata
                    .insert(rollback.destination.clone(), rollback.clone());
            }
            Event::DirectoryMetadataRestored {
                destination,
                observation,
            } => {
                let rollback = self.directory_metadata.get(destination).ok_or_else(|| {
                    StateError::Integrity(
                        "native restored-directory receipt lacks its metadata grant".into(),
                    )
                })?;
                if observation.id != rollback.original.id
                    || observation.kind != NativeEntryKind::Directory
                    || !observation.same_security(&rollback.original)
                    || observation.mtime_ns != rollback.original.mtime_ns
                {
                    return Err(StateError::Integrity(
                        "native directory recovery changed approved identity/metadata".into(),
                    ));
                }
                if rollback.existed {
                    self.control
                        .recovered
                        .lock()
                        .map_err(|_| {
                            StateError::Storage("native recovered directory lock poisoned".into())
                        })?
                        .insert(destination.clone(), observation.clone());
                }
            }
            Event::Published {
                destination,
                observation,
            } => {
                let publication = self.publications.get_mut(destination).ok_or_else(|| {
                    StateError::Integrity(
                        "native durable receipt lacks its publication intent".into(),
                    )
                })?;
                if !publication
                    .output
                    .as_ref()
                    .is_some_and(|output| output.after_move_matches(observation))
                {
                    return Err(StateError::Integrity(
                        "native durable receipt changed created-file ownership".into(),
                    ));
                }
                publication.output = Some(observation.clone());
                publication.durable = true;
            }
            Event::BackupStored {
                destination,
                observation,
            } => {
                let publication = self.publications.get_mut(destination).ok_or_else(|| {
                    StateError::Integrity(
                        "native backup receipt lacks its approved publication intent".into(),
                    )
                })?;
                if !publication
                    .original
                    .as_ref()
                    .is_some_and(|original| original.after_move_matches(observation))
                {
                    return Err(StateError::Integrity(
                        "native backup receipt changed the approved original ID".into(),
                    ));
                }
                publication.original = Some(observation.clone());
                publication.backup_durable = true;
            }
            Event::Restored {
                destination,
                observation,
            } => {
                let original = self
                    .publications
                    .get(destination)
                    .and_then(|publication| publication.original.as_ref())
                    .ok_or_else(|| {
                        StateError::Integrity(
                            "native recovery receipt lacks an approved original".into(),
                        )
                    })?;
                if !original.after_move_matches(observation) {
                    return Err(StateError::Integrity(
                        "native recovery receipt changed the original ID/payload".into(),
                    ));
                }
                self.control
                    .recovered
                    .lock()
                    .map_err(|_| {
                        StateError::Storage("native recovery receipt lock poisoned".into())
                    })?
                    .insert(destination.clone(), observation.clone());
            }
            Event::Committed => self.committed = true,
            Event::RolledBack => self.rolled_back = true,
        }
        Ok(())
    }

    pub fn approved_action(
        &self,
        logical_root: &str,
        relative_path: &str,
    ) -> Result<NativeRestoreAction> {
        let index = self
            .control
            .preview
            .entries
            .binary_search_by(|entry| {
                entry
                    .logical_root
                    .as_str()
                    .cmp(logical_root)
                    .then_with(|| entry.relative_path.as_str().cmp(relative_path))
            })
            .map_err(|_| {
                StateError::Conflict(
                    "native pipeline attempted to widen the approved selection".into(),
                )
            })?;
        let entry = &self.control.preview.entries[index];
        if self.control.completed(&entry.destination_relative)? {
            Ok(NativeRestoreAction::Reuse)
        } else {
            Ok(entry.action)
        }
    }

    pub fn flush_intents(&mut self) -> Result<()> {
        self.journal.flush()
    }

    pub fn checkpoint_publication(&self) -> Result<()> {
        self.control.check_gate()?;
        self.control.checkpoint_credentials()
    }

    pub fn journal_metrics(&self) -> (u64, u64) {
        (self.journal.records, self.journal.flushes)
    }

    pub fn captured_bytes(&self) -> u64 {
        self.captured_bytes
    }

    pub fn original_copy_metrics(&self) -> (u64, u64) {
        (self.copied_original_bytes, self.cow_original_bytes)
    }

    /// No app-wide consistency claim: each original is captured through its
    /// held no-follow file handle and the source stable-file identity checks.
    /// An app retaining a writable fd to a moved original cannot corrupt this
    /// separate durable rollback copy.
    pub fn capture_originals(&mut self) -> Result<()> {
        use std::io::Read;
        let count = self.control.preview.entries.len() + self.control.preview.tombstones.len();
        for index in 0..count {
            let entry = if index < self.control.preview.entries.len() {
                &self.control.preview.entries[index]
            } else {
                &self.control.preview.tombstones[index - self.control.preview.entries.len()]
            };
            if !matches!(
                entry.action,
                NativeRestoreAction::Replace | NativeRestoreAction::Remove
            ) || entry
                .expected
                .as_ref()
                .is_none_or(|prior| prior.kind != NativeEntryKind::File)
                || self.captures.contains_key(&entry.destination_relative)
                || self.control.completed(&entry.destination_relative)?
            {
                continue;
            }
            let destination = entry.destination_relative.clone();
            let expected = self
                .control
                .expected(entry)?
                .ok_or_else(|| StateError::Integrity("native rollback original missing".into()))?;
            self.control.check_gate()?;
            if self.root.observe(&destination)? != expected {
                return Err(StateError::Conflict(
                    "native original changed before stable rollback capture".into(),
                ));
            }
            let mut input = self.root.open_regular(&destination)?;
            let before = noland_snapshot::SourceMetadata::from_file(&input)?;
            if filesystem::handle_id(&input)? != expected.id {
                return Err(StateError::Conflict(
                    "native rollback original handle changed".into(),
                ));
            }
            let artifact = format!(
                "native-original-{}.capture",
                blake3::hash(destination.as_bytes()).to_hex()
            );
            let mut output = self.workspace_root.open_partial(&artifact, true)?;
            // Preserve the source snapshot's independent-extent FICLONE fast
            // path on Linux. This is never a mutable hardlink. Other native
            // backends retain the validated bounded-copy fallback.
            #[cfg(target_os = "linux")]
            let cloned = {
                use std::os::fd::AsRawFd;
                let cloned = unsafe {
                    libc::ioctl(
                        output.as_raw_fd(),
                        0x40049409u64 as libc::c_ulong,
                        input.as_raw_fd(),
                    )
                } == 0;
                if !cloned {
                    output.set_len(0)?;
                }
                cloned
            };
            #[cfg(not(target_os = "linux"))]
            let cloned = false;
            let mut hash = blake3::Hasher::new();
            let mut buffer = [0u8; 256 * 1024];
            let mut total = 0u64;
            loop {
                let count = if cloned {
                    output.read(&mut buffer)?
                } else {
                    input.read(&mut buffer)?
                };
                if count == 0 {
                    break;
                }
                total = total.checked_add(count as u64).ok_or_else(|| {
                    StateError::Integrity("native original copy byte overflow".into())
                })?;
                if total > expected.size {
                    return Err(StateError::Conflict(
                        "native original grew during rollback capture".into(),
                    ));
                }
                if !cloned {
                    output.write_all(&buffer[..count])?;
                }
                hash.update(&buffer[..count]);
            }
            if total != expected.size
                || !noland_snapshot::same_file_identity(
                    &before,
                    &noland_snapshot::SourceMetadata::from_file(&input)?,
                )
                || self.root.observe(&destination)? != expected
            {
                return Err(StateError::Conflict(
                    "native original changed during stable rollback capture".into(),
                ));
            }
            output.sync_all()?;
            let observation = self.workspace_root.observe(&artifact)?;
            if observation.id != filesystem::handle_id(&output)? || observation.size != total {
                return Err(StateError::Conflict(
                    "native rollback capture file was replaced".into(),
                ));
            }
            self.workspace_root.sync_directory("")?;
            self.record(Event::CapturedOriginal {
                destination,
                capture: RollbackCapture {
                    artifact,
                    observation,
                    file_hash: format!("blake3:{}", hash.finalize().to_hex()),
                    copied_bytes: if cloned { 0 } else { total },
                    cow_bytes: if cloned { total } else { 0 },
                },
            })?;
        }
        // Reconstruct authenticated empty directory roots too, without
        // fabricating file entries, packs or an empty application bundle.
        let layout_roots = self
            .control
            .preview
            .root_entries
            .iter()
            .filter(|entry| !entry.is_scaffold_root())
            .map(|entry| {
                self.control
                    .preview
                    .destination
                    .join(&entry.destination_relative)
            })
            .collect::<Vec<_>>();
        for path in layout_roots {
            self.create_directories(&path)?;
        }
        // All rollback bytes/IDs precede any target publication, with batched
        // MAC metadata durability rather than per-chunk or per-file MAC flushes.
        self.flush_intents()
    }

    pub fn record_publication_receipt(&mut self, destination: &Path) -> Result<()> {
        let relative = relative_to(&self.control.preview.destination, destination)?;
        if let Some(backup) = self
            .publications
            .get(&relative)
            .and_then(|publication| publication.backup.clone())
        {
            let observation = self.root.observe(&backup)?;
            self.record(Event::BackupStored {
                destination: relative.clone(),
                observation,
            })?;
        }
        let observation = self.root.observe(&relative)?;
        self.record(Event::Published {
            destination: relative,
            observation,
        })
    }

    pub fn filesystem(&self) -> Arc<NativeRoot> {
        Arc::clone(&self.root)
    }

    pub fn open_partial(&self, path: &Path) -> Result<File> {
        let relative = relative_to(&self.control.preview.destination, path)?;
        self.root.open_partial(&relative, true)
    }

    pub fn flush_namespace(&mut self) -> Result<u64> {
        let count = self.dirty_parents.len() as u64;
        for parent in &self.dirty_parents {
            self.root.sync_directory(parent)?;
        }
        self.dirty_parents.clear();
        self.root.check()?;
        Ok(count)
    }

    fn dirty_parent(&mut self, path: &str) -> Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new(""));
        let text = if parent.as_os_str().is_empty() {
            String::new()
        } else {
            path_text(parent)?
        };
        self.dirty_parents.insert(text);
        Ok(())
    }

    fn validate_parents(&self, relative: &str) -> Result<()> {
        self.root.validate_path(relative)
    }

    pub fn create_directories(&mut self, destination: &Path) -> Result<()> {
        let relative = relative_to(&self.control.preview.destination, destination)?;
        let mut current = PathBuf::new();
        for part in Path::new(&relative).components() {
            current.push(part);
            let path = path_text(&current)?;
            self.validate_parents(&path)?;
            match self.root.observe_if_present(&path)? {
                Some(observed) if observed.kind == NativeEntryKind::Directory => {
                    if !self.control.preview.parents.contains_key(&path)
                        && !self.owned.contains_key(&path)
                        && !self.control.by_destination.get(&path).is_some_and(|index| {
                            self.control.preview.entries[*index]
                                .expected
                                .as_ref()
                                .is_some_and(|prior| {
                                    prior.kind == NativeEntryKind::Directory
                                        && prior.id == observed.id
                                })
                        })
                    {
                        return Err(StateError::Conflict(
                            "unapproved directory appeared during native restore".into(),
                        ));
                    }
                }
                Some(_) => {
                    return Err(StateError::Conflict(
                        "native restore ancestor is not a directory".into(),
                    ));
                }
                None => {
                    self.control.check_gate()?;
                    let observation = self.root.create_directory(&path)?;
                    // A crash between mkdir and this record leaves an unknown
                    // empty directory, never path-authorized deletion authority.
                    self.record(Event::Owned {
                        path,
                        observation,
                        role: OwnershipRole::Directory,
                    })?;
                }
            }
        }
        Ok(())
    }

    pub fn own_partial(&mut self, partial: &Path, file: &File) -> Result<()> {
        let relative = relative_to(&self.control.preview.destination, partial)?;
        self.validate_parents(&relative)?;
        let observation = self.root.observe(&relative)?;
        if observation.kind != NativeEntryKind::File
            || observation.links != 1
            || observation.id != filesystem::handle_id(file)?
        {
            return Err(StateError::Conflict(
                "native partial was replaced before ownership was recorded".into(),
            ));
        }
        let id = observation.id;
        self.record(Event::Owned {
            path: relative.clone(),
            observation,
            role: OwnershipRole::Partial,
        })?;
        self.root.register_partial(&relative, id)
    }

    pub fn prepare_publication(&mut self, partial: &Path, destination: &Path) -> Result<()> {
        self.control.check_gate()?;
        let destination = relative_to(&self.control.preview.destination, destination)?;
        let partial = relative_to(&self.control.preview.destination, partial)?;
        self.validate_parents(&destination)?;
        let entry = self
            .control
            .by_destination
            .get(&destination)
            .map(|index| &self.control.preview.entries[*index])
            .ok_or_else(|| StateError::UnsafePath("unapproved native publication".into()))?;
        let action = entry.action;
        let expected = self.control.expected(entry)?;
        let output = self.root.observe(&partial)?;
        if !self
            .owned
            .get(&partial)
            .is_some_and(|(owned, _)| owned.id == output.id)
        {
            return Err(StateError::Integrity(
                "native publication has no authenticated created-file ID".into(),
            ));
        }
        if self.root.observe_if_present(&destination)? != expected {
            return Err(StateError::Conflict(
                "native overwrite destination changed after preview".into(),
            ));
        }
        let backup = if action == NativeRestoreAction::Replace {
            Some(self.rollback_slot(&destination)?)
        } else {
            None
        };
        self.record(Event::Publish(Publication {
            destination: destination.clone(),
            partial: Some(partial.clone()),
            output: Some(output.clone()),
            original: expected,
            backup,
            durable: false,
            backup_durable: false,
        }))
    }

    pub fn execute_publication(&mut self, destination: &Path) -> Result<()> {
        self.control.check_gate()?;
        let destination = relative_to(&self.control.preview.destination, destination)?;
        self.validate_parents(&destination)?;
        let publication = self
            .publications
            .get(&destination)
            .ok_or_else(|| {
                StateError::Integrity("native publication lacks a durable ownership intent".into())
            })?
            .clone();
        let partial = publication.partial.as_ref().ok_or_else(|| {
            StateError::Integrity("native file publication lacks its owned partial".into())
        })?;
        let output = publication.output.as_ref().ok_or_else(|| {
            StateError::Integrity("native file publication lacks its created-file ID".into())
        })?;
        // All possible crash outcomes have authorized IDs before either rename.
        if let (Some(backup), Some(original)) = (&publication.backup, &publication.original) {
            self.root.move_new(&destination, backup, original)?;
            self.dirty_parent(backup)?;
        }
        // This is kernel create-new/no-replace even for approved overwrites.
        // A leaf appearing after backup is retained, never clobbered.
        self.root.move_new(partial, &destination, output)?;
        self.dirty_parent(partial)?;
        self.dirty_parent(&destination)?;
        Ok(())
    }

    pub fn publish_symlink(&mut self, file: &ManifestFile, destination: &Path) -> Result<()> {
        self.checkpoint_publication()?;
        let target = file
            .symlink_target
            .as_deref()
            .ok_or_else(|| StateError::Integrity("native symlink target missing".into()))?;
        noland_state_core::validate_relative_symlink_target_within_root(
            &file.relative_path,
            target,
        )?;
        let parent = destination
            .parent()
            .ok_or_else(|| StateError::UnsafePath("native link has no parent".into()))?;
        self.create_directories(parent)?;
        let partial = crate::destination_partial_path(destination, self.journal.restore_id)?;
        let relative = relative_to(&self.control.preview.destination, &partial)?;
        self.validate_parents(&relative)?;
        self.control.check_gate()?;
        let destination_relative = relative_to(&self.control.preview.destination, destination)?;
        let hint = self
            .control
            .by_destination
            .get(&destination_relative)
            .map(|index| self.control.preview.entries[*index].target_is_directory)
            .ok_or_else(|| {
                StateError::Conflict("native link is outside its approved plan".into())
            })?;
        let observation = self.root.create_symlink(&relative, target, hint)?;
        self.record(Event::Owned {
            path: relative,
            observation,
            role: OwnershipRole::Partial,
        })?;
        self.prepare_publication(&partial, destination)?;
        self.flush_intents()?;
        self.execute_publication(destination)?;
        self.flush_namespace()?;
        self.record_publication_receipt(destination)?;
        self.flush_intents()
    }

    fn rollback_slot(&mut self, destination: &str) -> Result<String> {
        let device = self.root.observe(destination)?.id.device;
        // Keep same-volume rollback artifacts outside reconstructed app trees
        // whenever possible. Their cleanup must not perturb app-directory mtime.
        let parent = if device == self.control.preview.destination_identity.device {
            Path::new("")
        } else {
            self.control
                .preview
                .parents
                .iter()
                .filter(|(path, id)| {
                    id.device == device && Path::new(destination).starts_with(path)
                })
                .min_by_key(|(path, _)| Path::new(path).components().count())
                .map(|(path, _)| Path::new(path))
                .ok_or_else(|| {
                    StateError::UnsafePath(
                        "native rollback has no approved same-volume directory".into(),
                    )
                })?
        };
        let directory = parent.join(format!(".quicksave-restore-{}", self.journal.restore_id));
        let directory = path_text(&directory)?;
        if let Some((owned, role)) = self.owned.get(&directory) {
            if *role != OwnershipRole::RollbackDirectory
                || self.root.observe(&directory)?.id != owned.id
            {
                return Err(StateError::Conflict(
                    "native rollback directory identity changed".into(),
                ));
            }
        } else {
            let observation = self.root.create_directory(&directory)?;
            self.record(Event::Owned {
                path: directory.clone(),
                observation,
                role: OwnershipRole::RollbackDirectory,
            })?;
        }
        let name = blake3::hash(destination.as_bytes()).to_hex().to_string();
        Ok(format!("{directory}/{name}.original"))
    }

    pub fn apply_tombstones(&mut self) -> Result<()> {
        self.checkpoint_publication()?;
        for index in 0..self.control.preview.tombstones.len() {
            let entry = self.control.preview.tombstones[index].clone();
            if entry.action != NativeRestoreAction::Remove {
                continue;
            }
            self.control.check_gate()?;
            self.validate_parents(&entry.destination_relative)?;
            let expected = self.control.expected(&entry)?;
            if self.root.observe_if_present(&entry.destination_relative)? != expected {
                return Err(StateError::Conflict(
                    "native tombstone destination changed after preview".into(),
                ));
            }
            let backup = self.rollback_slot(&entry.destination_relative)?;
            let publication = Publication {
                destination: entry.destination_relative.clone(),
                partial: None,
                output: None,
                original: expected,
                backup: Some(backup.clone()),
                durable: false,
                backup_durable: false,
            };
            self.record(Event::Publish(publication.clone()))?;
            self.flush_intents()?;
            self.root.move_new(
                &entry.destination_relative,
                &backup,
                publication
                    .original
                    .as_ref()
                    .expect("preview remove exists"),
            )?;
            self.dirty_parent(&entry.destination_relative)?;
            self.dirty_parent(&backup)?;
        }
        self.flush_namespace()?;
        for index in 0..self.control.preview.tombstones.len() {
            let destination = &self.control.preview.tombstones[index].destination_relative;
            let backup = self
                .publications
                .get(destination)
                .and_then(|publication| publication.backup.clone());
            if let Some(backup) = backup {
                self.record(Event::BackupStored {
                    destination: destination.clone(),
                    observation: self.root.observe(&backup)?,
                })?;
            }
        }
        self.flush_intents()
    }

    fn apply_directory_metadata(&mut self) -> Result<()> {
        let mut indices = self
            .control
            .preview
            .entries
            .iter()
            .chain(&self.control.preview.root_entries)
            .enumerate()
            .filter(|(_, entry)| {
                entry.kind == NativeEntryKind::Directory
                    && (entry.mode.is_some()
                        || entry.mtime_ns.is_some()
                        || entry.uid.is_some()
                        || entry.gid.is_some())
            })
            .map(|(index, entry)| {
                (
                    index,
                    Path::new(&entry.destination_relative).components().count(),
                )
            })
            .collect::<Vec<_>>();
        // Child mutations/metadata precede parent directory mtime.
        indices.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
        for (index, _) in &indices {
            let entry = self.control.directory_entry_at(*index);
            if self.control.completed(&entry.destination_relative)? {
                continue;
            }
            let current = self.root.observe(&entry.destination_relative)?;
            let original = self
                .control
                .expected(entry)?
                .or_else(|| {
                    self.owned
                        .get(&entry.destination_relative)
                        .map(|(owned, _)| owned.clone())
                })
                .ok_or_else(|| {
                    StateError::Integrity(
                        "native directory metadata lacks a previewed/created ID".into(),
                    )
                })?;
            if original.id != current.id
                || current.kind != NativeEntryKind::Directory
                || !original.same_security(&current)
            {
                return Err(StateError::Conflict(
                    "native directory identity/permissions changed before metadata publication"
                        .into(),
                ));
            }
            self.record(Event::DirectoryMetadata(DirectoryMetadataRollback {
                destination: entry.destination_relative.clone(),
                original,
                existed: entry.expected.is_some(),
                requested_mode: entry.mode,
                requested_mtime_ns: entry.mtime_ns,
                requested_uid: entry.uid,
                requested_gid: entry.gid,
            }))?;
        }
        self.flush_intents()?;
        for (index, _) in indices {
            self.control.check_gate()?;
            let entry = self.control.directory_entry_at(index);
            if self.control.completed(&entry.destination_relative)? {
                continue;
            }
            self.root.apply_owned_directory_metadata(
                &entry.destination_relative,
                entry.mode,
                entry.mtime_ns,
                entry.uid,
                entry.gid,
            )?;
        }
        Ok(())
    }

    fn restore_directory_metadata(
        &mut self,
        with_times: bool,
        report: &mut NativeRestoreRecoveryReport,
    ) {
        let mut rollbacks = self
            .directory_metadata
            .values()
            .cloned()
            .collect::<Vec<_>>();
        // Restore traversal/write permissions from ancestors down; after child
        // rollback restore directory times from children back to their parents.
        rollbacks.sort_by_key(|rollback| {
            let depth = Path::new(&rollback.destination).components().count();
            if with_times {
                usize::MAX - depth
            } else {
                depth
            }
        });
        for rollback in rollbacks {
            let result = (|| -> Result<()> {
                let Some(current) = self.root.observe_if_present(&rollback.destination)? else {
                    if !rollback.existed {
                        return Ok(());
                    }
                    return Err(StateError::Conflict(
                        "original native directory was removed; metadata recovery retained".into(),
                    ));
                };
                let expected = &rollback.original;
                let requested_mode = rollback
                    .requested_mode
                    .zip(expected.mode)
                    .map(|(mode, prior)| (prior & !0o7777) | (mode & 0o7777));
                if current.id != expected.id
                    || current.kind != NativeEntryKind::Directory
                    || !(current.mode == expected.mode
                        || requested_mode.is_some() && requested_mode == current.mode)
                    || !(current.uid == expected.uid
                        || rollback.requested_uid.is_some()
                            && rollback.requested_uid == current.uid)
                    || !(current.gid == expected.gid
                        || rollback.requested_gid.is_some()
                            && rollback.requested_gid == current.gid)
                    || current.windows != expected.windows
                {
                    return Err(StateError::Conflict(
                        "foreign native directory identity/permissions retained during recovery"
                            .into(),
                    ));
                }
                #[cfg(unix)]
                let (mode, uid, gid) = (expected.mode, expected.uid, expected.gid);
                #[cfg(windows)]
                let (mode, uid, gid) = (None, None, None);
                self.root.apply_owned_directory_metadata(
                    &rollback.destination,
                    mode,
                    with_times.then_some(expected.mtime_ns),
                    uid,
                    gid,
                )?;
                if with_times && rollback.existed {
                    let observation = self.root.observe(&rollback.destination)?;
                    self.record(Event::DirectoryMetadataRestored {
                        destination: rollback.destination,
                        observation,
                    })?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                report.retain(error);
            }
        }
    }

    pub fn commit(&mut self) -> Result<NativeRestoreRecoveryReport> {
        self.checkpoint_publication()?;
        for entry in self
            .control
            .preview
            .entries
            .iter()
            .chain(&self.control.preview.root_entries)
        {
            if !self.optional_scaffold(entry) {
                self.validate_parents(&entry.destination_relative)?;
            }
            let Some(observed) = self.root.observe_if_present(&entry.destination_relative)? else {
                if self.optional_scaffold(entry) {
                    continue;
                }
                return Err(StateError::Conflict(
                    "native restored output/directory is missing before commit".into(),
                ));
            };
            if let Some(publication) = self.publications.get(&entry.destination_relative) {
                if !publication.output.as_ref().is_some_and(|output| {
                    if publication.durable {
                        output == &observed
                    } else {
                        output.after_move_matches(&observed)
                    }
                }) {
                    return Err(StateError::Conflict(
                        "native restored output changed before durable commit".into(),
                    ));
                }
            } else if entry.kind == NativeEntryKind::Directory {
                let expected_id = entry.expected.as_ref().map(|prior| prior.id).or_else(|| {
                    self.owned
                        .get(&entry.destination_relative)
                        .map(|(owned, _)| owned.id)
                });
                if expected_id != Some(observed.id) || observed.kind != NativeEntryKind::Directory {
                    return Err(StateError::Conflict(
                        "native restored directory ID changed before commit".into(),
                    ));
                }
            } else if entry.kind != NativeEntryKind::Directory
                && self.control.expected(entry)?.as_ref() != Some(&observed)
            {
                return Err(StateError::Conflict(
                    "native reused output changed before durable commit".into(),
                ));
            }
        }
        self.apply_directory_metadata()?;
        for entry in &self.control.preview.tombstones {
            if entry.action == NativeRestoreAction::Remove
                && self
                    .root
                    .observe_if_present(&entry.destination_relative)?
                    .is_some()
            {
                return Err(StateError::Conflict(
                    "native tombstone was replaced before durable commit".into(),
                ));
            }
        }
        self.flush_namespace()?;
        let reconstruction = self.assess_reconstruction()?;
        self.record(Event::Committed)?;
        self.flush_intents()?;
        self.control.require_committed_recovery();
        let recorder = self
            .control
            .commit_recorder
            .lock()
            .map_err(|_| {
                StateError::Storage("native restore commit recorder lock poisoned".into())
            })?
            .clone();
        if let Some(recorder) = recorder {
            recorder(self.journal.restore_id)?;
        }
        // Cleanup after the durable commit never relabels publication failed.
        let mut report = match self.recover() {
            Ok(report) => report,
            Err(error) => {
                let mut report = NativeRestoreRecoveryReport {
                    committed: true,
                    ..Default::default()
                };
                report.retain(error);
                report
            }
        };
        report.reconstruction = Some(reconstruction);
        // Cleanup may touch a rollback directory on a nested mount boundary.
        // Never report metadata fidelity merely because chmod/set-times
        // succeeded before that cleanup. Bytes remain committed on failure.
        for entry in self
            .control
            .preview
            .entries
            .iter()
            .chain(&self.control.preview.root_entries)
        {
            if entry.kind != NativeEntryKind::Directory {
                continue;
            }
            let Some(current) = self.root.observe_if_present(&entry.destination_relative)? else {
                if self.optional_scaffold(entry) {
                    continue;
                }
                return Err(StateError::Conflict(
                    "committed native directory is missing after cleanup".into(),
                ));
            };
            if !current.metadata_matches(entry.mode, entry.mtime_ns, entry.uid, entry.gid) {
                return Err(StateError::Conflict(
                    "native file data is durably committed, but final directory metadata changed during cleanup; preserve the data and obtain a fresh metadata approval".into(),
                ));
            }
        }
        if !report.retained_artifacts.is_empty() {
            tracing::warn!(
                retained_diagnostics = report.retained_artifacts.len(),
                "native committed restore retained artifacts for authenticated recovery"
            );
        }
        if report
            .completion
            .as_ref()
            .is_none_or(|receipt| !receipt.is_clean_committed())
        {
            return Err(StateError::Conflict(
                "native file data is committed, but working artifacts or an unverified receipt remain; finish authenticated recovery before reporting completion".into(),
            ));
        }
        Ok(report)
    }

    pub fn abort(&mut self) -> Result<NativeRestoreRecoveryReport> {
        // The buffered ownership batch precedes plaintext admission. If a later
        // failure prevents flushing, only already authenticated IDs from disk
        // can be recovered; never fall back to path-authorized cleanup.
        self.flush_intents()?;
        let report = self.recover()?;
        if !report.retained_artifacts.is_empty() {
            return Err(StateError::Conflict(format!(
                "native restore retained recovery artifacts: {}",
                report.retained_artifacts.join("; ")
            )));
        }
        Ok(report)
    }

    fn recover(&mut self) -> Result<NativeRestoreRecoveryReport> {
        let mut recovery = Self::load(self.journal.workspace(), Arc::clone(&self.control))?;
        recovery.recover_verified()
    }

    fn recover_verified(&mut self) -> Result<NativeRestoreRecoveryReport> {
        self.root.check()?;
        let mut report = NativeRestoreRecoveryReport {
            committed: self.committed,
            rolled_back: self.rolled_back,
            ..Default::default()
        };
        if self.rolled_back {
            // A signed terminal receipt is not a standing cleanup grant for
            // new entries later created at the old attempt's directory names.
            self.cleanup_captures(&mut report);
            if report.retained_artifacts.is_empty() {
                match self.audit_receipt_layout() {
                    Ok(_) => {
                        report.owned_artifacts_clean = true;
                        report.metadata_only_workspace = true;
                    }
                    Err(error) => report.retain(error),
                }
            }
            return Ok(report);
        }
        if !self.committed {
            // Undo read-only/ownership attributes before removing owned child
            // entries, then restore original directory times after the children.
            self.restore_directory_metadata(false, &mut report);
        }
        let mut previous: Option<String> = None;
        loop {
            let next = match &previous {
                Some(previous) => self.publications.range(..previous.clone()).next_back(),
                None => self.publications.iter().next_back(),
            }
            .map(|(path, publication)| (path.clone(), publication.clone()));
            let Some((path, publication)) = next else {
                break;
            };
            let result = if self.committed {
                self.cleanup_backup(&publication, &mut report)
            } else if self.rolled_back {
                Ok(())
            } else {
                self.rollback_publication(&publication, &mut report)
            };
            if let Err(error) = result {
                report.retain(error);
            }
            previous = Some(path);
        }
        for (path, (observation, role)) in &self.owned {
            if *role != OwnershipRole::Partial {
                continue;
            }
            let result = self.remove_owned_if_present(path, observation, true);
            match result {
                Ok(true) => report.removed_owned_entries += 1,
                Ok(false) => {}
                Err(error) => report.retain(error),
            }
        }
        let mut directories = self.owned.iter().collect::<Vec<_>>();
        directories
            .sort_by_key(|(path, _)| std::cmp::Reverse(Path::new(path).components().count()));
        for (path, (observation, role)) in directories {
            if *role == OwnershipRole::Partial
                || self.committed && *role == OwnershipRole::Directory
            {
                continue;
            }
            let result = self.remove_owned_if_present(&path, &observation, true);
            match result {
                Ok(true) => report.removed_owned_entries += 1,
                Ok(false) => {}
                Err(error) => report.retain(error),
            }
        }
        if !self.committed {
            self.restore_directory_metadata(true, &mut report);
        }
        // Persist successful subset undo receipts even when another entry is
        // retained. This is one recovery barrier, never a per-chunk flush.
        self.flush_namespace()?;
        self.flush_intents()?;
        if report.retained_artifacts.is_empty() {
            if let Err(error) = self.verify_unlogged_artifacts_absent() {
                report.retain(error);
            }
        }
        if report.retained_artifacts.is_empty() && !self.committed && !self.rolled_back {
            self.record(Event::RolledBack)?;
            self.flush_namespace()?;
            self.flush_intents()?;
            report.rolled_back = true;
        }
        if report.retained_artifacts.is_empty() && (self.committed || report.rolled_back) {
            // Terminal decision is already durable. Snapshot cleanup is allowed
            // only by its authenticated actual file ID; never sweep staging.
            self.cleanup_captures(&mut report);
        }
        if self.committed && report.retained_artifacts.is_empty() {
            match self.completion_receipt() {
                Ok(receipt) => report.completion = Some(receipt),
                Err(error) => report.retain(error),
            }
            if report.completion.is_some() {
                report.owned_artifacts_clean = true;
                report.metadata_only_workspace = true;
            }
        } else if report.rolled_back && report.retained_artifacts.is_empty() {
            match self.audit_receipt_layout() {
                Ok(_) => {
                    report.owned_artifacts_clean = true;
                    report.metadata_only_workspace = true;
                }
                Err(error) => report.retain(error),
            }
        }
        // Signed journals are retained as durable audit/retry authority, not
        // swept using a workspace pathname. They contain no vault key.
        Ok(report)
    }

    fn completion_receipt(&self) -> Result<NativeRestoreCompletionReceipt> {
        if !self.committed || self.rolled_back {
            return Err(StateError::Integrity(
                "native completion requires a committed decision".into(),
            ));
        }
        let (retained_metadata_files, scaffold_directories) = self.audit_receipt_layout()?;
        Ok(NativeRestoreCompletionReceipt {
            version: 1,
            restore_id: self.journal.restore_id,
            committed: true,
            authenticated_journal: true,
            owned_artifacts_clean: true,
            metadata_only_workspace: true,
            retained_metadata_files,
            scaffold_directories,
        })
    }

    fn audit_receipt_layout(&self) -> Result<(u64, u64)> {
        self.verify_working_artifacts_absent()?;
        self.journal.verify_receipt_snapshot()?;
        let files = self.journal.receipt_files();
        let result = self.workspace_root.audit_receipt_workspace(&files)?;
        self.verify_working_artifacts_absent()?;
        self.journal.verify_receipt_snapshot()?;
        Ok(result)
    }

    fn verify_working_artifacts_absent(&self) -> Result<()> {
        self.root.check()?;
        self.verify_unlogged_artifacts_absent()?;
        for (path, (_, role)) in &self.owned {
            if !(self.committed && *role == OwnershipRole::Directory)
                && self.root.observe_if_present(path)?.is_some()
            {
                return Err(StateError::Conflict(
                    "native working artifact or foreign replacement remains after restore".into(),
                ));
            }
        }
        for publication in self.publications.values() {
            if let Some(backup) = &publication.backup {
                if self.root.observe_if_present(backup)?.is_some() {
                    return Err(StateError::Conflict(
                        "native original backup remains after restore".into(),
                    ));
                }
            }
        }
        for capture in self.captures.values() {
            if self
                .workspace_root
                .observe_if_present(&capture.artifact)?
                .is_some()
            {
                return Err(StateError::Conflict(
                    "native original capture remains after restore".into(),
                ));
            }
        }
        self.root.check()
    }

    /// A create can fail/crash before its actual ID is journaled. That gap never
    /// grants pathname cleanup authority, but neither may it be called clean.
    /// Inspect only this attempt's bounded proposed slots; retain all unknown
    /// entries/ancestors without recursively enumerating unrelated user data.
    fn verify_unlogged_artifacts_absent(&self) -> Result<()> {
        for entry in self
            .control
            .preview
            .entries
            .iter()
            .chain(&self.control.preview.root_entries)
        {
            if !self.committed
                && entry.expected.is_none()
                && !self.publications.contains_key(&entry.destination_relative)
                && !self.owned.contains_key(&entry.destination_relative)
                && self
                    .root
                    .observe_if_present(&entry.destination_relative)?
                    .is_some()
            {
                return Err(StateError::Conflict(
                    "unlogged/foreign entry remains in a proposed native destination slot".into(),
                ));
            }
            if entry.kind != NativeEntryKind::Directory
                && matches!(
                    entry.action,
                    NativeRestoreAction::Create | NativeRestoreAction::Replace
                )
            {
                let destination = self
                    .control
                    .preview
                    .destination
                    .join(&entry.destination_relative);
                let partial =
                    crate::destination_partial_path(&destination, self.journal.restore_id)?;
                let relative = relative_to(&self.control.preview.destination, &partial)?;
                if !self.owned.contains_key(&relative)
                    && self.root.observe_if_present(&relative)?.is_some()
                {
                    return Err(StateError::Conflict(
                        "unlogged/foreign partial retained without owned native-ID authority"
                            .into(),
                    ));
                }
            }
        }
        let mut volumes = BTreeMap::new();
        volumes.insert(
            self.control.preview.destination_identity.device,
            (0usize, ""),
        );
        for (path, id) in &self.control.preview.parents {
            let depth = Path::new(path).components().count();
            let candidate = volumes.entry(id.device).or_insert((depth, path.as_str()));
            if depth < candidate.0 {
                *candidate = (depth, path.as_str());
            }
        }
        for (_, parent) in volumes.values() {
            let directory =
                Path::new(parent).join(format!(".quicksave-restore-{}", self.journal.restore_id));
            let relative = path_text(&directory)?;
            if !self.owned.contains_key(&relative)
                && self.root.observe_if_present(&relative)?.is_some()
            {
                return Err(StateError::Conflict(
                    "unlogged/foreign rollback directory retained without cleanup authority".into(),
                ));
            }
        }
        Ok(())
    }

    fn cleanup_captures(&self, report: &mut NativeRestoreRecoveryReport) {
        for capture in self.captures.values() {
            match self.workspace_root.observe_if_present(&capture.artifact) {
                Ok(None) => {}
                Ok(Some(current)) if current == capture.observation => {
                    match self
                        .workspace_root
                        .remove_owned(&capture.artifact, &current)
                    {
                        Ok(()) => report.removed_owned_entries += 1,
                        Err(error) => report.retain(error),
                    }
                }
                Ok(Some(_)) => {
                    report.retain("modified/foreign rollback capture retained in native workspace")
                }
                Err(error) => report.retain(error),
            }
        }
    }

    fn verify_original_capture(&self, destination: &str) -> Result<Option<&RollbackCapture>> {
        let capture = self.captures.get(destination);
        if let Some(capture) = capture {
            let observed = self.workspace_root.observe(&capture.artifact)?;
            if observed != capture.observation
                || self
                    .workspace_root
                    .hash_stable(&capture.artifact, &observed)?
                    != capture.file_hash
            {
                return Err(StateError::Conflict(
                    "authenticated stable original capture changed; retaining all recovery data"
                        .into(),
                ));
            }
        }
        Ok(capture)
    }

    fn remove_owned_if_present(
        &self,
        path: &str,
        expected: &NativeEntryObservation,
        id_only: bool,
    ) -> Result<bool> {
        let Some(current) = self.root.observe_if_present(path)? else {
            return Ok(false);
        };
        if current.id != expected.id
            || current.kind != expected.kind
            || !id_only && !expected.after_move_matches(&current)
        {
            return Err(StateError::Conflict(format!(
                "foreign/modified replacement retained at {path}"
            )));
        }
        self.root.remove_owned(path, &current)?;
        Ok(true)
    }

    fn rollback_publication(
        &mut self,
        publication: &Publication,
        report: &mut NativeRestoreRecoveryReport,
    ) -> Result<()> {
        self.validate_parents(&publication.destination)?;
        let current = self.root.observe_if_present(&publication.destination)?;
        // First prove that a restorable original still exists. An app can keep
        // a writable fd after rename; its later edits must not destroy the
        // separately captured original or cause us to delete a valid output.
        if let (Some(backup), Some(original)) = (&publication.backup, &publication.original) {
            if let Some(backup_observation) = self.root.observe_if_present(backup)? {
                let stamp_matches = if publication.backup_durable {
                    original == &backup_observation
                } else {
                    original.after_move_matches(&backup_observation)
                };
                if !stamp_matches {
                    return Err(StateError::Conflict(
                        "modified/foreign original backup retained with its stable captured original".into(),
                    ));
                }
                if original.kind == NativeEntryKind::File {
                    let capture = self
                        .verify_original_capture(&publication.destination)?
                        .ok_or_else(|| {
                            StateError::Integrity(
                                "native regular-file rollback has no stable original capture"
                                    .into(),
                            )
                        })?;
                    if self.root.hash_stable(backup, &backup_observation)? != capture.file_hash {
                        return Err(StateError::Conflict(
                            "original backup content changed; preserving stable capture and restored output".into(),
                        ));
                    }
                }
            } else if !current
                .as_ref()
                .is_some_and(|current| original.after_move_matches(current))
            {
                return Err(StateError::Conflict(
                    "native rollback original is unavailable; preserving the restored output and all recovery evidence".into(),
                ));
            }
        }
        if let Some(current) = current {
            if publication
                .original
                .as_ref()
                .is_some_and(|prior| prior.after_move_matches(&current))
            {
                if current != *publication.original.as_ref().expect("matched original")
                    && current.kind == NativeEntryKind::File
                {
                    let capture = self
                        .verify_original_capture(&publication.destination)?
                        .ok_or_else(|| {
                            StateError::Integrity(
                                "native original receipt lacks stable content proof".into(),
                            )
                        })?;
                    if self.root.hash_stable(&publication.destination, &current)?
                        != capture.file_hash
                    {
                        return Err(StateError::Conflict(
                            "modified original retained without retry authorization".into(),
                        ));
                    }
                }
                // Intent was durable but original move never happened, or a
                // previous recovery already restored this exact original inode.
                self.record(Event::Restored {
                    destination: publication.destination.clone(),
                    observation: current,
                })?;
                return Ok(());
            }
            if publication.output.as_ref().is_some_and(|output| {
                if publication.durable {
                    output == &current
                } else {
                    output.after_move_matches(&current)
                }
            }) {
                if !publication.durable && current.kind == NativeEntryKind::File {
                    let entry = self
                        .control
                        .by_destination
                        .get(&publication.destination)
                        .map(|index| &self.control.preview.entries[*index])
                        .ok_or_else(|| {
                            StateError::Integrity("native recovery payload scope missing".into())
                        })?;
                    let manifest = ManifestFile {
                        logical_root: entry.logical_root.clone(),
                        relative_path: entry.relative_path.clone(),
                        source_path_hint: None,
                        file_type: "file".into(),
                        size: entry.size,
                        file_hash: entry.file_hash.clone(),
                        chunks: Vec::new(),
                        mode: entry.mode,
                        mtime_ns: entry.mtime_ns,
                        uid: entry.uid,
                        gid: entry.gid,
                        symlink_target: None,
                        persistence_class: noland_state_core::PersistenceClass::PersistentState,
                        semantic_role: noland_state_core::SemanticRole::UserState,
                        association_confidence: 1.0,
                        shared_app_ids: Vec::new(),
                    };
                    if !self
                        .root
                        .matches_manifest_file(&publication.destination, &manifest)?
                    {
                        return Err(StateError::Conflict(
                            "unreceipted native output has modified bytes; retained".into(),
                        ));
                    }
                }
                self.root.remove_owned(&publication.destination, &current)?;
                report.removed_owned_entries += 1;
            } else {
                return Err(StateError::Conflict(format!(
                    "foreign/modified output retained at {} (original backup retained)",
                    publication.destination
                )));
            }
        }
        if let (Some(backup), Some(original)) = (&publication.backup, &publication.original) {
            let backup_observation = self.root.observe(backup)?;
            if !(if publication.backup_durable {
                original == &backup_observation
            } else {
                original.after_move_matches(&backup_observation)
            }) {
                return Err(StateError::Conflict(
                    "native rollback original backup identity/metadata changed".into(),
                ));
            }
            let restored =
                self.root
                    .move_new(backup, &publication.destination, &backup_observation)?;
            self.dirty_parent(backup)?;
            self.dirty_parent(&publication.destination)?;
            self.flush_namespace()?;
            self.record(Event::Restored {
                destination: publication.destination.clone(),
                observation: restored,
            })?;
            report.restored_original_entries += 1;
        }
        Ok(())
    }

    fn cleanup_backup(
        &self,
        publication: &Publication,
        report: &mut NativeRestoreRecoveryReport,
    ) -> Result<()> {
        if let (Some(backup), Some(original)) = (&publication.backup, &publication.original) {
            let current = self.root.observe_if_present(backup)?;
            if let Some(current) = current {
                if (publication.backup_durable && original != &current)
                    || (!publication.backup_durable && !original.after_move_matches(&current))
                {
                    return Err(StateError::Conflict(
                        "modified/foreign original backup retained".into(),
                    ));
                }
                if current.kind == NativeEntryKind::File {
                    let capture = self.captures.get(&publication.destination).ok_or_else(|| {
                        StateError::Integrity(
                            "native original retirement lacks its stable capture receipt".into(),
                        )
                    })?;
                    if self.root.hash_stable(backup, &current)? != capture.file_hash {
                        return Err(StateError::Conflict(
                            "an app modified its moved original; preserving those bytes and the stable original capture".into(),
                        ));
                    }
                }
                self.root.remove_owned(backup, &current)?;
                report.removed_owned_entries += 1;
            }
        }
        Ok(())
    }
}

pub(super) fn is_native_workspace(workspace: &Path) -> bool {
    journal::is_native_workspace(workspace)
}

pub(super) fn validate_relative(relative: &str) -> Result<()> {
    noland_state_core::validate_native_relative_path(relative)?;
    #[cfg(windows)]
    for part in relative.split('/') {
        crate::windows::validate_component(part)?;
    }
    Ok(())
}

/// Native dataset names never pass through the legacy backslash-normalizing
/// constructor/join. Check target compatibility before invoking Path on them.
pub(super) fn resolve_destination(
    roots: &LogicalRootMap,
    file: &ManifestFile,
) -> Result<(PathBuf, PathBuf)> {
    validate_relative(&file.relative_path)?;
    let logical = file
        .logical_root_parsed()
        .ok_or_else(|| StateError::UnsafePath(file.logical_root.clone()))?;
    let root = roots
        .resolve(&logical)
        .ok_or_else(|| StateError::NotFound(format!("logical root {}", file.logical_root)))?;
    let root = crate::canonicalize_root_if_present(root)?;
    let destination = noland_state_core::join_native_relative(&root, &file.relative_path)?;
    Ok((root, destination))
}

fn path_text(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| StateError::UnsafePath("non-UTF8 native restore path".into()))?;
    let text = text.replace(std::path::MAIN_SEPARATOR, "/");
    validate_relative(&text)?;
    Ok(text)
}

fn relative_to(boundary: &Path, path: &Path) -> Result<String> {
    path_text(
        path.strip_prefix(boundary)
            .map_err(|_| StateError::UnsafePath("native restore escaped approved root".into()))?,
    )
}

fn payload_digest(manifest: &BundleManifest, mode: RestoreMode) -> Result<String> {
    // Include source/completeness/parent/relationship/native metadata too.
    // Exclude only the local transport marker that the agent itself adds.
    struct Environment<'a>(&'a serde_json::Value);
    impl Serialize for Environment<'_> {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            if self.0.is_null() {
                serializer.serialize_map(Some(0))?.end()
            } else if let Some(object) = self.0.as_object() {
                let mut map = serializer.serialize_map(Some(
                    object.len() - usize::from(object.contains_key("quicksave_native_download")),
                ))?;
                for (key, value) in object {
                    if key != "quicksave_native_download" {
                        map.serialize_entry(key, value)?;
                    }
                }
                map.end()
            } else {
                self.0.serialize(serializer)
            }
        }
    }
    struct Payload<'a>(&'a BundleManifest, RestoreMode);
    impl Serialize for Payload<'_> {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            use serde::ser::SerializeStruct;
            let m = self.0;
            let mut state = serializer.serialize_struct("NativeExpectedRestorePayload", 18)?;
            state.serialize_field("restore_mode", &self.1)?;
            state.serialize_field("schema_version", &m.schema_version)?;
            state.serialize_field("bundle_id", &m.bundle_id)?;
            state.serialize_field("commit_id", &m.commit_id)?;
            state.serialize_field("parent_bundle_id", &m.parent_bundle_id)?;
            state.serialize_field("app", &m.app)?;
            state.serialize_field("source", &m.source)?;
            state.serialize_field("mode", &m.mode)?;
            state.serialize_field("consistency", &m.consistency)?;
            state.serialize_field("chunking", &m.chunking)?;
            state.serialize_field("hash", &m.hash)?;
            state.serialize_field("base", &m.base)?;
            state.serialize_field("files", &m.files)?;
            state.serialize_field("tombstones", &m.tombstones)?;
            state.serialize_field("environment", &Environment(&m.environment))?;
            state.serialize_field("relationships", &m.relationships)?;
            state.serialize_field("restore_plan", &m.restore_plan)?;
            state.serialize_field("learned_state_ref", &m.learned_state_ref)?;
            state.end()
        }
    }
    bounded_digest(&Payload(manifest, mode))
}

#[cfg(windows)]
fn native_link_directory_hint(
    hints: &BTreeMap<(&str, &str), bool>,
    file: &ManifestFile,
) -> Result<Option<bool>> {
    if file.file_type != "symlink" {
        return Ok(None);
    }
    let target = file
        .symlink_target
        .as_deref()
        .ok_or_else(|| StateError::Integrity("native link target missing".into()))?;
    noland_state_core::validate_relative_symlink_target_within_root(&file.relative_path, target)?;
    hints
        .get(&(file.logical_root.as_str(), file.relative_path.as_str()))
        .copied()
        .map(Some)
        .ok_or_else(|| {
            StateError::Integrity(
                "Windows link lacks its exact authenticated windowsSymlinkMetadata type hint"
                    .into(),
            )
        })
}

fn bounded_digest(value: &impl Serialize) -> Result<String> {
    Ok(bounded_fingerprint(value)?.0)
}

fn bounded_fingerprint(value: &impl Serialize) -> Result<(String, usize)> {
    struct HashWriter {
        hash: blake3::Hasher,
        bytes: usize,
    }
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("native restore metadata length overflow"))?;
            if self.bytes > MAX_NATIVE_RESTORE_METADATA {
                return Err(std::io::Error::other(
                    "native restore metadata exceeds 512 MiB",
                ));
            }
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter {
        hash: blake3::Hasher::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok((writer.hash.finalize().to_hex().to_string(), writer.bytes))
}
