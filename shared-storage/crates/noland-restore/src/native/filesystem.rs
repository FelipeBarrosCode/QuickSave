// SPDX-License-Identifier: GPL-3.0-only
//! Native namespace operations always use held, no-follow parents. No operation
//! recursively deletes a tree or derives leaf ownership from its pathname.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use noland_snapshot::SourcePath;
use noland_state_core::{ManifestFile, Result, StateError};

use super::{
    path_text, validate_relative, NativeEntryKind, NativeEntryObservation, NativeObjectId,
};

#[cfg(unix)]
pub(super) fn file_id(metadata: &fs::Metadata) -> NativeObjectId {
    use std::os::unix::fs::MetadataExt;
    NativeObjectId {
        device: metadata.dev(),
        file_id: [metadata.ino(), 0],
    }
}

pub(super) fn handle_id(file: &File) -> Result<NativeObjectId> {
    #[cfg(unix)]
    return Ok(file_id(&file.metadata()?));
    #[cfg(windows)]
    {
        let native = noland_snapshot::native_metadata::identity_from_file(file)?;
        Ok(NativeObjectId {
            device: native.volume,
            file_id: native.file_id,
        })
    }
}

#[cfg(unix)]
fn observation(metadata: &fs::Metadata, target: Option<String>) -> Result<NativeEntryObservation> {
    let kind = if metadata.file_type().is_symlink() {
        NativeEntryKind::Symlink
    } else if metadata.is_file() {
        NativeEntryKind::File
    } else if metadata.is_dir() {
        NativeEntryKind::Directory
    } else {
        return Err(StateError::UnsafePath(
            "native restore encountered a special/reparse entry".into(),
        ));
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(NativeEntryObservation {
            id: file_id(metadata),
            kind,
            size: metadata.len(),
            mode: Some(metadata.mode()),
            mtime_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
            ctime_ns: metadata
                .ctime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.ctime_nsec()),
            links: metadata.nlink(),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            symlink_target: target,
            target_is_directory: None,
            windows: None,
        })
    }
}

pub(crate) struct NativeRoot {
    boundary: PathBuf,
    identity: NativeObjectId,
    ancestors: Vec<(PathBuf, NativeObjectId, File)>,
    directory: File,
    #[cfg(windows)]
    security: super::NativeWindowsSecurity,
    /// An entry in this map is a native identity, never a string-only grant.
    parents: Mutex<Option<BTreeMap<String, NativeObjectId>>>,
    partial_ids: Mutex<BTreeMap<String, NativeObjectId>>,
}

impl NativeRoot {
    pub fn validate_observation_scope(&self, observation: &NativeEntryObservation) -> Result<()> {
        observation.validate_platform()?;
        #[cfg(windows)]
        if observation.windows.as_ref().is_none_or(|windows| {
            windows.security.current_user_sid != self.security.current_user_sid
        }) {
            return Err(StateError::Integrity(
                "Windows restore ownership receipt belongs to another native user scope".into(),
            ));
        }
        Ok(())
    }

    pub fn open(boundary: &Path, expected: NativeObjectId) -> Result<Self> {
        crate::validate_absolute_journal_path(boundary, "native restore root")?;
        let mut ancestors = Vec::new();
        for path in boundary.ancestors() {
            if ancestors.len() > 128 {
                return Err(StateError::UnsafePath(
                    "native restore root exceeds its ancestor bound".into(),
                ));
            }
            let held = SourcePath::new(path)?.open_directory()?;
            ancestors.push((path.to_path_buf(), handle_id(&held)?, held));
        }
        let directory = SourcePath::new(boundary)?.open_directory()?;
        if handle_id(&directory)? != expected {
            return Err(StateError::Conflict(
                "approved native restore root identity changed".into(),
            ));
        }
        let root = Self {
            boundary: boundary.into(),
            identity: expected,
            ancestors,
            #[cfg(windows)]
            security: crate::windows::security(&directory)?,
            directory,
            parents: Mutex::new(None),
            partial_ids: Mutex::new(BTreeMap::new()),
        };
        root.check()?;
        Ok(root)
    }

    pub fn bind_parents(&self, parents: BTreeMap<String, NativeObjectId>) -> Result<()> {
        *self
            .parents
            .lock()
            .map_err(|_| StateError::Storage("native restore parent lock poisoned".into()))? =
            Some(parents);
        Ok(())
    }

    pub fn bind_created_directory(&self, path: &str, id: NativeObjectId) -> Result<()> {
        if let Some(parents) = &mut *self
            .parents
            .lock()
            .map_err(|_| StateError::Storage("native restore parent lock poisoned".into()))?
        {
            parents.insert(path.into(), id);
        }
        Ok(())
    }

    pub fn check(&self) -> Result<()> {
        if handle_id(&self.directory)? != self.identity {
            return Err(StateError::Conflict(
                "held native destination identity changed".into(),
            ));
        }
        #[cfg(windows)]
        if crate::windows::security(&self.directory)? != self.security {
            return Err(StateError::Conflict(
                "approved Windows root owner/DACL changed".into(),
            ));
        }
        for (index, (path, expected, held)) in self.ancestors.iter().enumerate() {
            // Check each namespace edge relative to its already-held parent.
            // Reopening every absolute ancestor separately is O(depth²) per
            // chunk; these checks are O(depth) and never follow replacement
            // links or redirect through a detached parent's new pathname.
            let current = if let Some((_, _, parent)) = self.ancestors.get(index + 1) {
                SourcePath::child(
                    parent,
                    path.file_name()
                        .ok_or_else(|| {
                            StateError::UnsafePath("native ancestor has no leaf".into())
                        })?
                        .to_owned(),
                )?
                .open_directory()?
            } else {
                SourcePath::new(path)?.open_directory()?
            };
            if handle_id(&current)? != *expected || handle_id(held)? != *expected {
                return Err(StateError::Conflict(
                    "native restore root or an ancestor was renamed/replaced".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn sync_directory(&self, relative: &str) -> Result<()> {
        self.check()?;
        if relative.is_empty() {
            noland_snapshot::native_metadata::flush_directory(&self.directory)?;
        } else {
            noland_snapshot::native_metadata::flush_directory(
                &self.source(relative)?.open_directory()?,
            )?;
        }
        self.check()
    }

    fn parent(&self, relative: &str) -> Result<(File, std::ffi::OsString)> {
        validate_relative(relative)?;
        self.check()?;
        let path = Path::new(relative);
        let name = path
            .file_name()
            .ok_or_else(|| StateError::UnsafePath("native entry has no leaf".into()))?
            .to_owned();
        let mut directory = self.directory.try_clone()?;
        let mut current = PathBuf::new();
        for part in path.parent().unwrap_or(Path::new("")).components() {
            current.push(part);
            let child = SourcePath::child(&directory, part.as_os_str().to_owned())?;
            let next = child.open_directory()?;
            #[cfg(windows)]
            crate::windows::security(&next)?;
            let id = handle_id(&next)?;
            let parents = self
                .parents
                .lock()
                .map_err(|_| StateError::Storage("native restore parent lock poisoned".into()))?;
            if let Some(parents) = &*parents {
                if parents.get(&path_text(&current)?) != Some(&id) {
                    return Err(StateError::Conflict(
                        "native ancestor does not match the frozen/created directory ID".into(),
                    ));
                }
            }
            drop(parents);
            directory = next;
        }
        self.check()?;
        Ok((directory, name))
    }

    fn source(&self, relative: &str) -> Result<SourcePath> {
        let (parent, name) = self.parent(relative)?;
        SourcePath::child(&parent, name)
    }

    pub fn validate_path(&self, relative: &str) -> Result<()> {
        self.parent(relative).map(|_| ())
    }

    pub fn open_partial(&self, relative: &str, create_new: bool) -> Result<File> {
        let source = self.source(relative)?;
        let file = source.open_partial_private(create_new)?;
        if !create_new {
            self.verify_partial(relative, &file)?;
        }
        Ok(file)
    }

    pub fn register_partial(&self, relative: &str, identity: NativeObjectId) -> Result<()> {
        self.partial_ids
            .lock()
            .map_err(|_| StateError::Storage("native partial identity lock poisoned".into()))?
            .insert(relative.into(), identity);
        Ok(())
    }

    pub fn verify_partial(&self, relative: &str, file: &File) -> Result<()> {
        let observed = self.observe(relative)?;
        let expected = self
            .partial_ids
            .lock()
            .map_err(|_| StateError::Storage("native partial identity lock poisoned".into()))?
            .get(relative)
            .copied()
            .ok_or_else(|| {
                StateError::Integrity("native partial lacks an owned native ID".into())
            })?;
        if observed.id != expected
            || observed.id != handle_id(file)?
            || observed.kind != NativeEntryKind::File
        {
            return Err(StateError::Conflict(
                "native partial file ID was replaced".into(),
            ));
        }
        Ok(())
    }

    pub fn relative_path(&self, path: &Path) -> Result<String> {
        super::relative_to(&self.boundary, path)
    }

    /// Read-only completion audit. Only the authenticated receipt files and
    /// data-free standard scaffolding may remain. Unknown entries are retained
    /// and rejected, never recursively swept.
    pub fn audit_receipt_workspace(
        &self,
        receipts: &[(&str, NativeObjectId)],
    ) -> Result<(u64, u64)> {
        const SCAFFOLD: &[&str] = &[
            "packs",
            "materialized",
            "materialized/.chunks",
            "pre_restore",
            "logs",
        ];
        self.check()?;
        let mut directories = vec![(String::new(), self.directory.try_clone()?)];
        let mut seen_files = std::collections::BTreeSet::new();
        let mut inspected_directories = Vec::new();
        let mut scaffold_directories = 0u64;
        let mut entries_seen = 0usize;
        while let Some((relative, directory)) = directories.pop() {
            let before = noland_snapshot::SourceMetadata::from_file(&directory)?;
            for name in receipt_directory_names(&directory)? {
                entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
                    StateError::Integrity("native receipt entry count overflow".into())
                })?;
                if entries_seen > 16 {
                    return Err(StateError::Conflict(
                        "unknown entries remain in native restore workspace".into(),
                    ));
                }
                let leaf = name.to_str().ok_or_else(|| {
                    StateError::UnsafePath("native receipt entry is not UTF-8".into())
                })?;
                let path = if relative.is_empty() {
                    leaf.to_owned()
                } else {
                    format!("{relative}/{leaf}")
                };
                validate_relative(&path)?;
                let source = SourcePath::child(&directory, name.clone())?;
                let observed = source.metadata()?;
                if observed.is_dir() && !observed.is_symlink() {
                    if !SCAFFOLD.contains(&path.as_str()) {
                        return Err(StateError::Conflict(
                            "unapproved directory remains in native restore workspace".into(),
                        ));
                    }
                    let child = source.open_directory()?;
                    if !noland_snapshot::same_file_identity(
                        &noland_snapshot::SourceMetadata::from_file(&child)?,
                        &observed,
                    ) {
                        return Err(StateError::Conflict(
                            "native receipt scaffold was replaced".into(),
                        ));
                    }
                    directories.push((path, child));
                    scaffold_directories += 1;
                } else if observed.is_file() && !observed.is_symlink() {
                    let expected = receipts.iter().find(|(name,_)| *name == path)
                        .ok_or_else(|| StateError::Conflict(
                            "plaintext, pack, or unknown file remains in native restore workspace".into(),
                        ))?;
                    #[cfg(unix)]
                    let file = source.open_regular()?;
                    #[cfg(windows)]
                    let file = crate::windows::open_entry(&directory, &name, 1)?;
                    noland_snapshot::native_metadata::verify_private_file(&file)?;
                    if handle_id(&file)? != expected.1
                        || !noland_snapshot::same_file_identity(
                            &noland_snapshot::SourceMetadata::from_file(&file)?,
                            &observed,
                        )
                    {
                        return Err(StateError::Conflict(
                            "native completion metadata file was replaced".into(),
                        ));
                    }
                    seen_files.insert(path);
                } else {
                    return Err(StateError::UnsafePath(
                        "link or special entry remains in native receipt workspace".into(),
                    ));
                }
            }
            if !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&directory)?,
                &before,
            ) {
                return Err(StateError::Conflict(
                    "native receipt workspace changed during audit".into(),
                ));
            }
            inspected_directories.push((relative, directory, before));
            self.check()?;
        }
        // Keep every inspected directory pinned until the audit ends. Recheck
        // both its state and its namespace edge after scanning descendants, so
        // a detached/replaced scaffold cannot hide working data.
        for (relative, directory, before) in &inspected_directories {
            let current = if relative.is_empty() {
                self.directory.try_clone()?
            } else {
                self.source(relative)?.open_directory()?
            };
            if !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(directory)?,
                before,
            ) || !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&current)?,
                before,
            ) {
                return Err(StateError::Conflict(
                    "native receipt scaffold changed before audit completion".into(),
                ));
            }
        }
        self.check()?;
        if seen_files.len() != receipts.len() {
            return Err(StateError::Integrity(
                "native completion metadata receipt is incomplete".into(),
            ));
        }
        Ok((seen_files.len() as u64, scaffold_directories))
    }

    pub fn open_regular(&self, relative: &str) -> Result<File> {
        self.source(relative)?.open_regular()
    }

    pub fn hash_stable(&self, relative: &str, expected: &NativeEntryObservation) -> Result<String> {
        if self.observe(relative)? != *expected {
            return Err(StateError::Conflict(
                "native rollback entry changed before hashing".into(),
            ));
        }
        let mut file = self.open_regular(relative)?;
        let before = noland_snapshot::SourceMetadata::from_file(&file)?;
        if handle_id(&file)? != expected.id {
            return Err(StateError::Conflict(
                "native rollback hash handle changed".into(),
            ));
        }
        let mut hash = blake3::Hasher::new();
        let mut buffer = [0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total.checked_add(count as u64).ok_or_else(|| {
                StateError::Integrity("native rollback hash byte overflow".into())
            })?;
            if total > expected.size {
                return Err(StateError::Conflict(
                    "native rollback entry grew during hashing".into(),
                ));
            }
            hash.update(&buffer[..count]);
        }
        if total != expected.size
            || !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&file)?,
                &before,
            )
            || self.observe(relative)? != *expected
        {
            return Err(StateError::Conflict(
                "native rollback entry changed while hashing".into(),
            ));
        }
        Ok(format!("blake3:{}", hash.finalize().to_hex()))
    }

    pub fn apply_owned_directory_metadata(
        &self,
        relative: &str,
        mode: Option<u32>,
        mtime_ns: Option<i64>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<()> {
        let before = self.observe(relative)?;
        if before.kind != NativeEntryKind::Directory {
            return Err(StateError::Conflict(
                "native directory metadata target was replaced".into(),
            ));
        }
        #[cfg(unix)]
        let directory = self.source(relative)?.open_directory()?;
        #[cfg(windows)]
        let directory = {
            let (parent, name) = self.parent(relative)?;
            // SetFileInformationByHandle requires FILE_WRITE_ATTRIBUTES.
            crate::windows::open_entry(&parent, &name, 0x100)?
        };
        if handle_id(&directory)? != before.id {
            return Err(StateError::Conflict(
                "native directory changed before metadata application".into(),
            ));
        }
        crate::apply_file_metadata_fields(&directory, mode, mtime_ns, uid, gid)?;
        noland_snapshot::native_metadata::flush_directory(&directory)?;
        let after = self.observe(relative)?;
        if after.id != before.id
            || after.kind != before.kind
            || after.windows != before.windows
            || !after.metadata_matches(mode, mtime_ns, uid, gid)
        {
            return Err(StateError::Conflict(
                "native directory changed during metadata application".into(),
            ));
        }
        Ok(())
    }

    pub fn observe(&self, relative: &str) -> Result<NativeEntryObservation> {
        #[cfg(windows)]
        {
            use noland_snapshot::native_metadata::NativeEntryKind as Kind;
            let source = self.source(relative)?;
            let (parent, name) = self.parent(relative)?;
            let held = crate::windows::open_entry(&parent, &name, 0)?;
            let native = noland_snapshot::native_metadata::WindowsMetadata::from_file(&held)?;
            let security = crate::windows::security(&held)?;
            let (symlink_target, reparse_data) = if native.kind == Kind::Symlink {
                let (target, digest) = crate::windows::read_symlink(&held)?;
                (Some(target), Some(digest))
            } else {
                (None, None)
            };
            if !native.same_file_state(&source.native_metadata()?)
                || !native.same_file_state(
                    &noland_snapshot::native_metadata::WindowsMetadata::from_file(&held)?,
                )
            {
                return Err(StateError::Conflict(
                    "native Windows entry changed during observation".into(),
                ));
            }
            self.check()?;
            let observation = NativeEntryObservation {
                id: NativeObjectId {
                    device: native.identity.volume,
                    file_id: native.identity.file_id,
                },
                kind: match native.kind {
                    Kind::File => NativeEntryKind::File,
                    Kind::Directory => NativeEntryKind::Directory,
                    Kind::Symlink => NativeEntryKind::Symlink,
                },
                size: native.size,
                mode: None,
                mtime_ns: native.mtime_ns().ok_or_else(|| {
                    StateError::Invalid(
                        "Windows mtime is outside the supported nanosecond range".into(),
                    )
                })?,
                ctime_ns: native.ctime_ns().ok_or_else(|| {
                    StateError::Invalid(
                        "Windows change time is outside the supported nanosecond range".into(),
                    )
                })?,
                links: u64::from(native.number_of_links),
                uid: None,
                gid: None,
                symlink_target,
                target_is_directory: (native.kind == Kind::Symlink)
                    .then(|| native.is_directory_link()),
                windows: Some(super::NativeWindowsObservation {
                    version: 1,
                    attributes: native.attributes,
                    creation_time: native.creation_time,
                    reparse_tag: native.reparse_tag,
                    reparse_data,
                    security,
                }),
            };
            self.validate_observation_scope(&observation)?;
            return Ok(observation);
        }
        #[cfg(unix)]
        {
            let source = self.source(relative)?;
            let before = source.metadata()?;
            let metadata = fs::symlink_metadata(self.boundary.join(relative))?;
            if !noland_snapshot::same_file_identity(&before, &metadata) {
                return Err(StateError::Conflict(
                    "native entry or ancestor changed during observation".into(),
                ));
            }
            let target = if before.is_symlink() {
                Some(
                    source
                        .read_link()?
                        .to_str()
                        .ok_or_else(|| {
                            StateError::UnsafePath(
                                "native symbolic link target is not UTF-8".into(),
                            )
                        })?
                        .to_owned(),
                )
            } else {
                None
            };
            if !noland_snapshot::same_file_identity(&before, &source.metadata()?) {
                return Err(StateError::Conflict(
                    "native entry changed during observation".into(),
                ));
            }
            self.check()?;
            observation(&metadata, target)
        }
    }

    pub fn observe_if_present(&self, relative: &str) -> Result<Option<NativeEntryObservation>> {
        match self.observe(relative) {
            Ok(value) => Ok(Some(value)),
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn collect_parents(
        &self,
        relative: &str,
        parents: &mut BTreeMap<String, NativeObjectId>,
    ) -> Result<()> {
        validate_relative(relative)?;
        let mut current = PathBuf::new();
        for part in Path::new(relative)
            .parent()
            .unwrap_or(Path::new(""))
            .components()
        {
            current.push(part);
            let text = path_text(&current)?;
            match self.observe_if_present(&text)? {
                Some(observation) if observation.kind == NativeEntryKind::Directory => {
                    if parents
                        .insert(text, observation.id)
                        .is_some_and(|prior| prior != observation.id)
                    {
                        return Err(StateError::Conflict(
                            "native ancestor changed during preview".into(),
                        ));
                    }
                }
                Some(_) => {
                    return Err(StateError::UnsafePath(
                        "native preview refuses a symlink/non-directory ancestor".into(),
                    ));
                }
                None => break,
            }
        }
        Ok(())
    }

    pub fn matches_manifest_file(&self, relative: &str, file: &ManifestFile) -> Result<bool> {
        let before = self.observe(relative)?;
        if before.kind != NativeEntryKind::File
            || before.size != file.size
            || !before.metadata_matches(file.mode, file.mtime_ns, file.uid, file.gid)
        {
            return Ok(false);
        }
        let mut input = self.source(relative)?.open_regular()?;
        if handle_id(&input)? != before.id {
            return Err(StateError::Conflict(
                "native reused file changed before verification".into(),
            ));
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 256 * 1024];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        if self.observe(relative)? != before || handle_id(&input)? != before.id {
            return Err(StateError::Conflict(
                "native reused file changed during verification".into(),
            ));
        }
        Ok(format!("blake3:{}", hasher.finalize().to_hex()) == file.file_hash)
    }

    pub fn create_directory(&self, relative: &str) -> Result<NativeEntryObservation> {
        #[cfg(unix)]
        {
            let source = self.source(relative)?;
            source.create_private_directory()?;
        }
        #[cfg(windows)]
        let held = {
            let (parent, name) = self.parent(relative)?;
            crate::windows::create_private_directory(&parent, &name)?
        };
        let observation = self.observe(relative)?;
        if observation.kind != NativeEntryKind::Directory {
            return Err(StateError::Conflict(
                "new native directory was replaced before identity capture".into(),
            ));
        }
        #[cfg(windows)]
        if observation.id != handle_id(&held)? {
            return Err(StateError::Conflict(
                "created Windows directory does not match its held create result".into(),
            ));
        }
        self.bind_created_directory(relative, observation.id)?;
        Ok(observation)
    }

    pub fn create_symlink(
        &self,
        relative: &str,
        target: &str,
        target_is_directory: Option<bool>,
    ) -> Result<NativeEntryObservation> {
        validate_relative(relative)?;
        noland_state_core::validate_relative_symlink_target_within_root(relative, target)?;
        #[cfg(unix)]
        {
            let _ = target_is_directory;
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let (parent, name) = self.parent(relative)?;
            let name = std::ffi::CString::new(name.as_bytes())
                .map_err(|_| StateError::UnsafePath("NUL in native symlink leaf".into()))?;
            let target = std::ffi::CString::new(target)
                .map_err(|_| StateError::UnsafePath("NUL in native symlink target".into()))?;
            if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            parent.sync_all()?;
        }
        #[cfg(windows)]
        {
            let identity = noland_snapshot::native_metadata::NativeIdentity {
                volume: self.identity.device,
                file_id: self.identity.file_id,
            };
            let source = SourcePath::new_beneath_native(
                &self.boundary.join(relative),
                &self.boundary,
                identity,
            )?;
            let created = source.create_new_relative_symlink(
                Path::new(target),
                Path::new(relative),
                target_is_directory,
            )?;
            if !noland_snapshot::same_file_identity(&source.metadata()?, &created.metadata) {
                return Err(StateError::Conflict(
                    "created native link was replaced before ownership capture".into(),
                ));
            }
            let observed = self.observe(relative)?;
            if created.metadata.native_identity()
                != Some(noland_snapshot::native_metadata::NativeIdentity {
                    volume: observed.id.device,
                    file_id: observed.id.file_id,
                })
            {
                return Err(StateError::Conflict(
                    "created native link identity changed".into(),
                ));
            }
            return Ok(observed);
        }
        self.observe(relative)
    }

    pub fn move_new(
        &self,
        source: &str,
        destination: &str,
        expected: &NativeEntryObservation,
    ) -> Result<NativeEntryObservation> {
        if self.observe(source)? != *expected {
            return Err(StateError::Conflict(
                "native entry changed before guarded no-replace move".into(),
            ));
        }
        let (source_parent, source_leaf) = self.parent(source)?;
        let (target_parent, target_leaf) = self.parent(destination)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let source_leaf = std::ffi::CString::new(source_leaf.as_bytes())
                .map_err(|_| StateError::UnsafePath("NUL in native move source".into()))?;
            let target_leaf = std::ffi::CString::new(target_leaf.as_bytes())
                .map_err(|_| StateError::UnsafePath("NUL in native move target".into()))?;
            #[cfg(target_vendor = "apple")]
            let result = unsafe {
                libc::renameatx_np(
                    source_parent.as_raw_fd(),
                    source_leaf.as_ptr(),
                    target_parent.as_raw_fd(),
                    target_leaf.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    source_parent.as_raw_fd(),
                    source_leaf.as_ptr(),
                    target_parent.as_raw_fd(),
                    target_leaf.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            };
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            return Err(StateError::UnsafePath(
                "this native filesystem has no audited kernel no-replace rename backend".into(),
            ));
            #[cfg(any(target_vendor = "apple", target_os = "linux"))]
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return Err(StateError::Conflict(format!(
                    "native kernel no-replace move failed without overwriting a destination: {error}"
                )));
            }
        }
        #[cfg(windows)]
        {
            let source_path = SourcePath::child(&source_parent, source_leaf)?;
            let stamp = source_path.metadata()?;
            if self.observe(source)? != *expected {
                return Err(StateError::Conflict(
                    "native move source changed before handle-checked publication".into(),
                ));
            }
            source_path
                .move_new_to_checked(&SourcePath::child(&target_parent, target_leaf)?, &stamp)?;
        }
        // Publication coalesces directory durability at the existing verified
        // batch barrier. Recovery callers flush their guarded moves explicitly.
        let observed = self.observe(destination)?;
        if !expected.after_move_matches(&observed) {
            // Never delete a raced replacement now resident in the rollback
            // slot. Its path is not ownership authority.
            return Err(StateError::Conflict(
                "raced native entry retained in guarded move destination".into(),
            ));
        }
        Ok(observed)
    }

    pub fn remove_owned(&self, relative: &str, expected: &NativeEntryObservation) -> Result<()> {
        if self.observe(relative)? != *expected {
            return Err(StateError::Conflict(
                "native owned entry changed before removal".into(),
            ));
        }
        let source = self.source(relative)?;
        let metadata = source.metadata()?;
        if self.observe(relative)? != *expected {
            return Err(StateError::Conflict(
                "native removal source changed before handle-checked deletion".into(),
            ));
        }
        if expected.kind != NativeEntryKind::Directory {
            // SourcePath quarantines before unlinking and verifies the moved
            // native file ID. A raced-in leaf is retained, never unlinked.
            return source.delete_leaf(&metadata);
        }
        #[cfg(windows)]
        {
            source.remove_empty_directory_owned(
                noland_snapshot::native_metadata::NativeIdentity {
                    volume: expected.id.device,
                    file_id: expected.id.file_id,
                },
            )?;
            return self.sync_directory(
                Path::new(relative)
                    .parent()
                    .and_then(Path::to_str)
                    .unwrap_or(""),
            );
        }
        #[cfg(unix)]
        {
            // Move the exact directory into an unpredictable, create-new sibling
            // slot before rmdir; never rmdir the mutable public path after a stat.
            let parent = Path::new(relative).parent().unwrap_or(Path::new(""));
            let quarantine = parent.join(format!(".quicksave-rmdir-{}", Uuid::new_v4()));
            let quarantine = path_text(&quarantine)?;
            let moved = self.move_new(relative, &quarantine, expected)?;
            let source = self.source(&quarantine)?;
            match source.remove_empty_directory() {
                Ok(()) => self.sync_directory(
                    Path::new(relative)
                        .parent()
                        .and_then(Path::to_str)
                        .unwrap_or(""),
                ),
                Err(error) => {
                    // A foreign child makes rmdir fail. Restore the owned directory
                    // name only if the public slot remains empty; otherwise retain.
                    let _ = self.move_new(&quarantine, relative, &moved);
                    Err(error)
                }
            }
        }
    }
}

use uuid::Uuid;

#[cfg(unix)]
fn receipt_directory_names(directory: &File) -> Result<Vec<std::ffi::OsString>> {
    use std::{
        ffi::CStr,
        os::{
            fd::{AsRawFd, FromRawFd, IntoRawFd},
            unix::ffi::OsStringExt,
        },
    };
    // A fresh directory description avoids sharing enumeration offsets with
    // pinned root handles. fdopendir takes ownership of this descriptor.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let stream = unsafe { libc::fdopendir(file.into_raw_fd()) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error.into());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Directory(stream);
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_vendor = "apple")]
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() == 16 || name.len() > 255 {
            return Err(StateError::Conflict(
                "unknown entries exceed native receipt-only workspace bounds".into(),
            ));
        }
        names.push(std::ffi::OsString::from_vec(name.to_vec()));
    }
    Ok(names)
}

#[cfg(windows)]
fn receipt_directory_names(directory: &File) -> Result<Vec<std::ffi::OsString>> {
    crate::windows::receipt_directory_names(directory)
}
