// SPDX-License-Identifier: GPL-3.0-only
//! Native adapters for No Land CAS/pack algorithms derived from commit
//! e81238a7536aae201540956ce76981364fd36595. Original adapter code; root license
//! review remains separate from inherited engine manifest notices.
//!
//! Directory/file names are single-component opens under pinned native handles.
//! Cache mutation takes shared OS locks; GC takes an exclusive lock. Hashing and
//! independent chunk writes are not serialized behind one exclusive mutex.

use noland_snapshot::{
    native_metadata, same_file_identity, NativeIdentity, SourceMetadata, SourcePath,
};
use noland_state_core::{Result, StateError};
use std::{
    ffi::OsStr,
    fs::File,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

const MAX_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 128;
const MAX_PATH: usize = 32_768;
const MAX_NAMES: usize = 128 * 1024 * 1024;

fn invalid(message: &str) -> StateError {
    StateError::UnsafePath(message.into())
}

pub fn identity(metadata: &SourceMetadata) -> Result<NativeIdentity> {
    metadata
        .native_identity()
        .ok_or_else(|| invalid("native 128-bit file identity is unavailable"))
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("native store path must be UTF-8"))?;
    if text.is_empty()
        || text.len() > MAX_PATH
        || text.contains('\0')
        || text
            .split(['/', '\\'])
            .any(|part| part == "." || part == "..")
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid("invalid native store path"));
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if !path.is_absolute()
        || path.to_string_lossy().len() > MAX_PATH
        || path.components().count() > MAX_DEPTH + 2
    {
        return Err(invalid(
            "native store path exceeds its absolute/depth bound",
        ));
    }
    Ok(path)
}

/// No symlink canonicalization or permission repair. Existing ancestors can be
/// shared system directories, but every created component and final root must be
/// private to this account. All new components use exclusive native creation.
pub fn ensure_private_directory(path: &Path) -> Result<PathBuf> {
    let path = absolute(path)?;
    match SourcePath::new(&path).and_then(|source| source.open_directory()) {
        Ok(directory) => {
            native_metadata::verify_private_directory_live(&directory)?;
            return Ok(path);
        }
        Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for current in ancestors {
        if current.as_os_str().is_empty() {
            continue;
        }
        let source = SourcePath::new(current)?;
        let (directory, created) = match source.open_directory() {
            Ok(directory) => (directory, false),
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                match source.create_private_directory() {
                    Ok(()) => {}
                    Err(StateError::Io(error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                (source.open_directory()?, true)
            }
            Err(error) => return Err(error),
        };
        if created || current == path {
            native_metadata::verify_private_directory_live(&directory)?;
        }
    }
    Ok(path)
}

struct Boundary {
    path: PathBuf,
    source: SourcePath,
    directory: File,
    identity: NativeIdentity,
}

#[derive(Clone)]
pub struct PrivateRoot {
    inner: Arc<Boundary>,
}

impl std::fmt::Debug for PrivateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateRoot")
            .field("path", &self.inner.path)
            .field("identity", &self.inner.identity)
            .finish()
    }
}

impl PrivateRoot {
    pub fn create(path: &Path) -> Result<Self> {
        Self::open(&ensure_private_directory(path)?)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let source = SourcePath::new(&path)?;
        let directory = source.open_directory()?;
        native_metadata::verify_private_directory_live(&directory)?;
        let identity = native_metadata::identity_from_file(&directory)?;
        if source.native_identity()? != identity {
            return Err(invalid("private store root changed while opening"));
        }
        let root = Self {
            inner: Arc::new(Boundary {
                path,
                source,
                directory,
                identity,
            }),
        };
        root.check()?;
        Ok(root)
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }
    pub fn native_identity(&self) -> NativeIdentity {
        self.inner.identity
    }

    pub fn check(&self) -> Result<()> {
        native_metadata::verify_private_directory_live(&self.inner.directory)?;
        if native_metadata::identity_from_file(&self.inner.directory)? != self.inner.identity
            || self.inner.source.native_identity()? != self.inner.identity
            || SourcePath::new(self.path())?.native_identity()? != self.inner.identity
        {
            return Err(StateError::Conflict(
                "native store root or ancestor was replaced".into(),
            ));
        }
        Ok(())
    }

    pub fn source(&self, name: &str) -> Result<SourcePath> {
        self.check()?;
        SourcePath::child(&self.inner.directory, OsStr::new(name).to_owned())
    }

    pub fn subdirectory(&self, name: &str, create: bool) -> Result<Self> {
        let source = self.source(name)?;
        if create {
            match source.metadata() {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Err(invalid("private subdirectory name is not a real directory")),
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    match source.create_private_directory() {
                        Ok(()) => {}
                        Err(StateError::Io(error))
                            if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let before = source.native_identity()?;
        let root = Self::open(&self.path().join(name))?;
        if root.native_identity() != before {
            return Err(invalid("private subdirectory was replaced"));
        }
        self.check()?;
        Ok(root)
    }

    pub fn metadata(&self, name: &str) -> Result<SourceMetadata> {
        self.source(name)?.metadata()
    }

    pub fn read(&self, name: &str) -> Result<File> {
        let file = self.source(name)?.open_private_object()?;
        self.check()?;
        Ok(file)
    }

    pub fn create_file(&self, name: &str) -> Result<File> {
        let file = self.source(name)?.open_partial_private(true)?;
        native_metadata::verify_private_file(&file)?;
        self.check()?;
        Ok(file)
    }

    pub fn names(&self) -> Result<Vec<String>> {
        self.check()?;
        let mut names = native_metadata::directory_names(&self.inner.directory)?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| invalid("non-Unicode private store name"))
            })
            .collect::<Result<Vec<_>>>()?;
        names.sort_unstable();
        self.check()?;
        Ok(names)
    }

    pub fn flush(&self) -> Result<()> {
        self.check()?;
        native_metadata::flush_directory(&self.inner.directory)?;
        self.check()
    }

    pub fn remove_file(&self, name: &str, expected: NativeIdentity) -> Result<()> {
        self.source(name)?.remove_file_owned(expected)?;
        self.check()
    }

    pub fn lock(&self, exclusive: bool) -> Result<StoreLock> {
        let source = self.source(".cas.lock")?;
        let file = source.open_or_create_private()?;
        let expected = native_metadata::identity_from_file(&file)?;
        let lock = if exclusive {
            native_metadata::ScopedFileLock::lock(&file)?
        } else {
            native_metadata::ScopedFileLock::lock_shared(&file)?
        };
        if source.native_identity()? != expected || lock.identity() != expected {
            return Err(invalid("native CAS lock namespace was replaced"));
        }
        self.check()?;
        Ok(StoreLock {
            root: self.clone(),
            source,
            lock,
            expected,
        })
    }

    /// Only operation-owned lease trees use this bounded cleanup. No followed
    /// links, recursive std::fs sweep, or "delete whatever replaced the root".
    pub fn remove_tree(self) -> Result<()> {
        let mut count = 0;
        let mut bytes = 0;
        self.remove_contents(0, &mut count, &mut bytes)?;
        self.check()?;
        let inner = Arc::try_unwrap(self.inner)
            .map_err(|_| invalid("private cleanup still has active directory owners"))?;
        let Boundary {
            directory,
            source,
            identity,
            ..
        } = inner;
        drop(directory);
        source.remove_empty_directory_owned(identity)
    }

    fn remove_contents(&self, depth: usize, count: &mut usize, bytes: &mut usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(invalid("private cleanup tree is too deep"));
        }
        for name in self.names()? {
            *count = count
                .checked_add(1)
                .ok_or_else(|| invalid("private cleanup count overflow"))?;
            *bytes = bytes
                .checked_add(name.len())
                .ok_or_else(|| invalid("private cleanup size overflow"))?;
            if *count > MAX_ENTRIES || *bytes > MAX_NAMES {
                return Err(invalid("private cleanup exceeds its bounded inventory"));
            }
            let observed = self.metadata(&name)?;
            if observed.is_file() {
                let file = self.read(&name)?;
                if identity(&SourceMetadata::from_file(&file)?)? != identity(&observed)? {
                    return Err(invalid("private cleanup file was replaced"));
                }
                drop(file);
                self.remove_file(&name, identity(&observed)?)?;
            } else if observed.is_dir() {
                if depth != 0 || name != ".segments" {
                    return Err(invalid("lease cleanup refuses an unknown nested directory"));
                }
                let child = self.subdirectory(&name, false)?;
                if child.native_identity() != identity(&observed)? {
                    return Err(invalid("private cleanup directory changed"));
                }
                child.remove_contents(depth + 1, count, bytes)?;
                child.check()?;
                let expected = child.native_identity();
                let source = self.source(&name)?;
                drop(child);
                source.remove_empty_directory_owned(expected)?;
            } else {
                return Err(invalid("private cleanup refuses links or special entries"));
            }
        }
        self.flush()
    }
}

pub struct StoreLock {
    root: PrivateRoot,
    source: SourcePath,
    lock: native_metadata::ScopedFileLock,
    expected: NativeIdentity,
}

impl StoreLock {
    pub fn check(&self) -> Result<()> {
        self.lock.check()?;
        if self.source.native_identity()? != self.expected {
            return Err(invalid("CAS lock inode changed"));
        }
        self.root.check()
    }
}

pub struct StagedFile {
    root: PrivateRoot,
    temporary: String,
    destination: String,
    identity: NativeIdentity,
    committed: bool,
}

impl StagedFile {
    pub fn create(root: &PrivateRoot, destination: &str) -> Result<(Self, File)> {
        // Validate the final leaf before creating anything.
        root.source(destination)?;
        let temporary = format!(".noland-stage-{}.partial", uuid::Uuid::new_v4());
        let file = root.create_file(&temporary)?;
        let identity = native_metadata::identity_from_file(&file)?;
        Ok((
            Self {
                root: root.clone(),
                temporary,
                destination: destination.into(),
                identity,
                committed: false,
            },
            file,
        ))
    }

    pub fn check_writer(&self, file: &File) -> Result<()> {
        native_metadata::verify_private_file(file)?;
        if native_metadata::identity_from_file(file)? != self.identity
            || self.root.source(&self.temporary)?.native_identity()? != self.identity
        {
            return Err(invalid("native output staging handle/name was replaced"));
        }
        self.root.check()
    }

    /// The writer is flushed and closed by the caller before this method.
    /// Errors after publication can leave a complete new final file; never
    /// interpret failure as rollback or remove the final destination.
    pub fn publish(&mut self, bytes: u64) -> Result<PathBuf> {
        let source = self.root.source(&self.temporary)?;
        let before = source.metadata()?;
        if !before.is_file() || identity(&before)? != self.identity || before.len() != bytes {
            return Err(invalid("native staged output identity/length changed"));
        }
        source.publish_new_to(&self.root.source(&self.destination)?)?;
        let published = self.root.metadata(&self.destination)?;
        if !published.is_file()
            || identity(&published)? != self.identity
            || published.len() != bytes
        {
            return Err(invalid("native output publication identity/length changed"));
        }
        self.root.check()?;
        self.committed = true;
        Ok(self.root.path().join(&self.destination))
    }

    pub fn abort(&mut self) -> Result<()> {
        if self.committed {
            return Ok(());
        }
        match self.root.metadata(&self.temporary) {
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(observed) => {
                if identity(&observed)? != self.identity {
                    return Err(invalid("refusing to delete a replaced staging file"));
                }
                self.root.remove_file(&self.temporary, self.identity)
            }
        }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

pub fn observe_file(file: &File) -> Result<SourceMetadata> {
    let observed = SourceMetadata::from_file(file)?;
    if !observed.is_file() || observed.native_identity().is_none() || observed.ctime_ns().is_none()
    {
        return Err(invalid(
            "regular native file identity/change time is unavailable",
        ));
    }
    Ok(observed)
}

pub fn verify_file(file: &File, before: &SourceMetadata) -> Result<()> {
    if !same_file_identity(before, &observe_file(file)?) {
        return Err(StateError::Integrity(
            "native file identity/length/write/change metadata changed".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn staged_publication_never_replaces_a_winner_or_accepts_a_swapped_writer() {
        let path = crate::tests::temp_test_dir("native-publication");
        let root = PrivateRoot::open(&path).unwrap();
        let (mut staged, mut file) = StagedFile::create(&root, "winner").unwrap();
        file.write_all(b"loser").unwrap();
        file.sync_all().unwrap();
        staged.check_writer(&file).unwrap();
        drop(file);
        let mut winner = root.create_file("winner").unwrap();
        winner.write_all(b"winner").unwrap();
        winner.sync_all().unwrap();
        drop(winner);
        assert!(staged.publish(5).is_err());
        staged.abort().unwrap();
        let mut actual = Vec::new();
        root.read("winner")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, b"winner");
        let (mut staged2, mut writer) = StagedFile::create(&root, "must-not-publish").unwrap();
        let unrelated = root.create_file("unrelated").unwrap();
        let original = std::mem::replace(&mut writer, unrelated);
        assert!(staged2.check_writer(&writer).is_err());
        drop(original);
        drop(writer);
        staged2.abort().unwrap();
        assert!(root.metadata("unrelated").unwrap().is_file());
        drop(staged);
        drop(staged2);
        drop(root);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn cache_shared_os_locks_admit_independent_writers() {
        let path = crate::tests::temp_test_dir("native-shared-locks");
        let root = PrivateRoot::open(&path).unwrap();
        let first = root.lock(false).unwrap();
        let other = root.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let lock = other.lock(false).unwrap();
            send.send(()).unwrap();
            lock.check().unwrap();
        });
        let admitted = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .is_ok();
        drop(first); // Always release before assertion/join, including a failure.
        thread.join().unwrap();
        assert!(
            admitted,
            "ordinary CAS writers must not be globally exclusive"
        );
        drop(root);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_private_roots_and_symlinked_objects_fail_without_following() {
        let path = crate::tests::temp_test_dir("native-replacement");
        let root = PrivateRoot::create(&path.join("store")).unwrap();
        let mut outside = std::fs::File::create(path.join("outside")).unwrap();
        outside.write_all(b"keep").unwrap();
        drop(outside);
        std::os::unix::fs::symlink("../outside", root.path().join("link")).unwrap();
        assert!(root.read("link").is_err());
        std::fs::rename(root.path(), path.join("detached")).unwrap();
        assert!(root.check().is_err());
        assert_eq!(std::fs::read(path.join("outside")).unwrap(), b"keep");
        drop(root);
        std::fs::remove_dir_all(path).unwrap();
    }
}
