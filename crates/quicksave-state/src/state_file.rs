// SPDX-License-Identifier: GPL-3.0-only
//! Private, handle-anchored replacement of this application's state.json only.
//! Every caller reloads under a scoped OS lock. The lock inode is never replaced.

#[cfg(not(windows))]
use anyhow::bail;
use anyhow::Result;
use std::path::Path;

pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;

#[cfg(unix)]
mod native {
    use super::*;
    use anyhow::{ensure, Context};
    use quicksave_platform::{ensure_private_directory, verify_private_file};
    use std::{
        cell::RefCell,
        ffi::CString,
        fs::File,
        io::{self, Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, PathBuf},
    };

    const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    const FILE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

    struct Directory {
        file: File,
        name: Option<CString>,
        device: u64,
        inode: u64,
    }

    pub struct StateFile {
        path: PathBuf,
        directories: Vec<Directory>,
    }

    pub struct LockedState<'a> {
        owner: &'a StateFile,
        lock: File,
        observed: RefCell<Option<Option<FileVersion>>>,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct FileVersion {
        device: u64,
        inode: u64,
        length: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl FileVersion {
        fn of(file: &File) -> Result<Self> {
            let metadata = file.metadata()?;
            Ok(Self::from_metadata(&metadata))
        }

        fn from_metadata(metadata: &std::fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    fn cstring(value: &str) -> Result<CString> {
        Ok(CString::new(value)?)
    }

    fn file(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful open/openat returns a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_at(parent: &File, name: &CString, flags: i32, mode: u32) -> io::Result<File> {
        // SAFETY: parent and name remain live; mode is supplied when O_CREAT is set.
        file(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) })
    }

    fn same_identity(left: &File, right: &File) -> Result<bool> {
        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    impl StateFile {
        pub fn open(path: &Path) -> Result<Self> {
            ensure!(
                path.is_absolute(),
                "workspace data directory must be absolute"
            );
            ensure!(
                path.as_os_str().as_bytes().len() <= quicksave_platform::MAX_PATH_BYTES,
                "workspace data directory exceeds path limit"
            );
            ensure_private_directory(path)?;
            let slash = cstring("/")?;
            // SAFETY: slash is a live NUL-terminated string and O_CREAT is absent.
            let root = file(unsafe { libc::open(slash.as_ptr(), DIR_FLAGS) })?;
            let metadata = root.metadata()?;
            let mut result = Self {
                path: path.to_path_buf(),
                directories: vec![Directory {
                    file: root,
                    name: None,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                }],
            };
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => {
                        ensure!(result.directories.len() <= 128, "state path is too deep");
                        let name = CString::new(name.as_bytes())?;
                        result.check()?;
                        let child = open_at(result.directory(), &name, DIR_FLAGS, 0)
                            .context("open pinned state directory")?;
                        let metadata = child.metadata()?;
                        ensure!(
                            metadata.is_dir(),
                            "state ancestor is not a native directory"
                        );
                        result.directories.push(Directory {
                            file: child,
                            name: Some(name),
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        });
                    }
                    _ => bail!("state path cannot contain dot or parent components"),
                }
            }
            result.check_private()?;
            Ok(result)
        }

        fn directory(&self) -> &File {
            &self
                .directories
                .last()
                .expect("filesystem root pinned")
                .file
        }

        fn check(&self) -> Result<()> {
            for (index, directory) in self.directories.iter().enumerate() {
                let metadata = directory.file.metadata()?;
                ensure!(
                    metadata.is_dir()
                        && metadata.dev() == directory.device
                        && metadata.ino() == directory.inode,
                    "pinned state directory changed"
                );
                if let Some(name) = &directory.name {
                    let current = open_at(&self.directories[index - 1].file, name, DIR_FLAGS, 0)?;
                    ensure!(
                        same_identity(&current, &directory.file)?,
                        "state directory namespace was replaced"
                    );
                }
            }
            Ok(())
        }

        fn check_private(&self) -> Result<()> {
            self.check()?;
            // Platform helper rejects ACLs as well as non-private permissions.
            // Checking both sides binds its pathname inspection to our pinned IDs.
            ensure_private_directory(&self.path)?;
            let metadata = self.directory().metadata()?;
            // SAFETY: geteuid has no preconditions.
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == 0o700,
                "state directory is not private to the current user"
            );
            self.check()
        }

        pub fn lock(&self) -> Result<LockedState<'_>> {
            self.check_private()?;
            let name = cstring("state.lock")?;
            let lock = open_at(
                self.directory(),
                &name,
                libc::O_RDWR | libc::O_CREAT | FILE_FLAGS,
                0o600,
            )
            .context("open private state lock")?;
            verify_private_file(&lock)?;
            // SAFETY: descriptor is a live, verified regular private file.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error()).context("lock workspace state");
            }
            let locked = LockedState {
                owner: self,
                lock,
                observed: RefCell::new(None),
            };
            locked.check()?;
            Ok(locked)
        }
    }

    impl LockedState<'_> {
        fn check(&self) -> Result<()> {
            self.owner.check_private()?;
            verify_private_file(&self.lock)?;
            let current = open_at(
                self.owner.directory(),
                &cstring("state.lock")?,
                libc::O_RDWR | FILE_FLAGS,
                0,
            )?;
            ensure!(
                same_identity(&self.lock, &current)?,
                "state lock inode was replaced"
            );
            Ok(())
        }

        fn current_file(&self) -> Result<Option<File>> {
            self.check()?;
            match open_at(
                self.owner.directory(),
                &cstring("state.json")?,
                libc::O_RDONLY | FILE_FLAGS,
                0,
            ) {
                Ok(file) => {
                    verify_private_file(&file)?;
                    Ok(Some(file))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error).context("open private state.json"),
            }
        }

        pub fn read(&self) -> Result<Option<Vec<u8>>> {
            let Some(mut file) = self.current_file()? else {
                *self.observed.borrow_mut() = Some(None);
                return Ok(None);
            };
            let before = file.metadata()?;
            ensure!(
                before.len() <= MAX_STATE_BYTES as u64,
                "state.json exceeds 8 MiB"
            );
            let mut bytes = Vec::new();
            (&mut file)
                .take(MAX_STATE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= MAX_STATE_BYTES, "state.json exceeds 8 MiB");
            verify_private_file(&file)?;
            let after = file.metadata()?;
            ensure!(
                before.dev() == after.dev()
                    && before.ino() == after.ino()
                    && before.len() == after.len()
                    && before.mtime() == after.mtime()
                    && before.mtime_nsec() == after.mtime_nsec()
                    && before.ctime() == after.ctime()
                    && before.ctime_nsec() == after.ctime_nsec(),
                "state.json changed while reading"
            );
            let current = self.current_file()?.context("state.json disappeared")?;
            ensure!(
                same_identity(&current, &file)?,
                "state.json was replaced while reading"
            );
            self.check()?;
            *self.observed.borrow_mut() = Some(Some(FileVersion::from_metadata(&after)));
            Ok(Some(bytes))
        }

        pub fn replace(&self, bytes: &[u8]) -> Result<()> {
            ensure!(bytes.len() <= MAX_STATE_BYTES, "state.json exceeds 8 MiB");
            self.check()?;
            let previous = self.current_file()?;
            let observed = self
                .observed
                .borrow()
                .clone()
                .context("state replacement requires a prior locked read")?;
            ensure!(
                observed == previous.as_ref().map(FileVersion::of).transpose()?,
                "state.json contents changed after the locked read"
            );
            let temporary = cstring(&format!(".state.{}.tmp", uuid::Uuid::new_v4()))?;
            let mut staging = open_at(
                self.owner.directory(),
                &temporary,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | FILE_FLAGS,
                0o600,
            )
            .context("stage private state replacement")?;
            let outcome = (|| {
                verify_private_file(&staging)?;
                staging.write_all(bytes)?;
                staging.sync_all().context("flush staged state.json")?;
                verify_private_file(&staging)?;
                self.check()?;
                let current = self.current_file()?;
                ensure!(
                    observed == current.as_ref().map(FileVersion::of).transpose()?,
                    "state.json contents changed before atomic commit"
                );
                match (&previous, &current) {
                    (Some(previous), Some(current)) => ensure!(
                        same_identity(previous, current)?,
                        "state.json replaced before atomic commit"
                    ),
                    (None, None) => {}
                    _ => bail!("state.json appeared/disappeared before atomic commit"),
                }
                // SAFETY: both names are single components under the pinned private
                // directory; the only replacement target is this app's state.json.
                if unsafe {
                    libc::renameat(
                        self.owner.directory().as_raw_fd(),
                        temporary.as_ptr(),
                        self.owner.directory().as_raw_fd(),
                        cstring("state.json")?.as_ptr(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error())
                        .context("atomically replace state.json");
                }
                self.owner
                    .directory()
                    .sync_all()
                    .context("flush state directory after replacement")?;
                self.check()?;
                let published = self
                    .current_file()?
                    .context("published state disappeared")?;
                ensure!(
                    same_identity(&published, &staging)?,
                    "published state inode did not match staged file"
                );
                Ok(())
            })();
            if outcome.is_err() {
                // SAFETY: remove only our randomly named private staging entry.
                // After publication this name is absent; never unlink state.json.
                unsafe {
                    libc::unlinkat(self.owner.directory().as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            outcome
        }
    }

    impl Drop for LockedState<'_> {
        fn drop(&mut self) {
            // SAFETY: live lock descriptor. Closing also releases flock.
            unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[cfg(unix)]
pub use native::StateFile;

#[cfg(windows)]
mod windows {
    use super::*;
    use anyhow::Context;
    use quicksave_platform::{PrivateDirectory, PrivateFileVersion, PrivateLock};
    use std::cell::RefCell;

    pub struct StateFile {
        directory: PrivateDirectory,
    }

    pub struct LockedState<'a> {
        owner: &'a StateFile,
        lock: PrivateLock,
        observed: RefCell<Option<Option<PrivateFileVersion>>>,
    }

    impl StateFile {
        pub fn open(path: &Path) -> Result<Self> {
            Ok(Self {
                directory: PrivateDirectory::open(path)?,
            })
        }

        pub fn lock(&self) -> Result<LockedState<'_>> {
            Ok(LockedState {
                owner: self,
                lock: self.directory.lock("state.lock")?,
                observed: RefCell::new(None),
            })
        }
    }

    impl LockedState<'_> {
        pub fn read(&self) -> Result<Option<Vec<u8>>> {
            self.lock.check()?;
            let result = self.owner.directory.read("state.json", MAX_STATE_BYTES)?;
            self.lock.check()?;
            match result {
                Some((bytes, version)) => {
                    *self.observed.borrow_mut() = Some(Some(version));
                    Ok(Some(bytes))
                }
                None => {
                    *self.observed.borrow_mut() = Some(None);
                    Ok(None)
                }
            }
        }

        pub fn replace(&self, bytes: &[u8]) -> Result<()> {
            self.lock.check()?;
            let observed = self
                .observed
                .borrow()
                .clone()
                .context("state replacement requires a prior locked read")?;
            self.owner
                .directory
                .replace("state.json", bytes, observed.as_ref())?;
            self.lock.check()
        }
    }
}

#[cfg(windows)]
pub use windows::StateFile;

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    #[ignore = "native Windows NTFS/ReFS acceptance: requires actual volume flush permission"]
    fn private_state_requires_locked_read_and_rejects_stale_versions() -> Result<()> {
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-state-native-")
            .tempdir()?;
        let state = StateFile::open(&temporary.path().join("private"))?;
        let locked = state.lock()?;
        assert!(locked.replace(b"must read first").is_err());
        assert!(locked.read()?.is_none());
        locked.replace(b"one")?;
        assert!(locked.replace(b"stale absence").is_err());
        assert_eq!(locked.read()?.unwrap(), b"one");
        locked.replace(b"two")?;
        assert!(locked.replace(b"stale identity").is_err());
        drop(locked);
        let locked = state.lock()?;
        assert_eq!(locked.read()?.unwrap(), b"two");
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
pub struct StateFile;
#[cfg(not(any(unix, windows)))]
pub struct LockedState;

#[cfg(not(any(unix, windows)))]
impl StateFile {
    pub fn open(_: &Path) -> Result<Self> {
        bail!("private durable state replacement/locking is unsupported on this platform")
    }
    pub fn lock(&self) -> Result<LockedState> {
        bail!("native state locking is unsupported on this platform")
    }
}

#[cfg(not(any(unix, windows)))]
impl LockedState {
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        bail!("native state reads are unsupported on this platform")
    }
    pub fn replace(&self, _: &[u8]) -> Result<()> {
        bail!("native durable state replacement is unsupported on this platform")
    }
}
