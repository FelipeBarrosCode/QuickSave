//! Source names are resolved one component at a time, relative to held directory
//! descriptors. A rename can detach a directory, but cannot redirect a later open
//! through its replacement. Never canonicalize a source (that follows links).
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::SourceMetadata;
use noland_state_core::{Result, StateError};

#[path = "native_metadata.rs"]
pub mod native_metadata;
#[cfg(windows)]
pub use native_metadata::WindowsMetadata;
pub use native_metadata::{NativeEntryKind, NativeIdentity};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLinkStamp {
    pub metadata: SourceMetadata,
    pub target: PathBuf,
    pub target_is_directory: Option<bool>,
}

fn validate_leaf(name: &std::ffi::OsStr) -> Result<()> {
    let text = name
        .to_str()
        .ok_or_else(|| StateError::UnsafePath("native name is not UTF-8".into()))?;
    // GPL-3.0-only native integration for the audited e81238a source fork.
    // Dataset filenames use the actual filesystem's rules, not control-ID or
    // provider-key rules. Unix colon/backslash bytes are never separators.
    noland_state_core::validate_native_component(text)
}

fn confined_link_target(relative: &Path, target: &Path) -> Result<()> {
    let relative = relative
        .to_str()
        .ok_or_else(|| StateError::UnsafePath("logical link name is not UTF-8".into()))?;
    let target = target
        .to_str()
        .ok_or_else(|| StateError::UnsafePath("logical link target is not UTF-8".into()))?;
    noland_state_core::validate_relative_symlink_target_within_root(relative, target)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CStr, CString, OsStr, OsString};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::Component;

    pub struct SourcePath {
        parent: File,
        name: OsString,
        logical_relative: Option<PathBuf>,
    }

    fn name(value: &OsStr) -> Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| StateError::UnsafePath("NUL in capture path".into()))
    }

    fn open_at(parent: &File, leaf: &OsStr, flags: libc::c_int) -> Result<File> {
        let leaf = name(leaf)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                return Err(StateError::UnsafePath(
                    "symlink or non-directory in capture path".into(),
                ));
            }
            return Err(error.into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    impl SourcePath {
        pub fn new(path: &Path) -> Result<Self> {
            Self::new_scoped(path, None)
        }

        /// Resolve a native restore target through a pinned approved boundary.
        /// Checking the boundary while opening each directory prevents an
        /// ancestor swap from redirecting later writes into a replacement tree.
        pub fn new_beneath(path: &Path, boundary: &Path, identity: (u64, u64)) -> Result<Self> {
            if !path.is_absolute()
                || !boundary.is_absolute()
                || path == boundary
                || !path.starts_with(boundary)
            {
                return Err(StateError::UnsafePath(
                    "restore target escapes its native boundary".into(),
                ));
            }
            Self::new_scoped(path, Some((boundary, identity)))
        }

        pub fn new_beneath_native(
            path: &Path,
            boundary: &Path,
            identity: NativeIdentity,
        ) -> Result<Self> {
            if identity.file_id[1] != 0 {
                return Err(StateError::UnsafePath(
                    "Unix boundary identity has a nonzero high file-ID word".into(),
                ));
            }
            Self::new_beneath(path, boundary, (identity.volume, identity.file_id[0]))
        }

        fn new_scoped(path: &Path, boundary: Option<(&Path, (u64, u64))>) -> Result<Self> {
            if path.as_os_str().as_bytes().len() > 32768 {
                return Err(StateError::UnsafePath(
                    "native source path exceeds size bound".into(),
                ));
            }
            let mut parent = File::open(if path.is_absolute() { "/" } else { "." })?;
            let mut components = Vec::new();
            for part in path.components() {
                match part {
                    Component::Normal(part) => {
                        if part.as_bytes().len() > 255 || components.len() >= 128 {
                            return Err(StateError::UnsafePath(
                                "native source path exceeds component/depth bound".into(),
                            ));
                        }
                        components.push(part);
                    }
                    Component::RootDir | Component::CurDir => {}
                    _ => {
                        return Err(StateError::UnsafePath(format!(
                            "invalid capture path: {}",
                            path.display()
                        )))
                    }
                }
            }
            let leaf = components.pop().unwrap_or(OsStr::new("."));
            let mut current = PathBuf::from(if path.is_absolute() { "/" } else { "." });
            let mut checked_boundary = boundary.is_none();
            if let Some((boundary, expected)) = boundary {
                if current == boundary {
                    use std::os::unix::fs::MetadataExt;
                    let metadata = parent.metadata()?;
                    if (metadata.dev(), metadata.ino()) != expected {
                        return Err(StateError::Conflict(
                            "native restore boundary changed".into(),
                        ));
                    }
                    checked_boundary = true;
                }
            }
            for part in components {
                parent = open_at(&parent, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
                current.push(part);
                if let Some((boundary, expected)) = boundary {
                    if current == boundary {
                        use std::os::unix::fs::MetadataExt;
                        let metadata = parent.metadata()?;
                        if (metadata.dev(), metadata.ino()) != expected {
                            return Err(StateError::Conflict(
                                "native restore boundary changed".into(),
                            ));
                        }
                        checked_boundary = true;
                    }
                }
            }
            if !checked_boundary {
                return Err(StateError::UnsafePath(
                    "native restore boundary was not anchored".into(),
                ));
            }
            Ok(Self {
                parent,
                name: leaf.to_owned(),
                logical_relative: boundary.map(|(root, _)| {
                    path.strip_prefix(root)
                        .expect("checked boundary")
                        .to_path_buf()
                }),
            })
        }

        pub fn open_regular(&self) -> Result<File> {
            // NONBLOCK prevents a replaced FIFO/device from blocking before fstat.
            let file = open_at(&self.parent, &self.name, libc::O_RDONLY | libc::O_NONBLOCK)?;
            if !file.metadata()?.is_file() {
                return Err(StateError::UnsafePath(
                    "capture source is not a regular file".into(),
                ));
            }
            Ok(file)
        }

        /// Private immutable-store reader. Explicit hard-link leases are
        /// permitted; ordinary source/recovery-key readers retain their policy.
        pub fn open_private_object(&self) -> Result<File> {
            let file = self.open_regular()?;
            native_metadata::verify_private_object(&file, true)?;
            Ok(file)
        }

        pub fn open_regular_delete_shared(&self) -> Result<File> {
            self.open_regular()
        }

        pub fn hard_link_new_to(&self, target: &Self) -> Result<()> {
            let file = self.open_private_object()?;
            let before = SourceMetadata::from_file(&file)?;
            if self.metadata()?.native_identity() != before.native_identity() {
                return Err(StateError::Conflict(
                    "hard-link source namespace changed".into(),
                ));
            }
            let source = name(&self.name)?;
            let destination = name(&target.name)?;
            if unsafe {
                libc::linkat(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    target.parent.as_raw_fd(),
                    destination.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if target.metadata()?.native_identity() != before.native_identity() {
                return Err(StateError::Conflict(
                    "hard-link publication identity changed".into(),
                ));
            }
            Ok(())
        }

        /// Delete one operation-owned regular-file name, never its aliases or a
        /// replacement. The existing quarantine primitive retains raced entries.
        pub fn remove_file_owned(&self, expected: NativeIdentity) -> Result<()> {
            let observed = self.metadata()?;
            if !observed.is_file() || observed.native_identity() != Some(expected) {
                return Err(StateError::Conflict(
                    "owned immutable file was replaced".into(),
                ));
            }
            self.delete_leaf(&observed)
        }

        pub fn open_partial_private(&self, create_new: bool) -> Result<File> {
            let leaf = name(&self.name)?;
            let flags = libc::O_RDWR
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if create_new {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                };
            let fd = unsafe { libc::openat(self.parent.as_raw_fd(), leaf.as_ptr(), flags, 0o600) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            if !file.metadata()?.is_file() {
                return Err(StateError::UnsafePath(
                    "native restore partial is not a regular file".into(),
                ));
            }
            native_metadata::verify_private(&file, false)?;
            Ok(file)
        }

        pub fn create_private_directory(&self) -> Result<()> {
            let leaf = name(&self.name)?;
            if unsafe { libc::mkdirat(self.parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let child = self.open_directory()?;
            native_metadata::verify_private(&child, true)?;
            child.sync_all()?;
            self.parent.sync_all()?;
            Ok(())
        }

        pub fn publish_new_to(&self, target: &Self) -> Result<()> {
            // Restore may already have applied an authenticated public mode.
            // Publication validates the exact inode, not a fictitious promise
            // that every restored application file remains a private key file.
            let opened = self.open_regular()?;
            use std::os::unix::fs::MetadataExt;
            if opened.metadata()?.nlink() != 1 {
                return Err(StateError::UnsafePath(
                    "native restore publication source must have one hard link".into(),
                ));
            }
            let before = SourceMetadata::from_file(&opened)?;
            if self.metadata()? != before {
                return Err(StateError::Conflict(
                    "native publication source was replaced".into(),
                ));
            }
            opened.sync_all()?;
            let source_name = name(&self.name)?;
            let target_name = name(&target.name)?;
            if unsafe {
                libc::linkat(
                    self.parent.as_raw_fd(),
                    source_name.as_ptr(),
                    target.parent.as_raw_fd(),
                    target_name.as_ptr(),
                    0,
                )
            } != 0
            {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(StateError::Conflict(
                        "native no-replace target already exists".into(),
                    ));
                }
                return Err(error.into());
            }
            let published = target.metadata()?;
            // link/unlink changes ctime and nlink; content and ownership must
            // retain the already-verified staging inode.
            if published.dev() != before.dev()
                || published.ino() != before.ino()
                || published.len() != before.len()
                || published.mtime_ns() != before.mtime_ns()
                || published.mode() != before.mode()
                || published.uid() != before.uid()
                || published.gid() != before.gid()
            {
                return Err(StateError::Conflict(
                    "native published file identity changed".into(),
                ));
            }
            target.parent.sync_all()?;
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), source_name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            opened.sync_all()?;
            self.parent.sync_all()?;
            Ok(())
        }

        pub fn flush_parent(&self) -> Result<()> {
            self.parent.sync_all()?;
            Ok(())
        }

        /// Private persistent lock file, opened relative to the held parent.
        /// Never follow a replacement symlink, truncate it, or open a device.
        pub fn open_or_create_private(&self) -> Result<File> {
            let leaf = name(&self.name)?;
            let fd = unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            if !file.metadata()?.is_file() {
                return Err(StateError::UnsafePath(
                    "repository lock is not a regular file".into(),
                ));
            }
            native_metadata::verify_private(&file, false)?;
            Ok(file)
        }

        /// Observe the final entry without following it or opening its data.
        /// Content readers must still compare with metadata from their opened
        /// descriptor, since the entry can be replaced after this observation.
        pub fn metadata(&self) -> Result<SourceMetadata> {
            let leaf = name(&self.name)?;
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // No source open and no data-read permission: fstatat observes the
            // final entry itself, relative to the already anchored parent.
            if unsafe {
                libc::fstatat(
                    self.parent.as_raw_fd(),
                    leaf.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            // A successful fstatat initialized the stat fields.
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_size < 0 {
                return Err(StateError::UnsafePath(
                    "native source has a negative length".into(),
                ));
            }
            Ok(SourceMetadata::from_stat(&metadata))
        }

        pub fn read_link(&self) -> Result<PathBuf> {
            let leaf = name(&self.name)?;
            let mut bytes = vec![0u8; 256];
            loop {
                let count = unsafe {
                    libc::readlinkat(
                        self.parent.as_raw_fd(),
                        leaf.as_ptr(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if count < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if (count as usize) < bytes.len() {
                    bytes.truncate(count as usize);
                    return Ok(PathBuf::from(OsString::from_vec(bytes)));
                }
                if bytes.len() >= 64 * 1024 {
                    return Err(StateError::UnsafePath(
                        "capture symlink target is too long".into(),
                    ));
                }
                bytes.resize(bytes.len() * 2, 0);
            }
        }

        pub fn native_link_stamp(&self) -> Result<SourceLinkStamp> {
            let before = self.metadata()?;
            if !before.is_symlink() {
                return Err(StateError::UnsafePath(
                    "entry is not a native symbolic link".into(),
                ));
            }
            let target = self.read_link()?;
            if self.metadata()? != before {
                return Err(StateError::Conflict(
                    "native symbolic link changed while reading".into(),
                ));
            }
            Ok(SourceLinkStamp {
                metadata: before,
                target,
                target_is_directory: None,
            })
        }

        pub fn create_new_relative_symlink(
            &self,
            target: &Path,
            logical_relative: &Path,
            target_is_directory: Option<bool>,
        ) -> Result<SourceLinkStamp> {
            if self.logical_relative.as_deref() != Some(logical_relative) {
                return Err(StateError::UnsafePath(
                    "symbolic-link creation requires its pinned approved logical root".into(),
                ));
            }
            confined_link_target(logical_relative, target)?;
            if target_is_directory.is_some() {
                return Err(StateError::UnsafePath(
                    "Unix symbolic links have no directory-link bit".into(),
                ));
            }
            let target = CString::new(target.as_os_str().as_bytes())
                .map_err(|_| StateError::UnsafePath("NUL in symbolic-link target".into()))?;
            let leaf = name(&self.name)?;
            if unsafe { libc::symlinkat(target.as_ptr(), self.parent.as_raw_fd(), leaf.as_ptr()) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let observed = self.native_link_stamp()?;
            if observed.target.as_os_str().as_bytes() != target.as_bytes() {
                return Err(StateError::Conflict(
                    "new native symlink does not match its authenticated target".into(),
                ));
            }
            self.parent.sync_all()?;
            if self.native_link_stamp()? != observed {
                return Err(StateError::Conflict(
                    "new native symlink changed before commit".into(),
                ));
            }
            Ok(observed)
        }

        pub fn native_identity(&self) -> Result<NativeIdentity> {
            let metadata = self.metadata()?;
            Ok(NativeIdentity {
                volume: metadata.dev(),
                file_id: [metadata.ino(), 0],
            })
        }

        pub fn parent_native_identity(&self) -> Result<NativeIdentity> {
            let (volume, inode) = self.parent_identity()?;
            Ok(NativeIdentity {
                volume,
                file_id: [inode, 0],
            })
        }

        pub fn parent_identity(&self) -> Result<(u64, u64)> {
            use std::os::unix::fs::MetadataExt;
            let metadata = self.parent.metadata()?;
            Ok((metadata.dev(), metadata.ino()))
        }

        /// Empty-directory removal only; never follows or recursively sweeps a
        /// replacement. Kernel AT_REMOVEDIR refuses symlinks and nonempty trees.
        pub fn remove_empty_directory(&self) -> Result<()> {
            if !self.metadata()?.is_dir() {
                return Err(StateError::UnsafePath("expected an empty directory".into()));
            }
            let leaf = name(&self.name)?;
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), leaf.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            self.parent.sync_all()?;
            Ok(())
        }

        pub fn remove_empty_directory_owned(&self, expected: NativeIdentity) -> Result<()> {
            if self.native_identity()? != expected {
                return Err(StateError::Conflict("owned directory was replaced".into()));
            }
            self.remove_empty_directory()
        }

        /// Move a leaf into a private, same-filesystem quarantine before unlink.
        /// A replacement racing the rename is retained there, never deleted.
        /// Directories and symlink traversal are deliberately unsupported.
        pub fn delete_leaf(&self, expected: &SourceMetadata) -> Result<()> {
            if !(expected.is_file() || expected.is_symlink()) || self.metadata()? != *expected {
                return Err(StateError::Conflict(
                    "file changed since deletion preview".into(),
                ));
            }
            let quarantine = OsString::from(format!(".noland-delete-{}", uuid::Uuid::new_v4()));
            let quarantine_c = name(&quarantine)?;
            if unsafe { libc::mkdirat(self.parent.as_raw_fd(), quarantine_c.as_ptr(), 0o700) } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let directory = open_at(
                &self.parent,
                &quarantine,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let source = name(&self.name)?;
            let entry = name(OsStr::new("entry"))?;
            if unsafe {
                libc::renameat(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    entry.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            self.parent.sync_all()?;
            directory.sync_all()?;
            let observed = Self::child(&directory, OsString::from("entry"))?.metadata()?;
            // rename changes ctime; all other identity/content fields must agree.
            if observed.dev() != expected.dev()
                || observed.ino() != expected.ino()
                || observed.len() != expected.len()
                || observed.mtime_ns() != expected.mtime_ns()
                || observed.mode() != expected.mode()
                || observed.uid() != expected.uid()
                || observed.gid() != expected.gid()
            {
                return Err(StateError::Conflict(format!(
                    "raced deletion entry retained in {}/entry beside the source",
                    quarantine.to_string_lossy()
                )));
            }
            if unsafe { libc::unlinkat(directory.as_raw_fd(), entry.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            directory.sync_all()?;
            if unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    quarantine_c.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            self.parent.sync_all()?;
            Ok(())
        }

        pub fn open_directory(&self) -> Result<File> {
            open_at(&self.parent, &self.name, libc::O_RDONLY | libc::O_DIRECTORY)
        }

        /// Anchor a child to an already-owned directory handle. The ordinary
        /// no-follow/component checks still apply to every operation.
        pub fn child(parent: &File, name: OsString) -> Result<Self> {
            validate_leaf(&name)?;
            if !parent.metadata()?.is_dir() {
                return Err(StateError::UnsafePath(
                    "native child parent is not a directory".into(),
                ));
            }
            Ok(Self {
                parent: parent.try_clone()?,
                name,
                logical_relative: None,
            })
        }
    }

    pub(crate) fn directory_names(directory: &File) -> Result<Vec<OsString>> {
        // fdopendir takes ownership. Opening '.' gives enumeration its own offset.
        let file = open_at(
            directory,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        let stream = unsafe { libc::fdopendir(fd) };
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
        let mut name_bytes = 0usize;
        loop {
            // POSIX readdir distinguishes EOF from errors via errno.
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "android")]
            unsafe {
                *libc::__errno() = 0;
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
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes != b"." && bytes != b".." {
                if names.len() >= 1_000_000 {
                    return Err(StateError::UnsafePath(
                        "native directory exceeds entry limit".into(),
                    ));
                }
                name_bytes = name_bytes.checked_add(bytes.len()).ok_or_else(|| {
                    StateError::UnsafePath("native directory name budget overflow".into())
                })?;
                if name_bytes > 128 * 1024 * 1024 {
                    return Err(StateError::UnsafePath(
                        "native directory exceeds name-memory limit".into(),
                    ));
                }
                validate_leaf(OsStr::from_bytes(bytes))?;
                names.push(OsString::from_vec(bytes.to_vec()));
            }
        }
        Ok(names)
    }
}

#[cfg(unix)]
pub(crate) use unix::directory_names;
#[cfg(unix)]
pub use unix::SourcePath;

#[cfg(windows)]
#[path = "windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::directory_names;
#[cfg(windows)]
pub use windows::SourcePath;

#[cfg(not(any(unix, windows)))]
pub struct SourcePath;
#[cfg(not(any(unix, windows)))]
impl SourcePath {
    pub fn new(_: &Path) -> Result<Self> {
        Err(StateError::UnsafePath(
            "descriptor-anchored capture is unsupported on this platform".into(),
        ))
    }
    pub fn open_regular(&self) -> Result<File> {
        Err(StateError::UnsafePath(
            "native regular-file opens are unsupported on this platform".into(),
        ))
    }
    pub fn open_or_create_private(&self) -> Result<File> {
        Err(StateError::UnsafePath(
            "native private creation is unsupported on this platform".into(),
        ))
    }
    pub fn metadata(&self) -> Result<SourceMetadata> {
        Err(StateError::UnsafePath(
            "native no-follow metadata is unsupported on this platform".into(),
        ))
    }
    pub fn read_link(&self) -> Result<PathBuf> {
        Err(StateError::UnsafePath(
            "native no-follow link inspection is unsupported on this platform".into(),
        ))
    }
    pub fn parent_identity(&self) -> Result<(u64, u64)> {
        Err(StateError::UnsafePath(
            "native parent identity is unsupported on this platform".into(),
        ))
    }
    pub fn remove_empty_directory(&self) -> Result<()> {
        Err(StateError::UnsafePath(
            "native directory removal is unsupported on this platform".into(),
        ))
    }
    pub fn delete_leaf(&self, _: &SourceMetadata) -> Result<()> {
        Err(StateError::UnsafePath(
            "native leaf deletion is unsupported on this platform".into(),
        ))
    }
}

pub fn open_regular_nofollow(path: &Path) -> Result<File> {
    SourcePath::new(path)?.open_regular()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    #[test]
    fn explicit_leaf_deletion_preserves_symlink_targets_and_rejects_replacements() {
        let root = std::env::current_dir()
            .unwrap()
            .join(format!("target/delete-leaf-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let outside = root.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        let link = root.join("link");
        symlink(&outside, &link).unwrap();
        let source = SourcePath::new(&link).unwrap();
        source.delete_leaf(&source.metadata().unwrap()).unwrap();
        assert!(!link.exists());
        assert!(outside.exists());
        let source = SourcePath::new(&outside).unwrap();
        let original = source.metadata().unwrap();
        std::fs::rename(&outside, root.join("old")).unwrap();
        std::fs::write(&outside, b"new").unwrap();
        assert!(source.delete_leaf(&original).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"new");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metadata_does_not_require_file_data_read_permission() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::current_dir()
            .unwrap()
            .join(format!("target/metadata-only-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("unreadable");
        std::fs::write(&path, b"metadata only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let metadata = SourcePath::new(&path).unwrap().metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 13);
        assert_eq!(metadata.mode() & 0o777, 0);
        assert!(crate::same_file_identity(
            &metadata,
            &std::fs::symlink_metadata(&path).unwrap()
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn held_parent_cannot_be_redirected_by_ancestor_or_leaf_replacement() {
        let root = std::env::current_dir()
            .unwrap()
            .join(format!("target/anchored-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("owned/nested")).unwrap();
        std::fs::create_dir_all(root.join("outside/nested")).unwrap();
        std::fs::write(root.join("owned/nested/save"), b"owned").unwrap();
        std::fs::write(root.join("outside/nested/save"), b"outside").unwrap();
        let path = root.join("owned/nested/save");
        let anchored = SourcePath::new(&path).unwrap();
        let before = anchored.metadata().unwrap();
        std::fs::rename(root.join("owned"), root.join("detached")).unwrap();
        symlink(root.join("outside"), root.join("owned")).unwrap();
        assert!(crate::same_file_identity(
            &before,
            &anchored.metadata().unwrap()
        ));
        let mut bytes = Vec::new();
        anchored
            .open_regular()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"owned");
        assert!(open_regular_nofollow(&path).is_err());
        let leaf = root.join("detached/nested/save");
        std::fs::remove_file(&leaf).unwrap();
        symlink(root.join("outside/nested/save"), &leaf).unwrap();
        assert!(anchored.open_regular().is_err());
        assert!(anchored.metadata().unwrap().is_symlink());
        assert!(!crate::same_file_identity(
            &before,
            &anchored.metadata().unwrap()
        ));
        std::fs::remove_file(root.join("outside/nested/save")).unwrap();
        assert!(anchored.metadata().unwrap().is_symlink());
        assert!(crate::same_file_identity(
            &anchored.metadata().unwrap(),
            &std::fs::symlink_metadata(&leaf).unwrap()
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
