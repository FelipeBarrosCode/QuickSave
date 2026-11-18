// SPDX-License-Identifier: GPL-3.0-only
//! Original native metadata adapter for the audited fork. ABI declarations are
//! from the Windows SDK; no Unix ownership or truncated Windows IDs are invented.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeIdentity {
    pub volume: u64,
    pub file_id: [u64; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeEntryKind {
    File,
    Directory,
    Symlink,
}

pub fn identity_from_file(file: &std::fs::File) -> noland_state_core::Result<NativeIdentity> {
    #[cfg(windows)]
    return Ok(WindowsMetadata::from_file(file)?.identity);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        return Ok(NativeIdentity {
            volume: metadata.dev(),
            file_id: [metadata.ino(), 0],
        });
    }
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native file identity is unsupported".into(),
    ))
}

pub fn flush_directory(file: &std::fs::File) -> noland_state_core::Result<()> {
    #[cfg(windows)]
    return super::windows::flush_directory(file);
    #[cfg(unix)]
    {
        if !file.metadata()?.is_dir() {
            return Err(noland_state_core::StateError::UnsafePath(
                "expected native directory for durability barrier".into(),
            ));
        }
        file.sync_all()?;
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native directory durability is unsupported".into(),
    ))
}

pub fn verify_private_file(file: &std::fs::File) -> noland_state_core::Result<()> {
    #[cfg(windows)]
    return super::windows::verify_private(file, false);
    #[cfg(unix)]
    return verify_private(file, false);
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native private-file verification is unsupported".into(),
    ))
}

pub fn verify_private_directory(file: &std::fs::File) -> noland_state_core::Result<()> {
    #[cfg(windows)]
    return super::windows::verify_private(file, true);
    #[cfg(unix)]
    return verify_private(file, true);
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native private-directory verification is unsupported".into(),
    ))
}

/// Privacy/identity check for a private directory with legitimate concurrent
/// child creation. Entry timestamps are NOT content or ACL stability evidence.
/// This is not a snapshot proof and does not replace strict file verification.
pub fn verify_private_directory_live(file: &std::fs::File) -> noland_state_core::Result<()> {
    #[cfg(windows)]
    return super::windows::verify_private_directory_live(file);
    #[cfg(unix)]
    return verify_private_policy_inner(file, true, false, false, true);
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native live-directory privacy is unsupported".into(),
    ))
}

/// Immutable CAS/pack objects may be readonly and explicitly hard-link leased.
/// This policy never relaxes recovery-key or private-state verification.
pub fn verify_private_object(
    file: &std::fs::File,
    allow_hard_links: bool,
) -> noland_state_core::Result<()> {
    #[cfg(windows)]
    return super::windows::verify_private_policy(file, false, allow_hard_links);
    #[cfg(unix)]
    return verify_private_policy(file, false, true, allow_hard_links);
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "private immutable-object verification is unsupported".into(),
    ))
}

pub fn link_count(file: &std::fs::File) -> noland_state_core::Result<u64> {
    #[cfg(windows)]
    return Ok(WindowsMetadata::from_file(file)?.number_of_links as u64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(file.metadata()?.nlink());
    }
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native link counts are unsupported".into(),
    ))
}

pub fn directory_names(
    directory: &std::fs::File,
) -> noland_state_core::Result<Vec<std::ffi::OsString>> {
    #[cfg(any(unix, windows))]
    return super::directory_names(directory);
    #[cfg(not(any(unix, windows)))]
    Err(noland_state_core::StateError::UnsafePath(
        "native directory enumeration is unsupported".into(),
    ))
}

/// Persistent-inode private lock for standalone repository/database adapters.
/// Immutable object verification is separate: it does not weaken this strict
/// single-link private lock-file policy.
/// The caller also validates the lock's parent/name against the held namespace.
pub struct ScopedFileLock {
    file: std::fs::File,
    identity: NativeIdentity,
}

impl ScopedFileLock {
    pub fn lock(file: &std::fs::File) -> noland_state_core::Result<Self> {
        Self::lock_kind(file, true)
    }

    pub fn lock_shared(file: &std::fs::File) -> noland_state_core::Result<Self> {
        Self::lock_kind(file, false)
    }

    fn lock_kind(file: &std::fs::File, exclusive: bool) -> noland_state_core::Result<Self> {
        verify_private_file(file)?;
        let file = file.try_clone()?;
        let identity = identity_from_file(&file)?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut overlapped = ffi::Overlapped::default();
            if unsafe {
                ffi::LockFileEx(
                    file.as_raw_handle(),
                    if exclusive { 2 } else { 0 },
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe {
                libc::flock(
                    file.as_raw_fd(),
                    if exclusive {
                        libc::LOCK_EX
                    } else {
                        libc::LOCK_SH
                    },
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err(noland_state_core::StateError::UnsafePath(
            "native scoped file locking is unsupported".into(),
        ));
        let lock = Self { file, identity };
        lock.check()?;
        Ok(lock)
    }

    pub fn check(&self) -> noland_state_core::Result<()> {
        verify_private_file(&self.file)?;
        if identity_from_file(&self.file)? != self.identity {
            return Err(noland_state_core::StateError::Conflict(
                "scoped native lock identity changed".into(),
            ));
        }
        Ok(())
    }

    pub fn identity(&self) -> NativeIdentity {
        self.identity
    }
}

impl Drop for ScopedFileLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut overlapped = ffi::Overlapped::default();
            unsafe { ffi::UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

impl crate::SourceMetadata {
    /// Prefer this over `fs::Metadata` conversion when identity is security-
    /// relevant: Rust's legacy Windows metadata exposes only a 64-bit file index.
    pub fn from_file(file: &std::fs::File) -> noland_state_core::Result<Self> {
        #[cfg(windows)]
        return Ok(Self::from_windows(&WindowsMetadata::from_file(file)?));
        #[cfg(unix)]
        return Ok(Self::from(&file.metadata()?));
        #[cfg(not(any(unix, windows)))]
        Err(noland_state_core::StateError::UnsafePath(
            "native source metadata is unsupported".into(),
        ))
    }
}

/// Raw FILETIME values are 100-nanosecond ticks since 1601, not Unix seconds.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsMetadata {
    pub identity: NativeIdentity,
    pub size: u64,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
    pub number_of_links: u32,
    pub reparse_tag: u32,
    pub kind: NativeEntryKind,
}

#[cfg(windows)]
impl WindowsMetadata {
    /// Reads can change access time. Access time is recorded, but is not a
    /// content/identity-stability signal.
    pub fn same_file_state(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.size == other.size
            && self.creation_time == other.creation_time
            && self.last_write_time == other.last_write_time
            && self.change_time == other.change_time
            && self.attributes == other.attributes
            && self.number_of_links == other.number_of_links
            && self.reparse_tag == other.reparse_tag
            && self.kind == other.kind
    }

    pub fn from_file(file: &std::fs::File) -> noland_state_core::Result<Self> {
        use ffi::*;
        use noland_state_core::StateError;
        use std::os::windows::io::AsRawHandle;
        if unsafe { GetFileType(file.as_raw_handle()) } != 1 {
            return Err(StateError::UnsafePath(
                "native source is not a disk file".into(),
            ));
        }
        let basic: BasicInfo = query(file, 0)?;
        let standard: StandardInfo = query(file, 1)?;
        let id: IdInfo = query(file, 18)?;
        if basic.attributes & 0x40 != 0
            || standard.delete_pending != 0
            || standard.number_of_links == 0
            || id.id == [0; 16]
            || standard.end_of_file < 0
        {
            return Err(StateError::UnsafePath(
                "unsupported native entry or missing 128-bit file identity".into(),
            ));
        }
        let directory = basic.attributes & 0x10 != 0;
        if directory != (standard.directory != 0) {
            return Err(StateError::Integrity(
                "inconsistent native directory metadata".into(),
            ));
        }
        let mut tag = 0;
        let kind = if basic.attributes & 0x400 != 0 {
            let observed: TagInfo = query(file, 9)?;
            if observed.attributes != basic.attributes || observed.tag != 0xa000_000c {
                return Err(StateError::UnsafePath(
                    "junctions and unknown reparse tags are unsupported".into(),
                ));
            }
            tag = observed.tag;
            NativeEntryKind::Symlink
        } else if directory {
            NativeEntryKind::Directory
        } else {
            NativeEntryKind::File
        };
        Ok(Self {
            identity: NativeIdentity {
                volume: id.volume,
                file_id: [
                    u64::from_le_bytes(id.id[..8].try_into().unwrap()),
                    u64::from_le_bytes(id.id[8..].try_into().unwrap()),
                ],
            },
            size: standard.end_of_file as u64,
            creation_time: basic.creation_time,
            last_access_time: basic.last_access_time,
            last_write_time: basic.last_write_time,
            change_time: basic.change_time,
            attributes: basic.attributes,
            number_of_links: standard.number_of_links,
            reparse_tag: tag,
            kind,
        })
    }

    pub fn is_directory_link(&self) -> bool {
        self.kind == NativeEntryKind::Symlink && self.attributes & 0x10 != 0
    }

    pub fn modified(&self) -> Option<std::time::SystemTime> {
        let ticks = self.last_write_time as i128 - 116_444_736_000_000_000i128;
        let nanos = ticks.checked_mul(100)?;
        let duration = std::time::Duration::new(
            u64::try_from(nanos.unsigned_abs() / 1_000_000_000).ok()?,
            (nanos.unsigned_abs() % 1_000_000_000) as u32,
        );
        if nanos >= 0 {
            std::time::UNIX_EPOCH.checked_add(duration)
        } else {
            std::time::UNIX_EPOCH.checked_sub(duration)
        }
    }

    pub fn mtime_ns(&self) -> Option<i64> {
        i64::try_from((self.last_write_time as i128 - 116_444_736_000_000_000i128) * 100).ok()
    }

    pub fn ctime_ns(&self) -> Option<i64> {
        i64::try_from((self.change_time as i128 - 116_444_736_000_000_000i128) * 100).ok()
    }
}

/// Windows has no native Unix mode/UID/GID fidelity. Cross-platform restore must
/// reject those requested fields, not apply synthetic zeros or silent no-ops.
#[cfg(windows)]
pub fn apply_file_metadata(
    file: &std::fs::File,
    mode: Option<u32>,
    mtime_ns: Option<i64>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> noland_state_core::Result<()> {
    use noland_state_core::{Result, StateError};
    use std::{io, mem::size_of, os::windows::io::AsRawHandle};
    if mode.is_some() || uid.is_some() || gid.is_some() {
        return Err(StateError::Invalid(
            "Unix mode/UID/GID metadata cannot be faithfully applied on Windows".into(),
        ));
    }
    let before = WindowsMetadata::from_file(file)?;
    if before.kind == NativeEntryKind::Symlink {
        return Err(StateError::UnsafePath(
            "file metadata helper does not follow symbolic links".into(),
        ));
    }
    let Some(nanos) = mtime_ns else {
        return Ok(());
    };
    if nanos % 100 != 0 {
        return Err(StateError::Invalid(
            "mtime is not exactly representable by Windows 100-nanosecond FILETIME".into(),
        ));
    }
    let ticks = i64::try_from(nanos as i128 / 100 + 116_444_736_000_000_000i128)
        .map_err(|_| StateError::Invalid("mtime exceeds native FILETIME range".into()))?;
    if ticks <= 0 {
        return Err(StateError::Invalid(
            "mtime predates supported native FILETIME range".into(),
        ));
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            file: ffi::Handle,
            class: i32,
            info: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let info = ffi::BasicInfo {
        creation_time: 0,
        last_access_time: 0,
        last_write_time: ticks,
        change_time: 0,
        attributes: 0,
    };
    let set = (|| -> Result<()> {
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                0,
                (&info as *const ffi::BasicInfo).cast(),
                size_of::<ffi::BasicInfo>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let after = WindowsMetadata::from_file(file)?;
        if after.identity != before.identity || after.last_write_time != ticks {
            return Err(StateError::Conflict(
                "native identity/mtime changed during metadata application".into(),
            ));
        }
        Ok(())
    })();
    set
}

#[cfg(unix)]
pub(crate) fn verify_private(
    file: &std::fs::File,
    directory: bool,
) -> noland_state_core::Result<()> {
    verify_private_policy(file, directory, false, false)
}

#[cfg(unix)]
fn verify_private_policy(
    file: &std::fs::File,
    directory: bool,
    allow_readonly: bool,
    allow_hard_links: bool,
) -> noland_state_core::Result<()> {
    verify_private_policy_inner(file, directory, allow_readonly, allow_hard_links, false)
}

#[cfg(unix)]
fn verify_private_policy_inner(
    file: &std::fs::File,
    directory: bool,
    allow_readonly: bool,
    allow_hard_links: bool,
    mutable_namespace: bool,
) -> noland_state_core::Result<()> {
    use noland_state_core::StateError;
    use std::{
        io,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    let before = file.metadata()?;
    let check = |metadata: &std::fs::Metadata| -> noland_state_core::Result<()> {
        if (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }) || metadata.uid() != unsafe { libc::geteuid() }
            || !(metadata.mode() & 0o7777 == (if directory { 0o700 } else { 0o600 })
                || (!directory && allow_readonly && metadata.mode() & 0o7777 == 0o400))
            || (if directory {
                metadata.nlink() == 0
            } else {
                if allow_hard_links {
                    metadata.nlink() == 0
                } else {
                    metadata.nlink() != 1
                }
            })
        {
            return Err(StateError::UnsafePath(
                "native private entry ownership, mode, type, or link count is invalid".into(),
            ));
        }
        Ok(())
    };
    check(&before)?;
    #[cfg(target_os = "linux")]
    {
        let mut native = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), native.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let kind = unsafe { native.assume_init() }.f_type as u32;
        if ![
            libc::EXT4_SUPER_MAGIC as u32,
            0x5846_5342,
            libc::BTRFS_SUPER_MAGIC as u32,
            libc::TMPFS_MAGIC as u32,
            libc::F2FS_SUPER_MAGIC as u32,
            libc::OVERLAYFS_SUPER_MAGIC as u32,
        ]
        .contains(&kind)
        {
            return Err(StateError::UnsafePath(
                "private ACL verification is unsupported for this filesystem".into(),
            ));
        }
        for name in [
            Some(c"system.posix_acl_access"),
            directory.then_some(c"system.posix_acl_default"),
        ]
        .into_iter()
        .flatten()
        {
            let result = unsafe {
                libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0)
            };
            if result >= 0 {
                return Err(StateError::UnsafePath(
                    "private native entry has an extended ACL".into(),
                ));
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
                return Err(io::Error::last_os_error().into());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut std::ffi::c_void;
            fn acl_free(acl: *mut std::ffi::c_void) -> libc::c_int;
        }
        let mut native = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), native.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let native = unsafe { native.assume_init() };
        let name: Vec<u8> = native
            .f_fstypename
            .iter()
            .map(|byte| *byte as u8)
            .take_while(|byte| *byte != 0)
            .collect();
        if name != b"apfs" && name != b"hfs" {
            return Err(StateError::UnsafePath(
                "private ACL verification requires APFS/HFS".into(),
            ));
        }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        if !acl.is_null() {
            unsafe { acl_free(acl) };
            return Err(StateError::UnsafePath(
                "private native entry has extended ACL metadata".into(),
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(StateError::UnsafePath(
        "private ACL verification is unsupported on this Unix target".into(),
    ));
    let after = file.metadata()?;
    check(&after)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || (!mutable_namespace
            && (before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()))
    {
        return Err(StateError::Conflict(
            "private native entry changed during ACL inspection".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod ffi {
    use noland_state_core::Result;
    use std::{
        ffi::c_void,
        fs::File,
        io,
        mem::{size_of, MaybeUninit},
        os::windows::io::AsRawHandle,
    };

    pub type Handle = *mut c_void;
    #[repr(C)]
    #[derive(Default)]
    pub struct Overlapped {
        pub internal: usize,
        pub internal_high: usize,
        pub offset: u32,
        pub offset_high: u32,
        pub event: Handle,
    }
    #[repr(C)]
    pub struct BasicInfo {
        pub creation_time: i64,
        pub last_access_time: i64,
        pub last_write_time: i64,
        pub change_time: i64,
        pub attributes: u32,
    }
    #[repr(C)]
    pub struct StandardInfo {
        pub allocation_size: i64,
        pub end_of_file: i64,
        pub number_of_links: u32,
        pub delete_pending: u8,
        pub directory: u8,
    }
    #[repr(C)]
    pub struct IdInfo {
        pub volume: u64,
        pub id: [u8; 16],
    }
    #[repr(C)]
    pub struct TagInfo {
        pub attributes: u32,
        pub tag: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetFileInformationByHandleEx(
            file: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        pub fn GetFileType(file: Handle) -> u32;
        pub fn LockFileEx(
            file: Handle,
            flags: u32,
            reserved: u32,
            low: u32,
            high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        pub fn UnlockFileEx(
            file: Handle,
            reserved: u32,
            low: u32,
            high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }

    pub fn query<T>(file: &File, class: i32) -> Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                value.as_mut_ptr().cast(),
                size_of::<T>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { value.assume_init() })
    }
}
