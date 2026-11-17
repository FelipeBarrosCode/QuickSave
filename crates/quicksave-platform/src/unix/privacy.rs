// SPDX-License-Identifier: GPL-3.0-only
//! Strict handle-based ACL inspection. Unknown filesystem ACL models do not
//! inherit a successful "private" result from Unix permission bits.

use anyhow::{bail, ensure, Context, Result};
use std::{fs::File, io, mem::MaybeUninit, os::fd::AsRawFd};

pub(super) fn reject_extended_acl(file: &File, directory: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = directory;
        macos(file)
    }
    #[cfg(target_os = "linux")]
    {
        linux(file, directory)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (file, directory);
        bail!("native ACL privacy verification is unsupported on this Unix platform")
    }
}

#[cfg(target_os = "macos")]
fn macos(file: &File) -> Result<()> {
    use std::ffi::c_void;

    // ABI declarations/constants from the platform SDK's sys/acl.h. ACL objects
    // remain opaque; no Apple ACL implementation code is copied.
    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry: libc::c_int,
            output: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_valid(acl: *mut c_void) -> libc::c_int;
        fn acl_size(acl: *mut c_void) -> libc::ssize_t;
        fn acl_free(acl: *mut c_void) -> libc::c_int;
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: acl_get_fd_np returned this owned ACL exactly once.
            unsafe { acl_free(self.0) };
        }
    }

    let mut native = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: file is live and fstatfs initializes native on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), native.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("inspect private file's native filesystem");
    }
    let native = unsafe { native.assume_init() };
    let name: Vec<u8> = native
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect();
    ensure!(
        name == b"apfs" || name == b"hfs",
        "private ACL verification supports only native APFS/HFS filesystems on macOS"
    );

    // SAFETY: this is a live native descriptor and the SDK's extended ACL type.
    let pointer = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if pointer.is_null() {
        let error = io::Error::last_os_error();
        // On a valid APFS/HFS descriptor, Darwin returns ENOENT when no extended
        // ACL is attached. The caller fstats before/after and requires a live,
        // linked regular file or directory, ruling out an absent object.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error).context("cannot verify native macOS extended ACL");
    }
    let acl = Acl(pointer);
    // SAFETY: native ACL is owned, live, and independent of subsequent updates.
    if unsafe { acl_valid(acl.0) } != 0 {
        return Err(io::Error::last_os_error()).context("native ACL is not valid");
    }
    let size = unsafe { acl_size(acl.0) };
    ensure!(
        (1..=65_536).contains(&size),
        "native ACL exceeds its supported size bound"
    );
    let mut entry = std::ptr::null_mut();
    // Darwin returns 0 for an entry (NOT POSIX's 1), and -1/EINVAL at the end.
    let status = unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) };
    if status == 0 {
        bail!("private file/directory has an extended ACL; refusing all ACL entries");
    }
    let error = io::Error::last_os_error();
    if status == -1 && error.raw_os_error() == Some(libc::EINVAL) && entry.is_null() {
        // Even an explicit empty ACL can carry inheritance flags. Do not
        // interpret unknown/deferred inheritance policy as proof of privacy.
        bail!("explicit macOS extended ACL metadata is unsupported for private files/directories");
    }
    Err(error).context("cannot enumerate native macOS extended ACL")
}

#[cfg(target_os = "linux")]
fn linux(file: &File, directory: bool) -> Result<()> {
    let mut native = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: file is live and fstatfs initializes native on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), native.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("inspect private file's native filesystem");
    }
    let kind = unsafe { native.assume_init() }.f_type as u32;
    ensure!(
        [
            libc::EXT4_SUPER_MAGIC as u32,
            0x5846_5342, // XFS_SUPER_MAGIC (not exposed by every libc target)
            libc::BTRFS_SUPER_MAGIC as u32,
            libc::TMPFS_MAGIC as u32,
            libc::F2FS_SUPER_MAGIC as u32,
            libc::OVERLAYFS_SUPER_MAGIC as u32,
        ]
        .contains(&kind),
        "private ACL verification is unsupported for this Linux filesystem's ACL model"
    );
    for name in [
        Some(c"system.posix_acl_access"),
        directory.then_some(c"system.posix_acl_default"),
    ]
    .into_iter()
    .flatten()
    {
        // A zero-length query inspects presence without allocating arbitrary
        // xattr input. ENODATA is the only accepted absence result. ENOTSUP,
        // permission, I/O, and unknown errors are explicit verification failures.
        let size =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size >= 0 {
            bail!("private file/directory has a POSIX ACL; refusing all ACL entries");
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENODATA) {
            return Err(error).context("cannot verify native Linux POSIX ACL");
        }
    }
    Ok(())
}
