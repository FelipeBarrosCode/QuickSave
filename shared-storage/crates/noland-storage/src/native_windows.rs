// SPDX-License-Identifier: GPL-3.0-only
//! Storage-owned Windows namespace operations missing from SourcePath's
//! no-replace restore API. SDK ABI only; no std 64-bit identity conversion.

use noland_snapshot::{native_metadata, NativeEntryKind, SourcePath, WindowsMetadata};
use noland_state_core::{Result, StateError};
use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
type Handle = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetVolumeInformationByHandleW(
        file: Handle,
        volume: *mut u16,
        volume_size: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_size: u32,
    ) -> i32;
}

pub(crate) fn verify_filesystem(file: &File) -> Result<()> {
    let mut name = [0u16; 32];
    let mut flags = 0;
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let end = name
        .iter()
        .position(|word| *word == 0)
        .ok_or_else(rejected)?;
    let name = String::from_utf16(&name[..end]).map_err(|_| rejected())?;
    if !matches!(name.as_str(), "NTFS" | "ReFS") || flags & 8 == 0 {
        return Err(StateError::UnsafePath(
            "private credential storage requires native NTFS/ReFS persistent ACLs".into(),
        ));
    }
    Ok(())
}

pub(crate) fn system_root() -> Result<std::path::PathBuf> {
    let mut text = vec![0u16; 32768];
    let count =
        unsafe { GetSystemWindowsDirectoryW(text.as_mut_ptr(), text.len() as u32) } as usize;
    if count == 0 || count >= text.len() {
        return Err(io::Error::last_os_error().into());
    }
    let path =
        std::path::PathBuf::from(String::from_utf16(&text[..count]).map_err(|_| rejected())?);
    let _ = SourcePath::new(&path)?.open_directory()?;
    Ok(path)
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: Handle,
    name: *const UnicodeString,
    attributes: u32,
    security: *const c_void,
    quality: *const c_void,
}
#[repr(C)]
#[derive(Default)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[repr(C)]
struct RenameInformation {
    replace: u8,
    root: Handle,
    length: u32,
    name: [u16; 1],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file: *mut Handle,
        access: u32,
        attributes: *const ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file: Handle,
        status: *mut IoStatus,
        information: *const c_void,
        length: u32,
        class: i32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

fn rejected() -> StateError {
    StateError::UnsafePath("private Windows storage namespace validation failed".into())
}
fn nt(status: i32) -> Result<()> {
    if status == 0x103 || status == 0x104 {
        return Err(rejected());
    }
    if status < 0 {
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    Ok(())
}
fn open(parent: &File, leaf: &str, directory: bool, access: u32, sharing: u32) -> Result<File> {
    // Only fixed internal single leaves, never arbitrary incoming native paths.
    if leaf != "."
        && (leaf.is_empty()
            || leaf == ".."
            || leaf.len() > 255
            || leaf.contains(['/', '\\', ':'])
            || leaf.chars().any(char::is_control))
    {
        return Err(rejected());
    }
    let mut encoded: Vec<u16> = leaf.encode_utf16().collect();
    let name = UnicodeString {
        length: (encoded.len() * 2) as u16,
        maximum_length: (encoded.len() * 2) as u16,
        buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: parent.as_raw_handle(),
        name: &name,
        attributes: 0x40 | 0x1000,
        security: ptr::null(),
        quality: ptr::null(),
    };
    let mut status = IoStatus::default();
    let mut raw = ptr::null_mut();
    nt(unsafe {
        NtCreateFile(
            &mut raw,
            access | 0x100000,
            &attributes,
            &mut status,
            ptr::null(),
            0,
            sharing,
            1,
            0x0020_0000 | 0x20 | if directory { 1 } else { 0x40 },
            ptr::null(),
            0,
        )
    })?;
    if raw.is_null() || raw as isize == -1 {
        return Err(rejected());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let metadata = WindowsMetadata::from_file(&file)?;
    if metadata.kind
        != if directory {
            NativeEntryKind::Directory
        } else {
            NativeEntryKind::File
        }
    {
        return Err(rejected());
    }
    Ok(file)
}

/// Sharing deletion is intentional for this owned UUID directory only. Every
/// use still compares its named leaf with this full native identity. It permits
/// checked POSIX namespace removal even while closed storage handles survive.
pub(crate) fn share_owned_directory(directory: &File) -> Result<File> {
    super::native_fs::verify_private_directory(directory)?;
    let shared = open(directory, ".", true, 0x80 | 0x20000 | 1 | 0x20, 7)?;
    super::native_fs::verify_private_directory(&shared)?;
    if WindowsMetadata::from_file(&shared)?.identity
        != WindowsMetadata::from_file(directory)?.identity
    {
        return Err(rejected());
    }
    Ok(shared)
}

pub(crate) fn directory_acl_control(directory: &File) -> Result<File> {
    let control = open(directory, ".", true, 0x80 | 0x20000 | 0x40000 | 1 | 0x20, 7)?;
    if WindowsMetadata::from_file(&control)?.identity
        != WindowsMetadata::from_file(directory)?.identity
    {
        return Err(rejected());
    }
    Ok(control)
}

pub(crate) fn replace_private_config(directory: &File) -> Result<()> {
    replace_private_file(directory, "rclone-native.tmp", "rclone.conf")
}

pub(crate) fn replace_private_file(directory: &File, temporary: &str, target: &str) -> Result<()> {
    let _validated_target = SourcePath::child(directory, target.into())?;
    super::native_fs::verify_private_directory(directory)?;
    native_metadata::flush_directory(directory)?;
    let source = SourcePath::child(directory, temporary.into())?;
    let original = source.open_regular()?;
    super::native_fs::verify_private_file(&original)?;
    let observed = WindowsMetadata::from_file(&original)?;
    drop(original);
    let destination = open(directory, target, false, 0x80 | 0x20000, 7)?;
    super::native_fs::verify_private_file(&destination)?;
    if WindowsMetadata::from_file(&destination)?.identity == observed.identity {
        return Err(rejected());
    }
    drop(destination);
    let file = open(directory, temporary, false, 0x80 | 0x20000 | 0x10000, 1)?;
    super::native_fs::verify_private_file(&file)?;
    if !WindowsMetadata::from_file(&file)?.same_file_state(&observed) {
        return Err(rejected());
    }
    let encoded: Vec<u16> = target.encode_utf16().collect();
    let length = size_of::<RenameInformation>() + encoded.len() * 2;
    let mut storage = vec![0u64; length.max(size_of::<RenameInformation>()).div_ceil(8)];
    let rename = storage.as_mut_ptr().cast::<RenameInformation>();
    unsafe {
        (*rename).replace = 1;
        (*rename).root = directory.as_raw_handle();
        (*rename).length = (encoded.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            ptr::addr_of_mut!((*rename).name).cast(),
            encoded.len(),
        );
    }
    let mut status = IoStatus::default();
    nt(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            rename.cast(),
            length as u32,
            10,
        )
    })?;
    let published = WindowsMetadata::from_file(&file)?;
    if published.identity != observed.identity
        || published.size != observed.size
        || published.last_write_time != observed.last_write_time
        || published.number_of_links != observed.number_of_links
    {
        return Err(rejected());
    }
    native_metadata::flush_directory(directory)?;
    let named = open(directory, target, false, 0x80 | 0x20000, 7)?;
    super::native_fs::verify_private_file(&named)?;
    if !published.same_file_state(&WindowsMetadata::from_file(&named)?)
        || !published.same_file_state(&WindowsMetadata::from_file(&file)?)
    {
        return Err(rejected());
    }
    Ok(())
}

pub(crate) fn remove_owned_directory(source: &SourcePath, directory: &File) -> Result<()> {
    super::native_fs::verify_private_directory(directory)?;
    let expected = WindowsMetadata::from_file(directory)?.identity;
    if source.native_identity()? != expected {
        return Err(rejected());
    }
    source.flush_parent()?;
    let control = open(directory, ".", true, 0x80 | 0x20000 | 0x10000, 7)?;
    if WindowsMetadata::from_file(&control)?.identity != expected {
        return Err(rejected());
    }
    // FILE_DISPOSITION_INFORMATION_EX: DELETE | POSIX_SEMANTICS. Unlike marking
    // delete-on-last-close, this removes the empty owned namespace entry now.
    // Unsupported filesystem/OS/permissions return the actual error, not success.
    let flags = 3u32;
    let mut status = IoStatus::default();
    nt(unsafe {
        NtSetInformationFile(
            control.as_raw_handle(),
            &mut status,
            (&flags as *const u32).cast(),
            size_of::<u32>() as u32,
            64,
        )
    })?;
    drop(control);
    source.flush_parent()?;
    match source.metadata() {
        Err(StateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(StateError::Conflict(
            "owned credential directory was not removed or was replaced".into(),
        )),
    }
}

/// Unlink only the exact owned staging leaf. Ignoring its readonly ATTRIBUTE
/// does not chmod/truncate the inode or any external hard-linked pack object.
pub(crate) fn remove_staged_file(
    parent: &File,
    leaf: &str,
    expected: &noland_snapshot::SourceMetadata,
) -> Result<()> {
    super::native_fs::verify_private_directory(parent)?;
    let file = open(parent, leaf, false, 0x80 | 0x20000 | 0x10000, 7)?;
    let observed = WindowsMetadata::from_file(&file)?;
    if expected.native_identity() != Some(observed.identity)
        || expected.len() != observed.size
        || expected.mtime_ns() != observed.mtime_ns()
        || expected.ctime_ns() != observed.ctime_ns()
    {
        return Err(rejected());
    }
    native_metadata::flush_directory(parent)?;
    let flags = 1u32 | 2 | 0x10; // DELETE | POSIX | IGNORE_READONLY_ATTRIBUTE
    let mut status = IoStatus::default();
    nt(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&flags as *const u32).cast(),
            size_of::<u32>() as u32,
            64,
        )
    })?;
    drop(file);
    native_metadata::flush_directory(parent)
}
