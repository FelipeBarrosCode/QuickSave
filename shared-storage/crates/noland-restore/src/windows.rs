// SPDX-License-Identifier: GPL-3.0-only
//! Handle-only Windows metadata/ACL and bounded directory enumeration adapter.
//! ABI declarations follow the Windows SDK. Native NT lookup/enumeration derives
//! from the active audited noland-snapshot Windows adapter; original notices and
//! No Land e81238a7536aae201540956ce76981364fd36595 provenance are preserved.
//! No keychain, account, network, executable or credential operations.
use crate::native::NativeWindowsSecurity;
use noland_snapshot::native_metadata::{NativeEntryKind, WindowsMetadata};
use noland_state_core::{Result, StateError};
use std::{
    collections::BTreeMap,
    ffi::{c_void, OsStr, OsString},
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::Path,
    ptr,
    sync::OnceLock,
};

type Handle = *mut c_void;
const READ_ATTRIBUTES: u32 = 0x80;
const READ_CONTROL: u32 = 0x20000;
const SYNCHRONIZE: u32 = 0x100000;
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
struct DirectoryInformation {
    next: u32,
    index: u32,
    creation: i64,
    access: i64,
    write: i64,
    change: i64,
    end: i64,
    allocation: i64,
    attributes: u32,
    name_length: u32,
    ea_size: u32,
    reparse_tag: u32,
    file_id: [u8; 16],
    name: [u16; 1],
}
#[repr(C)]
struct TokenUser {
    sid: Handle,
    attributes: u32,
}
#[repr(C)]
struct Acl {
    revision: u8,
    reserved: u8,
    size: u16,
    count: u16,
    reserved2: u16,
}
#[repr(C)]
struct Ace {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
    sid: u32,
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
    fn NtQueryDirectoryFile(
        file: Handle,
        event: Handle,
        apc: *const c_void,
        context: *const c_void,
        status: *mut IoStatus,
        info: *mut c_void,
        length: u32,
        class: i32,
        single: u8,
        name: *const UnicodeString,
        restart: u8,
    ) -> i32;
    fn NtQueryInformationFile(
        file: Handle,
        status: *mut IoStatus,
        info: *mut c_void,
        length: u32,
        class: i32,
    ) -> i32;
    fn NtSetInformationFile(
        file: Handle,
        status: *mut IoStatus,
        info: *const c_void,
        length: u32,
        class: i32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
#[link(name = "normaliz")]
unsafe extern "system" {
    fn NormalizeString(
        form: i32,
        source: *const u16,
        source_length: i32,
        destination: *mut u16,
        destination_length: i32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThread() -> Handle;
    fn DeviceIoControl(
        file: Handle,
        control: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        info: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn GetKernelObjectSecurity(
        file: Handle,
        info: u32,
        descriptor: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn IsValidSecurityDescriptor(descriptor: *mut c_void) -> i32;
    fn IsValidSid(sid: Handle) -> i32;
    fn GetLengthSid(sid: Handle) -> u32;
    fn GetSecurityDescriptorOwner(
        descriptor: *mut c_void,
        owner: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: *mut i32,
        acl: *mut *mut Acl,
        defaulted: *mut i32,
    ) -> i32;
    fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn EqualSid(left: Handle, right: Handle) -> i32;
    fn IsWellKnownSid(sid: Handle, kind: i32) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        length: *mut u32,
    ) -> i32;
}

fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(StateError::UnsafePath(message.into()))
    }
}
fn win(value: i32) -> Result<()> {
    if value != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}
fn nt(status: i32) -> Result<()> {
    if status >= 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into())
    }
}
struct Token(Handle);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalMemory(Handle);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn private_descriptor() -> Result<LocalMemory> {
    let user = current_user_sid()?;
    let mut raw = ptr::null_mut();
    win(unsafe { ConvertSidToStringSidW(user.as_ptr().cast_mut().cast(), &mut raw) })?;
    require(!raw.is_null(), "native current-user SID text is missing")?;
    let text = LocalMemory(raw.cast());
    let mut length = 0usize;
    while length < 184 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    require(
        length < 184,
        "native current-user SID text exceeds its bound",
    )?;
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| StateError::UnsafePath("native current-user SID text is invalid".into()))?;
    drop(text);
    let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    let mut bytes = 0;
    win(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            &mut bytes,
        )
    })?;
    let descriptor = LocalMemory(descriptor);
    require(
        !descriptor.0.is_null()
            && (20..=65536).contains(&bytes)
            && unsafe { IsValidSecurityDescriptor(descriptor.0) } != 0,
        "invalid protected current-user directory descriptor",
    )?;
    Ok(descriptor)
}

pub(crate) fn validate_component(name: &str) -> Result<()> {
    require(
        name.len() <= 255,
        "Windows restore component exceeds its byte bound",
    )?;
    let normalized = normalization_key(name)?;
    let stem = normalized
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    require(
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.ends_with(['.', ' '])
            && !name
                .chars()
                .any(|c| c.is_control() || "/\\:\0<>\"|?*".contains(c))
            && normalized != "."
            && normalized != ".."
            && !normalized.ends_with(['.', ' '])
            && !normalized
                .chars()
                .any(|c| c.is_control() || "/\\:\0<>\"|?*".contains(c))
            && !matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            && !((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.chars().count() == 4
                && stem
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))),
        "invalid, reserved, alternate-stream or device Windows restore component",
    )
}

fn normalization_key(text: &str) -> Result<String> {
    require(
        text.len() <= 32_768,
        "Windows normalization input bound exceeded",
    )?;
    require(!text.is_empty(), "empty Windows native name")?;
    if text.is_ascii() {
        return Ok(text.to_ascii_lowercase());
    }
    let source = text.encode_utf16().collect::<Vec<_>>();
    require(!source.is_empty(), "empty Windows native name")?;
    let required =
        unsafe { NormalizeString(5, source.as_ptr(), source.len() as i32, ptr::null_mut(), 0) };
    let capacity = required
        .checked_abs()
        .filter(|size| (1..=131_072).contains(size))
        .ok_or_else(|| {
            StateError::UnsafePath("Windows NFKC normalization size is invalid".into())
        })? as usize;
    let mut destination = vec![0u16; capacity];
    let written = unsafe {
        NormalizeString(
            5,
            source.as_ptr(),
            source.len() as i32,
            destination.as_mut_ptr(),
            destination.len() as i32,
        )
    };
    require(
        written > 0 && written as usize <= destination.len(),
        "Windows native NFKC normalization failed",
    )?;
    let normalized = String::from_utf16(&destination[..written as usize])
        .map_err(|_| StateError::UnsafePath("Windows normalized name is not Unicode".into()))?;
    Ok(normalized
        .chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect())
}

/// Check the complete selected namespace before mutation, including ancestors
/// that differ only in spelling/case. NUL separates components in this private
/// sort key so a file "a" cannot hide an illegal "a/child" behind "a-other".
pub(crate) fn validate_namespace<'a>(
    paths: impl IntoIterator<Item = (&'a str, crate::NativeEntryKind)>,
) -> Result<()> {
    let mut normalized = BTreeMap::new();
    let mut bytes = 0usize;
    for (path, kind) in paths {
        crate::native::validate_relative(path)?;
        let mut key = String::new();
        for (index, component) in path.split('/').enumerate() {
            if index != 0 {
                key.push('\0');
            }
            key.push_str(&normalization_key(component)?);
        }
        bytes = bytes.checked_add(key.len()).ok_or_else(|| {
            StateError::Invalid("Windows namespace normalization byte overflow".into())
        })?;
        require(
            bytes <= 128 * 1024 * 1024,
            "Windows namespace normalization exceeds 128 MiB bound",
        )?;
        if normalized
            .insert(key, (path, kind))
            .is_some_and(|prior| prior != (path, kind))
        {
            return Err(StateError::Conflict(
                "Windows native restore has a case/normalization or entry-kind collision".into(),
            ));
        }
    }
    let mut previous: Option<(String, &str, crate::NativeEntryKind)> = None;
    for (key, (path, kind)) in normalized {
        if let Some((prior_key, prior_path, prior_kind)) = &previous {
            let mut raw_prior = prior_path.split('/');
            let mut raw_current = path.split('/');
            for (prior, current) in prior_key.split('\0').zip(key.split('\0')) {
                let prior_spelling = raw_prior.next();
                let current_spelling = raw_current.next();
                if prior != current {
                    break;
                }
                require(
                    prior_spelling == current_spelling,
                    "Windows restore aliases an ancestor with different case/normalization",
                )?;
            }
            if key
                .strip_prefix(prior_key)
                .is_some_and(|suffix| suffix.starts_with('\0'))
                && *prior_kind != crate::NativeEntryKind::Directory
            {
                return Err(StateError::Conflict(
                    "Windows restore file/link cannot be a selected directory ancestor".into(),
                ));
            }
        }
        previous = Some((key, path, kind));
    }
    Ok(())
}

/// Lookup only one component beneath a real held directory. The only allowed
/// "." is the internal fresh enumeration description, never an incoming path.
pub(crate) fn open_entry(parent: &File, name: &OsStr, extra_access: u32) -> Result<File> {
    open_entry_inner(parent, name, extra_access, None)
}

fn open_entry_inner(
    parent: &File,
    name: &OsStr,
    extra_access: u32,
    creation_security: Option<Handle>,
) -> Result<File> {
    let name = name
        .to_str()
        .ok_or_else(|| StateError::UnsafePath("non-Unicode Windows leaf".into()))?;
    if name != "." {
        validate_component(name)?;
    }
    require(
        name != "." || creation_security.is_none(),
        "native directory creation requires one new leaf",
    )?;
    require(
        WindowsMetadata::from_file(parent)?.kind == NativeEntryKind::Directory,
        "Windows restore parent is not a real directory",
    )?;
    let mut encoded = name.encode_utf16().collect::<Vec<_>>();
    require(
        encoded.len() * 2 < u16::MAX as usize,
        "native name exceeds NT bound",
    )?;
    let name = UnicodeString {
        length: (encoded.len() * 2) as u16,
        maximum_length: (encoded.len() * 2) as u16,
        buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: parent.as_raw_handle(),
        name: &name,
        attributes: 0x40
            | if creation_security.is_some() {
                0x1000
            } else {
                0
            },
        security: creation_security.unwrap_or(ptr::null_mut()),
        quality: ptr::null(),
    };
    let mut status = IoStatus::default();
    let mut handle = ptr::null_mut();
    nt(unsafe {
        NtCreateFile(
            &mut handle,
            READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | extra_access,
            &attributes,
            &mut status,
            ptr::null(),
            0,
            1 | 2 | if creation_security.is_some() { 0 } else { 4 },
            if creation_security.is_some() { 2 } else { 1 },
            0x00200000 | 0x20 | u32::from(creation_security.is_some()),
            ptr::null(),
            0,
        )
    })?;
    require(
        !handle.is_null() && handle as isize != -1,
        "invalid NT metadata handle",
    )?;
    let file = unsafe { File::from_raw_handle(handle) };
    WindowsMetadata::from_file(&file)?; // Reject devices, junctions and unknown tags.
    Ok(file)
}

/// Create-new under the actual held parent, with the same protected current-
/// user descriptor used by the standalone source adapter. The returned handle
/// denies delete-sharing, so ownership is captured before a leaf can be swapped.
/// This is a native filesystem primitive, never a separate restore pipeline.
pub(crate) fn create_private_directory(parent: &File, name: &OsStr) -> Result<File> {
    security(parent)?;
    noland_snapshot::native_metadata::flush_directory(parent)?;
    let descriptor = private_descriptor()?;
    let file = open_entry_inner(parent, name, 1 | 0x20 | 0x10000, Some(descriptor.0))?;
    let validation = (|| -> Result<()> {
        noland_snapshot::native_metadata::verify_private_directory(&file)?;
        noland_snapshot::native_metadata::flush_directory(parent)
    })();
    if let Err(error) = validation {
        // The live create result (not a pathname or checksum) is authority for
        // this failed, still-held empty directory. Never sweep a foreign child.
        let delete = 1u8;
        let mut status = IoStatus::default();
        let cleanup = nt(unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                (&delete as *const u8).cast(),
                1,
                13,
            )
        });
        drop(file);
        if let Err(cleanup) = cleanup {
            return Err(StateError::Conflict(format!(
                "native directory creation failed: {error}; created directory retained: {cleanup}"
            )));
        }
        noland_snapshot::native_metadata::flush_directory(parent)?;
        return Err(error);
    }
    Ok(file)
}

pub(crate) fn open_path_metadata(path: &Path, extra_access: u32) -> Result<File> {
    crate::validate_absolute_journal_path(path, "native metadata path")?;
    let parent = path.parent().unwrap_or(path);
    let directory = noland_snapshot::SourcePath::new(parent)?.open_directory()?;
    open_entry(
        &directory,
        path.file_name().unwrap_or(OsStr::new(".")),
        extra_access,
    )
}

fn current_user_sid() -> Result<Vec<u8>> {
    // Never let a thread's impersonated principal silently reuse process-owner
    // receipts. This is local native token metadata, not provider/account I/O.
    let mut thread = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut thread) } != 0 {
        let _token = Token(thread);
        return Err(StateError::Conflict(
            "impersonated Windows restore context is unsupported".into(),
        ));
    }
    require(
        io::Error::last_os_error().raw_os_error() == Some(1008),
        "cannot establish non-impersonated Windows identity",
    )?;
    static SID: OnceLock<Vec<u8>> = OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid.clone());
    }
    let mut token = ptr::null_mut();
    win(unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) })?;
    let token = Token(token);
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut needed);
    }
    require(
        (size_of::<TokenUser>() as u32..=4096).contains(&needed),
        "invalid native token-user bound",
    )?;
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    win(unsafe {
        GetTokenInformation(token.0, 1, buffer.as_mut_ptr().cast(), needed, &mut needed)
    })?;
    let sid = unsafe { (*buffer.as_ptr().cast::<TokenUser>()).sid };
    require(
        !sid.is_null() && unsafe { IsValidSid(sid) } != 0,
        "invalid current-user SID",
    )?;
    let length = unsafe { GetLengthSid(sid) } as usize;
    require((8..=68).contains(&length), "native SID bound exceeded")?;
    let value = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec();
    let _ = SID.set(value.clone());
    Ok(value)
}

/// Current-user ownership plus an immutable owner/DACL witness. Broad read
/// permissions may remain on an approved destination, but write/replace grants
/// to unrelated principals are rejected. New artifacts use SourcePath's stricter
/// protected current-user-only descriptor, never an inherited permission guess.
pub(crate) fn security(file: &File) -> Result<NativeWindowsSecurity> {
    let before = WindowsMetadata::from_file(file)?;
    verify_unnamed_stream(file, &before)?;
    let user = current_user_sid()?;
    let mut needed = 0;
    let first = unsafe {
        GetKernelObjectSecurity(file.as_raw_handle(), 1 | 4, ptr::null_mut(), 0, &mut needed)
    };
    require(
        first == 0
            && io::Error::last_os_error().raw_os_error() == Some(122)
            && (20..=65536).contains(&needed),
        "invalid Windows owner/DACL bound",
    )?;
    let capacity = needed;
    let mut storage = vec![0u64; (capacity as usize).div_ceil(8)];
    let descriptor = storage.as_mut_ptr().cast();
    win(unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            1 | 4,
            descriptor,
            capacity,
            &mut needed,
        )
    })?;
    require(
        needed <= capacity && unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
        "invalid Windows security descriptor",
    )?;
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    win(unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) })?;
    win(unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) })?;
    require(
        !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0
            && unsafe { EqualSid(owner, user.as_ptr().cast_mut().cast()) } != 0
            && present != 0
            && !acl.is_null(),
        "Windows restore requires current-user owner and a real DACL",
    )?;
    let header = unsafe { &*acl };
    require(
        header.count <= 4096 && matches!(header.revision, 2 | 4),
        "unsupported Windows DACL structure",
    )?;
    for index in 0..header.count as u32 {
        let mut entry = ptr::null_mut();
        win(unsafe { GetAce(acl, index, &mut entry) })?;
        require(!entry.is_null(), "missing Windows ACE")?;
        let ace = unsafe { &*entry.cast::<Ace>() };
        require(
            ace.size as usize >= size_of::<Ace>() && matches!(ace.kind, 0 | 1),
            "unsupported Windows object/callback ACE",
        )?;
        if ace.kind == 1 || ace.flags & 8 != 0 {
            continue;
        }
        let sid = unsafe { ptr::addr_of!((*entry.cast::<Ace>()).sid).cast_mut().cast() };
        require(
            unsafe { IsValidSid(sid) } != 0
                && offset_of!(Ace, sid) + unsafe { GetLengthSid(sid) } as usize
                    <= ace.size as usize,
            "invalid Windows ACE SID",
        )?;
        let trusted = unsafe { EqualSid(sid, user.as_ptr().cast_mut().cast()) } != 0
            || unsafe { IsWellKnownSid(sid, 22) } != 0
            || unsafe { IsWellKnownSid(sid, 26) } != 0;
        let writes =
            0x10000000u32 | 0x40000000 | 0x10000 | 0x40000 | 0x80000 | 2 | 4 | 0x10 | 0x40 | 0x100;
        require(
            trusted || ace.mask & writes == 0,
            "Windows destination grants unrelated principals write/replace authority",
        )?;
    }
    require(
        before.same_file_state(&WindowsMetadata::from_file(file)?),
        "Windows ACL observation changed",
    )?;
    let raw = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) };
    let sid = *blake3::hash(&user).as_bytes();
    Ok(NativeWindowsSecurity {
        current_user_sid: sid,
        owner_sid: sid,
        dacl: *blake3::hash(raw).as_bytes(),
    })
}

/// FILE_STREAM_INFORMATION is queried on the exact opened object. Addressing
/// only an unnamed path is insufficient: retiring an original with hidden ADS
/// would otherwise lose data absent from its stable rollback capture.
fn verify_unnamed_stream(file: &File, before: &WindowsMetadata) -> Result<()> {
    require(
        before.kind != NativeEntryKind::Symlink || before.size == 0,
        "native symlink has unrepresented regular-file data",
    )?;
    let mut storage = [0u64; 8192];
    let mut status = IoStatus::default();
    let result = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status,
            storage.as_mut_ptr().cast(),
            (storage.len() * 8) as u32,
            22,
        )
    };
    if result as u32 == 0xc0000011 && before.kind != NativeEntryKind::File {
        return Ok(());
    }
    nt(result)?;
    require(
        status.information <= storage.len() * 8,
        "invalid native stream-information bound",
    )?;
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), status.information) };
    crate::native::windows_contract::validate_stream_records(
        bytes,
        (before.kind == NativeEntryKind::File).then_some(before.size),
    )
}

pub(crate) fn read_symlink(file: &File) -> Result<(String, [u8; 32])> {
    let before = WindowsMetadata::from_file(file)?;
    require(
        before.kind == NativeEntryKind::Symlink,
        "native entry is not a symbolic link",
    )?;
    let mut data = [0u64; 2048];
    let mut returned = 0;
    win(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x000900a8,
            ptr::null(),
            0,
            data.as_mut_ptr().cast(),
            (data.len() * 8) as u32,
            &mut returned,
            ptr::null_mut(),
        )
    })?;
    require(
        returned as usize <= data.len() * 8
            && before.same_file_state(&WindowsMetadata::from_file(file)?),
        "native symlink changed during reparse observation",
    )?;
    let bytes =
        unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), returned as usize) };
    crate::native::windows_contract::symlink_reparse_data(bytes)
}

pub(crate) fn receipt_directory_names(directory: &File) -> Result<Vec<OsString>> {
    let scanner = open_entry(directory, OsStr::new("."), 1 | 0x20)?;
    let before = WindowsMetadata::from_file(&scanner)?;
    require(
        before.kind == NativeEntryKind::Directory,
        "native receipt enumeration requires directory",
    )?;
    let mut names = Vec::new();
    let mut restart = 1;
    loop {
        let mut storage = [0u64; 8192];
        let mut status = IoStatus::default();
        let result = unsafe {
            NtQueryDirectoryFile(
                scanner.as_raw_handle(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                &mut status,
                storage.as_mut_ptr().cast(),
                (storage.len() * 8) as u32,
                60,
                0,
                ptr::null(),
                restart,
            )
        };
        restart = 0;
        if result as u32 == 0x80000006 {
            break;
        }
        nt(result)?;
        require(
            status.information > 0 && status.information <= storage.len() * 8,
            "invalid native directory response",
        )?;
        let bytes = unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), status.information)
        };
        let header = offset_of!(DirectoryInformation, name);
        let mut offset = 0usize;
        loop {
            require(
                offset + header <= bytes.len()
                    && offset + size_of::<DirectoryInformation>() <= storage.len() * 8,
                "truncated native directory entry",
            )?;
            let info = unsafe {
                ptr::read_unaligned(
                    storage
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<DirectoryInformation>(),
                )
            };
            let length = info.name_length as usize;
            require(
                length > 0
                    && length % 2 == 0
                    && length <= 510
                    && offset + header + length <= bytes.len(),
                "invalid native directory name bound",
            )?;
            let words = bytes[offset + header..offset + header + length]
                .chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect::<Vec<_>>();
            let name = String::from_utf16(&words)
                .map_err(|_| StateError::UnsafePath("non-Unicode native receipt name".into()))?;
            if name != "." && name != ".." {
                validate_component(&name)?;
                require(
                    names.len() < 16
                        && info.attributes & 0x40 == 0
                        && (info.attributes & 0x400 == 0 || info.reparse_tag == 0xa000000c),
                    "unknown/special native receipt entries exceed the metadata-only bound",
                )?;
                names.push(OsString::from(name));
            }
            if info.next == 0 {
                break;
            }
            let next = info.next as usize;
            let end = offset
                .checked_add(next)
                .ok_or_else(|| StateError::Integrity("native directory offset overflow".into()))?;
            require(
                next >= header + length && next % 8 == 0 && end < bytes.len(),
                "invalid native directory offset",
            )?;
            offset = end;
        }
    }
    require(
        before.same_file_state(&WindowsMetadata::from_file(&scanner)?),
        "native receipt directory changed",
    )?;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeEntryKind as Kind, RestoreTarget};

    #[test]
    fn names_and_namespace_aliases_fail_before_windows_mutation() {
        for name in [
            "CON",
            "con.txt",
            "NUL",
            "LPT¹.log",
            "a:stream",
            r"a\b",
            "a/b",
            "trailing.",
            "trailing ",
            ".",
            "..",
            "name\0tail",
            "ＣＯＮ",
        ] {
            assert!(validate_component(name).is_err(), "{name}");
        }
        for paths in [
            vec![("App/File", Kind::File), ("app/Other", Kind::File)],
            vec![("App/File", Kind::File), ("App/FILE", Kind::File)],
            vec![("App/café", Kind::File), ("App/cafe\u{301}", Kind::File)],
            vec![
                ("Root/a", Kind::File),
                ("Root/a-other", Kind::File),
                ("Root/a/child", Kind::File),
            ],
            vec![
                ("Root/link", Kind::Symlink),
                ("Root/link/child", Kind::File),
            ],
        ] {
            assert!(validate_namespace(paths).is_err());
        }
        validate_namespace([
            ("Root", Kind::Directory),
            ("Root/Sub", Kind::Directory),
            ("Root/Sub/file", Kind::File),
            ("Root/Other", Kind::File),
        ])
        .unwrap();
    }

    #[test]
    fn legacy_windows_transactions_fail_without_touching_any_path() {
        use noland_state_core::*;
        let manifest = BundleManifest::new(
            ManifestApp::from(&AppIdentity::new(AppId("fixture".into()), "Fixture")),
            ManifestSource {
                instance_id: uuid::Uuid::new_v4(),
                image_id: "isolated-no-filesystem-fixture".into(),
                captured_at: chrono::Utc::now(),
            },
            BackupMode::Custom,
        );
        let plan = crate::RestorePlan {
            restore_id: uuid::Uuid::new_v4(),
            staging: r"Z:\never-opened-isolated-fixture".into(),
            manifest,
            mode: RestoreMode::Custom,
        };
        let roots = LogicalRootMap::default();
        let mut transaction = crate::RestoreTransaction::new(&plan, &roots, None);
        assert!(transaction.publish_to(RestoreTarget::Complete).is_err());
        assert!(transaction.enable_chunk_eviction().is_err());
        assert!(transaction.abort().is_err());
        assert!(plan.release_staged_pack_links().is_err());
        assert!(transaction.commit_with_metrics().is_err());
        let paths = AgentPaths::from_roots(
            std::path::PathBuf::from(r"Z:\never-opened-state-fixture"),
            std::path::PathBuf::from(r"Z:\never-opened-runtime-fixture"),
        );
        assert!(crate::recover_interrupted_restores(&paths).is_err());
    }

    #[test]
    fn windows_partial_names_do_not_overflow_valid_original_leaf_names() {
        let destination =
            std::path::PathBuf::from(r"Z:\never-opened-fixture").join("a".repeat(255));
        let partial = crate::destination_partial_path(&destination, uuid::Uuid::new_v4()).unwrap();
        assert_eq!(partial.parent(), destination.parent());
        let leaf = partial.file_name().unwrap().to_str().unwrap();
        assert!(leaf.len() < 255);
        validate_component(leaf).unwrap();
    }
}
