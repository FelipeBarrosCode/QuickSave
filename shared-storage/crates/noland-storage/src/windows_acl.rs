// SPDX-License-Identifier: GPL-3.0-only
//! Exact user-only ACL inheritance for app-owned rclone config replacements.
//! Snapshot's original strict private ACL remains the first accepted policy.
//! No source/import ACL, provider authority, or general filesystem policy changes.
use noland_snapshot::{NativeEntryKind, WindowsMetadata};
use noland_state_core::{Result, StateError};
use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr,
};
type Handle = *mut c_void;

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
struct AllowedAce {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
    sid: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThread() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenThreadToken(thread: Handle, access: u32, self_open: i32, token: *mut Handle) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
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
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn SetKernelObjectSecurity(file: Handle, info: u32, descriptor: *const c_void) -> i32;
    fn IsValidSecurityDescriptor(descriptor: *const c_void) -> i32;
    fn GetSecurityDescriptorOwner(
        descriptor: *const c_void,
        owner: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *const c_void,
        present: *mut i32,
        acl: *mut *mut Acl,
        defaulted: *mut i32,
    ) -> i32;
    fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn IsValidSid(sid: Handle) -> i32;
    fn EqualSid(left: Handle, right: Handle) -> i32;
    fn GetLengthSid(sid: Handle) -> u32;
    fn ConvertSidToStringSidW(sid: Handle, output: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        size: *mut u32,
    ) -> i32;
}
fn denied() -> StateError {
    StateError::UnsafePath("credential ACL is not the exact current-user-only native policy".into())
}
fn check(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(denied())
    }
}
fn win(status: i32) -> Result<()> {
    if status == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
struct Token(Handle);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
struct Local(Handle);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
struct User {
    _storage: Vec<u64>,
    sid: Handle,
}
impl User {
    fn current() -> Result<Self> {
        let mut token = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } == 0 {
            check(io::Error::last_os_error().raw_os_error() == Some(1008))?;
            win(unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) })?;
        }
        let token = Token(token);
        let mut needed = 0;
        let status = unsafe { GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut needed) };
        check(
            status == 0
                && io::Error::last_os_error().raw_os_error() == Some(122)
                && (size_of::<TokenUser>() as u32..=65536).contains(&needed),
        )?;
        let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
        win(unsafe {
            GetTokenInformation(token.0, 1, storage.as_mut_ptr().cast(), needed, &mut needed)
        })?;
        let sid = unsafe { (*storage.as_ptr().cast::<TokenUser>()).sid };
        check(
            !sid.is_null()
                && unsafe { IsValidSid(sid) } != 0
                && (8..=68).contains(&unsafe { GetLengthSid(sid) }),
        )?;
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

pub(crate) fn verify(file: &File, directory: bool) -> Result<()> {
    super::native_windows::verify_filesystem(file)?;
    let before = WindowsMetadata::from_file(file)?;
    check(
        before.kind
            == if directory {
                NativeEntryKind::Directory
            } else {
                NativeEntryKind::File
            },
    )?;
    check(directory || before.number_of_links == 1)?;
    let user = User::current()?;
    let mut needed = 0;
    let status = unsafe {
        GetKernelObjectSecurity(file.as_raw_handle(), 1 | 4, ptr::null_mut(), 0, &mut needed)
    };
    check(
        status == 0
            && io::Error::last_os_error().raw_os_error() == Some(122)
            && (20..=65536).contains(&needed),
    )?;
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let descriptor = storage.as_mut_ptr().cast();
    win(unsafe {
        GetKernelObjectSecurity(file.as_raw_handle(), 1 | 4, descriptor, needed, &mut needed)
    })?;
    check(unsafe { IsValidSecurityDescriptor(descriptor) } != 0)?;
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut control = 0;
    let mut revision = 0;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    win(unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) })?;
    win(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
    win(unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) })?;
    check(
        !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0
            && unsafe { EqualSid(owner, user.sid) } != 0
            && present != 0
            && defaulted == 0
            && !acl.is_null(),
    )?;
    let header = unsafe { &*acl };
    check(header.revision == 2 && header.count == if directory { 2 } else { 1 })?;
    // Directory: protected normal user ACE + file-only/inherit-only user ACE.
    // Rclone replacement: exactly its one inherited user ACE, no other grant.
    check(if directory {
        control & 4096 != 0
    } else {
        control & 4096 == 0
    })?;
    let mut flags_seen = 0u32;
    for index in 0..header.count as u32 {
        let mut raw = ptr::null_mut();
        win(unsafe { GetAce(acl, index, &mut raw) })?;
        check(!raw.is_null())?;
        let ace = unsafe { &*raw.cast::<AllowedAce>() };
        check(
            ace.kind == 0 && ace.mask == 0x1f01ff && ace.size as usize >= size_of::<AllowedAce>(),
        )?;
        let bit = match (directory, ace.flags) {
            (true, 0) => 1,
            (true, 9) => 2,   // OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE
            (false, 16) => 4, // INHERITED_ACE, file-effective user-only ACE
            _ => return Err(denied()),
        };
        check(flags_seen & bit == 0)?;
        flags_seen |= bit;
        let sid = ptr::addr_of!(ace.sid).cast_mut().cast();
        check(
            unsafe { IsValidSid(sid) } != 0
                && unsafe { EqualSid(sid, user.sid) } != 0
                && offset_of!(AllowedAce, sid) + unsafe { GetLengthSid(sid) } as usize
                    == ace.size as usize,
        )?;
    }
    check(flags_seen == if directory { 3 } else { 4 })?;
    check(before.same_file_state(&WindowsMetadata::from_file(file)?))
}

/// Only a newly created strict Snapshot-private directory can opt into this
/// policy. It grants no new principal access and does not repair source data.
pub(crate) fn enable_config_inheritance(directory: &File) -> Result<()> {
    noland_snapshot::native_metadata::verify_private_directory(directory)?;
    let expected = WindowsMetadata::from_file(directory)?.identity;
    let user = User::current()?;
    let mut sid = ptr::null_mut();
    win(unsafe { ConvertSidToStringSidW(user.sid, &mut sid) })?;
    let memory = Local(sid.cast());
    let mut length = 0;
    while length < 184 && unsafe { *sid.add(length) } != 0 {
        length += 1;
    }
    check(length < 184)?;
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, length) })
        .map_err(|_| denied())?;
    drop(memory);
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})(A;OIIO;FA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut raw = ptr::null_mut();
    let mut size = 0;
    win(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut raw, &mut size)
    })?;
    let descriptor = Local(raw);
    check((20..=65536).contains(&size) && unsafe { IsValidSecurityDescriptor(descriptor.0) } != 0)?;
    let control = super::native_windows::directory_acl_control(directory)?;
    win(unsafe {
        SetKernelObjectSecurity(control.as_raw_handle(), 4 | 0x8000_0000, descriptor.0)
    })?;
    check(WindowsMetadata::from_file(&control)?.identity == expected)?;
    verify(&control, true)?;
    noland_snapshot::native_metadata::flush_directory(directory)
}
