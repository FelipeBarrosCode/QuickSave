// SPDX-License-Identifier: GPL-3.0-only
//! New native Windows boundary code. A private ACL is deliberately narrower
//! than "not Everyone": exactly one explicit current-user allow ACE, protected
//! against inheritance, with that same user as owner.

use super::*;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN},
    Security::{
        AddAccessAllowedAceEx, EqualSid, GetAce, GetKernelObjectSecurity, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
        IsValidSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE, ACL,
        ACL_REVISION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
        SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{GetVolumeInformationByHandleW, FILE_ALL_ACCESS},
    System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) struct User {
    // u64 storage supplies alignment for TOKEN_USER and SID.
    _storage: Vec<u64>,
    sid: PSID,
}

impl User {
    fn current() -> Result<Self> {
        let mut token = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(ERROR_NO_TOKEN as i32),
                "inspect effective thread token: {error}"
            );
            ensure!(
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
                "open current-user token: {}",
                io::Error::last_os_error()
            );
        }
        let token = Token(token);
        let mut length = 0;
        let result =
            unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length) };
        ensure!(
            result == 0
                && io::Error::last_os_error().raw_os_error()
                    == Some(ERROR_INSUFFICIENT_BUFFER as i32)
                && (size_of::<TOKEN_USER>()..=65536).contains(&(length as usize)),
            "invalid current-user token size"
        );
        let mut storage = vec![0u64; (length as usize).div_ceil(8)];
        ensure!(
            unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    storage.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } != 0,
            "read current-user SID: {}",
            io::Error::last_os_error()
        );
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        let sid = user.User.Sid;
        ensure!(
            !sid.is_null() && unsafe { IsValidSid(sid) } != 0,
            "invalid current-user SID"
        );
        ensure!(
            (8..=68).contains(&unsafe { GetLengthSid(sid) }),
            "SID exceeds native bound"
        );
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

pub(super) struct Descriptor {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _acl: Vec<u64>,
    _user: User,
}

impl Descriptor {
    pub(super) fn new() -> Result<Self> {
        let user = User::current()?;
        let length = size_of::<ACL>()
            + offset_of!(ACCESS_ALLOWED_ACE, SidStart)
            + unsafe { GetLengthSid(user.sid) } as usize;
        let mut acl = vec![0u64; length.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let mut descriptor = Box::<SECURITY_DESCRIPTOR>::default();
        let pointer = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
        ensure!(
            unsafe { InitializeAcl(acl_ptr, length as u32, ACL_REVISION) } != 0
                && unsafe {
                    AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, 0, FILE_ALL_ACCESS, user.sid)
                } != 0
                && unsafe { InitializeSecurityDescriptor(pointer, 1) } != 0
                && unsafe { SetSecurityDescriptorOwner(pointer, user.sid, 0) } != 0
                && unsafe { SetSecurityDescriptorDacl(pointer, 1, acl_ptr, 0) } != 0
                && unsafe {
                    SetSecurityDescriptorControl(pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                } != 0,
            "construct protected current-user security descriptor: {}",
            io::Error::last_os_error()
        );
        ensure!(
            unsafe { IsValidSecurityDescriptor(pointer) } != 0,
            "invalid private security descriptor"
        );
        Ok(Self {
            descriptor,
            _acl: acl,
            _user: user,
        })
    }

    pub(super) fn pointer(&self) -> *const SECURITY_DESCRIPTOR {
        // The boxed descriptor, ACL storage and owner SID all remain owned by
        // self across the synchronous NtCreateFile call.
        &*self.descriptor
    }
}

pub(super) fn filesystem(file: &File) -> Result<(String, u32)> {
    let mut name = [0u16; 32];
    let mut serial = 0;
    let mut flags = 0;
    ensure!(
        unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                &mut serial,
                ptr::null_mut(),
                &mut flags,
                name.as_mut_ptr(),
                name.len() as u32,
            )
        } != 0,
        "query native filesystem: {}",
        io::Error::last_os_error()
    );
    let length = name
        .iter()
        .position(|value| *value == 0)
        .context("unterminated filesystem name")?;
    let name = String::from_utf16(&name[..length])?;
    ensure!(
        name == "NTFS" || name == "ReFS",
        "private durability requires local NTFS or ReFS, found {name}"
    );
    ensure!(flags & 8 != 0, "filesystem does not report persistent ACLs");
    Ok((name, serial))
}

pub(super) fn verify(file: &File, directory: bool) -> Result<()> {
    let before = metadata(file, directory)?;
    filesystem(file)?;
    let standard: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    ensure!(
        if directory {
            standard.NumberOfLinks > 0
        } else {
            standard.NumberOfLinks == 1
        },
        "private entry has an invalid native hard-link count"
    );
    let user = User::current()?;
    let mut needed = 0;
    let result = unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    ensure!(
        result == 0
            && io::Error::last_os_error().raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
            && (20..=65536).contains(&needed),
        "cannot determine a bounded native security descriptor"
    );
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let descriptor = buffer.as_mut_ptr().cast();
    ensure!(
        unsafe {
            GetKernelObjectSecurity(
                file.as_raw_handle(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                descriptor,
                needed,
                &mut needed,
            )
        } != 0
            && unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
        "read valid native owner/DACL: {}",
        io::Error::last_os_error()
    );
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut control = 0;
    let mut revision = 0;
    let mut present = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    ensure!(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } != 0
            && !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0
            && unsafe { EqualSid(owner, user.sid) } != 0
            && unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                != 0
            && control & SE_DACL_PROTECTED != 0
            && unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            } != 0
            && present != 0
            && defaulted == 0
            && !acl.is_null(),
        "private entry must have a protected DACL and current-user owner"
    );
    let acl_header = unsafe { &*acl };
    ensure!(
        acl_header.AceCount == 1 && acl_header.AclRevision == ACL_REVISION as u8,
        "private DACL must contain exactly one explicit allow ACE"
    );
    let mut ace = ptr::null_mut();
    ensure!(
        unsafe { GetAce(acl, 0, &mut ace) } != 0 && !ace.is_null(),
        "read private DACL ACE"
    );
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    ensure!(
        allowed.Header.AceType == 0
            && allowed.Header.AceFlags == 0
            && allowed.Header.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>()
            && allowed.Mask == FILE_ALL_ACCESS,
        "unsupported, inherited, or nonprivate ACL entry"
    );
    let sid = ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    ensure!(
        unsafe { IsValidSid(sid) } != 0
            && offset_of!(ACCESS_ALLOWED_ACE, SidStart) + unsafe { GetLengthSid(sid) } as usize
                == allowed.Header.AceSize as usize
            && unsafe { EqualSid(sid, user.sid) } != 0,
        "private DACL grants access to another principal"
    );
    let after: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    ensure!(
        metadata(file, directory)? == before
            && after.NumberOfLinks == standard.NumberOfLinks
            && !after.DeletePending,
        "private entry changed during native ACL verification"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::{
        Wdk::Storage::FileSystem::FILE_CREATE,
        Win32::Security::{
            Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
    };

    #[test]
    fn private_acl_is_protected_user_owned_and_rejects_inheritance() -> Result<()> {
        let temp = tempfile::Builder::new()
            .prefix("quicksave-acl-")
            .tempdir()?;
        let root = Root::open(temp.path())?;
        let descriptor = Descriptor::new()?;
        let file = open_options(
            root.file(),
            "private",
            Some(false),
            FILE_ALL_ACCESS,
            FILE_CREATE,
            descriptor.pointer(),
            false,
            false,
        )?;
        verify(&file, false)?;
        let result = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                descriptor._acl.as_ptr().cast_mut().cast(),
                ptr::null(),
            )
        };
        ensure!(result == 0, "alter only synthetic fixture ACL: {result}");
        assert!(verify(&file, false).is_err());
        Ok(())
    }

    #[test]
    fn private_file_rejects_additional_native_hard_links() -> Result<()> {
        let temp = tempfile::Builder::new()
            .prefix("quicksave-links-")
            .tempdir()?;
        let root = Root::open(temp.path())?;
        let file = write::create_private(root.file(), "private", false, false)?;
        verify(&file, false)?;
        drop(file);
        std::fs::hard_link(temp.path().join("private"), temp.path().join("alias"))?;
        let file = open_child(root.file(), "private", false)?;
        assert!(verify(&file, false).is_err());
        Ok(())
    }

    #[test]
    fn inherited_default_acl_is_not_a_private_configuration_proof() -> Result<()> {
        let temp = tempfile::Builder::new()
            .prefix("quicksave-inherited-")
            .tempdir()?;
        std::fs::write(temp.path().join("ordinary"), b"fixture")?;
        let root = Root::open(temp.path())?;
        let file = open_child(root.file(), "ordinary", false)?;
        assert!(verify(&file, false).is_err());
        Ok(())
    }
}
