// SPDX-License-Identifier: GPL-3.0-only
//! Original standalone Windows source/restore adapter. No QuickSave dependency.
//! Only the drive/volume roots use absolute Win32 names. Every user-controlled
//! child is a single no-follow name under an owned NT directory handle.

use super::*;
use native_metadata::{ffi::*, NativeEntryKind, NativeIdentity, WindowsMetadata};
use std::{
    ffi::{c_void, OsStr, OsString},
    io,
    mem::{offset_of, size_of, size_of_val},
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Component, Prefix},
    ptr,
};

const READ_ATTRIBUTES: u32 = 0x80;
const READ_DATA: u32 = 1;
const WRITE_DATA: u32 = 2;
const WRITE_ATTRIBUTES: u32 = 0x100;
const READ_CONTROL: u32 = 0x20000;
const DELETE: u32 = 0x10000;
const SYNCHRONIZE: u32 = 0x100000;
const OPEN: u32 = 1;
const CREATE: u32 = 2;
const SYMLINK_TAG: u32 = 0xa000_000c;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
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
    root_directory: Handle,
    name_length: u32,
    name: [u16; 1],
}
#[repr(C)]
struct DirectoryInformation {
    next: u32,
    index: u32,
    creation: i64,
    access: i64,
    write: i64,
    change: i64,
    end_of_file: i64,
    allocation: i64,
    attributes: u32,
    name_length: u32,
    ea_size: u32,
    reparse_tag: u32,
    file_id: [u8; 16],
    name: [u16; 1],
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
#[repr(C)]
struct TokenUser {
    sid: Handle,
    attributes: u32,
}
#[repr(C)]
#[derive(Default)]
struct Luid {
    low: u32,
    high: i32,
}
#[repr(C)]
struct Privilege {
    luid: Luid,
    attributes: u32,
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
        info: *const c_void,
        length: u32,
        class: i32,
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
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: Handle) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThread() -> Handle;
    fn FlushFileBuffers(file: Handle) -> i32;
    fn ReOpenFile(file: Handle, access: u32, share: u32, flags: u32) -> Handle;
    fn GetVolumeInformationByHandleW(
        file: Handle,
        volume_name: *mut u16,
        volume_name_size: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        fs_name: *mut u16,
        fs_name_size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, length: u32, flags: u32) -> u32;
    fn DeviceIoControl(
        file: Handle,
        code: u32,
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
    fn OpenThreadToken(thread: Handle, access: u32, self_open: i32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
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
    fn EqualSid(left: Handle, right: Handle) -> i32;
    fn GetLengthSid(sid: Handle) -> u32;
    fn GetSecurityDescriptorOwner(
        descriptor: *mut c_void,
        owner: *mut Handle,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: *mut i32,
        acl: *mut *mut Acl,
        defaulted: *mut i32,
    ) -> i32;
    fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut Handle,
        size: *mut u32,
    ) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
}

fn unsafe_path(message: &str) -> StateError {
    StateError::UnsafePath(message.into())
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(unsafe_path(message))
    }
}
fn win(result: i32) -> Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
fn nt(status: i32) -> Result<()> {
    require(
        status != 0x103 && status != 0x104,
        "native operation did not establish complete no-follow semantics",
    )?;
    if status < 0 {
        Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into())
    } else {
        Ok(())
    }
}
fn owned(handle: Handle) -> Result<File> {
    require(
        !handle.is_null() && handle as isize != -1,
        "invalid native filesystem handle",
    )?;
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn component(value: &OsStr) -> Result<String> {
    validate_leaf(value)?;
    let value = value
        .to_str()
        .ok_or_else(|| unsafe_path("native name must be Unicode"))?;
    require(
        !value.ends_with(['.', ' '])
            && !value
                .chars()
                .any(|c| c < ' ' || matches!(c, '<' | '>' | '"' | '|' | '?' | '*')),
        "invalid Windows native component",
    )?;
    let stem = value.split('.').next().unwrap().to_ascii_uppercase();
    require(
        !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().count() == 4
            && stem
                .chars()
                .last()
                .is_some_and(|last| last.is_ascii_digit() || matches!(last, '¹' | '²' | '³'))),
        "reserved Windows device name",
    )?;
    Ok(value.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn open_at(
    parent: &File,
    name: &str,
    directory: Option<bool>,
    access: u32,
    disposition: u32,
    security: *const c_void,
    allow_link: bool,
    share_delete: bool,
) -> Result<File> {
    open_at_sharing(
        parent,
        name,
        directory,
        access,
        disposition,
        security,
        allow_link,
        1 | 2 | if share_delete { 4 } else { 0 },
    )
}

#[allow(clippy::too_many_arguments)]
fn open_at_sharing(
    parent: &File,
    name: &str,
    directory: Option<bool>,
    access: u32,
    disposition: u32,
    security: *const c_void,
    allow_link: bool,
    sharing: u32,
) -> Result<File> {
    if name != "." {
        component(OsStr::new(name))?;
    }
    // Only this private "." sentinel reopens the held directory. The NT
    // namespace requires a zero-length relative name, not a literal dot.
    let reopen_directory = name == ".";
    require(
        !reopen_directory || (directory == Some(true) && disposition == OPEN),
        "held-directory reopen cannot create or open a regular file",
    )?;
    let mut encoded: Vec<u16> = if reopen_directory { "" } else { name }
        .encode_utf16()
        .collect();
    require(
        encoded.len() * 2 < u16::MAX as usize,
        "native name exceeds UTF-16 bound",
    )?;
    let name = UnicodeString {
        length: (encoded.len() * 2) as u16,
        maximum_length: (encoded.len() * 2) as u16,
        buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        name: &name,
        attributes: 0x40
            | if allow_link || reopen_directory {
                0
            } else {
                0x1000
            },
        security,
        quality: ptr::null(),
    };
    let mut status = IoStatus::default();
    let mut file = ptr::null_mut();
    nt(unsafe {
        NtCreateFile(
            &mut file,
            access | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            0,
            sharing,
            disposition,
            0x0020_0000
                | 0x20
                | match directory {
                    Some(true) => 1,
                    Some(false) => 0x40,
                    None => 0,
                },
            ptr::null(),
            0,
        )
    })?;
    owned(file)
}

fn open_directory(parent: &File, name: &str) -> Result<File> {
    let file = open_at(
        parent,
        name,
        Some(true),
        READ_ATTRIBUTES | READ_CONTROL | READ_DATA | 0x20,
        OPEN,
        ptr::null(),
        false,
        false,
    )?;
    require(
        WindowsMetadata::from_file(&file)?.kind == NativeEntryKind::Directory,
        "expected a no-follow native directory",
    )?;
    Ok(file)
}

struct Directory {
    file: File,
    identity: NativeIdentity,
}

pub struct SourcePath {
    directories: Vec<Directory>,
    name: String,
    logical_relative: Option<PathBuf>,
}

impl SourcePath {
    pub fn new(path: &Path) -> Result<Self> {
        Self::new_scoped(path, None)
    }

    /// Never pretend that a 64-bit Unix inode approval is a 128-bit Windows ID.
    pub fn new_beneath(_: &Path, _: &Path, _: (u64, u64)) -> Result<Self> {
        Err(unsafe_path("Windows restore boundaries require new_beneath_native and a full 128-bit native identity"))
    }

    pub fn new_beneath_native(
        path: &Path,
        boundary: &Path,
        identity: NativeIdentity,
    ) -> Result<Self> {
        require(
            path.is_absolute()
                && boundary.is_absolute()
                && path != boundary
                && path.starts_with(boundary),
            "native restore target escapes its approved boundary",
        )?;
        Self::new_scoped(path, Some((boundary, identity)))
    }

    fn new_scoped(path: &Path, boundary: Option<(&Path, NativeIdentity)>) -> Result<Self> {
        let text = path
            .to_str()
            .ok_or_else(|| unsafe_path("native path must be Unicode"))?;
        require(
            !text.is_empty()
                && text.len() <= 32768
                && !text.contains('\0')
                && !text
                    .split(['/', '\\'])
                    .any(|part| part == "." || part == ".."),
            "invalid native source path",
        )?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        require(
            absolute.to_string_lossy().len() <= 32768,
            "absolute native path exceeds bound",
        )?;
        let mut components = absolute.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(unsafe_path("UNC and device namespaces are unsupported")),
            },
            _ => {
                return Err(unsafe_path(
                    "native source must resolve to a local disk root",
                ))
            }
        };
        require(
            matches!(components.next(), Some(Component::RootDir)),
            "native source path must be absolute",
        )?;
        // Preserve the caller's Disk versus VerbatimDisk spelling when binding
        // its already-validated logical boundary; never canonicalize/follow it.
        let root_path: PathBuf = absolute.components().take(2).collect();
        let root_name: Vec<u16> = format!(r"\\?\{}:\", drive as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let root_handle = unsafe {
            CreateFileW(
                root_name.as_ptr(),
                READ_ATTRIBUTES | READ_CONTROL | READ_DATA | 0x20 | SYNCHRONIZE,
                1 | 2,
                ptr::null(),
                3,
                0x0020_0000 | 0x0200_0000,
                ptr::null_mut(),
            )
        };
        if root_handle.is_null() || root_handle as isize == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let root = owned(root_handle)?;
        let root_metadata = WindowsMetadata::from_file(&root)?;
        require(
            root_metadata.kind == NativeEntryKind::Directory,
            "native root is not a directory",
        )?;
        let mut directories = vec![Directory {
            file: root,
            identity: root_metadata.identity,
        }];
        let mut names = Vec::new();
        for part in components {
            if let Component::Normal(part) = part {
                names.push(component(part)?);
            } else {
                return Err(unsafe_path("invalid native path component"));
            }
        }
        require(names.len() <= 128, "native source path exceeds depth bound")?;
        let leaf = names.pop().unwrap_or_else(|| ".".to_owned());
        let mut current = root_path;
        let mut checked_boundary = boundary.is_none();
        if let Some((boundary, expected)) = boundary {
            if current == boundary {
                require(
                    directories[0].identity == expected,
                    "native restore root identity changed",
                )?;
                checked_boundary = true;
            }
        }
        for name in names {
            let file = open_directory(&directories.last().unwrap().file, &name)?;
            let identity = WindowsMetadata::from_file(&file)?.identity;
            current.push(&name);
            if let Some((boundary, expected)) = boundary {
                if current == boundary {
                    require(
                        identity == expected,
                        "native restore boundary identity changed",
                    )?;
                    checked_boundary = true;
                }
            }
            directories.push(Directory { file, identity });
        }
        require(checked_boundary, "native restore boundary was not pinned")?;
        let result = Self {
            directories,
            name: leaf,
            logical_relative: boundary.map(|(root, _)| {
                path.strip_prefix(root)
                    .expect("checked boundary")
                    .to_path_buf()
            }),
        };
        result.check()?;
        Ok(result)
    }

    fn parent(&self) -> &File {
        &self.directories.last().expect("pinned parent").file
    }
    fn check(&self) -> Result<()> {
        for directory in &self.directories {
            let observed = WindowsMetadata::from_file(&directory.file)?;
            require(
                observed.kind == NativeEntryKind::Directory
                    && observed.identity == directory.identity,
                "pinned native parent changed",
            )?;
        }
        Ok(())
    }

    fn open_leaf(&self, access: u32, directory: Option<bool>, allow_link: bool) -> Result<File> {
        self.check()?;
        open_at(
            self.parent(),
            &self.name,
            directory,
            access | READ_ATTRIBUTES | READ_CONTROL,
            OPEN,
            ptr::null(),
            allow_link,
            false,
        )
    }

    fn control(&self, directory: Option<bool>, allow_link: bool) -> Result<File> {
        self.check()?;
        component(OsStr::new(&self.name))?;
        open_at_sharing(
            self.parent(),
            &self.name,
            directory,
            READ_ATTRIBUTES | READ_CONTROL | DELETE,
            OPEN,
            ptr::null(),
            allow_link,
            1,
        )
    }

    fn metadata_with_control(&self) -> Result<WindowsMetadata> {
        self.check()?;
        let file = open_at(
            self.parent(),
            &self.name,
            None,
            READ_ATTRIBUTES | READ_CONTROL,
            OPEN,
            ptr::null(),
            true,
            true,
        )?;
        WindowsMetadata::from_file(&file)
    }

    fn require_absent(&self) -> Result<()> {
        match self.native_metadata() {
            Err(StateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(StateError::Conflict(
                "native no-replace target already exists".into(),
            )),
        }
    }

    pub fn open_regular(&self) -> Result<File> {
        let opened = self.open_leaf(READ_DATA, Some(false), false)?;
        let before = WindowsMetadata::from_file(&opened)?;
        require(
            before.kind == NativeEntryKind::File,
            "capture source is not a native regular file",
        )?;
        let raw = unsafe {
            ReOpenFile(
                opened.as_raw_handle(),
                READ_DATA | READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                1,
                0x0020_0000,
            )
        };
        if raw.is_null() || raw as isize == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let file = owned(raw)?;
        let pinned = WindowsMetadata::from_file(&file)?;
        require(
            pinned.kind == NativeEntryKind::File && pinned.identity == before.identity,
            "reopened capture source native identity changed",
        )?;
        self.check()?;
        Ok(file)
    }

    pub fn open_private_object(&self) -> Result<File> {
        let file = self.open_regular_delete_shared()?;
        verify_private_policy(&file, false, true)?;
        Ok(file)
    }

    /// Immutable artifact readers allow lease hard-link/delete operations while
    /// denying ordinary data writers. Callers validate full metadata and hashes.
    pub fn open_regular_delete_shared(&self) -> Result<File> {
        self.check()?;
        let file = open_at_sharing(
            self.parent(),
            &self.name,
            Some(false),
            READ_ATTRIBUTES | READ_CONTROL | READ_DATA,
            OPEN,
            ptr::null(),
            false,
            1 | 4,
        )?;
        require(
            WindowsMetadata::from_file(&file)?.kind == NativeEntryKind::File,
            "immutable artifact reader requires a native regular file",
        )?;
        self.check()?;
        Ok(file)
    }

    pub fn hard_link_new_to(&self, target: &Self) -> Result<()> {
        self.check()?;
        target.check()?;
        target.require_absent()?;
        require(
            self.parent_native_identity()?.volume == target.parent_native_identity()?.volume,
            "native hard-link lease requires one filesystem",
        )?;
        // Delete-sharing allows independent leases/readers to coexist. The
        // operation links this exact handle, not a later source pathname.
        let file = open_at_sharing(
            self.parent(),
            &self.name,
            Some(false),
            READ_ATTRIBUTES | READ_CONTROL | DELETE,
            OPEN,
            ptr::null(),
            false,
            1 | 4,
        )?;
        verify_private_policy(&file, false, true)?;
        let before = WindowsMetadata::from_file(&file)?;
        set_name(&file, target.parent(), &target.name, false, 11)?;
        let linked = target.metadata_with_control()?;
        require(
            linked.identity == before.identity
                && linked.size == before.size
                && linked.last_write_time == before.last_write_time,
            "native lease hard-link identity changed",
        )?;
        self.check()?;
        target.check()
    }

    pub fn remove_file_owned(&self, expected: NativeIdentity) -> Result<()> {
        self.check()?;
        let file = self.control(Some(false), false)?;
        let observed = WindowsMetadata::from_file(&file)?;
        require(
            observed.kind == NativeEntryKind::File && observed.identity == expected,
            "refusing removal of a replaced immutable file",
        )?;
        verify_private_policy(&file, false, true)?;
        // FILE_DISPOSITION_DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE:
        // remove only this opened name, without chmodding every hard-link alias.
        let flags = 0x13u32;
        let mut status = IoStatus::default();
        nt(unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                (&flags as *const u32).cast(),
                4,
                64,
            )
        })?;
        drop(file);
        self.check()
    }

    pub fn open_directory(&self) -> Result<File> {
        let file = self.open_leaf(READ_DATA | 0x20, Some(true), false)?;
        require(
            WindowsMetadata::from_file(&file)?.kind == NativeEntryKind::Directory,
            "source is not a native directory",
        )?;
        Ok(file)
    }

    pub fn native_metadata(&self) -> Result<WindowsMetadata> {
        let file = self.open_leaf(0, None, true)?;
        let metadata = WindowsMetadata::from_file(&file)?;
        self.check()?;
        Ok(metadata)
    }

    pub fn metadata(&self) -> Result<SourceMetadata> {
        // Parent-owned metadata.rs must retain all native fields from this
        // constructor; returning fs::Metadata here would lose ReFS's high ID.
        Ok(SourceMetadata::from_windows(&self.native_metadata()?))
    }

    pub fn native_identity(&self) -> Result<NativeIdentity> {
        Ok(self.native_metadata()?.identity)
    }
    pub fn parent_native_identity(&self) -> Result<NativeIdentity> {
        self.check()?;
        Ok(WindowsMetadata::from_file(self.parent())?.identity)
    }
    pub fn parent_identity(&self) -> Result<(u64, u64)> {
        Err(unsafe_path("Windows parent approvals require parent_native_identity; 128-bit IDs cannot be truncated"))
    }

    pub fn child(parent: &File, name: OsString) -> Result<Self> {
        let name = component(&name)?;
        let observed = WindowsMetadata::from_file(parent)?;
        require(
            observed.kind == NativeEntryKind::Directory,
            "child parent is not a real native directory",
        )?;
        Ok(Self {
            directories: vec![Directory {
                file: parent.try_clone()?,
                identity: observed.identity,
            }],
            name,
            logical_relative: None,
        })
    }

    fn private_file(&self, disposition: u32) -> Result<File> {
        self.check()?;
        // Opening an existing private inode is not a namespace mutation. Do not
        // volume-flush on every lock/chunk-handle cache miss.
        let barrier = if disposition == OPEN {
            None
        } else {
            Some(Barrier::new(self.parent())?)
        };
        if let Some(barrier) = &barrier {
            barrier.flush()?;
        }
        let descriptor = Descriptor::new()?;
        let file = open_at(
            self.parent(),
            &self.name,
            Some(false),
            READ_ATTRIBUTES | READ_CONTROL | READ_DATA | WRITE_DATA | WRITE_ATTRIBUTES,
            disposition,
            descriptor.0,
            false,
            false,
        )?;
        verify_private(&file, false)?;
        if let Some(barrier) = &barrier {
            barrier.flush()?;
        }
        self.check()?;
        Ok(file)
    }

    pub fn open_partial_private(&self, create_new: bool) -> Result<File> {
        self.private_file(if create_new { CREATE } else { OPEN })
    }
    pub fn open_or_create_private(&self) -> Result<File> {
        match self.private_file(OPEN) {
            Ok(file) => Ok(file),
            Err(StateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                match self.private_file(CREATE) {
                    Err(StateError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                        self.private_file(OPEN)
                    }
                    result => result,
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn create_private_directory(&self) -> Result<()> {
        self.check()?;
        let barrier = Barrier::new(self.parent())?;
        barrier.flush()?;
        let descriptor = Descriptor::new()?;
        let file = open_at(
            self.parent(),
            &self.name,
            Some(true),
            READ_ATTRIBUTES | READ_CONTROL | READ_DATA | 0x20,
            CREATE,
            descriptor.0,
            false,
            false,
        )?;
        verify_private(&file, true)?;
        drop(file);
        barrier.flush()?;
        self.check()
    }

    pub fn publish_new_to(&self, target: &Self) -> Result<()> {
        self.check()?;
        target.check()?;
        target.require_absent()?;
        require(
            self.parent_native_identity()?.volume == target.parent_native_identity()?.volume,
            "native publication requires one filesystem",
        )?;
        let barrier = Barrier::new(target.parent())?;
        barrier.flush()?;
        let file = self.open_leaf(READ_DATA | WRITE_DATA, Some(false), false)?;
        verify_private(&file, false)?;
        let before = WindowsMetadata::from_file(&file)?;
        win(unsafe { FlushFileBuffers(file.as_raw_handle()) })?;
        drop(file);
        // Close every ordinary writer before publication, while the private
        // partial name is still hidden. The control handle denies write/delete
        // opens across rename, verification and the actual volume barrier.
        let file = self.control(Some(false), false)?;
        verify_private(&file, false)?;
        require(
            WindowsMetadata::from_file(&file)?.same_file_state(&before),
            "native restore partial changed while sealing for publication",
        )?;
        rename(&file, target.parent(), &target.name, false)?;
        let published = WindowsMetadata::from_file(&file)?;
        require(
            published.identity == before.identity
                && published.size == before.size
                && published.last_write_time == before.last_write_time
                && published.number_of_links == before.number_of_links,
            "native published file changed",
        )?;
        barrier.flush()?;
        require(
            WindowsMetadata::from_file(&file)?.same_file_state(&published)
                && target.metadata_with_control()?.same_file_state(&published),
            "native publication changed before durability completed",
        )?;
        self.check()?;
        target.check()
    }

    /// Atomic no-replace move for a caller-owned restore/quarantine entry. The
    /// caller revalidates its frozen observation; use the checked variant when
    /// the expected SourceMetadata is available.
    pub fn move_new_to(&self, target: &Self) -> Result<()> {
        self.move_new_to_inner(target, None)
    }

    pub fn move_new_to_checked(&self, target: &Self, expected: &SourceMetadata) -> Result<()> {
        self.move_new_to_inner(target, Some(expected))
    }

    fn move_new_to_inner(&self, target: &Self, expected: Option<&SourceMetadata>) -> Result<()> {
        self.check()?;
        target.check()?;
        target.require_absent()?;
        require(
            self.parent_native_identity()?.volume == target.parent_native_identity()?.volume,
            "native no-replace move requires one filesystem",
        )?;
        let barrier = Barrier::new(target.parent())?;
        barrier.flush()?;
        let file = self.control(None, true)?;
        let before = WindowsMetadata::from_file(&file)?;
        if expected.is_some_and(|expected| SourceMetadata::from_windows(&before) != *expected) {
            return Err(StateError::Conflict(
                "native move source changed since approval".into(),
            ));
        }
        rename(&file, target.parent(), &target.name, false)?;
        let after = WindowsMetadata::from_file(&file)?;
        require(
            after.identity == before.identity
                && after.kind == before.kind
                && after.size == before.size
                && after.last_write_time == before.last_write_time,
            "native move changed source identity/content",
        )?;
        barrier.flush()?;
        require(
            WindowsMetadata::from_file(&file)?.same_file_state(&after)
                && target.metadata_with_control()?.same_file_state(&after),
            "moved native entry changed before durability completed",
        )?;
        self.check()?;
        target.check()
    }

    pub fn flush_parent(&self) -> Result<()> {
        self.check()?;
        Barrier::new(self.parent())?.flush()?;
        self.check()
    }

    pub fn remove_empty_directory(&self) -> Result<()> {
        self.remove_empty_directory_inner(None)
    }

    pub fn remove_empty_directory_owned(&self, expected: NativeIdentity) -> Result<()> {
        self.remove_empty_directory_inner(Some(expected))
    }

    fn remove_empty_directory_inner(&self, expected: Option<NativeIdentity>) -> Result<()> {
        self.check()?;
        let barrier = Barrier::new(self.parent())?;
        barrier.flush()?;
        let file = self.control(Some(true), false)?;
        let observed = WindowsMetadata::from_file(&file)?;
        require(
            observed.kind == NativeEntryKind::Directory
                && expected.is_none_or(|expected| expected == observed.identity),
            "expected native empty directory",
        )?;
        dispose(&file)?; // Kernel refuses non-empty directories.
        drop(file);
        barrier.flush()?;
        self.check()
    }

    pub fn delete_leaf(&self, expected: &SourceMetadata) -> Result<()> {
        self.check()?;
        let barrier = Barrier::new(self.parent())?;
        barrier.flush()?;
        let file = self.control(None, true)?;
        let native = WindowsMetadata::from_file(&file)?;
        let observed = SourceMetadata::from_windows(&native);
        if !(observed.is_file() || observed.is_symlink()) || &observed != expected {
            return Err(StateError::Conflict(
                "native leaf changed since deletion preview".into(),
            ));
        }
        // This handle pins the exact previewed entry against name replacement.
        // Disposition cannot delete a replacement or follow a symlink target.
        dispose(&file)?;
        drop(file);
        barrier.flush()?;
        self.check()
    }

    pub fn native_link_stamp(&self) -> Result<SourceLinkStamp> {
        self.check()?;
        let file = open_at_sharing(
            self.parent(),
            &self.name,
            None,
            READ_ATTRIBUTES | READ_CONTROL,
            OPEN,
            ptr::null(),
            true,
            1,
        )?;
        let (native, target) = read_link_handle(&file)?;
        self.check()?;
        Ok(SourceLinkStamp {
            metadata: SourceMetadata::from_windows(&native),
            target,
            target_is_directory: Some(native.is_directory_link()),
        })
    }

    pub fn read_link(&self) -> Result<PathBuf> {
        Ok(self.native_link_stamp()?.target)
    }

    pub fn create_new_relative_symlink(
        &self,
        target: &Path,
        logical_relative: &Path,
        target_is_directory: Option<bool>,
    ) -> Result<SourceLinkStamp> {
        require(
            self.logical_relative.as_deref() == Some(logical_relative),
            "symlink creation requires its pinned approved logical root",
        )?;
        // Path uses native separators; convert only for the lexical logical
        // confinement check. Device/absolute targets are still rejected.
        let logical = PathBuf::from(
            logical_relative
                .to_str()
                .ok_or_else(|| unsafe_path("non-Unicode logical link"))?
                .replace('\\', "/"),
        );
        let target_text = target
            .to_str()
            .ok_or_else(|| unsafe_path("non-Unicode symlink target"))?;
        let portable_target = target_text.replace('\\', "/");
        confined_link_target(&logical, Path::new(&portable_target))?;
        for part in portable_target.split('/') {
            if part != "." && part != ".." {
                component(OsStr::new(part))?;
            }
        }
        let directory = target_is_directory
            .ok_or_else(|| unsafe_path("Windows requires the authenticated directory-link kind"))?;
        let encoded: Vec<u16> = portable_target.replace('/', "\\").encode_utf16().collect();
        let text_length = encoded.len() * 2;
        require(
            24 + text_length * 2 <= 16 * 1024,
            "native symlink exceeds reparse buffer bound",
        )?;
        require_symlink_privilege()?;
        self.check()?;
        let barrier = Barrier::new(self.parent())?;
        barrier.flush()?;
        let descriptor = Descriptor::new()?;
        let file = open_at(
            self.parent(),
            &self.name,
            Some(directory),
            READ_ATTRIBUTES | READ_CONTROL | READ_DATA | WRITE_DATA | WRITE_ATTRIBUTES | DELETE,
            CREATE,
            descriptor.0,
            false,
            false,
        )?;
        verify_private(&file, directory)?;
        let owned = WindowsMetadata::from_file(&file)?.identity;
        let outcome: Result<SourceLinkStamp> = (|| {
            let mut buffer = vec![0u8; 24 + text_length * 2];
            let data_length = (buffer.len() - 8) as u16;
            buffer[0..4].copy_from_slice(&SYMLINK_TAG.to_le_bytes());
            buffer[4..6].copy_from_slice(&data_length.to_le_bytes());
            buffer[10..12].copy_from_slice(&(text_length as u16).to_le_bytes());
            buffer[12..14].copy_from_slice(&((text_length + 2) as u16).to_le_bytes());
            buffer[14..16].copy_from_slice(&(text_length as u16).to_le_bytes());
            buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
            for (index, word) in encoded.iter().enumerate() {
                buffer[20 + index * 2..22 + index * 2].copy_from_slice(&word.to_le_bytes());
                let print_offset = 22 + text_length + index * 2;
                buffer[print_offset..print_offset + 2].copy_from_slice(&word.to_le_bytes());
            }
            let mut returned = 0;
            win(unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    0x0009_00a4,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            })?;
            let (metadata, target) = read_link_handle(&file)?;
            require(
                metadata.identity == owned
                    && target
                        .to_str()
                        .is_some_and(|target| target.replace('\\', "/") == portable_target)
                    && metadata.is_directory_link() == directory,
                "new native symlink identity or authenticated target changed",
            )?;
            Ok(SourceLinkStamp {
                metadata: SourceMetadata::from_windows(&metadata),
                target,
                target_is_directory: Some(directory),
            })
        })();
        if outcome.is_err() {
            require(
                WindowsMetadata::from_file(&file)?.identity == owned,
                "refusing cleanup of replaced symlink handle",
            )?;
            dispose(&file)?;
        }
        drop(file);
        barrier.flush()?;
        self.check()?;
        let stamp = outcome?;
        require(
            self.native_link_stamp()? == stamp,
            "native symbolic link changed during commit",
        )?;
        Ok(stamp)
    }
}

fn rename(file: &File, parent: &File, name: &str, replace: bool) -> Result<()> {
    set_name(file, parent, name, replace, 10)
}

fn set_name(file: &File, parent: &File, name: &str, replace: bool, class: i32) -> Result<()> {
    component(OsStr::new(name))?;
    let encoded: Vec<u16> = name.encode_utf16().collect();
    let length = offset_of!(RenameInformation, name) + encoded.len() * 2;
    let mut storage = vec![0u64; length.max(size_of::<RenameInformation>()).div_ceil(8)];
    let info = storage.as_mut_ptr().cast::<RenameInformation>();
    unsafe {
        (*info).replace = u8::from(replace);
        (*info).root_directory = parent.as_raw_handle();
        (*info).name_length = (encoded.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            ptr::addr_of_mut!((*info).name).cast::<u16>(),
            encoded.len(),
        );
    }
    let mut status = IoStatus::default();
    nt(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            info.cast(),
            length as u32,
            class,
        )
    })
}

fn dispose(file: &File) -> Result<()> {
    let remove: u8 = 1;
    let mut status = IoStatus::default();
    nt(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&remove as *const u8).cast(),
            1,
            13,
        )
    })
}

fn read_link_handle(file: &File) -> Result<(WindowsMetadata, PathBuf)> {
    let before = WindowsMetadata::from_file(file)?;
    require(
        before.kind == NativeEntryKind::Symlink && before.number_of_links == 1,
        "entry is not a supported native symlink",
    )?;
    let mut buffer = [0u8; 16 * 1024];
    let mut returned = 0;
    win(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00a8,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    })?;
    require(
        (20..=buffer.len()).contains(&(returned as usize)),
        "invalid native reparse buffer length",
    )?;
    let buffer = &buffer[..returned as usize];
    let word = |offset: usize| u16::from_le_bytes(buffer[offset..offset + 2].try_into().unwrap());
    require(
        u32::from_le_bytes(buffer[0..4].try_into().unwrap()) == SYMLINK_TAG
            && word(4) as usize + 8 == buffer.len()
            && word(6) == 0
            && u32::from_le_bytes(buffer[16..20].try_into().unwrap()) == 1,
        "only checked relative native symbolic links are supported",
    )?;
    let target_at = |offset: u16, length: u16| -> Result<String> {
        require(
            offset.is_multiple_of(2) && length.is_multiple_of(2),
            "unaligned native symlink text",
        )?;
        let bytes = buffer
            .get(20 + offset as usize..20 + offset as usize + length as usize)
            .ok_or_else(|| unsafe_path("native symlink text exceeds reparse buffer"))?;
        let encoded: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&encoded).map_err(|_| unsafe_path("non-Unicode native symlink target"))
    };
    let target = target_at(word(8), word(10))?;
    let print = target_at(word(12), word(14))?;
    require(
        (print.is_empty() || target == print)
            && !target.is_empty()
            && target.len() <= 32768
            && !target.starts_with(['/', '\\'])
            && !target.contains([':', '\0']),
        "absolute, NT namespace, stream, or ambiguous symbolic link target",
    )?;
    require(
        before.same_file_state(&WindowsMetadata::from_file(file)?),
        "native symlink changed during metadata read",
    )?;
    Ok((before, PathBuf::from(target)))
}

pub(crate) fn directory_names(directory: &File) -> Result<Vec<OsString>> {
    require(
        WindowsMetadata::from_file(directory)?.kind == NativeEntryKind::Directory,
        "native enumeration requires a directory",
    )?;
    let scanner = open_directory(directory, ".")?;
    let before = WindowsMetadata::from_file(&scanner)?;
    let mut names = Vec::new();
    let mut name_bytes = 0usize;
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
                size_of_val(&storage) as u32,
                60,
                0,
                ptr::null(),
                restart,
            )
        };
        restart = 0;
        if result as u32 == 0x8000_0006 {
            break;
        }
        nt(result)?;
        require(
            status.information > 0 && status.information <= size_of_val(&storage),
            "invalid native directory response length",
        )?;
        let bytes = unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), status.information)
        };
        let header = offset_of!(DirectoryInformation, name);
        let mut offset = 0usize;
        loop {
            require(
                offset + header <= bytes.len()
                    && offset + size_of::<DirectoryInformation>() <= size_of_val(&storage),
                "truncated native directory header",
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
                    && length.is_multiple_of(2)
                    && length <= 510
                    && offset + header + length <= bytes.len(),
                "invalid native filename length",
            )?;
            let encoded: Vec<u16> = bytes[offset + header..offset + header + length]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let name = String::from_utf16(&encoded)
                .map_err(|_| unsafe_path("non-Unicode native filename"))?;
            if name != "." && name != ".." {
                component(OsStr::new(&name))?;
                require(
                    info.attributes & 0x40 == 0
                        && (info.attributes & 0x400 == 0 || info.reparse_tag == SYMLINK_TAG),
                    "directory contains a device, junction, or unknown reparse kind",
                )?;
                name_bytes = name_bytes
                    .checked_add(name.len())
                    .ok_or_else(|| unsafe_path("native name size overflow"))?;
                require(
                    names.len() < 1_000_000 && name_bytes <= 128 * 1024 * 1024,
                    "native directory exceeds entry/name-memory bounds",
                )?;
                names.push(OsString::from(name));
            }
            if info.next == 0 {
                break;
            }
            let next = info.next as usize;
            let next_offset = offset
                .checked_add(next)
                .ok_or_else(|| unsafe_path("native directory offset overflow"))?;
            require(
                next >= header + length && next.is_multiple_of(8) && next_offset < bytes.len(),
                "invalid native directory record offset",
            )?;
            offset = next_offset;
        }
    }
    require(
        before.same_file_state(&WindowsMetadata::from_file(&scanner)?),
        "native directory changed during enumeration",
    )?;
    names.sort_unstable();
    Ok(names)
}

struct Token(Handle);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
struct LocalMemory(Handle);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
struct User {
    _storage: Vec<u64>,
    sid: Handle,
}

fn current_token() -> Result<Token> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } == 0 {
        require(
            io::Error::last_os_error().raw_os_error() == Some(1008),
            "cannot inspect effective token",
        )?;
        win(unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) })?;
    }
    Ok(Token(token))
}
fn token_info(token: &Token, class: i32) -> Result<Vec<u64>> {
    let mut needed = 0;
    let status = unsafe { GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut needed) };
    require(
        status == 0
            && io::Error::last_os_error().raw_os_error() == Some(122)
            && (4..=65536).contains(&needed),
        "invalid native token information size",
    )?;
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    win(unsafe {
        GetTokenInformation(
            token.0,
            class,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    })?;
    Ok(storage)
}
impl User {
    fn current() -> Result<Self> {
        let storage = token_info(&current_token()?, 1)?;
        require(
            size_of_val(storage.as_slice()) >= size_of::<TokenUser>(),
            "truncated user token",
        )?;
        let user = unsafe { &*storage.as_ptr().cast::<TokenUser>() };
        let sid = user.sid;
        require(
            !sid.is_null()
                && unsafe { IsValidSid(sid) } != 0
                && (8..=68).contains(&unsafe { GetLengthSid(sid) }),
            "invalid effective user SID",
        )?;
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

struct Descriptor(Handle);
impl Descriptor {
    fn new() -> Result<Self> {
        let user = User::current()?;
        let mut raw = ptr::null_mut();
        win(unsafe { ConvertSidToStringSidW(user.sid, &mut raw) })?;
        let text = LocalMemory(raw.cast());
        let mut length = 0;
        while length < 184 && unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        require(length < 184, "current-user SID text exceeds native bound")?;
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
            .map_err(|_| unsafe_path("invalid user SID text"))?;
        drop(text);
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        let mut size = 0;
        win(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                &mut size,
            )
        })?;
        let descriptor = Self(descriptor);
        require(
            (20..=65536).contains(&size) && unsafe { IsValidSecurityDescriptor(descriptor.0) } != 0,
            "invalid protected current-user security descriptor",
        )?;
        Ok(descriptor)
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn filesystem(file: &File) -> Result<(String, u32)> {
    let mut name = [0u16; 32];
    let mut serial = 0;
    let mut flags = 0;
    win(unsafe {
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
    })?;
    let end = name
        .iter()
        .position(|word| *word == 0)
        .ok_or_else(|| unsafe_path("unterminated native filesystem name"))?;
    let name = String::from_utf16(&name[..end])
        .map_err(|_| unsafe_path("invalid native filesystem name"))?;
    require(
        (name == "NTFS" || name == "ReFS") && flags & 8 != 0,
        "native private durability requires NTFS/ReFS with persistent ACLs",
    )?;
    Ok((name, serial))
}

pub(super) fn verify_private(file: &File, directory: bool) -> Result<()> {
    verify_private_policy(file, directory, false)
}

pub(super) fn verify_private_policy(
    file: &File,
    directory: bool,
    allow_hard_links: bool,
) -> Result<()> {
    verify_private_policy_inner(file, directory, allow_hard_links, false)
}

pub(super) fn verify_private_directory_live(file: &File) -> Result<()> {
    verify_private_policy_inner(file, true, false, true)
}

fn verify_private_policy_inner(
    file: &File,
    directory: bool,
    allow_hard_links: bool,
    mutable_namespace: bool,
) -> Result<()> {
    let before = WindowsMetadata::from_file(file)?;
    require(
        before.kind
            == (if directory {
                NativeEntryKind::Directory
            } else {
                NativeEntryKind::File
            })
            && (if directory || allow_hard_links {
                before.number_of_links > 0
            } else {
                before.number_of_links == 1
            }),
        "invalid private native entry kind or hard-link count",
    )?;
    filesystem(file)?;
    let user = User::current()?;
    let mut needed = 0;
    let status = unsafe {
        GetKernelObjectSecurity(file.as_raw_handle(), 1 | 4, ptr::null_mut(), 0, &mut needed)
    };
    require(
        status == 0
            && io::Error::last_os_error().raw_os_error() == Some(122)
            && (20..=65536).contains(&needed),
        "invalid native owner/DACL size",
    )?;
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let descriptor = storage.as_mut_ptr().cast();
    win(unsafe {
        GetKernelObjectSecurity(file.as_raw_handle(), 1 | 4, descriptor, needed, &mut needed)
    })?;
    require(
        unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
        "invalid native owner/DACL",
    )?;
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    let mut control = 0;
    let mut revision = 0;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    win(unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) })?;
    win(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
    win(unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) })?;
    require(
        !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0
            && unsafe { EqualSid(owner, user.sid) } != 0
            && control & 4096 != 0
            && present != 0
            && defaulted == 0
            && !acl.is_null(),
        "private native entry must have current-user owner and protected DACL",
    )?;
    let header = unsafe { &*acl };
    require(
        header.revision == 2 && header.count == 1,
        "private DACL must contain one explicit user-only ACE",
    )?;
    let mut ace = ptr::null_mut();
    win(unsafe { GetAce(acl, 0, &mut ace) })?;
    require(!ace.is_null(), "missing private ACL entry")?;
    let ace = unsafe { &*ace.cast::<AllowedAce>() };
    require(
        ace.kind == 0
            && ace.flags == 0
            && ace.mask == 0x1f01ff
            && ace.size as usize >= size_of::<AllowedAce>(),
        "unsupported or inherited private ACL entry",
    )?;
    let sid = ptr::addr_of!(ace.sid).cast_mut().cast();
    require(
        unsafe { IsValidSid(sid) } != 0
            && unsafe { EqualSid(sid, user.sid) } != 0
            && offset_of!(AllowedAce, sid) + unsafe { GetLengthSid(sid) } as usize
                == ace.size as usize,
        "private DACL grants another principal access",
    )?;
    let after = WindowsMetadata::from_file(file)?;
    require(
        if mutable_namespace {
            after.kind == NativeEntryKind::Directory
                && after.identity == before.identity
                && after.number_of_links > 0
        } else {
            before.same_file_state(&after)
        },
        "private native entry changed during ACL inspection",
    )
}

pub(super) fn flush_directory(file: &File) -> Result<()> {
    require(
        WindowsMetadata::from_file(file)?.kind == NativeEntryKind::Directory,
        "native directory durability requires a real directory handle",
    )?;
    Barrier::new(file)?.flush()
}

struct Barrier {
    volume: File,
    root: File,
    filesystem: (String, u32),
    identity: NativeIdentity,
}
impl Barrier {
    fn new(parent: &File) -> Result<Self> {
        let filesystem = filesystem(parent)?;
        let identity = WindowsMetadata::from_file(parent)?.identity;
        let mut text = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                parent.as_raw_handle(),
                text.as_mut_ptr(),
                text.len() as u32,
                1,
            )
        };
        require(
            length != 0 && (length as usize) < text.len(),
            "cannot obtain native volume GUID for durability",
        )?;
        let text = String::from_utf16(&text[..length as usize])
            .map_err(|_| unsafe_path("invalid native volume GUID path"))?;
        require(
            text.starts_with(r"\\?\Volume{"),
            "durability requires a local native volume GUID",
        )?;
        let end = text
            .find(r"}\")
            .ok_or_else(|| unsafe_path("invalid native volume GUID root"))?
            + 2;
        require(end <= 64, "native volume GUID exceeds bound")?;
        let root_name: Vec<u16> = text[..end].encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                root_name.as_ptr(),
                READ_ATTRIBUTES | SYNCHRONIZE,
                1 | 2,
                ptr::null(),
                3,
                0x0020_0000 | 0x0200_0000,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw as isize == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let root = owned(raw)?;
        require(
            WindowsMetadata::from_file(&root)?.identity.volume == identity.volume,
            "native durability volume mismatch",
        )?;
        let volume_name: Vec<u16> = text[..end - 1].encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                volume_name.as_ptr(),
                0x8000_0000 | 0x4000_0000,
                1 | 2,
                ptr::null(),
                3,
                0x8000_0000,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw as isize == -1 {
            return Err(StateError::Storage(format!("actual native volume durability barrier unavailable (flush permission required): {}", io::Error::last_os_error())));
        }
        let result = Self {
            volume: owned(raw)?,
            root,
            filesystem,
            identity,
        };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        require(
            filesystem(&self.root)? == self.filesystem
                && WindowsMetadata::from_file(&self.root)?.identity.volume == self.identity.volume,
            "native durability volume changed",
        )
    }
    fn flush(&self) -> Result<()> {
        self.check()?;
        win(unsafe { FlushFileBuffers(self.volume.as_raw_handle()) })?;
        self.check()
    }
}

fn require_symlink_privilege() -> Result<()> {
    let token = current_token()?;
    let name: Vec<u16> = "SeCreateSymbolicLinkPrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut luid = Luid::default();
    win(unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) })?;
    let storage = token_info(&token, 3)?;
    let bytes = size_of_val(storage.as_slice());
    let count = unsafe { *storage.as_ptr().cast::<u32>() } as usize;
    require(
        bytes >= 4 && count <= (bytes - 4) / size_of::<Privilege>(),
        "truncated native privilege list",
    )?;
    let values = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(4).cast::<Privilege>(),
            count,
        )
    };
    require(values.iter().any(|entry| entry.luid.low == luid.low && entry.luid.high == luid.high && entry.attributes & 2 != 0),
        "native relative symlink creation requires enabled SeCreateSymbolicLinkPrivilege; no privilege was silently enabled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let preferred = base.join("opencode");
            let base = if preferred.is_dir() { preferred } else { base };
            let path = base.join(format!("noland-native-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn private_creation_uses_real_acl_and_full_native_identity() -> Result<()> {
        let temp = Fixture::new();
        let directory = SourcePath::new(&temp.0)?.open_directory()?;
        let descriptor = Descriptor::new()?;
        let mut file = open_at(
            &directory,
            "private",
            Some(false),
            READ_ATTRIBUTES | READ_CONTROL | READ_DATA | WRITE_DATA,
            CREATE,
            descriptor.0,
            false,
            false,
        )?;
        verify_private(&file, false)?;
        file.write_all(b"native private bytes")?;
        let native = WindowsMetadata::from_file(&file)?;
        assert_eq!(native.identity, identity_from_file_for_test(&file)?);
        drop(file);
        let path = SourcePath::new(&temp.0.join("private"))?;
        assert_eq!(path.native_identity()?, native.identity);
        assert!(path.parent_identity().is_err());
        let mut input = path.open_regular()?;
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"native private bytes");
        assert!(std::fs::rename(temp.0.join("private"), temp.0.join("moved")).is_err());
        Ok(())
    }

    fn identity_from_file_for_test(file: &File) -> Result<NativeIdentity> {
        let id: IdInfo = query(file, 18)?;
        Ok(NativeIdentity {
            volume: id.volume,
            file_id: [
                u64::from_le_bytes(id.id[..8].try_into().unwrap()),
                u64::from_le_bytes(id.id[8..].try_into().unwrap()),
            ],
        })
    }

    #[test]
    fn child_names_never_select_parent_device_or_stream_names() -> Result<()> {
        let temp = Fixture::new();
        let directory = SourcePath::new(&temp.0)?.open_directory()?;
        for name in [
            "..",
            ".",
            "a/b",
            r"a\b",
            "a:stream",
            "CON",
            r"\??\C:\outside",
            "trailing.",
        ] {
            assert!(
                SourcePath::child(&directory, name.into()).is_err(),
                "{name}"
            );
        }
        Ok(())
    }

    #[test]
    fn native_filetime_and_high_file_id_word_are_not_discarded() {
        let native = WindowsMetadata {
            identity: NativeIdentity {
                volume: 23,
                file_id: [31, 47],
            },
            size: 5,
            creation_time: 116_444_736_000_000_000,
            last_access_time: 116_444_736_000_000_000,
            last_write_time: 116_444_736_000_000_001,
            change_time: 116_444_736_000_000_002,
            attributes: 0x20,
            number_of_links: 1,
            reparse_tag: 0,
            kind: NativeEntryKind::File,
        };
        assert_eq!(native.mtime_ns(), Some(100));
        assert_eq!(native.ctime_ns(), Some(200));
        let mut changed = native.clone();
        changed.identity.file_id[1] += 1;
        assert!(!native.same_file_state(&changed));
        let mut accessed = native.clone();
        accessed.last_access_time += 100;
        assert!(native.same_file_state(&accessed));
    }

    #[test]
    #[ignore = "native Windows NTFS/ReFS acceptance: requires actual volume flush permission"]
    fn no_replace_publication_is_handle_anchored_and_durable() -> Result<()> {
        let temp = Fixture::new();
        let partial = SourcePath::new(&temp.0.join("partial"))?;
        let mut file = partial.open_partial_private(true)?;
        file.write_all(b"verified private source")?;
        file.sync_all()?;
        drop(file);
        let target = SourcePath::new(&temp.0.join("final"))?;
        partial.publish_new_to(&target)?;
        assert_eq!(
            std::fs::read(temp.0.join("final"))?,
            b"verified private source"
        );
        let second = SourcePath::new(&temp.0.join("other"))?;
        drop(second.open_partial_private(true)?);
        assert!(second.publish_new_to(&target).is_err());
        assert!(temp.0.join("other").exists());
        Ok(())
    }
}
