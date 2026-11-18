// SPDX-License-Identifier: GPL-3.0-only
//! Real same-SID process/time/image-path sampling; no invented file-I/O events.
//! Kernel-File ETW is intentionally not installed or started by this adapter.
use crate::*;
use anyhow::{ensure, Result};
use std::{ffi::c_void, mem::size_of, path::PathBuf};

type Handle = *mut c_void;
const INVALID: Handle = -1_isize as Handle;
#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}
#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    pid: u32,
    default_heap: usize,
    module_id: u32,
    threads: u32,
    parent_pid: u32,
    base_priority: i32,
    flags: u32,
    executable: [u16; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetCurrentProcess() -> Handle;
    fn GetProcessTimes(
        process: Handle,
        created: *mut FileTime,
        exited: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: u32,
        path: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn GetLastError() -> u32;
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn EqualSid(first: *const c_void, second: *const c_void) -> i32;
}

struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Stable aligned allocation: TOKEN_USER's SID pointer refers into this buffer.
struct TokenUser {
    buffer: Box<[usize; 256]>,
}
impl TokenUser {
    fn for_process(process: Handle) -> Result<Self> {
        let mut token = std::ptr::null_mut();
        // SAFETY: borrowed valid process handle, initialized writable out handle.
        if unsafe { OpenProcessToken(process, 8, &mut token) } == 0 {
            return Err(native_failure("native process token unavailable"));
        }
        let token = Owned(token);
        let mut value = Self {
            buffer: Box::new([0; 256]),
        };
        let mut needed = 0_u32;
        // SAFETY: aligned, initialized, bounded token-user output buffer.
        let result = unsafe {
            GetTokenInformation(
                token.0,
                1,
                value.buffer.as_mut_ptr().cast(),
                size_of::<[usize; 256]>() as u32,
                &mut needed,
            )
        };
        if result == 0 {
            return Err(native_failure("native SID metadata unavailable"));
        }
        ensure!(
            needed as usize <= size_of::<[usize; 256]>(),
            "native SID metadata exceeds the bound"
        );
        ensure!(!value.sid().is_null(), "native process SID missing");
        Ok(value)
    }
    fn sid(&self) -> *const c_void {
        // SAFETY: successful GetTokenInformation(TokenUser) wrote SID_AND_ATTRIBUTES;
        // its first field is a pointer and allocation remains stable.
        unsafe { std::ptr::read(self.buffer.as_ptr().cast::<*const c_void>()) }
    }
}

pub struct WindowsProcesses {
    current_user: TokenUser,
}

impl WindowsProcesses {
    pub fn new(scope: &ObservationScope) -> Result<Self> {
        // Windows uses the approved current SID, not an invented Unix UID.
        ensure!(
            scope.uid() == 0,
            "Windows observation scopes use uid=0 and bind the current native SID"
        );
        Ok(Self {
            current_user: TokenUser::for_process(unsafe { GetCurrentProcess() })?,
        })
    }
}

impl ProcessProbe for WindowsProcesses {
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            source: SourceKind::WindowsProcess, state: CapabilityState::Available,
            process_generations: true, executable_stamps: true, running_image_native_identity: false,
            native_open_file_identity: false, bundle_identifier_verification: false,
            complete_lifecycle_stream: false, complete_file_stream: false,
            reason: "Same-SID GetProcessTimes and QueryFullProcessImageNameW with pinned approved path stamps only. Image-section file IDs and Kernel-File ETW are unavailable; no open-file attribution is emitted.",
        }
    }
    fn processes(&mut self, _: &ObservationScope, max: usize) -> Result<ProbeListing<u32>> {
        // SAFETY: toolhelp returns an owned local snapshot handle.
        let raw = unsafe { CreateToolhelp32Snapshot(2, 0) };
        if raw == INVALID || raw.is_null() {
            return Err(native_failure("native process snapshot unavailable"));
        }
        let snapshot = Owned(raw);
        let mut entry: ProcessEntry = unsafe { std::mem::zeroed() };
        entry.size = size_of::<ProcessEntry>() as u32;
        let mut items = Vec::new();
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while more != 0 {
            if items.len() >= max {
                return Ok(ProbeListing {
                    items,
                    complete: false,
                });
            }
            if entry.pid != 0 {
                items.push(entry.pid);
            }
            more = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        // ERROR_NO_MORE_FILES, not AccessDenied/truncated native output.
        let error = unsafe { GetLastError() };
        if error != 18 {
            return Err(
                anyhow::Error::new(std::io::Error::from_raw_os_error(error as i32))
                    .context("native process enumeration incomplete"),
            );
        }
        Ok(ProbeListing {
            items,
            complete: true,
        })
    }
    fn process(&mut self, scope: &ObservationScope, pid: u32) -> Result<Option<ProcessDescriptor>> {
        let raw = unsafe { OpenProcess(0x1000, 0, pid) };
        if raw.is_null() {
            return Err(native_failure(
                "native process query permission unavailable",
            ));
        }
        let process = Owned(raw);
        let user = TokenUser::for_process(process.0)?;
        if unsafe { EqualSid(self.current_user.sid(), user.sid()) } == 0 {
            return Ok(None);
        }
        let before = creation_time(process.0)?;
        let executable = image_path(process.0)?;
        if scope
            .locate(&executable, ObservationRootKind::Executable)
            .is_none()
        {
            return Ok(None);
        }
        let (_, _, stamp) = scope.stamp(&executable, ObservationRootKind::Executable)?;
        ensure!(
            creation_time(process.0)? == before && image_path(process.0)? == executable,
            "native process image or generation changed"
        );
        Ok(Some(ProcessDescriptor {
            generation: ProcessGeneration {
                pid,
                uid: 0,
                start: [before, 0],
                namespace: [0, 0],
            },
            executable,
            executable_identity: NativeFileIdentity::from(&stamp),
            image_binding: ImageIdentityBinding::ProcessImagePathAndPinnedStampOnly,
            bundle_identifier: None,
        }))
    }
    fn descriptors(&mut self, _: u32, _: usize) -> Result<ProbeListing<u64>> {
        anyhow::bail!(
            "Kernel-File ETW native source is not bound; polling is not open-file evidence"
        )
    }
    fn descriptor(
        &mut self,
        _: &ObservationScope,
        _: u32,
        _: u64,
    ) -> Result<Option<DescriptorSample>> {
        anyhow::bail!("Windows native file-I/O source requires an explicitly consented ETW binding")
    }
}

fn creation_time(process: Handle) -> Result<u64> {
    let mut created = FileTime { low: 0, high: 0 };
    let mut exited = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(native_failure("native process creation time unavailable"));
    }
    Ok((created.high as u64) << 32 | created.low as u64)
}

fn image_path(process: Handle) -> Result<PathBuf> {
    let mut buffer = [0_u16; 4096];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(native_failure("native process image path unavailable"));
    }
    ensure!(
        length > 0 && (length as usize) < buffer.len(),
        "native process image path exceeds the bound"
    );
    Ok(PathBuf::from(String::from_utf16(
        &buffer[..length as usize],
    )?))
}

fn native_failure(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(std::io::Error::last_os_error()).context(message)
}
