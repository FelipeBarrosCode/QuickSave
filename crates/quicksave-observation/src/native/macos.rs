// SPDX-License-Identifier: GPL-3.0-only
//! Unprivileged libproc polling. FFI layouts come from macOS proc_info.h.
use crate::*;
use anyhow::{ensure, Context, Result};
use std::{
    ffi::{c_void, CStr},
    mem::{size_of, zeroed},
    path::{Path, PathBuf},
};

const PROC_UID_ONLY: u32 = 4;
const PROC_PIDREGIONPATHINFO: i32 = 8;
const PROC_PIDFDVNODEPATHINFO: i32 = 2;
const MAX_IMAGE_REGIONS: usize = 64;

#[repr(C)]
struct ProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard_flags: u32,
}
#[repr(C)]
struct VnodeFdPath {
    file: ProcFileInfo,
    vnode: libc::vnode_info_path,
}
#[repr(C)]
struct RegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    wired: u32,
    user_tag: u32,
    resident: u32,
    shared_private: u32,
    swapped: u32,
    dirtied: u32,
    refs: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_resident: u32,
    shared_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}
#[repr(C)]
struct RegionPath {
    region: RegionInfo,
    vnode: libc::vnode_info_path,
}

pub struct MacLibproc {
    uid: u32,
    bundle_verification: bool,
}

impl MacLibproc {
    pub fn new(scope: &ObservationScope) -> Result<Self> {
        // SAFETY: no pointer arguments or side effects beyond reading euid.
        ensure!(
            scope.uid() == unsafe { libc::geteuid() },
            "libproc observation requires the approved effective UID"
        );
        Ok(Self {
            uid: scope.uid(),
            bundle_verification: signing::no_network_dynamic_validation_available(),
        })
    }
}

impl ProcessProbe for MacLibproc {
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            source: SourceKind::MacLibproc, state: CapabilityState::Available,
            process_generations: true, executable_stamps: true, running_image_native_identity: true, native_open_file_identity: true,
            bundle_identifier_verification: self.bundle_verification, complete_lifecycle_stream: false, complete_file_stream: false,
            reason: "Same-user libproc generation, mapped executable vnode and open-vnode sampling; native signing-ID verification for registered bundles. Permission failures and short-lived activity remain gaps.",
        }
    }

    fn processes(&mut self, _: &ObservationScope, max: usize) -> Result<ProbeListing<u32>> {
        let mut pids = vec![0_i32; max + 1];
        clear_errno();
        // SAFETY: writable buffer with exactly the advertised bounded byte size.
        let count = unsafe {
            libc::proc_listpids(
                PROC_UID_ONLY,
                self.uid,
                pids.as_mut_ptr().cast(),
                (pids.len() * size_of::<i32>()) as i32,
            )
        };
        if count <= 0 {
            return Err(native_failure("libproc PID enumeration unavailable"));
        }
        ensure!(
            count > 0 && count as usize % size_of::<i32>() == 0,
            "libproc PID enumeration failed"
        );
        let received = count as usize / size_of::<i32>();
        ensure!(
            received <= pids.len(),
            "libproc returned an invalid PID buffer size"
        );
        pids.truncate(received);
        let mut items: Vec<_> = pids
            .into_iter()
            .filter(|pid| *pid > 0)
            .map(|pid| pid as u32)
            .collect();
        let complete = received < max + 1 && items.len() <= max;
        items.truncate(max);
        items.sort_unstable();
        items.dedup();
        Ok(ProbeListing { items, complete })
    }

    fn process(&mut self, scope: &ObservationScope, pid: u32) -> Result<Option<ProcessDescriptor>> {
        ensure!(pid > 0 && pid <= i32::MAX as u32, "invalid libproc PID");
        let before: libc::proc_bsdinfo = pid_info(pid, libc::PROC_PIDTBSDINFO, 0)?;
        if before.pbi_uid != self.uid {
            return Ok(None);
        }
        let executable = process_path(pid)?;
        if scope
            .locate(&executable, ObservationRootKind::Executable)
            .is_none()
        {
            return Ok(None);
        }
        let native_image = image_identity(pid, &executable)?;
        let registered_bundle = scope.application(&executable).is_some_and(|app| {
            matches!(
                app.identity.product,
                quicksave_integrations::profiles::ProductIdentity::MacBundleIdentifier(_)
            )
        });
        let registered_bundle = registered_bundle
            || scope
                .native_application(&executable)
                .is_some_and(|app| app.mac_bundle.is_some());
        let bundle_identifier = if registered_bundle
            && self.bundle_verification
            && bundle_metadata_is_scoped(scope, &executable)
        {
            signing::identifier(pid)
        } else {
            None
        };
        let after: libc::proc_bsdinfo = pid_info(pid, libc::PROC_PIDTBSDINFO, 0)?;
        ensure!(
            same_generation(&before, &after) && process_path(pid)? == executable,
            "libproc generation/image changed"
        );
        ensure!(
            image_identity(pid, &executable)? == native_image,
            "mapped executable vnode changed"
        );
        Ok(Some(ProcessDescriptor {
            generation: ProcessGeneration {
                pid,
                uid: before.pbi_uid,
                start: [before.pbi_start_tvsec, before.pbi_start_tvusec],
                namespace: [0, 0],
            },
            executable,
            executable_identity: native_image,
            image_binding: ImageIdentityBinding::MappedImageNativeFile,
            bundle_identifier,
        }))
    }

    fn descriptors(&mut self, pid: u32, max: usize) -> Result<ProbeListing<u64>> {
        // Explicit repr(C) libc array, initialized prior to the native fill.
        let mut descriptors: Vec<libc::proc_fdinfo> =
            (0..max + 1).map(|_| unsafe { zeroed() }).collect();
        let bytes = descriptors.len() * size_of::<libc::proc_fdinfo>();
        clear_errno();
        // SAFETY: bounded, aligned, initialized native array.
        let count = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDLISTFDS,
                0,
                descriptors.as_mut_ptr().cast(),
                bytes as i32,
            )
        };
        if count < 0 {
            return Err(native_failure("libproc descriptor enumeration unavailable"));
        }
        ensure!(
            count >= 0
                && count as usize <= bytes
                && count as usize % size_of::<libc::proc_fdinfo>() == 0,
            "libproc descriptor enumeration failed"
        );
        // Zero is ambiguous (exit/denial vs no descriptors), so never claim a
        // complete descriptor listing from it.
        if count == 0 {
            return Err(native_failure(
                "libproc returned no verifiable descriptor enumeration",
            ));
        }
        let received = count as usize / size_of::<libc::proc_fdinfo>();
        descriptors.truncate(received);
        let complete = received < max + 1;
        let items = descriptors
            .into_iter()
            .take(max)
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32 && fd.proc_fd >= 0)
            .map(|fd| fd.proc_fd as u64)
            .collect();
        Ok(ProbeListing { items, complete })
    }

    fn descriptor(
        &mut self,
        scope: &ObservationScope,
        pid: u32,
        descriptor: u64,
    ) -> Result<Option<DescriptorSample>> {
        ensure!(
            descriptor <= i32::MAX as u64,
            "invalid libproc file descriptor"
        );
        let mut value: VnodeFdPath = unsafe { zeroed() };
        clear_errno();
        // SAFETY: native ABI layout, writable initialized value, exact byte size.
        let count = unsafe {
            libc::proc_pidfdinfo(
                pid as i32,
                descriptor as i32,
                PROC_PIDFDVNODEPATHINFO,
                (&mut value as *mut VnodeFdPath).cast(),
                size_of::<VnodeFdPath>() as i32,
            )
        };
        if count <= 0 {
            return Err(native_failure("libproc vnode descriptor unavailable"));
        }
        ensure!(
            count == size_of::<VnodeFdPath>() as i32,
            "libproc vnode descriptor lookup failed"
        );
        let path = vnode_path(&value.vnode)?;
        if scope.locate(&path, ObservationRootKind::Data).is_none() {
            return Ok(None);
        }
        ensure!(
            value.vnode.vip_vi.vi_stat.vst_mode & libc::S_IFMT == libc::S_IFREG,
            "libproc descriptor is not regular"
        );
        Ok(Some(DescriptorSample {
            path,
            identity: vnode_identity(&value.vnode),
        }))
    }
}

fn bundle_metadata_is_scoped(scope: &ObservationScope, executable: &Path) -> bool {
    if scope
        .native_application(executable)
        .into_iter()
        .filter_map(|app| app.mac_bundle.as_ref().map(|bundle| (app, bundle)))
        .any(|(app, bundle)| {
            scope.roots().any(|root| {
                app.root_ids.contains(&root.id)
                    && root.kind.allows(ObservationRootKind::Executable)
                    && root.allowed_files.is_none()
                    && bundle.path.starts_with(&root.path)
                    && !scope.request.excluded_paths.iter().any(|excluded| {
                        bundle.path.starts_with(excluded) || excluded.starts_with(&bundle.path)
                    })
            })
        })
    {
        return true;
    }
    scope.application(executable).into_iter().any(|app| {
        let Some(bundle) = &app.identity.install.location else {
            return false;
        };
        if !executable.starts_with(bundle.join("Contents/MacOS"))
            || app.identity.install.metadata_path != bundle.join("Contents/Info.plist")
        {
            return false;
        }
        scope.roots().any(|root| {
            root.kind.allows(ObservationRootKind::Executable)
                && root.allowed_files.is_none()
                && bundle.starts_with(&root.path)
                && !scope
                    .request
                    .excluded_paths
                    .iter()
                    .any(|excluded| bundle.starts_with(excluded) || excluded.starts_with(bundle))
        })
    })
}

fn pid_info<T>(pid: u32, flavor: i32, address: u64) -> Result<T> {
    let mut value: T = unsafe { zeroed() };
    clear_errno();
    // SAFETY: callers only use zero-valid repr(C) native ABI structs.
    let count = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            flavor,
            address,
            (&mut value as *mut T).cast(),
            size_of::<T>() as i32,
        )
    };
    if count <= 0 {
        return Err(native_failure("libproc native information unavailable"));
    }
    ensure!(
        count == size_of::<T>() as i32,
        "libproc native information unavailable"
    );
    Ok(value)
}

fn same_generation(a: &libc::proc_bsdinfo, b: &libc::proc_bsdinfo) -> bool {
    a.pbi_pid == b.pbi_pid
        && a.pbi_uid == b.pbi_uid
        && a.pbi_start_tvsec == b.pbi_start_tvsec
        && a.pbi_start_tvusec == b.pbi_start_tvusec
}

fn process_path(pid: u32) -> Result<PathBuf> {
    let mut bytes = [0_u8; 4096];
    clear_errno();
    // SAFETY: writable byte buffer sized per PROC_PIDPATHINFO_MAXSIZE.
    let count =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if count <= 0 {
        return Err(native_failure("libproc executable path unavailable"));
    }
    ensure!(
        count > 0 && (count as usize) < bytes.len(),
        "libproc executable path unavailable"
    );
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("libproc path is unterminated")?;
    Ok(PathBuf::from(std::str::from_utf8(&bytes[..nul])?))
}

fn image_identity(pid: u32, executable: &Path) -> Result<NativeFileIdentity> {
    let mut address = 0_u64;
    for _ in 0..MAX_IMAGE_REGIONS {
        let region: RegionPath = pid_info(pid, PROC_PIDREGIONPATHINFO, address)?;
        if vnode_path(&region.vnode).is_ok_and(|path| path == executable) {
            return Ok(vnode_identity(&region.vnode));
        }
        let next = region
            .region
            .address
            .checked_add(region.region.size)
            .context("native region overflow")?;
        ensure!(next > address, "libproc region enumeration did not advance");
        address = next;
    }
    anyhow::bail!("mapped executable identity unavailable within the native region bound")
}

fn vnode_identity(vnode: &libc::vnode_info_path) -> NativeFileIdentity {
    NativeFileIdentity {
        device: vnode.vip_vi.vi_stat.vst_dev as libc::dev_t as u64,
        file_id: [vnode.vip_vi.vi_stat.vst_ino, 0],
    }
}

fn vnode_path(vnode: &libc::vnode_info_path) -> Result<PathBuf> {
    // SAFETY: the fixed 1024-byte field is inspected with an explicit bound;
    // CStr is constructed only after finding a NUL inside that same field.
    let bytes = unsafe { std::slice::from_raw_parts(vnode.vip_path.as_ptr().cast::<u8>(), 1024) };
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated libproc vnode path")?;
    ensure!(nul > 0, "libproc vnode path unavailable");
    Ok(PathBuf::from(std::str::from_utf8(&bytes[..nul])?))
}

fn clear_errno() {
    // SAFETY: __error is the current thread's writable errno slot. Clearing it
    // distinguishes a valid empty result from a real native permission error.
    unsafe {
        *libc::__error() = 0;
    }
}

fn native_failure(message: &'static str) -> anyhow::Error {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error().unwrap_or(0) != 0 {
        anyhow::Error::new(error).context(message)
    } else {
        anyhow::anyhow!(message)
    }
}

mod signing {
    use super::*;
    type Cf = *const c_void;
    #[repr(C)]
    struct DictionaryKeyCallbacks {
        version: isize,
        retain: usize,
        release: usize,
        description: usize,
        equal: usize,
        hash: usize,
    }
    #[repr(C)]
    struct DictionaryValueCallbacks {
        version: isize,
        retain: usize,
        release: usize,
        description: usize,
        equal: usize,
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFTypeDictionaryKeyCallBacks: DictionaryKeyCallbacks;
        static kCFTypeDictionaryValueCallBacks: DictionaryValueCallbacks;
        fn CFNumberCreate(allocator: Cf, kind: isize, value: Cf) -> Cf;
        fn CFDictionaryCreate(
            allocator: Cf,
            keys: *const Cf,
            values: *const Cf,
            count: isize,
            key_callbacks: Cf,
            value_callbacks: Cf,
        ) -> Cf;
        fn CFDictionaryGetValue(dictionary: Cf, key: Cf) -> Cf;
        fn CFGetTypeID(value: Cf) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFStringGetCString(value: Cf, buffer: *mut i8, size: isize, encoding: u32) -> u8;
        fn CFRelease(value: Cf);
    }
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributePid: Cf;
        static kSecCodeInfoIdentifier: Cf;
        fn SecCodeCopyGuestWithAttributes(
            host: Cf,
            attributes: Cf,
            flags: u32,
            code: *mut Cf,
        ) -> i32;
        fn SecCodeCheckValidity(code: Cf, flags: u32, requirement: Cf) -> i32;
        fn SecCodeCopySigningInformation(code: Cf, flags: u32, information: *mut Cf) -> i32;
    }
    struct Owned(Cf);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    pub fn no_network_dynamic_validation_available() -> bool {
        // The running-code no-network flag is documented only on macOS 11.3+.
        // Query bounded kernel version metadata; on ambiguity, do not call the
        // Security API at all and report bundle identity as unverified.
        let mut bytes = [0_u8; 128];
        let mut length = bytes.len();
        let result = unsafe {
            libc::sysctlbyname(
                c"kern.osproductversion".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length == 0 || length > bytes.len() {
            return false;
        }
        let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
            return false;
        };
        let Ok(version) = std::str::from_utf8(&bytes[..end]) else {
            return false;
        };
        let mut parts = version.split('.');
        let Some(major) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
            return false;
        };
        let Some(minor) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
            return false;
        };
        (major, minor) >= (11, 3)
    }

    pub fn identifier(pid: u32) -> Option<String> {
        let pid = i32::try_from(pid).ok()?;
        // SAFETY: all CF allocations are retained until after dependent calls,
        // out-pointers start null, dictionary values live for its whole lifetime,
        // and the returned CFString is type-checked and copied within 1024 bytes.
        unsafe {
            let number = Owned(CFNumberCreate(
                std::ptr::null(),
                3,
                (&pid as *const i32).cast(),
            ));
            if number.0.is_null() {
                return None;
            }
            let keys = [kSecGuestAttributePid];
            let values = [number.0];
            let attributes = Owned(CFDictionaryCreate(
                std::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                (&kCFTypeDictionaryKeyCallBacks as *const DictionaryKeyCallbacks).cast(),
                (&kCFTypeDictionaryValueCallBacks as *const DictionaryValueCallbacks).cast(),
            ));
            if attributes.0.is_null() {
                return None;
            }
            let mut code = std::ptr::null();
            if SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.0, 0, &mut code) != 0 {
                return None;
            }
            let code = Owned(code);
            if code.0.is_null() {
                return None;
            }
            // kSecCSNoNetworkAccess: never fetch revocation or other network data.
            if SecCodeCheckValidity(code.0, 1 << 29, std::ptr::null()) != 0 {
                return None;
            }
            let mut information = std::ptr::null();
            if SecCodeCopySigningInformation(code.0, 0, &mut information) != 0 {
                return None;
            }
            let information = Owned(information);
            if information.0.is_null() {
                return None;
            }
            let identifier = CFDictionaryGetValue(information.0, kSecCodeInfoIdentifier);
            if identifier.is_null() || CFGetTypeID(identifier) != CFStringGetTypeID() {
                return None;
            }
            let mut bytes = [0_i8; 1024];
            if CFStringGetCString(
                identifier,
                bytes.as_mut_ptr(),
                bytes.len() as isize,
                0x08000100,
            ) == 0
            {
                return None;
            }
            let id = CStr::from_ptr(bytes.as_ptr()).to_str().ok()?;
            if id.is_empty() || id.len() > 400 || id.chars().any(char::is_control) {
                return None;
            }
            Some(id.to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn libproc_ffi_layouts_match_public_sdk_without_live_process_calls() {
        assert_eq!(size_of::<ProcFileInfo>(), 24);
        assert_eq!(size_of::<RegionInfo>(), 96);
        assert_eq!(
            size_of::<VnodeFdPath>(),
            24 + size_of::<libc::vnode_info_path>()
        );
        assert_eq!(
            size_of::<RegionPath>(),
            96 + size_of::<libc::vnode_info_path>()
        );
    }
}
