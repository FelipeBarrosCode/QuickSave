//! Per-filesystem admission for storage work; reservations never delete user data.
//!
//! Aggregate plans use [`check_admission`], which does not hold capacity. Active
//! writers use [`DiskWriteBudget`] and consume their reservation only after bytes
//! have been allocated on disk. Do not also hold an aggregate reservation for the
//! same writes: an independent writer budget would charge that capacity twice.
use crate::{Result, StateError};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

type ReservationRegistry = Arc<Mutex<BTreeMap<u64, u64>>>;
type DeviceRequests<'a> = BTreeMap<u64, (u64, u64, &'a Path)>;

static RESERVED: OnceLock<ReservationRegistry> = OnceLock::new();

fn registry() -> ReservationRegistry {
    Arc::clone(RESERVED.get_or_init(Default::default))
}

pub fn safety_margin() -> u64 {
    std::env::var("NOLAND_STORAGE_MIN_FREE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64 * 1024 * 1024)
}

#[cfg(unix)]
pub fn available(path: &Path) -> Result<(u64, u64)> {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
    };
    let ancestor = path.ancestors().find(|path| path.exists()).ok_or_else(|| {
        StateError::Storage(format!("no existing filesystem for {}", path.display()))
    })?;
    let name = CString::new(ancestor.as_os_str().as_bytes())
        .map_err(|_| StateError::UnsafePath("NUL in storage path".into()))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: name is NUL-terminated and stat points to writable statvfs storage.
    if unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    // statvfs field widths differ across the supported Unix targets.
    #[allow(clippy::unnecessary_cast)]
    let free = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    Ok((std::fs::metadata(ancestor)?.dev(), free))
}

/// Query caller-available bytes on the actual local Windows volume containing
/// this path. Missing descendants are admitted against their last existing
/// directory, never a guessed system drive. This is capacity, not path/write
/// authority: the writer must still keep its native namespace handles pinned.
#[cfg(windows)]
pub fn available(path: &Path) -> Result<(u64, u64)> {
    windows::available(path)
}

#[cfg(not(any(unix, windows)))]
pub fn available(_path: &Path) -> Result<(u64, u64)> {
    Err(StateError::Storage(
        "native storage disk admission is unsupported on this platform".into(),
    ))
}

// Windows native additions: SPDX-License-Identifier: GPL-3.0-only.
// Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
// Original Unix accounting and source notices remain unchanged.
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::c_void,
        fs::File,
        io,
        mem::{size_of, MaybeUninit},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::{Component, Prefix},
        ptr,
    };

    const MAX_PATH_UNITS: usize = 32_767;
    const MAX_COMPONENTS: usize = 128;
    const READ_ATTRIBUTES: u32 = 0x80;
    const SYNCHRONIZE: u32 = 0x10_0000;
    const SHARE_READ_WRITE: u32 = 3; // No FILE_SHARE_DELETE.
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const DIRECTORY: u32 = 0x10;
    const DEVICE: u32 = 0x40;
    const REPARSE_POINT: u32 = 0x400;
    const VOLUME_NAME_GUID: u32 = 1;

    #[repr(C)]
    struct IdInfo {
        volume: u64,
        id: [u8; 16],
    }
    #[repr(C)]
    struct TagInfo {
        attributes: u32,
        tag: u32,
    }
    #[repr(C)]
    struct StandardInfo {
        allocation: i64,
        size: i64,
        links: u32,
        delete_pending: u8,
        directory: u8,
    }
    const _: () = {
        assert!(size_of::<IdInfo>() == 24);
        assert!(size_of::<TagInfo>() == 8);
        assert!(size_of::<StandardInfo>() == 24);
        assert!(std::mem::offset_of!(StandardInfo, delete_pending) == 20);
        assert!(std::mem::offset_of!(StandardInfo, directory) == 21);
    };
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        volume: u64,
        id: [u8; 16],
        directory: bool,
    }
    struct Pin {
        file: File,
        identity: Identity,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetFileType(handle: *mut c_void) -> u32;
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            handle: *mut c_void,
            path: *mut u16,
            capacity: u32,
            flags: u32,
        ) -> u32;
        fn GetVolumeInformationByHandleW(
            handle: *mut c_void,
            name: *mut u16,
            name_capacity: u32,
            serial: *mut u32,
            maximum_component: *mut u32,
            flags: *mut u32,
            filesystem: *mut u16,
            filesystem_capacity: u32,
        ) -> i32;
        fn GetDiskFreeSpaceExW(
            directory: *const u16,
            caller_available: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }

    fn unsafe_path() -> StateError {
        StateError::UnsafePath(
            "Windows disk admission requires a bounded absolute local NTFS/ReFS path without traversal, device names or reparse points".into(),
        )
    }

    fn components(path: &Path) -> Result<(PathBuf, Vec<&std::ffi::OsStr>)> {
        let text = path.to_str().ok_or_else(unsafe_path)?;
        if !path.is_absolute()
            || text.is_empty()
            || text.contains('\0')
            || path.as_os_str().encode_wide().count() > MAX_PATH_UNITS
            || text
                .split(['\\', '/'])
                .any(|part| part == "." || part == "..")
        {
            return Err(unsafe_path());
        }
        let mut parts = path.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive)
                    if drive.is_ascii_alphabetic() =>
                {
                    drive
                }
                _ => return Err(unsafe_path()),
            },
            _ => return Err(unsafe_path()),
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(unsafe_path());
        }
        let root = PathBuf::from(format!("\\\\?\\{}:\\", drive.to_ascii_uppercase() as char));
        let mut normal = Vec::new();
        for part in parts {
            let Component::Normal(part) = part else {
                return Err(unsafe_path());
            };
            let text = part.to_str().ok_or_else(unsafe_path)?;
            if text.is_empty()
                || text.ends_with(['.', ' '])
                || text.encode_utf16().count() > 255
                || text.chars().any(|c| {
                    c.is_control()
                        || matches!(c, '\\' | '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
                })
            {
                return Err(unsafe_path());
            }
            let stem = text.split('.').next().unwrap().to_ascii_uppercase();
            if matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(*prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            }) {
                return Err(unsafe_path());
            }
            normal.push(part);
            if normal.len() > MAX_COMPONENTS {
                return Err(unsafe_path());
            }
        }
        Ok((root, normal))
    }

    fn query<T>(file: &File, class: i32) -> Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        // SAFETY: each caller supplies the exact native structure for its class;
        // Windows initializes that structure only on a successful call.
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

    fn identity(file: &File) -> Result<Identity> {
        if unsafe { GetFileType(file.as_raw_handle()) } != 1 {
            return Err(unsafe_path());
        }
        let tag: TagInfo = query(file, 9)?; // FileAttributeTagInfo
        let standard: StandardInfo = query(file, 1)?; // FileStandardInfo
        let id: IdInfo = query(file, 18)?; // FileIdInfo, NOT the legacy 64-bit file index.
        if tag.attributes & (REPARSE_POINT | DEVICE) != 0
            || tag.tag != 0
            || standard.delete_pending != 0
            || standard.links == 0
            || standard.size < 0
            || id.id == [0; 16]
            || (tag.attributes & DIRECTORY != 0) != (standard.directory != 0)
        {
            return Err(unsafe_path());
        }
        Ok(Identity {
            volume: id.volume,
            id: id.id,
            directory: standard.directory != 0,
        })
    }

    fn open(path: &Path) -> Result<Pin> {
        let file = File::options()
            .access_mode(READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(SHARE_READ_WRITE)
            .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
            .open(path)?;
        let identity = identity(&file)?;
        Ok(Pin { file, identity })
    }

    fn filesystem(file: &File) -> Result<()> {
        let mut name = [0u16; 32];
        if unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                name.as_mut_ptr(),
                name.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let end = name
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(unsafe_path)?;
        let name = String::from_utf16(&name[..end]).map_err(|_| unsafe_path())?;
        if !name.eq_ignore_ascii_case("NTFS") && !name.eq_ignore_ascii_case("ReFS") {
            return Err(unsafe_path());
        }
        Ok(())
    }

    fn volume_directory(file: &File) -> Result<Vec<u16>> {
        let mut path = vec![0u16; MAX_PATH_UNITS + 1];
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                VOLUME_NAME_GUID,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error().into());
        }
        if count as usize >= path.len() {
            return Err(unsafe_path());
        }
        path.truncate(count as usize);
        let prefix = "\\\\?\\Volume{".encode_utf16().collect::<Vec<_>>();
        if !path.starts_with(&prefix) || path.contains(&0) {
            return Err(unsafe_path());
        }
        if path.last() != Some(&(b'\\' as u16)) {
            path.push(b'\\' as u16);
        }
        if path.len() > MAX_PATH_UNITS {
            return Err(unsafe_path());
        }
        path.push(0);
        Ok(path)
    }

    pub(super) fn available(path: &Path) -> Result<(u64, u64)> {
        let (mut current, components) = components(path)?;
        let drive = current
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // Reject mapped/network/unknown drives before opening any path on them.
        if !matches!(unsafe { GetDriveTypeW(drive.as_ptr()) }, 2 | 3 | 6) {
            return Err(unsafe_path());
        }
        let mut pins = vec![open(&current)?];
        if !pins[0].identity.directory {
            return Err(unsafe_path());
        }
        for (number, component) in components.iter().enumerate() {
            current.push(component);
            match open(&current) {
                Ok(pin) => {
                    if pin.identity.volume != pins.last().unwrap().identity.volume {
                        return Err(unsafe_path());
                    }
                    if !pin.identity.directory {
                        // A regular existing final file occupies its parent's
                        // volume; a descendant of a file cannot be created.
                        if number + 1 != components.len() {
                            return Err(unsafe_path());
                        }
                        pins.push(pin);
                        break;
                    }
                    pins.push(pin);
                }
                Err(StateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error), // Never turn denied access into a missing ancestor.
            }
        }
        let directory = pins
            .iter()
            .rfind(|pin| pin.identity.directory)
            .ok_or_else(unsafe_path)?;
        filesystem(&directory.file)?;
        let native_path = volume_directory(&directory.file)?;
        let mut free = 0u64;
        let mut total = 0u64;
        let mut all_free = 0u64;
        if unsafe {
            GetDiskFreeSpaceExW(native_path.as_ptr(), &mut free, &mut total, &mut all_free)
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        for pin in &pins {
            if identity(&pin.file)? != pin.identity {
                return Err(unsafe_path());
            }
        }
        if volume_directory(&directory.file)? != native_path {
            return Err(unsafe_path());
        }
        // Use quota-aware bytes available to this caller, not total free bytes
        // or capacity on C:. Keep the native 64-bit volume ID for accounting.
        Ok((directory.identity.volume, free))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Fixture {
            root: PathBuf,
        }
        impl Fixture {
            fn new() -> Self {
                let base = std::env::temp_dir();
                // Validate the caller's temp root as local/no-reparse first.
                // No live application state, network drive or provider is used.
                available(&base).expect("a native local NTFS/ReFS test temp root is required");
                let root = base.join(format!("quicksave-disk-admission-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir(&root).unwrap();
                Self { root }
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                // This exact generated fixture only, never an application root.
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        #[test]
        fn native_windows_capacity_uses_the_existing_ancestor_and_full_volume_id() {
            let fixture = Fixture::new();
            let child = fixture.root.join("child");
            std::fs::create_dir(&child).unwrap();
            let directory = open(&child).unwrap();
            let expected = identity(&directory.file).unwrap().volume;
            let native_path = volume_directory(&directory.file).unwrap();
            assert!(native_path.starts_with(&"\\\\?\\Volume{".encode_utf16().collect::<Vec<_>>()));
            assert_eq!(available(&child).unwrap().0, expected);
            assert_eq!(
                available(&child.join("future/descendant/output.pack"))
                    .unwrap()
                    .0,
                expected
            );
            let file = child.join("existing.pack");
            std::fs::write(&file, b"bounded disk fixture").unwrap();
            assert_eq!(available(&file).unwrap().0, expected);
            assert!(available(&file.join("not-a-directory")).is_err());
        }

        #[test]
        fn native_windows_capacity_keeps_same_volume_reservations_aggregate() {
            let fixture = Fixture::new();
            let requests = [
                (fixture.root.join("capture/future"), 1),
                (fixture.root.join("packs/future"), 2),
            ];
            let devices = device_requests(&requests, available).unwrap();
            assert_eq!(devices.len(), 1);
            assert_eq!(devices.values().next().unwrap().1, 3);
        }

        #[test]
        fn native_windows_capacity_rejects_ambiguous_paths_before_access() {
            let fixture = Fixture::new();
            for relative in [
                "../escape",
                "a/../b",
                "a/./b",
                "stream:alternate",
                "trailing.",
                "trailing ",
                "NUL",
                "con.txt",
                "COM1",
                "LPT²",
                "bad?name",
            ] {
                assert!(
                    available(&fixture.root.join(relative)).is_err(),
                    "{relative}"
                );
            }
            for path in [
                r"C:drive-relative",
                r"\root-relative",
                r"relative\directory",
                r"\\server\share\directory",
                r"\\?\UNC\server\share",
                r"\\.\PhysicalDrive0",
            ] {
                assert!(available(Path::new(path)).is_err(), "{path}");
            }
            let embedded_nul = fixture.root.join("invalid\0component");
            assert!(available(&embedded_nul).is_err());
        }

        #[test]
        #[ignore = "requires native Windows Developer Mode or explicit symlink privilege in an isolated temp fixture"]
        fn native_windows_capacity_never_follows_a_directory_reparse_point() {
            let fixture = Fixture::new();
            let actual = fixture.root.join("actual");
            let link = fixture.root.join("link");
            std::fs::create_dir(&actual).unwrap();
            std::os::windows::fs::symlink_dir(&actual, &link).unwrap();
            assert!(available(&link).is_err());
            assert!(available(&link.join("missing/output.pack")).is_err());
        }
    }
}

pub fn ensure_space(path: &Path, bytes: u64) -> Result<()> {
    let (_, free) = available(path)?;
    require(free, bytes, safety_margin(), path)
}

/// Check the aggregate peak-space estimate without holding a reservation for it.
/// Existing active reservations are included, and paths on the same filesystem
/// are summed. Successful preflight is not a promise of future capacity: each
/// writer must still reserve its bounded, not-yet-allocated output before writing.
pub fn check_admission(requests: &[(PathBuf, u64)]) -> Result<()> {
    check_admission_using(&registry(), requests, safety_margin(), available)
}

fn require(free: u64, required: u64, margin: u64, path: &Path) -> Result<()> {
    if required
        .checked_add(margin)
        .is_none_or(|total| free < total)
    {
        return Err(StateError::Storage(format!(
            "insufficient storage at {}: {free} bytes available, {required} required plus {margin} safety margin", path.display()
        )));
    }
    Ok(())
}

fn device_requests<'a>(
    requests: &'a [(PathBuf, u64)],
    mut capacity: impl FnMut(&Path) -> Result<(u64, u64)>,
) -> Result<DeviceRequests<'a>> {
    let mut devices = BTreeMap::<u64, (u64, u64, &Path)>::new();
    for (path, bytes) in requests {
        let (device, free) = capacity(path)?;
        let entry = devices.entry(device).or_insert((free, 0, path));
        entry.0 = entry.0.min(free);
        entry.1 = entry
            .1
            .checked_add(*bytes)
            .ok_or_else(|| StateError::Storage("storage reservation overflow".into()))?;
    }
    Ok(devices)
}

fn check_devices(
    reserved: &BTreeMap<u64, u64>,
    devices: &DeviceRequests<'_>,
    margin: u64,
) -> Result<()> {
    for (device, (free, bytes, path)) in devices {
        let required = bytes
            .checked_add(*reserved.get(device).unwrap_or(&0))
            .ok_or_else(|| StateError::Storage("storage reservation overflow".into()))?;
        require(*free, required, margin, path)?;
    }
    Ok(())
}

fn check_admission_using(
    registry: &ReservationRegistry,
    requests: &[(PathBuf, u64)],
    margin: u64,
    capacity: impl FnMut(&Path) -> Result<(u64, u64)>,
) -> Result<()> {
    let reserved = registry
        .lock()
        .map_err(|_| StateError::Storage("storage reservation lock poisoned".into()))?;
    // Sample free space under the accounting lock. Otherwise a concurrent writer
    // could allocate and consume its reservation between the sample and check,
    // making the older free-space sample overstate unreserved capacity.
    check_devices(&reserved, &device_requests(requests, capacity)?, margin)
}

/// Fixed held capacity, released on drop. For output that is gradually allocated,
/// use [`DiskWriteBudget`] instead so allocated bytes stop counting as reserved.
pub struct DiskReservation {
    registry: ReservationRegistry,
    owned: Vec<(u64, u64)>,
}

impl DiskReservation {
    pub fn reserve(requests: &[(PathBuf, u64)]) -> Result<Self> {
        Self::reserve_using(registry(), requests, safety_margin(), available)
    }

    fn reserve_using(
        registry: ReservationRegistry,
        requests: &[(PathBuf, u64)],
        margin: u64,
        capacity: impl FnMut(&Path) -> Result<(u64, u64)>,
    ) -> Result<Self> {
        let mut reserved = registry
            .lock()
            .map_err(|_| StateError::Storage("storage reservation lock poisoned".into()))?;
        let devices = device_requests(requests, capacity)?;
        check_devices(&reserved, &devices, margin)?;
        let mut owned = Vec::new();
        for (device, (_, bytes, _)) in devices {
            *reserved.entry(device).or_default() += bytes;
            owned.push((device, bytes));
        }
        drop(reserved);
        Ok(Self { registry, owned })
    }
}

fn release(reserved: &mut BTreeMap<u64, u64>, device: u64, bytes: u64) {
    if let Some(total) = reserved.get_mut(&device) {
        *total = total.saturating_sub(bytes);
        if *total == 0 {
            reserved.remove(&device);
        }
    }
}

impl Drop for DiskReservation {
    fn drop(&mut self) {
        if let Ok(mut reserved) = self.registry.lock() {
            for (device, bytes) in &self.owned {
                release(&mut reserved, *device, *bytes);
            }
        }
    }
}

/// A bounded writer's unallocated capacity on one filesystem. Independent
/// writers share admission accounting, but own and consume separate budgets.
pub struct DiskWriteBudget {
    reservation: DiskReservation,
}

impl DiskWriteBudget {
    /// Reserve output capacity before writing. Avoid enclosing held reservations
    /// for the same output; use [`check_admission`] for aggregate plans instead.
    pub fn reserve(path: &Path, bytes: u64) -> Result<Self> {
        Ok(Self {
            reservation: DiskReservation::reserve(&[(path.to_path_buf(), bytes)])?,
        })
    }

    pub fn remaining(&self) -> u64 {
        self.reservation.owned[0].1
    }

    /// Stop reserving bytes now accounted for by the filesystem's free-space
    /// measurement. Call only after successful allocation/flush, not when bytes
    /// merely enter a userspace buffer. Unflushed bytes must remain reserved.
    ///
    /// Consumption is irreversible: deleting output does not replenish this
    /// budget. A later writer must obtain a fresh reservation. Drop releases only
    /// the unused remainder, including on cancellation or write failure.
    pub fn consume_allocated(&mut self, bytes: u64) -> Result<()> {
        let (device, remaining) = &mut self.reservation.owned[0];
        if bytes > *remaining {
            return Err(StateError::Storage(
                "allocated bytes exceed writer disk budget".into(),
            ));
        }
        let mut reserved = self
            .reservation
            .registry
            .lock()
            .map_err(|_| StateError::Storage("storage reservation lock poisoned".into()))?;
        release(&mut reserved, *device, bytes);
        *remaining -= bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer(registry: &ReservationRegistry, free: u64, bytes: u64) -> Result<DiskWriteBudget> {
        Ok(DiskWriteBudget {
            reservation: DiskReservation::reserve_using(
                Arc::clone(registry),
                &[(PathBuf::from("capture"), bytes)],
                20,
                |_| Ok((1, free)),
            )?,
        })
    }

    #[test]
    fn admission_includes_margin_and_overflow_fails_closed() {
        assert!(require(100, 80, 20, Path::new("fixture")).is_ok());
        assert!(require(99, 80, 20, Path::new("fixture")).is_err());
        assert!(require(100, u64::MAX, 20, Path::new("fixture")).is_err());
        assert!(require(u64::MAX, u64::MAX, 1, Path::new("fixture")).is_err());
    }

    #[test]
    fn aggregate_preflight_does_not_double_charge_active_writers() {
        let registry = ReservationRegistry::default();
        let requests = [(PathBuf::from("capture"), 40), (PathBuf::from("packs"), 40)];
        check_admission_using(&registry, &requests, 20, |_| Ok((1, 100))).unwrap();
        assert!(registry.lock().unwrap().is_empty());
        let capture = writer(&registry, 100, 40).unwrap();
        let packs = writer(&registry, 100, 40).unwrap();
        assert!(writer(&registry, 100, 1).is_err());
        // Preflight must still account for capacity held by other active writers.
        assert!(check_admission_using(&registry, &requests, 20, |_| Ok((1, 100))).is_err());
        drop(capture);
        drop(packs);
        assert!(registry.lock().unwrap().is_empty());
    }

    #[test]
    fn concurrent_writers_cannot_admit_the_same_capacity() {
        let registry = ReservationRegistry::default();
        let start = std::sync::Barrier::new(3);
        let outcomes = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        writer(&registry, 100, 80)
                    })
                })
                .collect();
            start.wait();
            // Keep the successful reservation alive until both have attempted
            // admission; either contender may win, but they cannot both win.
            writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(registry.lock().unwrap().get(&1), Some(&80));
        drop(outcomes);
        assert!(registry.lock().unwrap().is_empty());
        assert!(writer(&registry, 100, 80).is_ok());
    }

    #[test]
    fn allocated_bytes_are_not_charged_again_and_drop_releases_only_unused_capacity() {
        let registry = ReservationRegistry::default();
        let mut capture = writer(&registry, 100, 60).unwrap();
        // Forty bytes have reached the filesystem; the free-space sample is now
        // 60. Until the writer acknowledges its allocation, admission is conservative.
        assert!(writer(&registry, 60, 20).is_err());
        capture.consume_allocated(40).unwrap();
        assert_eq!(capture.remaining(), 20);
        let packs = writer(&registry, 60, 20).unwrap();
        assert!(writer(&registry, 60, 1).is_err());
        drop(capture);
        assert_eq!(registry.lock().unwrap().get(&1), Some(&20));
        drop(packs);
        assert!(registry.lock().unwrap().is_empty());
        // Previously allocated output still occupies disk after its budget dies.
        assert!(writer(&registry, 60, 41).is_err());
        assert!(writer(&registry, 60, 40).is_ok());
    }

    #[test]
    fn excess_consumption_cannot_release_another_writers_capacity() {
        let registry = ReservationRegistry::default();
        let mut capture = writer(&registry, 100, 30).unwrap();
        let packs = writer(&registry, 100, 50).unwrap();
        assert!(capture.consume_allocated(31).is_err());
        assert_eq!(capture.remaining(), 30);
        assert_eq!(registry.lock().unwrap().get(&1), Some(&80));
        capture.consume_allocated(30).unwrap();
        capture.consume_allocated(0).unwrap();
        drop(capture);
        assert_eq!(registry.lock().unwrap().get(&1), Some(&50));
        drop(packs);
        assert!(registry.lock().unwrap().is_empty());
    }

    #[test]
    fn filesystem_admission_is_aggregated_and_atomic() {
        let registry = ReservationRegistry::default();
        let requests = [
            (PathBuf::from("capture"), 40),
            (PathBuf::from("packs"), 30),
            (PathBuf::from("snapshots"), 35),
        ];
        let reserve = |second_free| {
            DiskReservation::reserve_using(Arc::clone(&registry), &requests, 20, |path| {
                Ok(if path == Path::new("snapshots") {
                    (2, second_free)
                } else {
                    (1, 100)
                })
            })
        };
        assert!(reserve(54).is_err());
        assert!(
            registry.lock().unwrap().is_empty(),
            "failed admission must be atomic"
        );
        let budget = reserve(55).unwrap();
        assert_eq!(
            *registry.lock().unwrap(),
            BTreeMap::from([(1, 70), (2, 35)])
        );
        drop(budget);
        assert!(registry.lock().unwrap().is_empty());
    }

    #[test]
    fn capacity_is_sampled_under_accounting_lock_and_overflows_do_not_mutate_it() {
        let registry = ReservationRegistry::default();
        let budget = DiskReservation::reserve_using(
            Arc::clone(&registry),
            &[(PathBuf::from("capture"), u64::MAX)],
            0,
            |_| {
                assert!(registry.try_lock().is_err());
                Ok((1, u64::MAX))
            },
        )
        .unwrap();
        assert!(DiskReservation::reserve_using(
            Arc::clone(&registry),
            &[(PathBuf::from("packs"), 1)],
            0,
            |_| Ok((1, u64::MAX)),
        )
        .is_err());
        assert_eq!(registry.lock().unwrap().get(&1), Some(&u64::MAX));
        drop(budget);
        assert!(DiskReservation::reserve_using(
            Arc::clone(&registry),
            &[
                (PathBuf::from("capture"), u64::MAX),
                (PathBuf::from("packs"), 1)
            ],
            0,
            |_| Ok((1, u64::MAX)),
        )
        .is_err());
        assert!(registry.lock().unwrap().is_empty());
    }
}
