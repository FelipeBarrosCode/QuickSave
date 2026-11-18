// SPDX-License-Identifier: GPL-3.0-only
//! Native Windows SQLite admission for the existing StateDb schema/journals.
//! Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//!
//! This is a narrow admission VFS over SQLite's real Windows VFS, not a new
//! database or a fake durability backend. The original VFS owns locking, WAL
//! mapping, writes and FlushFileBuffers. Main/WAL/SHM/rollback names are created
//! with protected current-user DACLs through native no-reparse handles before
//! SQLite opens them. Persistent WAL prevents unlinking live pinned sidecars.
//! Anonymous disk temp files, other databases and extension loading fail closed.
//!
//! Native root/ancestor handles deny delete sharing. This does not claim safety
//! against a compromised same-user process or administrator changing ACLs/objects
//! between OS calls, nor a fully handle-anchored replacement Windows VFS.
use super::*;
use quicksave_platform::{verify_private_file, PrivateDirectory, RootIdentity, SafeRoot};
use rusqlite::ffi;
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs::File,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::PathBuf,
    ptr,
};

struct FilePin {
    file: File,
    identity: RootIdentity,
}

/// Selected as `store::native::NativeDbFiles` under cfg(windows). Its guard
/// remains after both connection Arcs, including across StateDb clones.
pub(super) struct NativeDbFiles {
    root: SafeRoot,
    private: PrivateDirectory,
    directory: PathBuf,
    main: String,
    pins: Mutex<BTreeMap<String, FilePin>>,
    registration: Mutex<Option<Registration>>,
}

struct Registration {
    vfs: Box<ffi::sqlite3_vfs>,
    name: CString,
    original: *mut ffi::sqlite3_vfs,
}

// SQLite's built-in Windows VFS is process-static and supports concurrent
// connections. Our copied callback table is immutable once registered; all
// context mutation is protected by NativeDbFiles' mutexes.
unsafe impl Send for Registration {}
unsafe impl Sync for Registration {}

fn unsafe_path() -> StateError {
    StateError::UnsafePath(
        "native SQLite requires a pinned local NTFS/ReFS directory, protected current-user DACLs, single-link regular files and unchanged full 128-bit IDs".into(),
    )
}
fn fs_error(_: anyhow::Error) -> StateError {
    unsafe_path()
}

impl NativeDbFiles {
    fn prepare(path: &Path) -> Result<Arc<Self>> {
        if !path.is_absolute()
            || path
                .to_str()
                .is_none_or(|p| p.is_empty() || p.len() > 32768 || p.contains('\0'))
            || path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(unsafe_path());
        }
        let directory = path.parent().ok_or_else(unsafe_path)?.to_owned();
        let main = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(unsafe_path)?
            .to_owned();
        if main.len() > 220 || main.contains(['/', '\\', ':', '\0']) {
            return Err(unsafe_path());
        }
        let root = SafeRoot::open(&directory).map_err(fs_error)?;
        let private = PrivateDirectory::open(&directory).map_err(fs_error)?;
        let files = Arc::new(Self {
            root,
            private,
            directory,
            main,
            pins: Mutex::new(BTreeMap::new()),
            registration: Mutex::new(None),
        });
        // SHM opens occur inside the Windows io-method implementation rather
        // than xOpen, so admit and protect that exact name before SQLite exists.
        for name in [files.main.clone(), files.name("-wal"), files.name("-shm")] {
            files.admit(&name, true)?;
        }
        files.admit(&files.name("-journal"), false)?;
        files.private.flush().map_err(fs_error)?;
        files.check()?;
        files.register()?;
        Ok(files)
    }

    fn name(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.main)
    }
    fn accepted(&self, name: &str) -> bool {
        name == self.main
            || ["-wal", "-shm", "-journal"]
                .iter()
                .any(|suffix| name == self.name(suffix))
    }

    fn leaf(&self, path: *const c_char) -> Result<String> {
        if path.is_null() {
            return Err(unsafe_path());
        }
        // SQLite owns NUL-terminated UTF-8 names for the callback duration.
        let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
        if bytes.len() > 32768 {
            return Err(unsafe_path());
        }
        let path = Path::new(std::str::from_utf8(bytes).map_err(|_| unsafe_path())?);
        if !path.is_absolute()
            || path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(unsafe_path());
        }
        let parent = path.parent().ok_or_else(unsafe_path)?;
        // SQLite normalizes separators and may expand a DOS path prefix. Compare
        // the native parent ID, not case-sensitive spelling or a truncated ino64.
        if SafeRoot::open(parent)
            .map_err(fs_error)?
            .identity()
            .map_err(fs_error)?
            != self.root.identity().map_err(fs_error)?
        {
            return Err(unsafe_path());
        }
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(unsafe_path)?;
        if !self.accepted(leaf) {
            return Err(unsafe_path());
        }
        Ok(leaf.into())
    }

    fn admit(&self, name: &str, create: bool) -> Result<()> {
        if !self.accepted(name) {
            return Err(unsafe_path());
        }
        let opened = match self.open_pin(name) {
            Ok(opened) => Some(opened),
            Err(error) if not_found(&error) && !create => None,
            Err(error) if not_found(&error) => {
                // Native create-new publication uses protected explicit DACL,
                // write-through file handles and checked actual namespace flush.
                match self.root.write_new(name, |_| Ok(())) {
                    Ok(()) => {}
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
                    Err(error) => return Err(fs_error(error)),
                }
                Some(self.open_pin(name).map_err(fs_error)?)
            }
            Err(error) => return Err(fs_error(error)),
        };
        let mut pins = self
            .pins
            .lock()
            .map_err(|_| StateError::Database("native SQLite pin lock poisoned".into()))?;
        if let Some(file) = opened {
            verify_private_file(&file).map_err(fs_error)?;
            let identity = file_identity(&file)?;
            if let Some(held) = pins.get(name) {
                verify_private_file(&held.file).map_err(fs_error)?;
                if held.identity != identity {
                    return Err(unsafe_path());
                }
            } else {
                pins.insert(name.into(), FilePin { file, identity });
            }
        } else if pins.contains_key(name) {
            return Err(unsafe_path());
        }
        Ok(())
    }

    fn open_pin(&self, name: &str) -> anyhow::Result<File> {
        if !self.accepted(name) {
            return Err(anyhow::anyhow!("unapproved native SQLite name"));
        }
        self.root.identity()?;
        // FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, with
        // FILE_SHARE_READ | FILE_SHARE_WRITE but NOT FILE_SHARE_DELETE.
        // SafeRoot's live-source data read deliberately denies writers and
        // therefore must never be retained for a mutable SQLite database.
        let file = File::options()
            .access_mode(0x0000_0080 | 0x0002_0000 | 0x0010_0000)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(self.directory.join(name))?;
        verify_private_file(&file)?;
        self.root.identity()?;
        Ok(file)
    }

    pub(super) fn check(&self) -> Result<()> {
        self.root.identity().map_err(fs_error)?;
        // Main/WAL/SHM names remain persistently pinned. A rollback journal's
        // identity is checked until its own acknowledged SQLite xDelete.
        for name in [
            self.main.clone(),
            self.name("-wal"),
            self.name("-shm"),
            self.name("-journal"),
        ] {
            self.admit(&name, false)?;
        }
        self.root.identity().map_err(fs_error)?;
        Ok(())
    }

    fn register(self: &Arc<Self>) -> Result<()> {
        // Select SQLite's bundled native implementation explicitly, not an
        // unrelated process-default VFS installed by another dependency.
        let mut original = unsafe { ffi::sqlite3_vfs_find(c"win32-longpath".as_ptr()) };
        if original.is_null() {
            original = unsafe { ffi::sqlite3_vfs_find(c"win32".as_ptr()) };
        }
        if original.is_null() {
            return Err(StateError::Database(
                "SQLite native Windows VFS is unavailable".into(),
            ));
        }
        let name = CString::new(format!("quicksave-private-windows-{}", Uuid::new_v4())).unwrap();
        let mut vfs = Box::new(unsafe { *original });
        if self.directory.join(&self.main).to_string_lossy().len() >= vfs.mxPathname as usize {
            return Err(StateError::UnsafePath(
                "native SQLite path exceeds the actual bundled Windows VFS pathname limit".into(),
            ));
        }
        if vfs.iVersion < 2
            || vfs.xOpen.is_none()
            || vfs.xDelete.is_none()
            || vfs.xAccess.is_none()
            || vfs.xFullPathname.is_none()
        {
            return Err(StateError::Database(
                "SQLite Windows VFS lacks required native methods".into(),
            ));
        }
        vfs.pNext = ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.pAppData = Arc::as_ptr(self).cast_mut().cast::<c_void>();
        vfs.xOpen = Some(vfs_open);
        vfs.xDelete = Some(vfs_delete);
        vfs.xAccess = Some(vfs_access);
        vfs.xFullPathname = Some(vfs_full_path);
        // Disabled instead of forwarding a wrapper pAppData into the native
        // callback. No runtime extension/DLL can widen the admitted namespace.
        vfs.xDlOpen = Some(vfs_dl_open);
        vfs.xDlError = Some(vfs_dl_error);
        vfs.xDlSym = None;
        vfs.xDlClose = Some(vfs_dl_close);
        vfs.xRandomness = Some(vfs_randomness);
        vfs.xSleep = Some(vfs_sleep);
        vfs.xCurrentTime = Some(vfs_time);
        vfs.xGetLastError = Some(vfs_last_error);
        vfs.xCurrentTimeInt64 = Some(vfs_time64);
        vfs.iVersion = 2;
        vfs.xSetSystemCall = None;
        vfs.xGetSystemCall = None;
        vfs.xNextSystemCall = None;
        let mut registration = self
            .registration
            .lock()
            .map_err(|_| StateError::Database("native SQLite registration lock poisoned".into()))?;
        *registration = Some(Registration {
            vfs,
            name,
            original,
        });
        let registration = registration.as_mut().unwrap();
        if unsafe { ffi::sqlite3_vfs_register(&mut *registration.vfs, 0) } != ffi::SQLITE_OK {
            return Err(StateError::Database(
                "native private Windows VFS registration failed".into(),
            ));
        }
        Ok(())
    }

    fn vfs_name(&self) -> Result<String> {
        let registration = self
            .registration
            .lock()
            .map_err(|_| StateError::Database("native SQLite registration lock poisoned".into()))?;
        Ok(registration
            .as_ref()
            .ok_or_else(|| StateError::Database("native SQLite VFS missing".into()))?
            .name
            .to_str()
            .map_err(|_| unsafe_path())?
            .into())
    }
}

impl Drop for NativeDbFiles {
    fn drop(&mut self) {
        // StateDb keeps this field after BOTH connection Arcs, so callbacks have
        // stopped before the registration/context/pinned handles are destroyed.
        if let Ok(Some(registration)) = self.registration.get_mut() {
            unsafe { ffi::sqlite3_vfs_unregister(&mut *registration.vfs) };
        }
    }
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

fn file_identity(file: &File) -> Result<RootIdentity> {
    #[repr(C)]
    struct IdInfo {
        volume: u64,
        id: [u8; 16],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: c_int,
            info: *mut c_void,
            size: u32,
        ) -> c_int;
    }
    let mut info = std::mem::MaybeUninit::<IdInfo>::uninit();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            18,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<IdInfo>() as u32,
        )
    } == 0
    {
        return Err(unsafe_path());
    }
    let info = unsafe { info.assume_init() };
    if info.id == [0; 16] {
        return Err(unsafe_path());
    }
    Ok(RootIdentity {
        device: info.volume,
        file_id: [
            u64::from_le_bytes(info.id[..8].try_into().unwrap()),
            u64::from_le_bytes(info.id[8..].try_into().unwrap()),
        ],
    })
}
unsafe fn files<'a>(vfs: *mut ffi::sqlite3_vfs) -> &'a NativeDbFiles {
    unsafe { &*((*vfs).pAppData.cast::<NativeDbFiles>()) }
}
unsafe fn original(vfs: *mut ffi::sqlite3_vfs) -> *mut ffi::sqlite3_vfs {
    let context = unsafe { files(vfs) };
    context
        .registration
        .lock()
        .ok()
        .and_then(|r| r.as_ref().map(|r| r.original))
        .unwrap_or(ptr::null_mut())
}
fn guarded(work: impl FnOnce() -> Result<c_int>) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .ok()
        .and_then(std::result::Result::ok)
        .unwrap_or(ffi::SQLITE_CANTOPEN)
}

unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    path: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    if !file.is_null() {
        unsafe { (*file).pMethods = ptr::null() };
    }
    guarded(|| {
        if flags
            & (ffi::SQLITE_OPEN_DELETEONCLOSE
                | ffi::SQLITE_OPEN_TEMP_DB
                | ffi::SQLITE_OPEN_TEMP_JOURNAL
                | ffi::SQLITE_OPEN_TRANSIENT_DB)
            != 0
        {
            return Err(unsafe_path());
        }
        let context = unsafe { files(vfs) };
        let leaf = context.leaf(path)?;
        context.admit(&leaf, flags & ffi::SQLITE_OPEN_CREATE != 0)?;
        context.check()?;
        let original = unsafe { original(vfs) };
        if original.is_null() {
            return Err(unsafe_path());
        }
        let result = unsafe { ((*original).xOpen.unwrap())(original, path, file, flags, out) };
        if result == ffi::SQLITE_OK {
            if context.check().is_err() {
                // xOpen success transfers ownership to SQLite. Close exactly
                // that opened file if post-admission fails, then clear methods
                // as required by the SQLite failed-xOpen contract.
                unsafe {
                    if !(*file).pMethods.is_null() {
                        if let Some(close) = (*(*file).pMethods).xClose {
                            close(file);
                        }
                        (*file).pMethods = ptr::null();
                    }
                }
                return Err(unsafe_path());
            }
        }
        Ok(result)
    })
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    path: *const c_char,
    sync: c_int,
) -> c_int {
    guarded(|| {
        let context = unsafe { files(vfs) };
        let leaf = context.leaf(path)?;
        // PERSIST_WAL is mandatory: only SQLite's rollback journal may be
        // removed while this native DB exists. Never release main/WAL/SHM pins.
        if leaf != context.name("-journal") {
            return Err(unsafe_path());
        }
        context.admit(&leaf, false)?;
        context
            .pins
            .lock()
            .map_err(|_| unsafe_path())?
            .remove(&leaf);
        let original = unsafe { original(vfs) };
        if original.is_null() {
            return Err(unsafe_path());
        }
        let result = unsafe { ((*original).xDelete.unwrap())(original, path, sync) };
        if result != ffi::SQLITE_OK {
            return Ok(result);
        }
        match context.open_pin(&leaf) {
            Err(error) if not_found(&error) => {}
            _ => return Err(unsafe_path()),
        }
        context.private.flush().map_err(fs_error)?;
        context.check()?;
        Ok(result)
    })
}

unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    path: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    guarded(|| {
        let context = unsafe { files(vfs) };
        let leaf = context.leaf(path)?;
        context.admit(&leaf, false)?;
        let original = unsafe { original(vfs) };
        if original.is_null() {
            return Err(unsafe_path());
        }
        Ok(unsafe { ((*original).xAccess.unwrap())(original, path, flags, out) })
    })
}

unsafe extern "C" fn vfs_full_path(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    count: c_int,
    out: *mut c_char,
) -> c_int {
    guarded(|| {
        let original = unsafe { original(vfs) };
        if original.is_null() {
            return Err(unsafe_path());
        }
        let result = unsafe { ((*original).xFullPathname.unwrap())(original, name, count, out) };
        if result == ffi::SQLITE_OK {
            unsafe { files(vfs) }.leaf(out)?;
        }
        Ok(result)
    })
}

unsafe extern "C" fn vfs_dl_open(_: *mut ffi::sqlite3_vfs, _: *const c_char) -> *mut c_void {
    ptr::null_mut()
}
unsafe extern "C" fn vfs_dl_close(_: *mut ffi::sqlite3_vfs, _: *mut c_void) {}
unsafe extern "C" fn vfs_dl_error(_: *mut ffi::sqlite3_vfs, count: c_int, out: *mut c_char) {
    if count > 0 && !out.is_null() {
        unsafe { *out = 0 };
    }
}

// Always forward the ORIGINAL VFS pointer. Its pAppData is not our context.
macro_rules! delegate {
    ($name:ident, $field:ident, ($($arg:ident: $ty:ty),*) -> $ret:ty, $failure:expr) => {
        unsafe extern "C" fn $name(vfs: *mut ffi::sqlite3_vfs, $($arg: $ty),*) -> $ret {
            let original = unsafe { original(vfs) };
            if original.is_null() { return $failure; }
            match unsafe { (*original).$field } {
                Some(call) => unsafe { call(original, $($arg),*) },
                None => $failure,
            }
        }
    };
}
delegate!(vfs_randomness, xRandomness, (count: c_int, out: *mut c_char) -> c_int, 0);
delegate!(vfs_sleep, xSleep, (micros: c_int) -> c_int, 0);
delegate!(vfs_time, xCurrentTime, (out: *mut f64) -> c_int, ffi::SQLITE_IOERR);
delegate!(vfs_time64, xCurrentTimeInt64, (out: *mut ffi::sqlite3_int64) -> c_int, ffi::SQLITE_IOERR);
delegate!(vfs_last_error, xGetLastError, (count: c_int, out: *mut c_char) -> c_int, ffi::SQLITE_IOERR);

impl StateDb {
    pub fn open_native(path: &Path) -> Result<Self> {
        let files = NativeDbFiles::prepare(path)?;
        let name = files.vfs_name()?;
        let conn = Connection::open_with_flags_and_vfs(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            name.as_str(),
        )
        .map_err(db_err)?;
        persist_wal(&conn)?;
        files.check()?;
        conn.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(db_err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(db_err)?;
        conn.pragma_update(None, "mmap_size", 0).map_err(db_err)?;
        conn.pragma_update(None, "cache_size", -8192)
            .map_err(db_err)?;
        verify_durability(&conn)?;
        let mut db = Self {
            conn: Arc::new(Mutex::new(conn)),
            browse_reader: None,
            lock_timings: Arc::default(),
            native_files: Some(Arc::clone(&files)),
        };
        db.migrate()?;
        files.check()?;
        files.private.flush().map_err(fs_error)?;
        let reader = Connection::open_with_flags_and_vfs(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            name.as_str(),
        )
        .map_err(db_err)?;
        persist_wal(&reader)?;
        reader
            .pragma_update(None, "synchronous", "FULL")
            .map_err(db_err)?;
        reader
            .pragma_update(None, "query_only", true)
            .map_err(db_err)?;
        reader
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(db_err)?;
        reader.pragma_update(None, "mmap_size", 0).map_err(db_err)?;
        reader
            .busy_timeout(std::time::Duration::from_millis(250))
            .map_err(db_err)?;
        verify_durability(&reader)?;
        files.check()?;
        db.browse_reader = Some(Arc::new(Mutex::new(reader)));
        Ok(db)
    }
}

fn persist_wal(connection: &Connection) -> Result<()> {
    let mut enabled: c_int = 1;
    if unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut enabled as *mut c_int).cast(),
        )
    } != ffi::SQLITE_OK
    {
        return Err(StateError::Database(
            "SQLite Windows VFS cannot retain protected pinned WAL/SHM".into(),
        ));
    }
    let mut observed: c_int = -1;
    if unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut observed as *mut c_int).cast(),
        )
    } != ffi::SQLITE_OK
        || observed != 1
    {
        return Err(StateError::Database(
            "SQLite persistent WAL setting did not read back".into(),
        ));
    }
    Ok(())
}
fn verify_durability(connection: &Connection) -> Result<()> {
    let sync: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(db_err)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(db_err)?;
    if sync != 2 || !journal.eq_ignore_ascii_case("wal") {
        return Err(StateError::Database(
            "native Windows SQLite requires actual WAL + FULL synchronous mode".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quicksave_platform::ensure_private_directory;

    #[test]
    fn native_windows_sqlite_uses_real_private_wal_full_and_persistent_sidecars() {
        let root = std::env::temp_dir().join(format!("quicksave-win-db-{}", Uuid::new_v4()));
        ensure_private_directory(&root)
            .expect("native NTFS/ReFS protected-DACL and flush privileges are required");
        let path = root.join("state.db");
        let db = StateDb::open_native(&path).unwrap();
        assert_eq!(db.integrity_check().unwrap(), "ok");
        verify_durability(&db.conn.lock().unwrap()).unwrap();
        verify_durability(&db.browse_reader.as_ref().unwrap().lock().unwrap()).unwrap();
        drop(db);
        let root_handle = SafeRoot::open(&root).unwrap();
        for name in ["state.db", "state.db-wal", "state.db-shm"] {
            let (file, stamp) = root_handle.read_file(name).unwrap();
            verify_private_file(&file).unwrap();
            assert_ne!(stamp.file_id, [0; 2]);
        }
        drop(root_handle);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn native_windows_sqlite_rejects_hardlinked_sidecar_without_writing_sentinel() {
        let root = std::env::temp_dir().join(format!("quicksave-win-db-link-{}", Uuid::new_v4()));
        ensure_private_directory(&root).unwrap();
        let directory = SafeRoot::open(&root).unwrap();
        directory.create_dir("state").unwrap();
        directory
            .write_new("sentinel", |file| {
                use std::io::Write;
                file.write_all(b"not database authority")?;
                Ok(())
            })
            .unwrap();
        std::fs::hard_link(root.join("sentinel"), root.join("state/state.db-wal")).unwrap();
        assert!(StateDb::open_native(&root.join("state/state.db")).is_err());
        assert_eq!(
            std::fs::read(root.join("sentinel")).unwrap(),
            b"not database authority"
        );
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_windows_sqlite_clone_retains_private_vfs_and_mutable_wal_pins() {
        let root = std::env::temp_dir().join(format!("quicksave-win-db-owner-{}", Uuid::new_v4()));
        ensure_private_directory(&root).unwrap();
        let db = StateDb::open_native(&root.join("state.db")).unwrap();
        let clone = db.clone();
        drop(db);
        {
            let conn = clone.lock().unwrap();
            conn.execute_batch(
                "CREATE TABLE native_fixture (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO native_fixture VALUES (1, 'isolated native fixture');",
            )
            .unwrap();
        }
        {
            let reader = clone.browse_lock().unwrap();
            let value: String = reader
                .query_row("SELECT value FROM native_fixture WHERE id=1", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(value, "isolated native fixture");
            assert!(reader
                .execute(
                    "INSERT INTO native_fixture VALUES (2, 'must remain read only')",
                    []
                )
                .is_err());
        }
        assert_eq!(clone.integrity_check().unwrap(), "ok");
        verify_durability(&clone.lock().unwrap()).unwrap();
        clone.native_files.as_ref().unwrap().check().unwrap();
        drop(clone);
        std::fs::remove_dir_all(root).unwrap();
    }
}
