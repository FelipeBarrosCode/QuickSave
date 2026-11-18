// SPDX-License-Identifier: GPL-3.0-only
//! Native-only private SQLite admission. Main/sidecar names are inspected and
//! pinned before SQLite I/O; main opens also use SQLITE_OPEN_NOFOLLOW.
//!
//! SQLite still performs its own named WAL/SHM/journal VFS operations. These
//! checks plus a private directory/single native owner do NOT constitute a custom
//! handle-anchored VFS or close every hostile concurrent namespace race.
use super::*;
use noland_snapshot::SourcePath;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

struct RootPin {
    path: PathBuf,
    directory: File,
    identity: (u64, u64),
    parent_identity: (u64, u64),
}

fn privacy(metadata: &Metadata, directory: bool) -> Result<()> {
    let expected = if directory { 0o700 } else { 0o600 };
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != expected
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(StateError::UnsafePath("native SQLite requires a private owned 0700 directory and single-link 0600 regular files; existing permissions are not repaired".into()));
    }
    Ok(())
}

impl RootPin {
    fn open(path: &Path) -> Result<Self> {
        let source = SourcePath::new(path)?;
        let directory = source.open_directory()?;
        let metadata = directory.metadata()?;
        privacy(&metadata, true)?;
        let pin = Self {
            path: path.to_path_buf(),
            directory,
            identity: (metadata.dev(), metadata.ino()),
            parent_identity: source.parent_identity()?,
        };
        pin.check()?;
        Ok(pin)
    }

    fn check(&self) -> Result<()> {
        let held = self.directory.metadata()?;
        privacy(&held, true)?;
        let source = SourcePath::new(&self.path)?;
        let current = source.open_directory()?.metadata()?;
        privacy(&current, true)?;
        if (held.dev(), held.ino()) != self.identity
            || (current.dev(), current.ino()) != self.identity
            || source.parent_identity()? != self.parent_identity
        {
            return Err(StateError::Conflict(
                "native SQLite directory identity changed".into(),
            ));
        }
        Ok(())
    }

    fn source(&self, path: &Path) -> Result<SourcePath> {
        SourcePath::new_beneath(path, &self.path, self.identity)
    }
}

struct FilePin {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
}

impl FilePin {
    fn from_file(path: PathBuf, file: File) -> Result<Self> {
        let metadata = file.metadata()?;
        privacy(&metadata, false)?;
        Ok(Self {
            path,
            file,
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    fn check(&self, root: &RootPin) -> Result<()> {
        let held = self.file.metadata()?;
        privacy(&held, false)?;
        let current = root.source(&self.path)?.open_regular()?.metadata()?;
        privacy(&current, false)?;
        if (held.dev(), held.ino()) != self.identity
            || (current.dev(), current.ino()) != self.identity
        {
            return Err(StateError::Conflict(
                "native SQLite file identity changed".into(),
            ));
        }
        Ok(())
    }
}

pub(super) struct NativeDbFiles {
    root: RootPin,
    main: FilePin,
    sidecar_paths: [PathBuf; 3],
    sidecars: Mutex<Vec<FilePin>>,
}

impl NativeDbFiles {
    fn prepare(path: &Path) -> Result<Self> {
        if !is_valid_index_path(path) {
            return Err(StateError::UnsafePath(
                "native SQLite path must be a normalized absolute UTF-8 path".into(),
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| StateError::UnsafePath("native SQLite parent missing".into()))?;
        let root = RootPin::open(parent)?;
        let source = root.source(path)?;
        // O_CREAT|O_NOFOLLOW without truncation or a global umask change. New
        // files request 0600; a more restrictive umask fails privacy admission
        // rather than being repaired. Existing insecure/linked files are rejected.
        let main = FilePin::from_file(path.to_path_buf(), source.open_or_create_private()?)?;
        main.check(&root)?;
        main.file.sync_all()?;
        root.directory.sync_all()?;
        let sidecar = |suffix: &str| {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        };
        let files = Self {
            root,
            main,
            sidecar_paths: [sidecar("-wal"), sidecar("-shm"), sidecar("-journal")],
            sidecars: Mutex::new(Vec::new()),
        };
        files.check()?;
        Ok(files)
    }

    pub(super) fn check(&self) -> Result<()> {
        self.root.check()?;
        self.main.check(&self.root)?;
        let mut sidecars = self
            .sidecars
            .lock()
            .map_err(|_| StateError::Database("native SQLite file-pin mutex poisoned".into()))?;
        for pin in sidecars.iter() {
            pin.check(&self.root)?;
        }
        for path in &self.sidecar_paths {
            if sidecars.iter().any(|pin| pin.path == *path) {
                continue;
            }
            let source = self.root.source(path)?;
            match source.metadata() {
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue
                }
                Err(error) => return Err(error),
                Ok(metadata) if !metadata.is_file() || metadata.is_symlink() => {
                    return Err(StateError::UnsafePath(
                        "native SQLite sidecar is a symlink or special file".into(),
                    ));
                }
                Ok(_) => {}
            }
            let pin = FilePin::from_file(path.clone(), source.open_regular()?)?;
            pin.check(&self.root)?;
            sidecars.push(pin);
        }
        self.root.check()
    }
}

impl StateDb {
    /// Native-only shadow receipt DB. No global umask/chmod, external account,
    /// live No Land state, SQLite URI or default connection fallback is used.
    pub fn open_native(path: &Path) -> Result<Self> {
        let files = Arc::new(NativeDbFiles::prepare(path)?);
        files.check()?;
        let writer_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        // CREATE is deliberately absent: the native-owned main file is pinned
        // already, including the empty-file first-boot case.
        let conn = Connection::open_with_flags(path, writer_flags).map_err(db_err)?;
        files.check()?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
        files.check()?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(db_err)?;
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(db_err)?;
        if sync != 2 || !journal.eq_ignore_ascii_case("wal") {
            return Err(StateError::Database(
                "native SQLite requires actual WAL + FULL synchronous durability".into(),
            ));
        }
        let mut db = Self {
            conn: Arc::new(Mutex::new(conn)),
            browse_reader: None,
            lock_timings: Arc::default(),
            native_files: Some(Arc::clone(&files)),
        };
        db.migrate()?;
        files.check()?;
        let reader = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(db_err)?;
        files.check()?;
        reader
            .pragma_update(None, "synchronous", "FULL")
            .map_err(db_err)?;
        reader
            .pragma_update(None, "query_only", true)
            .map_err(db_err)?;
        reader
            .busy_timeout(std::time::Duration::from_millis(250))
            .map_err(db_err)?;
        files.check()?;
        db.browse_reader = Some(Arc::new(Mutex::new(reader)));
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    fn private_test_root(label: &str) -> PathBuf {
        let approved =
            Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
        let base = if approved.is_dir() {
            approved.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let root = base.join(format!("qs-native-sqlite-{label}-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    #[test]
    fn native_empty_private_main_initializes_wal_and_full_synchronous_for_both_connections() {
        let root = private_test_root("durability");
        let path = root.join("receipts.db");
        let db = StateDb::open_native(&path).unwrap();
        assert_eq!(db.integrity_check().unwrap(), "ok");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let writer_sync: i64 = db
            .conn
            .lock()
            .unwrap()
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        let reader_sync: i64 = db
            .browse_reader
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(writer_sync, 2);
        assert_eq!(reader_sync, 2);
        for suffix in ["-wal", "-shm"] {
            let sidecar = root.join(format!("receipts.db{suffix}"));
            if sidecar.exists() {
                let metadata = std::fs::metadata(sidecar).unwrap();
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                assert_eq!(metadata.nlink(), 1);
            }
        }
        drop(db);
        // The original non-native opener retains its upstream NORMAL policy.
        let ordinary = StateDb::open(&root.join("ordinary.db")).unwrap();
        let ordinary_sync: i64 = ordinary
            .conn
            .lock()
            .unwrap()
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(ordinary_sync, 1);
        drop(ordinary);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_private_sidecar_hardlinks_are_rejected_without_touching_outside_sentinel() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let root = private_test_root("hardlink");
            let state = root.join("private-db");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&state)
                .unwrap();
            let path = state.join("receipts.db");
            let db = StateDb::open_native(&path).unwrap();
            assert_eq!(db.integrity_check().unwrap(), "ok");
            drop(db); // A valid, cleanly closed DB, not an invalid-header fixture.

            let sentinel = root.join("outside-sentinel");
            let mut outside = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&sentinel)
                .unwrap();
            let payload = b"outside the private SQLite directory: do not write";
            outside.write_all(payload).unwrap();
            outside.sync_all().unwrap();
            drop(outside);
            let sidecar = state.join(format!("receipts.db{suffix}"));
            if sidecar.exists() {
                // Only a closed, test-owned DB's original sidecar, before linking.
                std::fs::remove_file(&sidecar).unwrap();
            }
            std::fs::hard_link(&sentinel, &sidecar).unwrap();
            let before = std::fs::metadata(&sentinel).unwrap();
            assert_eq!(before.mode() & 0o7777, 0o600);
            assert_eq!(before.nlink(), 2, "reject link count, not weak permissions");
            assert!(matches!(
                StateDb::open_native(&path),
                Err(StateError::UnsafePath(_))
            ));
            let after = std::fs::metadata(&sentinel).unwrap();
            assert_eq!(
                (
                    before.dev(),
                    before.ino(),
                    before.len(),
                    before.nlink(),
                    before.mode(),
                    before.mtime(),
                    before.mtime_nsec(),
                    before.ctime(),
                    before.ctime_nsec(),
                ),
                (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.nlink(),
                    after.mode(),
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec(),
                ),
                "rejected {suffix} admission mutated the outside file"
            );
            assert_eq!(std::fs::read(&sentinel).unwrap(), payload);
            assert_eq!(std::fs::metadata(&sidecar).unwrap().ino(), before.ino());
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
