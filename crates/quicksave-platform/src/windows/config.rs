// SPDX-License-Identifier: GPL-3.0-only
//! Scoped OS locks and compare-before-commit private configuration replacement.

use super::*;
use std::{
    io::{Read, Write},
    sync::Arc,
};
use windows_sys::{
    Wdk::Storage::FileSystem::FILE_OPEN_IF,
    Win32::{
        Storage::FileSystem::{LockFileEx, UnlockFileEx, FILE_WRITE_DATA, LOCKFILE_EXCLUSIVE_LOCK},
        System::IO::OVERLAPPED,
    },
};

const MAX_PRIVATE_BYTES: usize = 8 * 1024 * 1024;

pub struct PrivateDirectory {
    root: Arc<Root>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateFileVersion {
    stamp: FileStamp,
}

pub struct PrivateLock {
    root: Arc<Root>,
    name: String,
    file: File,
    identity: Identity,
}

impl PrivateDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "private configuration directory must be absolute"
        );
        let root = Root::open_impl(path, true)?;
        privacy::verify(root.file(), true)?;
        durability::Barrier::new(root.file())?.flush()?;
        root.check()?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    fn check(&self) -> Result<()> {
        self.root.check()?;
        privacy::verify(self.root.file(), true)?;
        self.root.check()
    }

    pub fn flush(&self) -> Result<()> {
        self.check()?;
        durability::Barrier::new(self.root.file())?.flush()?;
        self.check()
    }

    pub fn lock(&self, name: &str) -> Result<PrivateLock> {
        validate_windows_component(name)?;
        self.check()?;
        let descriptor = privacy::Descriptor::new()?;
        let file = open_options(
            self.root.file(),
            name,
            Some(false),
            FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN_IF,
            descriptor.pointer(),
            false,
            false,
        )?;
        privacy::verify(&file, false)?;
        let identity = identity(&metadata(&file, false)?);
        let mut overlapped = OVERLAPPED::default();
        ensure!(
            unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } != 0,
            "lock private native configuration: {}",
            io::Error::last_os_error()
        );
        let lock = PrivateLock {
            root: Arc::clone(&self.root),
            name: name.to_owned(),
            file,
            identity,
        };
        lock.check()?;
        Ok(lock)
    }

    fn current(&self, name: &str, data: bool) -> Result<Option<File>> {
        validate_windows_component(name)?;
        self.check()?;
        let access = FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | SYNCHRONIZE
            | if data { FILE_READ_DATA } else { 0 };
        match open_options(
            self.root.file(),
            name,
            Some(false),
            access,
            FILE_OPEN,
            ptr::null(),
            false,
            true,
        ) {
            Ok(file) => {
                privacy::verify(&file, false)?;
                Ok(Some(file))
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).context("open private native configuration"),
        }
    }

    fn version(&self, name: &str) -> Result<Option<PrivateFileVersion>> {
        self.current(name, false)?
            .map(|file| {
                Ok(PrivateFileVersion {
                    stamp: metadata(&file, false)?,
                })
            })
            .transpose()
    }

    pub fn read(&self, name: &str, limit: usize) -> Result<Option<(Vec<u8>, PrivateFileVersion)>> {
        ensure!(
            limit <= MAX_PRIVATE_BYTES,
            "private configuration read bound exceeds 8 MiB"
        );
        let Some(mut file) = self.current(name, true)? else {
            return Ok(None);
        };
        let before = metadata(&file, false)?;
        ensure!(
            before.size <= limit as u64,
            "private configuration exceeds read limit"
        );
        let mut bytes = Vec::new();
        (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= limit,
            "private configuration exceeds read limit"
        );
        privacy::verify(&file, false)?;
        ensure!(
            metadata(&file, false)? == before,
            "private configuration changed during read"
        );
        let version = PrivateFileVersion { stamp: before };
        ensure!(
            self.version(name)?.as_ref() == Some(&version),
            "private configuration name changed during read"
        );
        self.check()?;
        Ok(Some((bytes, version)))
    }

    /// Caller holds its persistent PrivateLock over read/replace. The observed
    /// version is mandatory: None means a previously observed absent file.
    pub fn replace(
        &self,
        name: &str,
        bytes: &[u8],
        observed: Option<&PrivateFileVersion>,
    ) -> Result<()> {
        validate_windows_component(name)?;
        ensure!(
            bytes.len() <= MAX_PRIVATE_BYTES,
            "private configuration exceeds 8 MiB"
        );
        self.check()?;
        ensure!(
            self.version(name)?.as_ref() == observed,
            "private configuration changed after locked read"
        );
        let barrier = durability::Barrier::new(self.root.file())?;
        barrier.flush()?;
        let mut stage = write::Stage::new(self.root.file())?;
        let outcome: Result<FileStamp> = (|| {
            stage.file.write_all(bytes)?;
            stage.check()?;
            let verified = stage.seal()?;
            barrier.flush()?;
            self.check()?;
            ensure!(
                stage.check()? == verified,
                "staged private configuration changed"
            );
            ensure!(
                self.version(name)?.as_ref() == observed,
                "private configuration changed before atomic commit"
            );
            let published = stage.publish(name, observed.is_some())?;
            Ok(published)
        })();
        let published = match outcome {
            Ok(published) => published,
            Err(error) => {
                let cleanup = stage.cleanup();
                drop(stage);
                let flush = barrier.flush();
                if let Err(cleanup) = cleanup {
                    return Err(error.context(format!(
                        "owned configuration staging cleanup failed: {cleanup:#}"
                    )));
                }
                if let Err(flush) = flush {
                    return Err(
                        error.context(format!("configuration cleanup flush failed: {flush:#}"))
                    );
                }
                return Err(error);
            }
        };
        // The writer closed under the private staging name. Keep the sealed
        // no-write/no-delete control handle through the actual volume barrier.
        barrier.flush()?;
        self.check()?;
        ensure!(
            metadata(&stage.file, false)? == published
                && self.version(name)?.as_ref() == Some(&PrivateFileVersion { stamp: published }),
            "published private configuration changed during durability check"
        );
        Ok(())
    }
}

impl PrivateLock {
    pub fn check(&self) -> Result<()> {
        self.root.check()?;
        privacy::verify(self.root.file(), true)?;
        privacy::verify(&self.file, false)?;
        ensure!(
            identity(&metadata(&self.file, false)?) == self.identity,
            "native configuration lock handle changed"
        );
        let current = write::observation(self.root.file(), &self.name, false)?;
        ensure!(
            identity(&metadata(&current, false)?) == self.identity,
            "native configuration lock inode was replaced"
        );
        self.root.check()
    }
}

impl Drop for PrivateLock {
    fn drop(&mut self) {
        let mut overlapped = OVERLAPPED::default();
        unsafe { UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    }
}

/// Adapter for native databases whose journaling code owns the directory
/// handle. This flushes the actual volume and does not claim SQLite transaction
/// semantics or repair a caller's ACLs.
pub fn flush_native_directory(directory: &File) -> Result<()> {
    metadata(directory, true)?;
    durability::Barrier::new(directory)?.flush()
}
