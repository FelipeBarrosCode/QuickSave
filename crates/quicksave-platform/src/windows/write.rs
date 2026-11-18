// SPDX-License-Identifier: GPL-3.0-only
//! Exclusive native creation, handle-based rename and operation-owned cleanup.

use super::*;
use rand::{rngs::OsRng, RngCore};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FileDispositionInformation, FileRenameInformation, NtSetInformationFile, FILE_CREATE,
        FILE_DISPOSITION_INFORMATION, FILE_RENAME_INFORMATION,
    },
    Win32::Storage::FileSystem::{
        FlushFileBuffers, DELETE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    },
};

pub(super) fn create_private(
    parent: &File,
    name: &str,
    directory: bool,
    delete: bool,
) -> Result<File> {
    validate_windows_component(name)?;
    let descriptor = privacy::Descriptor::new()?;
    let file = open_options(
        parent,
        name,
        Some(directory),
        FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | SYNCHRONIZE
            | if directory {
                FILE_LIST_DIRECTORY | FILE_TRAVERSE
            } else {
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
            }
            | if delete { DELETE } else { 0 },
        FILE_CREATE,
        descriptor.pointer(),
        false,
        false,
    )?;
    privacy::verify(&file, directory)?;
    Ok(file)
}

pub(super) fn observation(parent: &File, name: &str, directory: bool) -> Result<File> {
    validate_windows_component(name)?;
    let file = open_options(
        parent,
        name,
        Some(directory),
        FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_OPEN,
        ptr::null(),
        false,
        true,
    )?;
    metadata(&file, directory)?;
    Ok(file)
}

pub(super) fn rename(file: &File, parent: &File, name: &str, replace: bool) -> Result<()> {
    validate_windows_component(name)?;
    let encoded: Vec<u16> = name.encode_utf16().collect();
    let header = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let length = header
        .checked_add(encoded.len() * 2)
        .context("rename size overflow")?;
    let mut storage = vec![0u64; length.max(size_of::<FILE_RENAME_INFORMATION>()).div_ceil(8)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = (encoded.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            encoded.len(),
        );
    }
    let mut status = IO_STATUS_BLOCK::default();
    nt_result(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            info.cast(),
            length as u32,
            FileRenameInformation,
        )
    })
    .context(if replace {
        "native atomic private configuration replacement"
    } else {
        "native no-replace publication"
    })
}

pub(super) fn remove_owned(file: &File, expected: Identity) -> Result<()> {
    // No pathname deletion: this can remove only the still-open owned inode.
    let standard: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    ensure!(
        identity(&metadata(file, standard.Directory)?) == expected,
        "refusing cleanup of a swapped native handle"
    );
    let info = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status = IO_STATUS_BLOCK::default();
    nt_result(unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&info as *const FILE_DISPOSITION_INFORMATION).cast(),
            size_of_val(&info) as u32,
            FileDispositionInformation,
        )
    })
    .context("remove only owned native staging entry")
}

pub(super) fn flush_file(file: &File) -> Result<()> {
    ensure!(
        unsafe { FlushFileBuffers(file.as_raw_handle()) } != 0,
        "flush native file data and metadata: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

pub(super) struct Stage<'a> {
    parent: &'a File,
    name: String,
    pub(super) file: File,
    identity: Identity,
    published: bool,
    removed: bool,
    writer_closed: bool,
    sealed: bool,
}

impl<'a> Stage<'a> {
    pub(super) fn new(parent: &'a File) -> Result<Self> {
        for _ in 0..16 {
            let mut random = [0u8; 16];
            OsRng
                .try_fill_bytes(&mut random)
                .context("secure native staging-name randomness")?;
            let name = format!(".quicksave-stage-{:032x}", u128::from_ne_bytes(random));
            let file = match create_private(parent, &name, false, true) {
                Ok(file) => file,
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            };
            let identity = identity(&metadata(&file, false)?);
            let stage = Self {
                parent,
                name,
                file,
                identity,
                published: false,
                removed: false,
                writer_closed: false,
                sealed: false,
            };
            stage.check()?;
            return Ok(stage);
        }
        bail!("cannot allocate exclusive native staging entry")
    }

    pub(super) fn check(&self) -> Result<FileStamp> {
        privacy::verify(&self.file, false)?;
        let current = metadata(&self.file, false)?;
        ensure!(
            identity(&current) == self.identity,
            "writer replaced staging file handle"
        );
        let named = observation(self.parent, &self.name, false)?;
        ensure!(
            metadata(&named, false)? == current,
            "native staging name was replaced"
        );
        Ok(current)
    }

    fn control(&self) -> Result<File> {
        open_options_sharing(
            self.parent,
            &self.name,
            Some(false),
            FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
            FILE_OPEN,
            ptr::null(),
            false,
            FILE_SHARE_READ,
        )
    }

    /// Finalize writer timestamps under the unpredictable private name. A
    /// read-only DELETE control handle then denies writers/replacement through
    /// publication and the actual volume barrier.
    pub(super) fn seal(&mut self) -> Result<FileStamp> {
        ensure!(!self.writer_closed, "native stage was already sealed");
        let before = self.check()?;
        flush_file(&self.file)?;
        let placeholder = self.parent.try_clone()?;
        let writer = std::mem::replace(&mut self.file, placeholder);
        self.writer_closed = true;
        drop(writer);
        self.file = self.control()?;
        self.sealed = true;
        let closed = self.check()?;
        ensure!(
            identity(&closed) == self.identity && closed.size == before.size,
            "staged inode/content length changed when the writer closed"
        );
        Ok(closed)
    }

    pub(super) fn publish(&mut self, name: &str, replace: bool) -> Result<FileStamp> {
        ensure!(
            self.sealed,
            "native publication requires a sealed no-write control handle"
        );
        let before = self.check()?;
        rename(&self.file, self.parent, name, replace)?;
        // Never delete the final entry on any subsequent error.
        self.published = true;
        let published = observation(self.parent, name, false)?;
        privacy::verify(&published, false)?;
        let after = metadata(&published, false)?;
        ensure!(
            identity(&after) == self.identity
                && after.size == before.size
                && (after.modified_seconds, after.modified_nanoseconds)
                    == (before.modified_seconds, before.modified_nanoseconds),
            "published native identity/content metadata changed"
        );
        Ok(after)
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        if self.published || self.removed {
            return Ok(());
        }
        if self.writer_closed && !self.sealed {
            // Never delete the placeholder parent if seal failed while opening
            // its control handle. Reacquire only the saved owned staging inode.
            self.file = self.control()?;
            self.sealed = true;
        }
        // Privacy changes are a write failure, not a reason to retain our own
        // now-insecure staging data. Cleanup needs only exact owned identities;
        // it must still refuse a callback-swapped handle or replaced name.
        ensure!(
            identity(&metadata(&self.file, false)?) == self.identity,
            "refusing cleanup of a callback-swapped staging handle"
        );
        let named = observation(self.parent, &self.name, false)?;
        ensure!(
            identity(&metadata(&named, false)?) == self.identity,
            "refusing cleanup of a replaced staging entry"
        );
        drop(named);
        remove_owned(&self.file, self.identity)?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) fn write_new(
    parent: &File,
    name: &str,
    writer: impl FnOnce(&mut File) -> Result<()>,
    check_parents: impl Fn() -> Result<()>,
) -> Result<()> {
    validate_windows_component(name)?;
    let barrier = durability::Barrier::new(parent)?;
    barrier.flush()?; // Prove the actual barrier before creating or writing bytes.
    match observation(parent, name, false) {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error).context("inspect exclusive publication target"),
        Ok(_) => bail!("destination exists; no overwrite is allowed"),
    }
    let mut stage = Stage::new(parent)?;
    let result = (|| -> Result<FileStamp> {
        writer(&mut stage.file).context("native writer/verification failed before publication")?;
        stage.check()?;
        let verified = stage.seal()?;
        barrier.flush()?;
        check_parents()?;
        ensure!(
            stage.check()? == verified,
            "staging file changed after writer verification"
        );
        let published = stage.publish(name, false)?;
        Ok(published)
    })();
    match result {
        Ok(published) => {
            barrier.flush()?;
            check_parents()?;
            ensure!(
                metadata(&stage.file, false)? == published
                    && metadata(&observation(parent, name, false)?, false)? == published,
                "published target changed before durability completed"
            );
            Ok(())
        }
        Err(error) => {
            if let Err(cleanup) = stage.cleanup() {
                return Err(
                    error.context(format!("owned staging cleanup also failed: {cleanup:#}"))
                );
            }
            // DeletePending is actually removed by handle close before barrier.
            drop(stage);
            match barrier.flush() {
                Ok(()) => Err(error),
                Err(flush) => {
                    Err(error.context(format!("cleanup durability also failed: {flush:#}")))
                }
            }
        }
    }
}
