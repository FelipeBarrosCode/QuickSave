// SPDX-License-Identifier: GPL-3.0-only
//! Nonblocking engine owner, distinct from short configuration transaction locks.
use super::*;
use std::{
    mem::{size_of, MaybeUninit},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, LockFileEx, UnlockFileEx,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        READ_CONTROL, SYNCHRONIZE,
    },
    System::IO::OVERLAPPED,
};

pub(super) struct EngineOwner {
    root: SafeRoot,
    file: File,
    identity: RootIdentity,
    directory: PathBuf,
}
impl EngineOwner {
    pub fn open(directory: &Path) -> Result<Self> {
        let root = SafeRoot::open(directory)?;
        let name = "native-engine.lock";
        match attribute_pin(&directory.join(name)) {
            Ok(file) => verify_private_file(&file)?,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                match root.write_new(name, |_| Ok(())) {
                    Ok(()) => {}
                    Err(error)
                        if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                            error.kind() == std::io::ErrorKind::AlreadyExists
                        }) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
        let pin = attribute_pin(&directory.join(name))?;
        verify_private_file(&pin)?;
        let expected = identity(&pin)?;
        // Leaf and ancestors stay pinned without delete sharing during RW open.
        let file = File::options()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(directory.join(name))?;
        verify_private_file(&file)?;
        let identity = identity(&file)?;
        ensure!(
            identity == expected,
            "native engine owner name changed while opening"
        );
        let mut overlapped = OVERLAPPED::default();
        ensure!(
            unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } != 0,
            "another native engine owns this data directory, or native lock admission failed"
        );
        let owner = Self {
            root,
            file,
            identity,
            directory: directory.to_owned(),
        };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&self) -> Result<()> {
        verify_private_file(&self.file)?;
        self.root.identity()?;
        let file = attribute_pin(&self.directory.join("native-engine.lock"))?;
        verify_private_file(&file)?;
        ensure!(
            identity(&self.file)? == self.identity && identity(&file)? == self.identity,
            "native engine owner identity changed"
        );
        Ok(())
    }
}

fn attribute_pin(path: &Path) -> Result<File> {
    // Source read_file intentionally denies write sharing. A mutable owner lock
    // needs only metadata/ACL access, with read/write sharing but NO delete share.
    Ok(File::options()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}
impl Drop for EngineOwner {
    fn drop(&mut self) {
        let mut overlapped = OVERLAPPED::default();
        unsafe { UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    }
}
fn identity(file: &File) -> Result<RootIdentity> {
    let mut info = MaybeUninit::<FILE_ID_INFO>::uninit();
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                info.as_mut_ptr().cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0,
        "native engine owner 128-bit identity query failed"
    );
    let info = unsafe { info.assume_init() };
    let bytes = info.FileId.Identifier;
    ensure!(
        bytes != [0; 16],
        "native filesystem did not provide a stable full file ID"
    );
    Ok(RootIdentity {
        device: info.VolumeSerialNumber,
        file_id: [
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        ],
    })
}
