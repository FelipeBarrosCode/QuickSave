// SPDX-License-Identifier: GPL-3.0-only
//! A rename is not a durability barrier. Flush the actual local NTFS/ReFS
//! volume, not an arbitrary directory handle or an assumed write-through flag.
//! Windows may require elevation for this operation; that denial propagates.

use super::*;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, GetFinalPathNameByHandleW, FILE_FLAG_WRITE_THROUGH, VOLUME_NAME_GUID,
};

pub(super) struct Barrier {
    volume: File,
    _root: File,
    expected_volume: u64,
    expected_serial: u32,
    filesystem: String,
}

impl Barrier {
    pub(super) fn new(directory: &File) -> Result<Self> {
        let (filesystem, expected_serial) = privacy::filesystem(directory)?;
        let stamp = metadata(directory, true)?;
        let mut buffer = vec![0u16; MAX_PATH_BYTES];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                directory.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_GUID,
            )
        };
        ensure!(
            length != 0 && (length as usize) < buffer.len(),
            "obtain bounded native volume GUID path: {}",
            io::Error::last_os_error()
        );
        let text = String::from_utf16(&buffer[..length as usize])?;
        ensure!(
            text.starts_with(r"\\?\Volume{"),
            "durability requires a local volume GUID"
        );
        let end = text
            .find(r"}\")
            .context("invalid native volume GUID path")?
            + 2;
        let root_name = &text[..end];
        ensure!(root_name.len() <= 64, "invalid native volume GUID length");
        let root_encoded: Vec<u16> = root_name.encode_utf16().chain(Some(0)).collect();
        let root = unsafe {
            CreateFileW(
                root_encoded.as_ptr(),
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        ensure!(
            root != INVALID_HANDLE_VALUE && !root.is_null(),
            "open native volume root: {}",
            io::Error::last_os_error()
        );
        let root = unsafe { File::from_raw_handle(root) };
        ensure!(
            metadata(&root, true)?.device == stamp.device,
            "native volume identity mismatch"
        );
        let volume_name: Vec<u16> = root_name[..root_name.len() - 1]
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let volume = unsafe {
            CreateFileW(
                volume_name.as_ptr(),
                0x8000_0000 | 0x4000_0000,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_WRITE_THROUGH,
                ptr::null_mut(),
            )
        };
        ensure!(
            volume != INVALID_HANDLE_VALUE && !volume.is_null(),
            "cannot obtain actual NTFS/ReFS namespace durability barrier (volume flush permission required): {}",
            io::Error::last_os_error()
        );
        let barrier = Self {
            volume: unsafe { File::from_raw_handle(volume) },
            _root: root,
            expected_volume: stamp.device,
            expected_serial,
            filesystem,
        };
        barrier.check()?;
        Ok(barrier)
    }

    fn check(&self) -> Result<()> {
        ensure!(
            privacy::filesystem(&self._root)? == (self.filesystem.clone(), self.expected_serial)
                && metadata(&self._root, true)?.device == self.expected_volume,
            "durability volume changed"
        );
        Ok(())
    }

    pub(super) fn flush(&self) -> Result<()> {
        self.check()?;
        ensure!(
            unsafe { FlushFileBuffers(self.volume.as_raw_handle()) } != 0,
            "actual native volume flush failed; durability not established: {}",
            io::Error::last_os_error()
        );
        self.check()
    }
}
