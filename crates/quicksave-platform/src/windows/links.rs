// SPDX-License-Identifier: GPL-3.0-only
//! Only relative IO_REPARSE_TAG_SYMLINK is supported. Junctions, mount points,
//! cloud placeholders and every unknown tag fail without following the entry.

use super::*;
use crate::validate_link_target;
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FileDispositionInformation, NtSetInformationFile, FILE_CREATE, FILE_DISPOSITION_INFORMATION,
    },
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN},
        Security::{
            GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
        Storage::FileSystem::{
            FileAttributeTagInfo, DELETE, FILE_ATTRIBUTE_TAG_INFO, FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_DATA,
        },
        System::{
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
            IO::DeviceIoControl,
        },
    },
};

pub(super) const SYMLINK_TAG: u32 = 0xa000_000c;
const GET_REPARSE: u32 = 0x0009_00a8;
const SET_REPARSE: u32 = 0x0009_00a4;
const MAX_REPARSE: usize = 16 * 1024;

fn stamp_link(file: &File) -> Result<(FileStamp, bool)> {
    ensure!(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "non-disk symlink handle"
    );
    let basic: FILE_BASIC_INFO = query_info(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    let tag: FILE_ATTRIBUTE_TAG_INFO = query_info(file, FileAttributeTagInfo)?;
    ensure!(
        !standard.DeletePending
            && standard.NumberOfLinks == 1
            && basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            && basic.FileAttributes & FILE_ATTRIBUTE_DEVICE == 0
            && tag.ReparseTag == SYMLINK_TAG
            && tag.FileAttributes == basic.FileAttributes
            && (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == standard.Directory,
        "entry is not a supported native symbolic link"
    );
    let id: FILE_ID_INFO = query_info(file, FileIdInfo)?;
    ensure!(
        id.FileId.Identifier != [0; 16],
        "symlink has no stable 128-bit native ID"
    );
    let modified = native_time(basic.LastWriteTime);
    let changed = native_time(basic.ChangeTime);
    Ok((
        FileStamp {
            device: id.VolumeSerialNumber,
            file_id: id_parts(id.FileId.Identifier),
            size: u64::try_from(standard.EndOfFile).context("negative symbolic link size")?,
            modified_seconds: modified.0,
            modified_nanoseconds: modified.1,
            changed_seconds: changed.0,
            changed_nanoseconds: changed.1,
        },
        standard.Directory,
    ))
}

fn u16_at(buffer: &[u8], offset: usize) -> Result<u16> {
    let bytes = buffer
        .get(offset..offset + 2)
        .context("truncated reparse header")?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}
fn u32_at(buffer: &[u8], offset: usize) -> Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .context("truncated reparse header")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}
fn text_at(buffer: &[u8], offset: usize, length: usize) -> Result<String> {
    ensure!(
        offset.is_multiple_of(2) && length.is_multiple_of(2),
        "unaligned symlink text"
    );
    let bytes = buffer
        .get(20 + offset..20 + offset + length)
        .context("symlink text exceeds reparse buffer")?;
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&words).context("non-Unicode symbolic link target")
}

fn read_handle(file: &File, relative: &str) -> Result<NativeLinkStamp> {
    let (before, directory) = stamp_link(file)?;
    let mut buffer = [0u8; MAX_REPARSE];
    let mut returned = 0;
    ensure!(
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                GET_REPARSE,
                ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } != 0,
        "read checked symlink reparse metadata: {}",
        io::Error::last_os_error()
    );
    ensure!(
        (20..=MAX_REPARSE).contains(&(returned as usize)),
        "invalid symlink reparse size"
    );
    let buffer = &buffer[..returned as usize];
    ensure!(
        u32_at(buffer, 0)? == SYMLINK_TAG
            && u16_at(buffer, 4)? as usize + 8 == buffer.len()
            && u16_at(buffer, 6)? == 0
            && u32_at(buffer, 16)? == 1,
        "only native relative symbolic-link reparse data is supported"
    );
    let substitute = text_at(
        buffer,
        u16_at(buffer, 8)? as usize,
        u16_at(buffer, 10)? as usize,
    )?;
    let print = text_at(
        buffer,
        u16_at(buffer, 12)? as usize,
        u16_at(buffer, 14)? as usize,
    )?;
    ensure!(
        print.is_empty() || substitute == print,
        "ambiguous native symlink substitute/print targets"
    );
    // Windows stores separator backslashes. The logical-root API uses portable
    // separators; it never interprets a drive, stream or NT namespace.
    let target = substitute.replace('\\', "/");
    validate_link_target(relative, &target)?;
    for component in target.split('/') {
        if component != "." && component != ".." {
            validate_windows_component(component)?;
        }
    }
    ensure!(
        stamp_link(file)? == (before.clone(), directory),
        "native symbolic link changed during inspection"
    );
    Ok(NativeLinkStamp {
        stamp: before,
        target,
        target_is_directory: Some(directory),
    })
}

pub(super) fn read(parent: &File, name: &str, relative: &str) -> Result<NativeLinkStamp> {
    validate_windows_component(name)?;
    let file = open_options_sharing(
        parent,
        name,
        None,
        FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_OPEN,
        ptr::null(),
        true,
        FILE_SHARE_READ,
    )?;
    let first = read_handle(&file, relative)?;
    ensure!(
        read_handle(&file, relative)? == first,
        "native symlink changed while reading"
    );
    Ok(first)
}

fn require_creation_privilege() -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        ensure!(
            io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_TOKEN as i32),
            "cannot inspect effective symbolic-link privilege"
        );
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
            "cannot open symbolic-link privilege token: {}",
            io::Error::last_os_error()
        );
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);
    let name: Vec<u16> = "SeCreateSymbolicLinkPrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    ensure!(
        unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } != 0,
        "resolve symbolic-link privilege"
    );
    let mut needed = 0;
    let result =
        unsafe { GetTokenInformation(token.0, TokenPrivileges, ptr::null_mut(), 0, &mut needed) };
    ensure!(
        result == 0
            && io::Error::last_os_error().raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
            && (4..=65536).contains(&needed),
        "invalid symbolic-link privilege information"
    );
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenPrivileges,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0,
        "read symbolic-link privilege token"
    );
    let privileges = unsafe { &*storage.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let header = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let item_size = size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
    ensure!(
        (needed as usize) >= header
            && privileges.PrivilegeCount as usize <= (needed as usize - header) / item_size,
        "truncated native token privileges"
    );
    let items = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    ensure!(items.iter().any(|entry| entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart && entry.Attributes & 2 != 0),
        "native relative symlink creation requires enabled SeCreateSymbolicLinkPrivilege; no privilege was silently enabled");
    Ok(())
}

pub(super) fn create(
    parent: &File,
    name: &str,
    relative: &str,
    target: &str,
    directory: Option<bool>,
) -> Result<NativeLinkStamp> {
    validate_link_target(relative, target)?;
    validate_windows_component(name)?;
    let directory = directory
        .context("Windows symlink creation requires the authenticated directory-link bit")?;
    for component in target.split('/') {
        if component != "." && component != ".." {
            validate_windows_component(component)?;
        }
    }
    require_creation_privilege()?;
    let barrier = durability::Barrier::new(parent)?;
    barrier.flush()?;
    let expected_target = target.to_owned();
    let target: Vec<u16> = target.replace('/', "\\").encode_utf16().collect();
    let text_length = target.len() * 2;
    ensure!(
        24 + 2 * text_length <= MAX_REPARSE,
        "Windows reparse link target exceeds native size limit"
    );
    let descriptor = privacy::Descriptor::new()?;
    let file = open_options(
        parent,
        name,
        Some(directory),
        FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | FILE_WRITE_DATA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | SYNCHRONIZE
            | if directory {
                FILE_LIST_DIRECTORY | FILE_TRAVERSE
            } else {
                FILE_READ_DATA
            },
        FILE_CREATE,
        descriptor.pointer(),
        false,
        false,
    )?;
    privacy::verify(&file, directory)?;
    let owned = identity(&metadata(&file, directory)?);
    let result = (|| {
        let mut buffer = vec![0u8; 24 + 2 * text_length];
        let data_length = (buffer.len() - 8) as u16;
        buffer[0..4].copy_from_slice(&SYMLINK_TAG.to_le_bytes());
        buffer[4..6].copy_from_slice(&data_length.to_le_bytes());
        buffer[10..12].copy_from_slice(&(text_length as u16).to_le_bytes());
        buffer[12..14].copy_from_slice(&((text_length + 2) as u16).to_le_bytes());
        buffer[14..16].copy_from_slice(&(text_length as u16).to_le_bytes());
        buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
        for (index, word) in target.iter().enumerate() {
            buffer[20 + index * 2..22 + index * 2].copy_from_slice(&word.to_le_bytes());
            let print_offset = 22 + text_length + index * 2;
            buffer[print_offset..print_offset + 2].copy_from_slice(&word.to_le_bytes());
        }
        let mut returned = 0;
        ensure!(
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    SET_REPARSE,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            } != 0,
            "create native symlink reparse data: {}",
            io::Error::last_os_error()
        );
        let observed = read_handle(&file, relative)?;
        ensure!(
            identity(&observed.stamp) == owned
                && observed.target == expected_target
                && observed.target_is_directory == Some(directory),
            "new symlink identity or authenticated target changed"
        );
        barrier.flush()?;
        ensure!(
            read_handle(&file, relative)? == observed,
            "new symlink changed before durability completed"
        );
        Ok(observed)
    })();
    if result.is_err() {
        let id: FILE_ID_INFO = query_info(&file, FileIdInfo)?;
        ensure!(
            Identity {
                volume: id.VolumeSerialNumber,
                id: id_parts(id.FileId.Identifier)
            } == owned,
            "refusing cleanup after symlink handle identity changed"
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
        })?;
    }
    drop(file);
    barrier.flush()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    #[test]
    fn native_junction_tag_is_rejected_instead_of_followed_or_reclassified() -> Result<()> {
        let temp = tempfile::Builder::new()
            .prefix("quicksave-junction-")
            .tempdir()?;
        std::fs::create_dir(temp.path().join("actual"))?;
        std::fs::write(temp.path().join("actual/file"), b"not followed")?;
        let root = Root::open(temp.path())?;
        let descriptor = privacy::Descriptor::new()?;
        let directory = open_options(
            root.file(),
            "junction",
            Some(true),
            FILE_ALL_ACCESS,
            FILE_CREATE,
            descriptor.pointer(),
            false,
            false,
        )?;
        let actual = std::fs::canonicalize(temp.path().join("actual"))?;
        let print = actual.to_str().context("synthetic path must be Unicode")?;
        let print = print.strip_prefix(r"\\?\").unwrap_or(print);
        let substitute: Vec<u16> = format!(r"\??\{print}").encode_utf16().collect();
        let printed: Vec<u16> = print.encode_utf16().collect();
        let sub_bytes = substitute.len() * 2;
        let print_bytes = printed.len() * 2;
        let mut buffer = vec![0u8; 16 + sub_bytes + 2 + print_bytes + 2];
        let data_length = (buffer.len() - 8) as u16;
        buffer[0..4].copy_from_slice(&0xa000_0003u32.to_le_bytes());
        buffer[4..6].copy_from_slice(&data_length.to_le_bytes());
        buffer[10..12].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
        buffer[12..14].copy_from_slice(&((sub_bytes + 2) as u16).to_le_bytes());
        buffer[14..16].copy_from_slice(&(print_bytes as u16).to_le_bytes());
        for (index, word) in substitute.iter().enumerate() {
            buffer[16 + index * 2..18 + index * 2].copy_from_slice(&word.to_le_bytes());
        }
        for (index, word) in printed.iter().enumerate() {
            let offset = 18 + sub_bytes + index * 2;
            buffer[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
        }
        let mut returned = 0;
        ensure!(
            unsafe {
                DeviceIoControl(
                    directory.as_raw_handle(),
                    SET_REPARSE,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            } != 0,
            "create only synthetic native junction fixture: {}",
            io::Error::last_os_error()
        );
        drop(directory);
        assert!(root.entries().is_err());
        assert!(root.metadata_entries().is_err());
        assert!(root.read_link("junction").is_err());
        assert!(root.read_file("junction/file").is_err());
        assert_eq!(
            std::fs::read(temp.path().join("actual/file"))?,
            b"not followed"
        );
        std::fs::remove_dir(temp.path().join("junction"))?;
        Ok(())
    }
}
