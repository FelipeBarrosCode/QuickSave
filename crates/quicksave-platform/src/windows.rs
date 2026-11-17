// SPDX-License-Identifier: GPL-3.0-only
//! Windows reads use real NT root-directory handles, no reparse traversal, and
//! share modes that pin open names against deletion/rename. Durable writes and
//! private ACL creation are deliberately NOT emulated with path-based std APIs.

use crate::{
    validate_component, validate_relative, DirectoryIdentity, Entry, FileStamp, MAX_DEPTH,
    MAX_PATH_BYTES, MAX_TREE_ENTRIES, MAX_TREE_PATH_BYTES,
};
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of, size_of_val, MaybeUninit},
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Component, Path, Prefix},
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileIdExtdDirectoryInformation, NtCreateFile, NtQueryDirectoryFile,
            FILE_DIRECTORY_FILE, FILE_ID_EXTD_DIR_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
            OBJ_DONT_REPARSE, STATUS_NO_MORE_FILES, UNICODE_STRING,
        },
        Storage::FileSystem::{
            CreateFileW, FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
            GetFileType, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
            FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE,
            FILE_TYPE_DISK, OPEN_EXISTING, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    volume: u64,
    id: [u64; 2],
}

struct Directory {
    file: File,
    identity: Identity,
    name: Option<String>,
}

pub(crate) struct Root {
    // All ancestors remain open without FILE_SHARE_DELETE. A later path lookup
    // therefore cannot silently redirect the pinned approved root.
    ancestors: Vec<Directory>,
}

impl Root {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let text = path.to_str().context("root path must be Unicode")?;
        ensure!(
            !text.is_empty() && text.len() <= MAX_PATH_BYTES && !text.contains('\0'),
            "invalid root path"
        );
        ensure!(
            !text
                .split(['/', '\\'])
                .any(|part| part == "." || part == ".."),
            "root cannot contain traversal components"
        );
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        ensure!(
            absolute
                .to_str()
                .context("absolute root must be Unicode")?
                .len()
                <= MAX_PATH_BYTES,
            "absolute root exceeds path limit"
        );
        let mut components = absolute.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => bail!("UNC, device, and non-disk roots are unsupported"),
            },
            _ => bail!("root must resolve to an absolute local disk path"),
        };
        ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "root must be absolute"
        );
        let drive_path: Vec<u16> = format!(r"\\?\{}:\", drive as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // Only the disk root uses an absolute Win32 path. Every user-selected
        // component after it is opened relative to a pinned native NT handle.
        let raw = unsafe {
            CreateFileW(
                drive_path.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE_VALUE && !raw.is_null(),
            "open native disk root: {}",
            io::Error::last_os_error()
        );
        let file = unsafe { File::from_raw_handle(raw) };
        let root_metadata = metadata(&file, true)?;
        let mut root = Self {
            ancestors: vec![Directory {
                file,
                identity: identity(&root_metadata),
                name: None,
            }],
        };
        for component in components {
            let name = match component {
                Component::Normal(name) => name.to_str().context("root name must be Unicode")?,
                _ => bail!("invalid root component"),
            };
            validate_windows_component(name)?;
            ensure!(
                root.ancestors.len() <= MAX_DEPTH,
                "root exceeds depth limit"
            );
            let child = open_child(root.file(), name, true)?;
            let metadata = metadata(&child, true)?;
            root.ancestors.push(Directory {
                file: child,
                identity: identity(&metadata),
                name: Some(name.to_owned()),
            });
        }
        root.check()?;
        Ok(root)
    }

    fn file(&self) -> &File {
        &self.ancestors[self.ancestors.len() - 1].file
    }

    pub(crate) fn check(&self) -> Result<()> {
        for (index, directory) in self.ancestors.iter().enumerate() {
            ensure!(
                identity(&metadata(&directory.file, true)?) == directory.identity,
                "root identity changed"
            );
            if let Some(name) = &directory.name {
                let child = open_child(&self.ancestors[index - 1].file, name, true)?;
                ensure!(
                    identity(&metadata(&child, true)?) == directory.identity,
                    "root ancestor was replaced"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn ancestors_overlap(&self, other: &Self) -> bool {
        let own = self.ancestors.last().unwrap().identity;
        let theirs = other.ancestors.last().unwrap().identity;
        self.ancestors
            .iter()
            .any(|ancestor| ancestor.identity == theirs)
            || other
                .ancestors
                .iter()
                .any(|ancestor| ancestor.identity == own)
    }

    pub(crate) fn directory_identity(&self, relative: Option<&str>) -> Result<DirectoryIdentity> {
        self.check()?;
        let native_id = if let Some(relative) = relative {
            let (parents, name) = self.parents(relative)?;
            let parent = parents
                .last()
                .map(|directory| &directory.file)
                .unwrap_or_else(|| self.file());
            let directory = open_child(parent, &name, true)?;
            let before = identity(&metadata(&directory, true)?);
            let second = open_child(parent, &name, true)?;
            ensure!(
                identity(&metadata(&second, true)?) == before,
                "directory identity changed during overlap inspection"
            );
            self.check_parents(&parents)?;
            before
        } else {
            identity(&metadata(self.file(), true)?)
        };
        self.check()?;
        Ok(DirectoryIdentity {
            device: native_id.volume,
            file_id: native_id.id,
        })
    }

    fn parents(&self, relative: &str) -> Result<(Vec<Directory>, String)> {
        let components = validate_relative(relative)?;
        self.check()?;
        let mut directories: Vec<Directory> = Vec::new();
        for name in &components[..components.len() - 1] {
            let parent = directories
                .last()
                .map(|directory| &directory.file)
                .unwrap_or_else(|| self.file());
            let file = open_child(parent, name, true)?;
            let stat = metadata(&file, true)?;
            directories.push(Directory {
                file,
                identity: identity(&stat),
                name: Some((*name).to_owned()),
            });
        }
        Ok((directories, components.last().unwrap().to_string()))
    }

    fn check_parents(&self, parents: &[Directory]) -> Result<()> {
        self.check()?;
        let mut parent = self.file();
        for directory in parents {
            let file = open_child(parent, directory.name.as_ref().unwrap(), true)?;
            ensure!(
                identity(&metadata(&file, true)?) == directory.identity,
                "relative parent was replaced"
            );
            parent = &directory.file;
        }
        Ok(())
    }

    pub(crate) fn read_file(&self, relative: &str) -> Result<(File, FileStamp)> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        let file = open_child(parent, &name, false)?;
        let before = metadata(&file, false)?;
        let second = open_child(parent, &name, false)?;
        ensure!(
            metadata(&second, false)? == before,
            "source changed while opening"
        );
        self.check_parents(&parents)?;
        Ok((file, before))
    }

    pub(crate) fn entries(&self) -> Result<Vec<Entry>> {
        self.check()?;
        let mut entries = Vec::new();
        let mut budget = Budget::default();
        self.walk(self.file(), "", 0, &mut entries, &mut budget)?;
        self.check()?;
        entries.sort_unstable_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(entries)
    }

    fn walk(
        &self,
        directory: &File,
        prefix: &str,
        depth: usize,
        output: &mut Vec<Entry>,
        budget: &mut Budget,
    ) -> Result<()> {
        let before = metadata(directory, true)?;
        // Reopen through the same pinned namespace for an independent scan
        // offset, rather than duplicating a handle sharing an enumeration state.
        let scanner = open_dot(directory)?;
        for record in directory_records(&scanner, prefix, budget)? {
            ensure!(depth < MAX_DEPTH, "tree exceeds depth limit");
            let is_directory = record.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let child = open_child(directory, &record.name, is_directory)?;
            let current = metadata(&child, is_directory)?;
            ensure!(
                current.file_id == record.id,
                "tree entry identity changed during traversal"
            );
            let relative = if prefix.is_empty() {
                record.name
            } else {
                format!("{prefix}/{}", record.name)
            };
            output.push(Entry {
                relative_path: relative.clone(),
                is_directory,
                size: if is_directory { 0 } else { current.size },
            });
            if is_directory {
                self.walk(&child, &relative, depth + 1, output, budget)?;
            }
        }
        ensure!(
            metadata(directory, true)? == before,
            "directory changed during traversal"
        );
        self.check()?;
        Ok(())
    }

    pub(crate) fn create_dir(&self, _relative: &str) -> Result<()> {
        bail!("Windows durable directory creation is unsupported; no unsafe fallback was used")
    }

    pub(crate) fn write_new(
        &self,
        _relative: &str,
        _writer: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        bail!("Windows durable create-new writes are unsupported; no file was created and the callback was not run")
    }
}

pub(crate) fn ensure_private_directory(_path: &Path) -> Result<()> {
    bail!("Windows private directory ACL creation and durability are unsupported; no directory was created")
}

fn validate_windows_component(name: &str) -> Result<()> {
    validate_component(name)?;
    ensure!(
        !name.ends_with(['.', ' '])
            && !name.chars().any(|character| character < ' '
                || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')),
        "invalid Windows path component"
    );
    let stem = name.split('.').next().unwrap().to_ascii_uppercase();
    ensure!(
        !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()),
        "reserved Windows device name"
    );
    Ok(())
}

fn open_child(parent: &File, name: &str, directory: bool) -> Result<File> {
    validate_windows_component(name)?;
    open_native(parent, name, directory)
}

fn open_dot(parent: &File) -> Result<File> {
    open_native(parent, ".", true)
}

fn open_native(parent: &File, name: &str, directory: bool) -> Result<File> {
    let mut encoded: Vec<u16> = name.encode_utf16().collect();
    let bytes = encoded
        .len()
        .checked_mul(2)
        .context("native name length overflow")?;
    ensure!(
        bytes < u16::MAX as usize,
        "native name exceeds Unicode limit"
    );
    let native_name = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &native_name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // Exactly one component is passed. FILE_OPEN_REPARSE_POINT and the
    // subsequent native metadata check reject all reparse-point kinds.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if directory {
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE
                } else {
                    FILE_READ_DATA
                },
            &attributes,
            &mut status,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            ptr::null(),
            0,
        )
    };
    nt_result(result).with_context(|| format!("open native no-reparse component: {name:?}"))?;
    ensure!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "NT returned an invalid handle"
    );
    let file = unsafe { File::from_raw_handle(handle) };
    metadata(&file, directory)?;
    Ok(file)
}

fn metadata(file: &File, directory: bool) -> Result<FileStamp> {
    ensure!(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "unsupported non-disk file"
    );
    let basic: FILE_BASIC_INFO = query_info(file, FileBasicInfo)?;
    ensure!(
        basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) == 0,
        "symlinks, reparse points, and device files are unsupported"
    );
    let standard: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    ensure!(
        standard.Directory == directory && !standard.DeletePending,
        "unexpected or delete-pending native file type"
    );
    ensure!(
        (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory,
        "inconsistent native directory attributes"
    );
    let id: FILE_ID_INFO = query_info(file, FileIdInfo)?;
    ensure!(
        id.FileId.Identifier != [0; 16],
        "filesystem did not provide a stable native file ID"
    );
    let modified = native_time(basic.LastWriteTime);
    let changed = native_time(basic.ChangeTime);
    Ok(FileStamp {
        device: id.VolumeSerialNumber,
        file_id: id_parts(id.FileId.Identifier),
        size: u64::try_from(standard.EndOfFile).context("negative native file size")?,
        modified_seconds: modified.0,
        modified_nanoseconds: modified.1,
        changed_seconds: changed.0,
        changed_nanoseconds: changed.1,
    })
}

fn identity(stamp: &FileStamp) -> Identity {
    Identity {
        volume: stamp.device,
        id: stamp.file_id,
    }
}

fn query_info<T>(file: &File, class: i32) -> Result<T> {
    let mut result = MaybeUninit::<T>::uninit();
    let status = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            result.as_mut_ptr().cast(),
            size_of::<T>() as u32,
        )
    };
    if status == 0 {
        return Err(io::Error::last_os_error()).context("query native file identity/metadata");
    }
    Ok(unsafe { result.assume_init() })
}

fn native_time(ticks: i64) -> (i64, u32) {
    let seconds = ticks.div_euclid(10_000_000) - 11_644_473_600;
    let nanos = ticks.rem_euclid(10_000_000) as u32 * 100;
    (seconds, nanos)
}

fn id_parts(id: [u8; 16]) -> [u64; 2] {
    [
        u64::from_le_bytes(id[..8].try_into().unwrap()),
        u64::from_le_bytes(id[8..].try_into().unwrap()),
    ]
}

fn nt_result(status: i32) -> Result<()> {
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32))
            .context("native NT filesystem operation failed");
    }
    Ok(())
}

#[derive(Default)]
struct Budget {
    count: usize,
    path_bytes: usize,
}

struct Record {
    name: String,
    id: [u64; 2],
    attributes: u32,
}

fn directory_records(directory: &File, prefix: &str, budget: &mut Budget) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut first = true;
    loop {
        // A fixed-size, aligned native buffer, with every variable record
        // bounded by IO_STATUS_BLOCK.Information before parsing.
        let mut storage = [0u64; 8192];
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.as_raw_handle(),
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut io_status,
                storage.as_mut_ptr().cast(),
                size_of_val(&storage) as u32,
                FileIdExtdDirectoryInformation,
                false,
                ptr::null(),
                first,
            )
        };
        first = false;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        nt_result(status)?;
        let valid = io_status.Information;
        ensure!(
            valid > 0 && valid <= size_of_val(&storage),
            "invalid native directory buffer size"
        );
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), valid) };
        let mut offset = 0;
        let header = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        loop {
            ensure!(
                offset + header <= bytes.len(),
                "truncated native directory header"
            );
            // The fixed struct includes one WCHAR. Check it before reading the
            // structure, then separately validate the full variable name.
            ensure!(
                offset + size_of::<FILE_ID_EXTD_DIR_INFORMATION>() <= size_of_val(&storage),
                "truncated native directory record"
            );
            let record = unsafe {
                ptr::read_unaligned(
                    storage
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_EXTD_DIR_INFORMATION>(),
                )
            };
            let length = record.FileNameLength as usize;
            ensure!(
                length > 0 && length.is_multiple_of(2) && length <= 510,
                "invalid native directory name length"
            );
            ensure!(
                offset + header + length <= bytes.len(),
                "native directory name exceeds buffer"
            );
            let encoded: Vec<u16> = bytes[offset + header..offset + header + length]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let name =
                String::from_utf16(&encoded).context("tree contains a non-Unicode filename")?;
            if name != "." && name != ".." {
                validate_windows_component(&name)?;
                ensure!(
                    record.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)
                        == 0,
                    "tree contains a reparse point or device"
                );
                budget.count = budget
                    .count
                    .checked_add(1)
                    .context("tree entry count overflow")?;
                budget.path_bytes = budget
                    .path_bytes
                    .checked_add(
                        name.len()
                            + if prefix.is_empty() {
                                0
                            } else {
                                prefix.len() + 1
                            },
                    )
                    .context("tree path size overflow")?;
                ensure!(
                    budget.count <= MAX_TREE_ENTRIES && budget.path_bytes <= MAX_TREE_PATH_BYTES,
                    "tree exceeds entry or memory limits"
                );
                records.push(Record {
                    name,
                    id: id_parts(record.FileId.Identifier),
                    attributes: record.FileAttributes,
                });
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            let next = record.NextEntryOffset as usize;
            ensure!(
                next >= header + length && next.is_multiple_of(8) && offset + next < bytes.len(),
                "invalid native directory offset"
            );
            offset += next;
        }
    }
    Ok(records)
}
