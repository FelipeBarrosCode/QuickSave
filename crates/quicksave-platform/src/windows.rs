// SPDX-License-Identifier: GPL-3.0-only
//! Real NT root-directory handles and no-follow namespace operations. Writes
//! use explicit private security descriptors and actual NTFS/ReFS volume flushes;
//! failure to obtain those semantics is an error, never a path-based fallback.

use crate::{
    validate_component, validate_relative, DirectoryIdentity, Entry, EntryKind, FileStamp,
    MetadataEntry, NativeLinkStamp, MAX_DEPTH, MAX_PATH_BYTES, MAX_TREE_ENTRIES,
    MAX_TREE_PATH_BYTES,
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
        Security::SECURITY_DESCRIPTOR,
        Storage::FileSystem::{
            CreateFileW, FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
            GetFileType, ReOpenFile, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
            FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_STANDARD_INFO, FILE_TRAVERSE, FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL,
            SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

pub(super) mod browser;
mod config;
mod durability;
mod links;
mod overlap;
mod privacy;
mod write;

pub use config::{flush_native_directory, PrivateDirectory, PrivateFileVersion, PrivateLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        Self::open_impl(path, false)
    }

    fn open_impl(path: &Path, create_missing: bool) -> Result<Self> {
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
                FILE_LIST_DIRECTORY
                    | FILE_READ_ATTRIBUTES
                    | FILE_TRAVERSE
                    | READ_CONTROL
                    | SYNCHRONIZE,
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
            let child = match open_child(root.file(), name, true) {
                Ok(child) => child,
                Err(error)
                    if create_missing
                        && error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
                {
                    let barrier = durability::Barrier::new(root.file())?;
                    barrier.flush()?;
                    let child = write::create_private(root.file(), name, true, false)?;
                    privacy::verify(&child, true)?;
                    barrier.flush()?;
                    child
                }
                Err(error) => return Err(error),
            };
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
        let opened = open_child(parent, &name, false)?;
        let file = deny_write_handle(&opened)?;
        let before = metadata(&file, false)?;
        let second = open_child(parent, &name, false)?;
        ensure!(
            metadata(&second, false)? == before,
            "source changed while opening"
        );
        self.check_parents(&parents)?;
        Ok((file, before))
    }

    pub(crate) fn file_metadata(&self, relative: &str) -> Result<FileStamp> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        let observe = || -> Result<File> {
            open_options(
                parent,
                &name,
                Some(false),
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                ptr::null(),
                false,
                false,
            )
        };
        let held = observe()?;
        let before = metadata(&held, false)?;
        let second = observe()?;
        ensure!(
            metadata(&second, false)? == before,
            "native file metadata or identity changed during inspection"
        );
        self.check_parents(&parents)?;
        Ok(before)
    }

    pub(crate) fn open_directory(&self, relative: &str) -> Result<File> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        let before = open_child(parent, &name, true)?;
        let identity_before = identity(&metadata(&before, true)?);
        let directory = open_child(parent, &name, true)?;
        ensure!(
            identity(&metadata(&directory, true)?) == identity_before,
            "native relative directory changed while opening"
        );
        let after = open_child(parent, &name, true)?;
        ensure!(
            identity(&metadata(&after, true)?) == identity_before,
            "native relative directory namespace changed while opening"
        );
        self.check_parents(&parents)?;
        Ok(directory)
    }

    pub(crate) fn clone_root_directory_handle(&self) -> Result<File> {
        self.check()?;
        let before = identity(&metadata(self.file(), true)?);
        let directory = open_dot(self.file())?;
        ensure!(
            identity(&metadata(&directory, true)?) == before,
            "native root directory handle identity changed"
        );
        self.check()?;
        Ok(directory)
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
        for record in directory_records(&scanner, prefix, budget, false)? {
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

    pub(crate) fn create_dir(&self, relative: &str) -> Result<()> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        let barrier = durability::Barrier::new(parent)?;
        barrier.flush()?;
        let (child, created) = match write::create_private(parent, &name, true, false) {
            Ok(child) => (child, true),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
            {
                (open_child(parent, &name, true)?, false)
            }
            Err(error) => return Err(error),
        };
        let before = metadata(&child, true)?;
        if created {
            privacy::verify(&child, true)?;
        }
        self.check_parents(&parents)?;
        barrier.flush()?;
        ensure!(
            metadata(&child, true)? == before,
            "created directory changed"
        );
        self.check_parents(&parents)
    }

    pub(crate) fn write_new(
        &self,
        relative: &str,
        writer: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        write::write_new(parent, &name, writer, || self.check_parents(&parents))
    }

    pub(crate) fn read_link(&self, relative: &str) -> Result<NativeLinkStamp> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        let link = links::read(parent, &name, relative)?;
        self.check_parents(&parents)?;
        ensure!(
            links::read(parent, &name, relative)? == link,
            "symlink changed"
        );
        Ok(link)
    }

    pub(crate) fn create_new_relative_symlink(
        &self,
        relative: &str,
        target: &str,
        directory: Option<bool>,
    ) -> Result<NativeLinkStamp> {
        let (parents, name) = self.parents(relative)?;
        let parent = parents
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.file());
        self.check_parents(&parents)?;
        let link = links::create(parent, &name, relative, target, directory)?;
        self.check_parents(&parents)?;
        Ok(link)
    }

    pub(crate) fn metadata_entries(&self) -> Result<Vec<MetadataEntry>> {
        self.check()?;
        let mut entries = Vec::new();
        let mut budget = Budget::default();
        self.walk_metadata(self.file(), "", 0, &mut entries, &mut budget)?;
        self.check()?;
        entries.sort_unstable_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(entries)
    }

    fn walk_metadata(
        &self,
        directory: &File,
        prefix: &str,
        depth: usize,
        output: &mut Vec<MetadataEntry>,
        budget: &mut Budget,
    ) -> Result<()> {
        let before = metadata(directory, true)?;
        for record in directory_records(&open_dot(directory)?, prefix, budget, true)? {
            let relative = if prefix.is_empty() {
                record.name.clone()
            } else {
                format!("{prefix}/{}", record.name)
            };
            ensure!(
                depth < MAX_DEPTH && relative.len() <= MAX_PATH_BYTES,
                "tree exceeds depth/path limit"
            );
            let is_directory = record.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let (kind, stamp, link) = if record.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                let link = links::read(directory, &record.name, &relative)?;
                budget.path_bytes = budget
                    .path_bytes
                    .checked_add(link.target.len())
                    .context("link budget overflow")?;
                (EntryKind::Symlink, link.stamp.clone(), Some(link))
            } else {
                let child = open_child(directory, &record.name, is_directory)?;
                let stamp = metadata(&child, is_directory)?;
                let kind = if is_directory {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                if is_directory {
                    self.walk_metadata(&child, &relative, depth + 1, output, budget)?;
                    ensure!(
                        metadata(&child, true)? == stamp,
                        "directory changed during metadata walk"
                    );
                }
                (kind, stamp, None)
            };
            ensure!(
                budget.path_bytes <= MAX_TREE_PATH_BYTES,
                "metadata exceeds memory limit"
            );
            ensure!(stamp.file_id == record.id, "metadata entry was replaced");
            output.push(MetadataEntry {
                relative_path: relative,
                kind,
                stamp,
                link,
            });
        }
        ensure!(
            metadata(directory, true)? == before,
            "directory changed during metadata walk"
        );
        self.check()
    }
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    let root = Root::open_impl(path, true)?;
    privacy::verify(root.file(), true)?;
    durability::Barrier::new(root.file())?.flush()?;
    root.check()
}

pub(crate) fn verify_private_file(file: &File) -> Result<()> {
    privacy::verify(file, false)
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
        ) && !((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().count() == 4
            && stem
                .chars()
                .last()
                .is_some_and(|last| last.is_ascii_digit() || matches!(last, '¹' | '²' | '³'))),
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
                FILE_READ_DATA
            },
        FILE_OPEN,
        ptr::null(),
        false,
        false,
    )?;
    metadata(&file, directory)?;
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
fn open_options(
    parent: &File,
    name: &str,
    directory: Option<bool>,
    access: u32,
    disposition: u32,
    security: *const SECURITY_DESCRIPTOR,
    allow_reparse_leaf: bool,
    share_delete: bool,
) -> Result<File> {
    open_options_sharing(
        parent,
        name,
        directory,
        access,
        disposition,
        security,
        allow_reparse_leaf,
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
    )
}

#[allow(clippy::too_many_arguments)]
fn open_options_sharing(
    parent: &File,
    name: &str,
    directory: Option<bool>,
    access: u32,
    disposition: u32,
    security: *const SECURITY_DESCRIPTOR,
    allow_reparse_leaf: bool,
    sharing: u32,
) -> Result<File> {
    if name != "." {
        validate_windows_component(name)?;
    }
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
        Attributes: OBJ_CASE_INSENSITIVE
            | if allow_reparse_leaf {
                0
            } else {
                OBJ_DONT_REPARSE
            },
        SecurityDescriptor: security,
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // Exactly one component is passed. FILE_OPEN_REPARSE_POINT never follows
    // the leaf; each caller must verify its precise allowed native kind.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            ptr::null(),
            0,
            sharing,
            disposition,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | match directory {
                    Some(true) => FILE_DIRECTORY_FILE,
                    Some(false) => FILE_NON_DIRECTORY_FILE,
                    None => 0,
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
        standard.Directory == directory && !standard.DeletePending && standard.NumberOfLinks > 0,
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

fn deny_write_handle(file: &File) -> Result<File> {
    let before = metadata(file, false)?;
    // Windows can defer a writer's timestamp updates until close. A data read
    // must not call those stale times proof of stability while another ordinary
    // write handle remains open. ReOpenFile binds this deny-write/delete handle
    // to the already verified inode without another pathname traversal.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    ensure!(
        handle != INVALID_HANDLE_VALUE && !handle.is_null(),
        "cannot pin source against concurrent write/delete handles: {}",
        io::Error::last_os_error()
    );
    let pinned = unsafe { File::from_raw_handle(handle) };
    ensure!(
        identity(&metadata(&pinned, false)?) == identity(&before),
        "reopened source identity changed"
    );
    Ok(pinned)
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
    ensure!(
        status != 0x103 && status != 0x104,
        "native operation was pending or requested reparse; completion was not established"
    );
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

fn directory_records(
    directory: &File,
    prefix: &str,
    budget: &mut Budget,
    allow_links: bool,
) -> Result<Vec<Record>> {
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
                    record.FileAttributes & FILE_ATTRIBUTE_DEVICE == 0
                        && (record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                            || (allow_links && record.ReparsePointTag == links::SYMLINK_TAG)),
                    "tree contains an unsupported reparse point or device"
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
            let next_offset = offset
                .checked_add(next)
                .context("native directory offset overflow")?;
            ensure!(
                next >= header + length && next.is_multiple_of(8) && next_offset < bytes.len(),
                "invalid native directory offset"
            );
            offset = next_offset;
        }
    }
    Ok(records)
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    fn private_descriptor_pointer_matches_the_native_object_attributes_field() {
        // Compile-time prototype checks only: no token queries, zero security
        // descriptors, filesystem probes or NtCreateFile calls in this test.
        let _: fn(&privacy::Descriptor) -> *const SECURITY_DESCRIPTOR =
            privacy::Descriptor::pointer;
        fn native_field(attributes: &OBJECT_ATTRIBUTES) -> *const SECURITY_DESCRIPTOR {
            attributes.SecurityDescriptor
        }
        let _: fn(&OBJECT_ATTRIBUTES) -> *const SECURITY_DESCRIPTOR = native_field;
        let _: fn(
            &File,
            &str,
            Option<bool>,
            u32,
            u32,
            *const SECURITY_DESCRIPTOR,
            bool,
            bool,
        ) -> Result<File> = open_options;
        let _: fn(
            &File,
            &str,
            Option<bool>,
            u32,
            u32,
            *const SECURITY_DESCRIPTOR,
            bool,
            u32,
        ) -> Result<File> = open_options_sharing;
    }
}
