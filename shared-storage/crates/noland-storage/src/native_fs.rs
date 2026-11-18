// SPDX-License-Identifier: GPL-3.0-only
//! Shared native filesystem policy. Security observations always come from
//! opened handles, including Windows' actual FILE_ID_INFO (all 128 bits).

use noland_snapshot::{native_metadata, NativeIdentity, SourcePath};
use noland_state_core::{Result, StateError};
use std::{fs::File, path::Path};

pub(crate) struct FileState {
    #[cfg(unix)]
    metadata: std::fs::Metadata,
    #[cfg(windows)]
    metadata: noland_snapshot::WindowsMetadata,
}
impl FileState {
    pub(crate) fn read(file: &File) -> Result<Self> {
        #[cfg(unix)]
        let metadata = file.metadata()?;
        #[cfg(windows)]
        let metadata = noland_snapshot::WindowsMetadata::from_file(file)?;
        Ok(Self { metadata })
    }
    pub(crate) fn len(&self) -> u64 {
        #[cfg(unix)]
        return self.metadata.len();
        #[cfg(windows)]
        return self.metadata.size;
    }
    pub(crate) fn same_file(&self, file: &File) -> Result<bool> {
        #[cfg(unix)]
        return Ok(noland_snapshot::same_file_identity(
            &self.metadata,
            &file.metadata()?,
        ));
        #[cfg(windows)]
        return Ok(self
            .metadata
            .same_file_state(&noland_snapshot::WindowsMetadata::from_file(file)?));
    }
}

pub(crate) fn identity(file: &File) -> Result<NativeIdentity> {
    native_metadata::identity_from_file(file)
}
pub(crate) fn path_identity(path: &SourcePath) -> Result<NativeIdentity> {
    path.metadata()?.native_identity().ok_or_else(|| {
        StateError::UnsafePath("native path has no complete filesystem identity".into())
    })
}
pub(crate) fn directory_handle(path: &Path) -> Result<File> {
    let file = SourcePath::new(path)?.open_directory()?;
    verify_private_directory(&file)?;
    #[cfg(windows)]
    return super::native_windows::share_owned_directory(&file);
    #[cfg(unix)]
    Ok(file)
}
pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    SourcePath::new(path)?.create_private_directory()
}
pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    fn ensure(path: &Path, depth: usize) -> Result<()> {
        if !path.is_absolute() || depth >= 128 || path.as_os_str().len() > 32768 {
            return Err(StateError::UnsafePath(
                "invalid native private directory path".into(),
            ));
        }
        match SourcePath::new(path).and_then(|source| source.open_directory()) {
            Ok(file) => return native_metadata::verify_private_directory(&file),
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let parent = path
            .parent()
            .ok_or_else(|| StateError::UnsafePath("native directory has no parent".into()))?;
        // Existing OS-selected ancestors need not be private. Only newly
        // created app-owned directories and the requested leaf require it.
        if let Err(error) = SourcePath::new(parent).and_then(|source| source.open_directory()) {
            match error {
                StateError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    ensure(parent, depth + 1)?
                }
                error => return Err(error),
            }
        }
        match create_private_directory(path) {
            Ok(()) => {}
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        native_metadata::verify_private_directory(&SourcePath::new(path)?.open_directory()?)
    }
    ensure(path, 0)
}
pub(crate) fn verify_directory(source: &SourcePath, directory: &File, path: &Path) -> Result<()> {
    verify_private_directory(directory)?;
    let expected = identity(directory)?;
    if path_identity(source)? != expected
        || identity(&SourcePath::new(path)?.open_directory()?)? != expected
    {
        return Err(StateError::UnsafePath(
            "private native directory was replaced".into(),
        ));
    }
    Ok(())
}
pub(crate) fn remove_empty_directory(source: &SourcePath, directory: &File) -> Result<()> {
    verify_private_directory(directory)?;
    if path_identity(source)? != identity(directory)? {
        return Err(StateError::UnsafePath(
            "private cleanup directory was replaced".into(),
        ));
    }
    #[cfg(windows)]
    return super::native_windows::remove_owned_directory(source, directory);
    #[cfg(unix)]
    source.remove_empty_directory()
}
pub(crate) fn verify_private_directory(file: &File) -> Result<()> {
    let strict = native_metadata::verify_private_directory(file);
    #[cfg(windows)]
    if strict.is_err() {
        return super::windows_acl::verify(file, true);
    }
    strict
}
pub(crate) fn verify_private_file(file: &File) -> Result<()> {
    let strict = native_metadata::verify_private_file(file);
    #[cfg(windows)]
    if strict.is_err() {
        return super::windows_acl::verify(file, false);
    }
    strict
}
