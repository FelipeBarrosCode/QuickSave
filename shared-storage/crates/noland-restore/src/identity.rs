//! A verification observation, never a cached path-safety decision. ctime is
//! retained until commit to catch in-place edits even when mtime is restored.
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use noland_state_core::{ManifestFile, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct VerifiedIdentity {
    pub device: u64,
    #[cfg(unix)]
    pub inode: u64,
    #[cfg(windows)]
    pub file_id: [u64; 2],
    pub size: u64,
    #[cfg(unix)]
    pub mode: u32,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: i64,
    #[cfg(windows)]
    kind: u8,
    #[cfg(windows)]
    security: crate::native::NativeWindowsSecurity,
    pub mtime_ns: i64,
    ctime_ns: i64,
    links: u64,
}

impl VerifiedIdentity {
    // libc stat field widths differ across Darwin, Linux, and 32-bit targets.
    #[allow(clippy::unnecessary_cast)]
    #[cfg(unix)]
    pub fn from_stat(metadata: &libc::stat) -> Self {
        Self {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            size: metadata.st_size as u64,
            mode: metadata.st_mode as u32,
            mtime_ns: (metadata.st_mtime as i64)
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.st_mtime_nsec as i64),
            ctime_ns: (metadata.st_ctime as i64)
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.st_ctime_nsec as i64),
            links: metadata.st_nlink as u64,
        }
    }

    #[allow(clippy::unnecessary_cast)] // mode_t is u16 on Darwin and u32 on Linux.
    pub fn is_directory(self) -> bool {
        #[cfg(unix)]
        {
            self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
        }
        #[cfg(windows)]
        {
            self.kind == 2
        }
    }

    #[cfg(unix)]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            mtime_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
            ctime_ns: metadata
                .ctime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.ctime_nsec()),
            links: metadata.nlink(),
        }
    }

    pub fn from_file(file: &fs::File) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_metadata(&file.metadata()?))
        }
        #[cfg(windows)]
        {
            use noland_snapshot::native_metadata::{NativeEntryKind, WindowsMetadata};
            let before = WindowsMetadata::from_file(file)?;
            let security = crate::windows::security(file)?;
            if !before.same_file_state(&WindowsMetadata::from_file(file)?) {
                return Err(noland_state_core::StateError::Conflict(
                    "native identity changed during ACL verification".into(),
                ));
            }
            Ok(Self {
                device: before.identity.volume,
                file_id: before.identity.file_id,
                size: before.size,
                attributes: before.attributes,
                creation_time: before.creation_time,
                kind: match before.kind {
                    NativeEntryKind::File => 1,
                    NativeEntryKind::Directory => 2,
                    NativeEntryKind::Symlink => 3,
                },
                security,
                mtime_ns: before.mtime_ns().ok_or_else(|| {
                    noland_state_core::StateError::Invalid(
                        "native mtime exceeds restore range".into(),
                    )
                })?,
                ctime_ns: before.ctime_ns().ok_or_else(|| {
                    noland_state_core::StateError::Invalid(
                        "native ctime exceeds restore range".into(),
                    )
                })?,
                links: before.number_of_links as u64,
            })
        }
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_metadata(&fs::symlink_metadata(path)?))
        }
        #[cfg(windows)]
        {
            Self::from_file(&crate::windows::open_path_metadata(path, 0)?)
        }
    }

    pub fn object_id(self) -> crate::NativeObjectId {
        crate::NativeObjectId {
            device: self.device,
            #[cfg(unix)]
            file_id: [self.inode, 0],
            #[cfg(windows)]
            file_id: self.file_id,
        }
    }

    pub fn same_object(self, other: Self) -> bool {
        self.object_id() == other.object_id()
    }

    pub fn link_count(self) -> u64 {
        self.links
    }

    pub fn is_regular(self) -> bool {
        #[cfg(unix)]
        {
            self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
        }
        #[cfg(windows)]
        {
            self.kind == 1
        }
    }

    #[cfg(unix)]
    pub fn with_mode(self, mode: u32) -> Self {
        Self { mode, ..self }
    }

    /// rename may change ctime. All content-related metadata must still match,
    /// and the post-rename observation becomes the new commit-time guard.
    pub fn matches_after_rename(self, current: Self) -> bool {
        Self {
            ctime_ns: current.ctime_ns,
            ..self
        } == current
    }

    pub fn matches_path(self, path: &Path) -> bool {
        Self::from_path(path).is_ok_and(|current| current.is_regular() && current == self)
    }
}

pub(crate) fn verify_existing(
    path: &Path,
    manifest: &ManifestFile,
    metadata: Option<&fs::Metadata>,
) -> Result<Option<VerifiedIdentity>> {
    verify_contents(
        path,
        &manifest.file_hash,
        manifest.size,
        manifest.mode,
        metadata,
    )
}

pub(crate) fn verify_contents(
    path: &Path,
    hash: &str,
    size: u64,
    mode: Option<u32>,
    metadata: Option<&fs::Metadata>,
) -> Result<Option<VerifiedIdentity>> {
    #[cfg(windows)]
    {
        let _ = (path, hash, size, mode, metadata);
        return Err(noland_state_core::StateError::Invalid(
            "legacy Windows restore verification requires a typed native control".into(),
        ));
    }
    #[cfg(unix)]
    {
        if !metadata.is_some_and(|metadata| {
            metadata.is_file()
                && metadata.len() == size
                && mode.is_none_or(|mode| metadata.mode() & 0o7777 == mode & 0o7777)
        }) {
            return Ok(None);
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let before = VerifiedIdentity::from_metadata(&file.metadata()?);
        if Some(before) != metadata.map(VerifiedIdentity::from_metadata) {
            return Ok(None);
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 256 * 1024];
        loop {
            use std::io::Read;
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let after = VerifiedIdentity::from_metadata(&file.metadata()?);
        Ok((before == after
            && after.matches_path(path)
            && format!("blake3:{}", hasher.finalize().to_hex()) == hash)
            .then_some(after))
    }
}
