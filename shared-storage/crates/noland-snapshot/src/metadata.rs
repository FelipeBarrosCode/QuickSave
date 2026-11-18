//! Common observations for descriptor metadata and no-follow `fstatat` metadata.
//! Rust's `fs::Metadata` cannot be constructed from `libc::stat`, so normalize
//! only the fields used by capture instead of opening a file just to call fstat.
// Native adaptations derive from No Land e81238a7536aae201540956ce76981364fd36595.
use std::fs;
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMetadata {
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    ctime: (i64, i64),
    #[cfg(not(unix))]
    kind: Option<fs::FileType>,
    #[cfg(windows)]
    windows: Option<crate::WindowsMetadata>,
}

impl SourceMetadata {
    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn mtime_ns(&self) -> Option<i64> {
        let nanos = match self.modified?.duration_since(UNIX_EPOCH) {
            Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
            Err(error) => -i128::try_from(error.duration().as_nanos()).ok()?,
        };
        i64::try_from(nanos).ok()
    }

    pub fn ctime_ns(&self) -> Option<i64> {
        #[cfg(unix)]
        {
            if !(0..1_000_000_000).contains(&self.ctime.1) {
                return None;
            }
            return self
                .ctime
                .0
                .checked_mul(1_000_000_000)?
                .checked_add(self.ctime.1);
        }
        #[cfg(windows)]
        return self.windows.as_ref()?.ctime_ns();
        #[cfg(not(any(unix, windows)))]
        None
    }

    /// Never fabricates a 128-bit Windows identity from Rust's legacy 64-bit
    /// file-index fields. Security-sensitive callers require Some(actual ID).
    pub fn native_identity(&self) -> Option<crate::NativeIdentity> {
        #[cfg(unix)]
        return Some(crate::NativeIdentity {
            volume: self.device,
            file_id: [self.inode, 0],
        });
        #[cfg(windows)]
        return self.windows.as_ref().map(|metadata| metadata.identity);
        #[cfg(not(any(unix, windows)))]
        None
    }

    #[cfg(windows)]
    pub fn from_windows(metadata: &crate::WindowsMetadata) -> Self {
        Self {
            size: metadata.size,
            modified: metadata.modified(),
            kind: None,
            windows: Some(metadata.clone()),
        }
    }

    pub fn is_file(&self) -> bool {
        #[cfg(unix)]
        {
            self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
        }
        #[cfg(windows)]
        if let Some(metadata) = &self.windows {
            return metadata.kind == crate::NativeEntryKind::File;
        }
        #[cfg(not(unix))]
        {
            self.kind.as_ref().is_some_and(fs::FileType::is_file)
        }
    }

    pub fn is_dir(&self) -> bool {
        #[cfg(unix)]
        {
            self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
        }
        #[cfg(windows)]
        if let Some(metadata) = &self.windows {
            return metadata.kind == crate::NativeEntryKind::Directory;
        }
        #[cfg(not(unix))]
        {
            self.kind.as_ref().is_some_and(fs::FileType::is_dir)
        }
    }

    pub fn is_symlink(&self) -> bool {
        #[cfg(unix)]
        {
            self.mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32
        }
        #[cfg(windows)]
        if let Some(metadata) = &self.windows {
            return metadata.kind == crate::NativeEntryKind::Symlink;
        }
        #[cfg(not(unix))]
        {
            self.kind.as_ref().is_some_and(fs::FileType::is_symlink)
        }
    }

    #[cfg(unix)]
    pub fn dev(&self) -> u64 {
        self.device
    }
    #[cfg(unix)]
    pub fn ino(&self) -> u64 {
        self.inode
    }
    #[cfg(unix)]
    pub fn mode(&self) -> u32 {
        self.mode
    }
    #[cfg(unix)]
    pub fn uid(&self) -> u32 {
        self.uid
    }
    #[cfg(unix)]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast)] // libc field widths differ across targets.
    pub(crate) fn from_stat(metadata: &libc::stat) -> Self {
        Self {
            size: metadata.st_size as u64,
            modified: unix_time(metadata.st_mtime as i64, metadata.st_mtime_nsec as i64),
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            mode: metadata.st_mode as u32,
            uid: metadata.st_uid as u32,
            gid: metadata.st_gid as u32,
            ctime: (metadata.st_ctime as i64, metadata.st_ctime_nsec as i64),
        }
    }
}

#[cfg(unix)]
fn unix_time(seconds: i64, nanos: i64) -> Option<SystemTime> {
    if !(0..1_000_000_000).contains(&nanos) {
        return None;
    }
    let base = if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))?
    };
    base.checked_add(Duration::from_nanos(nanos as u64))
}

impl From<&fs::Metadata> for SourceMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            size: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            gid: metadata.gid(),
            #[cfg(unix)]
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            #[cfg(not(unix))]
            kind: Some(metadata.file_type()),
            #[cfg(windows)]
            windows: None,
        }
    }
}

impl From<&SourceMetadata> for SourceMetadata {
    fn from(metadata: &SourceMetadata) -> Self {
        metadata.clone()
    }
}

/// Accept both held-descriptor `fs::Metadata` and anchored `SourceMetadata`.
/// Keep type, device/inode, exact size/mtime/ctime and ownership/mode checks.
pub fn same_file_identity(
    before: impl Into<SourceMetadata>,
    after: impl Into<SourceMetadata>,
) -> bool {
    let before = before.into();
    let after = after.into();
    #[cfg(windows)]
    {
        // Access time may change because of reads. A held native file's full
        // identity/change-time/attributes remain mandatory; legacy metadata
        // cannot establish native identity stability on Windows.
        match (&before.windows, &after.windows) {
            (Some(before), Some(after)) => before.same_file_state(after),
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        before == after
    }
}

#[cfg(all(test, unix))]
mod native_time_tests {
    use super::*;

    #[test]
    fn complete_change_time_is_checked_without_clamping_distinct_values() {
        // Pure timestamp arithmetic fixture, not native identity authority.
        let mut observed = SourceMetadata {
            size: 0,
            modified: Some(UNIX_EPOCH),
            device: 0,
            inode: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            ctime: (0, 0),
        };
        observed.ctime = (-1, 500_000_000);
        assert_eq!(observed.ctime_ns(), Some(-500_000_000));
        observed.ctime = (i64::MAX, 0);
        assert_eq!(observed.ctime_ns(), None);
        observed.ctime = (1, 1_000_000_000);
        assert_eq!(observed.ctime_ns(), None);
        observed.modified = UNIX_EPOCH.checked_sub(std::time::Duration::from_nanos(1));
        assert_eq!(observed.mtime_ns(), Some(-1));
    }
}
