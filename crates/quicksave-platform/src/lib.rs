// SPDX-License-Identifier: GPL-3.0-only
//! Native, fail-closed filesystem access. All implementation in this crate is
//! original QuickSave code; no code was copied from the No Land snapshot.
//!
//! A root pins every ancestor, not just the final directory. Operations reject
//! changed namespace edges instead of following replacement paths. This provides
//! stable-file capture, NOT an application-consistent or atomic tree snapshot.
//! A failed durability check after publication can leave the new file present;
//! callers must treat errors as failures, not as a promise of rollback.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};

#[cfg(any(unix, windows))]
use std::collections::BTreeSet;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

mod directories;

/// Includes ctime/change-time as well as length and mtime, so replacing a file
/// or modifying it and restoring its mtime does not pass normal revalidation.
/// Native IDs are opaque and meaningful only on the originating filesystem.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileStamp {
    pub device: u64,
    pub file_id: [u64; 2],
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u32,
    pub changed_seconds: i64,
    pub changed_nanoseconds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub relative_path: String,
    pub is_directory: bool,
    /// Directories have size zero; file sizes are native metadata lengths.
    pub size: u64,
}

/// Exact no-follow kind. Links are metadata, never traversal edges.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

/// A stable observation of the link itself, not of its target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeLinkStamp {
    pub stamp: FileStamp,
    pub target: String,
    /// Windows needs this bit to recreate a link; Unix links have no such bit.
    pub target_is_directory: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataEntry {
    pub relative_path: String,
    pub kind: EntryKind,
    pub stamp: FileStamp,
    pub link: Option<NativeLinkStamp>,
}

#[cfg(windows)]
pub use windows::{flush_native_directory, PrivateDirectory, PrivateFileVersion, PrivateLock};
#[cfg(windows)]
pub use windows::browser::open_oauth_browser;
#[cfg(all(test, not(windows)))]
#[path = "windows/browser.rs"]
mod windows_browser_validation_tests;

/// Non-secret native directory identity for binding a prepared authorization to
/// a later owned worker. Paths and mutable timestamps are not directory IDs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RootIdentity {
    pub device: u64,
    pub file_id: [u64; 2],
}

pub const MAX_TREE_ENTRIES: usize = 1_000_000;
pub const MAX_DEPTH: usize = 128;
pub const MAX_PATH_BYTES: usize = 32_768;
pub const MAX_TREE_PATH_BYTES: usize = 128 * 1024 * 1024;

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DirectoryIdentity {
    device: u64,
    file_id: [u64; 2],
}

/// A pinned native root. It never creates the root or follows symlinks.
pub struct SafeRoot {
    #[cfg(unix)]
    inner: unix::Root,
    #[cfg(windows)]
    inner: windows::Root,
}

impl SafeRoot {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        return Ok(Self {
            inner: unix::Root::open(path)?,
        });
        #[cfg(windows)]
        return Ok(Self {
            inner: windows::Root::open(path)?,
        });
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            bail!("safe native filesystem access is unsupported on this platform")
        }
    }

    /// A bounded, deterministic, lexicographically ordered walk.
    /// Any invalid entry fails the whole walk; entries are never skipped.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        #[cfg(any(unix, windows))]
        return self.inner.entries();
        #[cfg(not(any(unix, windows)))]
        bail!("safe native directory traversal is unsupported on this platform")
    }

    /// Bounded deterministic metadata walk, including confined symbolic links.
    /// It never reads through a link; unknown reparse/special kinds fail.
    pub fn metadata_entries(&self) -> Result<Vec<MetadataEntry>> {
        #[cfg(any(unix, windows))]
        return self.inner.metadata_entries();
        #[cfg(not(any(unix, windows)))]
        bail!("native no-follow metadata enumeration is unsupported on this platform")
    }

    pub fn read_link(&self, relative: &str) -> Result<NativeLinkStamp> {
        validate_relative(relative)?;
        #[cfg(any(unix, windows))]
        return self.inner.read_link(relative);
        #[cfg(not(any(unix, windows)))]
        bail!("native no-follow symbolic link inspection is unsupported on this platform")
    }

    pub fn verify_link(&self, relative: &str, before: &NativeLinkStamp) -> Result<()> {
        anyhow::ensure!(
            self.read_link(relative)? == *before,
            "symbolic link changed: {relative}"
        );
        Ok(())
    }

    /// Creates exactly one link, without replacing any entry or resolving its
    /// target. Parents must be real existing directories beneath this root.
    pub fn create_new_relative_symlink(
        &self,
        relative: &str,
        target: &str,
        target_is_directory: Option<bool>,
    ) -> Result<NativeLinkStamp> {
        validate_link_target(relative, target)?;
        #[cfg(any(unix, windows))]
        return self
            .inner
            .create_new_relative_symlink(relative, target, target_is_directory);
        #[cfg(not(any(unix, windows)))]
        bail!("native confined symbolic link creation is unsupported on this platform")
    }

    pub fn read_file(&self, relative: &str) -> Result<(File, FileStamp)> {
        validate_relative(relative)?;
        #[cfg(any(unix, windows))]
        return self.inner.read_file(relative);
        #[cfg(not(any(unix, windows)))]
        bail!("safe native file reads are unsupported on this platform")
    }

    /// Open a real read-only native directory below this pinned root. Relative
    /// paths must be nonempty; no symlink/reparse component is ever followed.
    /// For the selected root itself use clone_root_directory_handle().
    pub fn open_directory(&self, relative: &str) -> Result<File> {
        validate_relative(relative)?;
        #[cfg(any(unix, windows))]
        return self.inner.open_directory(relative);
        #[cfg(not(any(unix, windows)))]
        bail!("native anchored directory opens are unsupported on this platform")
    }

    /// A fresh real handle to the pinned root, with namespace checks before and
    /// after. Its enumeration cursor is independent, not a dup-shared offset.
    pub fn clone_root_directory_handle(&self) -> Result<File> {
        #[cfg(any(unix, windows))]
        return self.inner.clone_root_directory_handle();
        #[cfg(not(any(unix, windows)))]
        bail!("native pinned root-directory handles are unsupported on this platform")
    }

    pub fn verify_file(&self, relative: &str, before: &FileStamp) -> Result<()> {
        let (_file, after) = self.read_file(relative)?;
        if before != &after {
            bail!("source file identity or contents changed: {relative}");
        }
        Ok(())
    }

    /// Cheap equality of pinned final native directory IDs. Unlike overlaps(),
    /// this does not scan descendants and does not equate parent/child roots.
    pub fn same_root(&self, other: &SafeRoot) -> Result<bool> {
        #[cfg(any(unix, windows))]
        {
            self.inner.check()?;
            other.inner.check()?;
            let same =
                self.inner.directory_identity(None)? == other.inner.directory_identity(None)?;
            self.inner.check()?;
            other.inner.check()?;
            Ok(same)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = other;
            bail!("native root-identity comparison is unsupported on this platform")
        }
    }

    pub fn identity(&self) -> Result<RootIdentity> {
        #[cfg(any(unix, windows))]
        {
            self.inner.check()?;
            let identity = self.inner.directory_identity(None)?;
            self.inner.check()?;
            Ok(RootIdentity {
                device: identity.device,
                file_id: identity.file_id,
            })
        }
        #[cfg(not(any(unix, windows)))]
        bail!("native directory identity is unsupported on this platform")
    }

    /// Detects native directory overlap, not lexical path-prefix overlap.
    ///
    /// After an ancestor-ID fast path, both bounded trees are inspected and all
    /// native directory IDs are intersected. This also catches shared descendant
    /// directories exposed by bind mounts/firmlinks that skip physical ancestors
    /// in a selected pathname. Confined links are metadata-only and never
    /// traversed; unsupported/escaping entries fail as in metadata_entries().
    /// A disjoint result is never inferred from strings alone.
    ///
    /// This is a validated scan, not an atomic namespace lock. Callers must
    /// recheck before mutation/commit if the selected trees can change.
    pub fn overlaps(&self, other: &SafeRoot) -> Result<bool> {
        #[cfg(any(unix, windows))]
        {
            self.inner.check()?;
            other.inner.check()?;
            let result = (|| -> Result<bool> {
                if self.inner.ancestors_overlap(&other.inner) {
                    return Ok(true);
                }
                let left = self.directory_identities()?;
                let right = other.directory_identities()?;
                Ok(!left.is_disjoint(&right))
            })();
            // Revalidate both even after a scan error; never turn a stale root
            // into a negative overlap result.
            self.inner.check()?;
            other.inner.check()?;
            result
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = other;
            bail!("native directory-overlap detection is unsupported on this platform")
        }
    }

    /// Finds a regular file with the same native device/file ID anywhere in this
    /// bounded tree, including hard-link and bind-mounted namespace aliases.
    ///
    /// Candidates are selected by the supplied length to bound unnecessary
    /// opens, then compared by device and file ID ONLY, not modification times.
    /// No file contents are read. The caller must independently verify a key's
    /// length/content/stability; this is an alias guard, not key verification.
    pub fn contains_file_identity(&self, stamp: &FileStamp) -> Result<bool> {
        #[cfg(any(unix, windows))]
        {
            self.inner.check()?;
            let result = (|| -> Result<bool> {
                for entry in self.metadata_entries()? {
                    if entry.kind != EntryKind::File || entry.stamp.size != stamp.size {
                        continue;
                    }
                    let (_file, current) = self.read_file(&entry.relative_path)?;
                    if current.device == stamp.device && current.file_id == stamp.file_id {
                        return Ok(true);
                    }
                }
                Ok(false)
            })();
            self.inner.check()?;
            result
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = stamp;
            bail!("native file-identity search is unsupported on this platform")
        }
    }

    #[cfg(any(unix, windows))]
    fn directory_identities(&self) -> Result<BTreeSet<DirectoryIdentity>> {
        let entries = self.metadata_entries()?;
        let mut identities = BTreeSet::new();
        identities.insert(self.inner.directory_identity(None)?);
        // Store entry indices rather than another copy of bounded path strings.
        let mut observed = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry.kind == EntryKind::Directory {
                let identity = self.inner.directory_identity(Some(&entry.relative_path))?;
                identities.insert(identity);
                observed.push((index, identity));
            }
        }
        // Detect replacements between enumeration and identity collection,
        // including replacement by a directory with the same relative names.
        for (index, before) in observed {
            anyhow::ensure!(
                self.inner
                    .directory_identity(Some(&entries[index].relative_path))?
                    == before,
                "directory identity changed during overlap inspection"
            );
        }
        anyhow::ensure!(
            self.metadata_entries()? == entries,
            "tree changed during overlap inspection"
        );
        self.inner.check()?;
        Ok(identities)
    }

    /// Creates one directory (parents must exist). An existing, verified real
    /// directory is accepted. A symlink or any other existing object is not.
    pub fn create_dir(&self, relative: &str) -> Result<()> {
        validate_relative(relative)?;
        #[cfg(any(unix, windows))]
        return self.inner.create_dir(relative);
        #[cfg(not(any(unix, windows)))]
        bail!("safe native directory creation is unsupported on this platform")
    }

    /// Stage new bytes privately, run the entire callback, sync file data, then
    /// publish without replacing any existing name. The callback is responsible
    /// for content authentication/verification and must return Err if it fails.
    ///
    /// Temporary staging entries are not a commit. Concurrent writers to the
    /// same final name cannot overwrite each other. Flush errors are never
    /// ignored. Errors after publication may leave a complete new file present.
    pub fn write_new(
        &self,
        relative: &str,
        writer: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        validate_relative(relative)?;
        #[cfg(any(unix, windows))]
        return self.inner.write_new(relative, writer);
        #[cfg(not(any(unix, windows)))]
        {
            let _ = writer;
            bail!("safe durable native writes are unsupported on this platform")
        }
    }
}

/// Creates missing components safely, but requires the final directory to be
/// private to the current user. Existing system ancestors may be shared/sticky.
/// Does not chmod, take ownership of, or otherwise repair an existing directory.
pub fn ensure_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    return unix::ensure_private_directory(path);
    #[cfg(windows)]
    return windows::ensure_private_directory(path);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        bail!("private native directory creation is unsupported on this platform")
    }
}

/// Requires a real regular file owned by the effective user and one native hard
/// link. Unix requires mode exactly 0600 and no extended ACL. Windows requires a
/// protected DACL containing only the current-user SID's explicit full-access
/// allow ACE. Inspection is handle-based; unknown ACL semantics fail explicitly.
///
/// Call before reading an external recovery key and again before trusting its
/// continued privacy. This checks privacy, not the key's length or contents.
pub fn verify_private_file(file: &File) -> Result<()> {
    #[cfg(unix)]
    return unix::verify_private_file(file);
    #[cfg(windows)]
    return windows::verify_private_file(file);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        bail!("native private-file ACL verification is unsupported on this platform")
    }
}

/// Computes OS-native application paths only. No directories or settings are
/// created, and no previous application state is loaded.
pub fn app_directories() -> Result<serde_json::Value> {
    directories::app_directories()
}

/// Native account home discovery without reading application state or trusting
/// a process-provided HOME override.
pub fn home_directory() -> Result<std::path::PathBuf> {
    directories::home_directory()
}

pub fn capabilities() -> serde_json::Value {
    let unix_writes = cfg!(any(target_os = "macos", target_os = "linux"));
    let native_writes = unix_writes || cfg!(windows);
    serde_json::json!({
        "platform": std::env::consts::OS,
        "application": "QuickSave",
        "filesystem": {
            "native_directory_handles": cfg!(any(unix, windows)),
            "handle_anchored_reads": cfg!(any(unix, windows)),
            "reject_symlink_ancestors": cfg!(any(unix, windows)),
            "reject_symlinks_and_reparse_points": true,
            "confined_symlink_metadata": cfg!(any(unix, windows)),
            "confined_create_new_relative_symlink": native_writes,
            "symlink_traversal": false,
            "reject_special_files": true,
            "require_utf8_names": true,
            "source_identity_revalidation": cfg!(any(unix, windows)),
            "root_identity_revalidation": cfg!(any(unix, windows)),
            "native_tree_overlap_detection": cfg!(any(unix, windows)),
            "native_file_identity_search": cfg!(any(unix, windows)),
            "native_root_equality": cfg!(any(unix, windows)),
            "bounded_deterministic_tree_walk": cfg!(any(unix, windows)),
            "durable_create_new": native_writes,
            "durable_directory_creation": native_writes,
            "private_directory_creation": native_writes,
            "private_file_verification": native_writes,
            "native_private_file_verification": native_writes,
            "private_acl_policy": "Unix: reject extended ACLs; Windows: protected current-user-only DACL and matching owner; fail if unverifiable",
            "private_acl_filesystems": {
                "macos": ["apfs", "hfs"],
                "linux": ["ext2/ext3/ext4", "xfs", "btrfs", "tmpfs", "f2fs", "overlayfs"],
                "windows": ["NTFS", "ReFS"]
            },
            "new_file_unix_mode": if unix_writes { Some("0600") } else { None },
            "new_directory_unix_mode": if unix_writes { Some("0700") } else { None },
            "overwrite_existing": false,
            "application_atomic_snapshots": false,
            "capture_consistency": "validated stable-file capture, not application-atomic",
            "max_tree_entries": MAX_TREE_ENTRIES,
            "max_depth": MAX_DEPTH,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_tree_path_bytes": MAX_TREE_PATH_BYTES,
            "windows_durable_write_status": "native NTFS/ReFS writes with protected current-user DACL; actual filesystem/volume flush required, unsupported semantics or privileges fail explicitly; native acceptance pending"
        },
        "app_directories_create_state": false,
        "native_vault": false,
        "external_recovery_key_required": true,
        "packaging_acceptance": {
            "macos": false,
            "windows": false,
            "linux": false
        }
    })
}

pub(crate) fn validate_relative(relative: &str) -> Result<Vec<&str>> {
    if relative.is_empty() || relative.len() > MAX_PATH_BYTES {
        bail!("relative path is empty or exceeds the {MAX_PATH_BYTES}-byte limit");
    }
    if relative.contains(['\\', '\0', ':']) {
        bail!("relative paths cannot contain backslashes, NUL, or colons");
    }
    let components: Vec<_> = relative.split('/').collect();
    if components.len() > MAX_DEPTH {
        bail!("relative path exceeds the {MAX_DEPTH}-component depth limit");
    }
    for component in &components {
        validate_component(component)?;
    }
    Ok(components)
}

pub(crate) fn validate_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > 255
        || component.contains(['/', '\\', '\0', ':'])
    {
        bail!("invalid or non-portable path component");
    }
    Ok(())
}

/// This is lexical logical-root confinement, not target resolution. Resolving a
/// target here would widen capture and reject useful dangling framework links.
pub(crate) fn validate_link_target(relative: &str, target: &str) -> Result<()> {
    let components = validate_relative(relative)?;
    anyhow::ensure!(
        !target.is_empty()
            && target.len() <= MAX_PATH_BYTES
            && !target.starts_with('/')
            && !target.contains(['\\', '\0', ':']),
        "symlink target must be a bounded relative logical-root path"
    );
    let mut depth = components.len() - 1;
    let mut count = 0usize;
    for component in target.split('/') {
        count += 1;
        anyhow::ensure!(count <= MAX_DEPTH, "symlink target exceeds depth limit");
        match component {
            "." => {}
            ".." => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("symlink target escapes logical root"))?;
            }
            "" => bail!("symlink target contains an empty path component"),
            normal => {
                validate_component(normal)?;
                depth += 1;
                anyhow::ensure!(depth <= MAX_DEPTH, "symlink target exceeds depth limit");
            }
        }
    }
    Ok(())
}
