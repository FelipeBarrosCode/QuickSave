// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, read-only stable-file capture. This is not an app-atomic snapshot.

use crate::{
    diagnostics::{InspectionSide, PolicyRootFailure, RootContext, ScopeGrantViolation},
    model::{
        is_secret_component, validate_absolute, validate_relative, ApprovedRoot, BaselineReference,
        NativeMetadata, Node, RootIdentity, Snapshot, TrackedSoftware, TrackingPolicy,
        MAX_BASELINE_BYTES, MAX_FILES, MAX_PATH_BYTES,
    },
    TrackingStore,
};
use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::{EntryKind, FileStamp, SafeRoot};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Default)]
pub(crate) struct IoCounters {
    pub bytes_read: AtomicU64,
    pub files_hashed: AtomicU64,
    pub fs_walks: AtomicU64,
    pub metadata_nodes: AtomicU64,
}

impl IoCounters {
    pub(crate) fn value(&self) -> Value {
        serde_json::json!({
            "bytesRead": self.bytes_read.load(Ordering::Relaxed),
            "filesHashed": self.files_hashed.load(Ordering::Relaxed),
            "fsWalks": self.fs_walks.load(Ordering::Relaxed),
            "metadataNodes": self.metadata_nodes.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug)]
pub(crate) struct AuthorityChanged;
impl std::fmt::Display for AuthorityChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("approved root identity changed; new native approval is required")
    }
}
impl std::error::Error for AuthorityChanged {}

#[cfg(unix)]
mod anchor {
    use super::*;
    use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
    use std::{os::fd::OwnedFd, path::Component};

    struct Directory {
        fd: OwnedFd,
        name: Option<String>,
        identity: RootIdentity,
    }

    /// Independent no-follow native ID snapshot, including every ancestor edge.
    /// SafeRoot continues to perform all content and enumeration operations.
    pub(super) struct Anchor(Vec<Directory>);
    impl Anchor {
        pub(super) fn open(path: &Path) -> Result<Self> {
            validate_absolute(path)?;
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let fd = open("/", flags, Mode::empty())?;
            let root_identity = identity(&fstat(&fd)?)?;
            let mut anchor = Self(vec![Directory {
                fd,
                name: None,
                identity: root_identity,
            }]);
            for component in path.components() {
                if let Component::Normal(name) = component {
                    ensure!(
                        anchor.0.len() <= 128,
                        "root exceeds native handle depth bound"
                    );
                    let name = name.to_str().context("native root name is not UTF-8")?;
                    anchor.check()?;
                    let fd = openat(&anchor.0.last().unwrap().fd, name, flags, Mode::empty())?;
                    let identity = identity(&fstat(&fd)?)?;
                    anchor.0.push(Directory {
                        fd,
                        name: Some(name.to_owned()),
                        identity,
                    });
                }
            }
            anchor.check()?;
            Ok(anchor)
        }

        pub(super) fn identity(&self) -> RootIdentity {
            self.0.last().unwrap().identity.clone()
        }

        pub(super) fn inside(&self, other: &Self) -> bool {
            let other_id = other.identity();
            self.0
                .iter()
                .any(|directory| directory.identity == other_id)
        }

        pub(super) fn check(&self) -> Result<()> {
            for (i, directory) in self.0.iter().enumerate() {
                ensure!(
                    identity(&fstat(&directory.fd)?)? == directory.identity,
                    AuthorityChanged
                );
                if let Some(name) = &directory.name {
                    let current =
                        statat(&self.0[i - 1].fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
                    ensure!(identity(&current)? == directory.identity, AuthorityChanged);
                }
            }
            Ok(())
        }

        pub(super) fn metadata(
            &self,
            relative: Option<&str>,
            expected: Option<&FileStamp>,
        ) -> Result<NativeMetadata> {
            self.check()?;
            let stat = if let Some(relative) = relative {
                validate_relative(relative)?;
                let names: Vec<_> = relative.split('/').collect();
                let mut parents = Self(vec![Directory {
                    fd: self.0.last().unwrap().fd.try_clone()?,
                    name: None,
                    identity: self.identity(),
                }]);
                for name in &names[..names.len() - 1] {
                    parents.check()?;
                    let fd = openat(
                        &parents.0.last().unwrap().fd,
                        *name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let identity = identity(&fstat(&fd)?)?;
                    parents.0.push(Directory {
                        fd,
                        name: Some((*name).to_owned()),
                        identity,
                    });
                }
                parents.check()?;
                let stat = statat(
                    &parents.0.last().unwrap().fd,
                    *names.last().unwrap(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
                parents.check()?;
                stat
            } else {
                fstat(&self.0.last().unwrap().fd)?
            };
            if let Some(expected) = expected {
                #[allow(clippy::unnecessary_cast)]
                let same = stat.st_dev as u64 == expected.device
                    && [stat.st_ino as u64, 0] == expected.file_id;
                ensure!(same, "native metadata identity changed during capture");
            }
            self.check()?;
            #[allow(clippy::unnecessary_cast)]
            Ok(NativeMetadata::Unix(crate::model::UnixMetadata {
                mode: stat.st_mode as u32,
                owner: stat.st_uid as u32,
                group: stat.st_gid as u32,
                link_count: stat.st_nlink as u64,
            }))
        }

        pub(super) fn trusted_change_stamps(&self) -> Result<bool> {
            self.check()?;
            let filesystem = rustix::fs::fstatfs(&self.0.last().unwrap().fd)?;
            #[cfg(target_os = "macos")]
            let trusted = {
                let name: Vec<u8> = filesystem
                    .f_fstypename
                    .iter()
                    .copied()
                    .take_while(|byte| *byte != 0)
                    .map(|byte| byte as u8)
                    .collect();
                // Darwin MNT_LOCAL. HFS/network/FUSE timestamp semantics are
                // not assumed equivalent to native APFS high-resolution stamps.
                name == b"apfs" && filesystem.f_flags & 0x1000 != 0
            };
            #[cfg(target_os = "linux")]
            let trusted = {
                // ext2/3/4 share a magic despite different inode timestamp
                // precision. Overlay/network/FUSE remain uncertain as well.
                matches!(
                    filesystem.f_type as u64,
                    0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0xf2f5_2010
                )
            };
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let trusted = {
                let _ = filesystem;
                false
            };
            self.check()?;
            Ok(trusted)
        }

        pub(super) fn root_stamp(&self) -> Result<FileStamp> {
            use std::os::unix::fs::MetadataExt;
            self.check()?;
            let file = File::from(self.0.last().unwrap().fd.try_clone()?);
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_dir()
                    && (0..1_000_000_000).contains(&metadata.mtime_nsec())
                    && (0..1_000_000_000).contains(&metadata.ctime_nsec()),
                "native root timestamps are not exactly representable"
            );
            let stamp = FileStamp {
                device: metadata.dev(),
                file_id: [metadata.ino(), 0],
                size: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec() as u32,
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec() as u32,
            };
            ensure!(
                stamp.device == self.identity().device && stamp.file_id == self.identity().file_id,
                "native root identity changed while reading its stamp"
            );
            self.check()?;
            Ok(stamp)
        }
    }

    fn identity(stat: &Stat) -> Result<RootIdentity> {
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
            "root/ancestor is not a real native directory"
        );
        #[allow(clippy::unnecessary_cast)]
        Ok(RootIdentity {
            device: stat.st_dev as u64,
            file_id: [stat.st_ino as u64, 0],
        })
    }
}

#[cfg(windows)]
#[path = "windows_anchor.rs"]
mod anchor;

#[cfg(not(any(unix, windows)))]
mod anchor {
    use super::*;
    pub(super) struct Anchor;
    impl Anchor {
        pub(super) fn open(_: &Path) -> Result<Self> {
            bail!("native tracking root identity snapshots are unsupported on this platform")
        }
        pub(super) fn identity(&self) -> RootIdentity {
            unreachable!("unsupported native root construction always fails")
        }
        pub(super) fn check(&self) -> Result<()> {
            bail!("native tracking root identity snapshots are unsupported on this platform")
        }
        pub(super) fn inside(&self, _: &Self) -> bool {
            false // Construction always fails on unsupported platforms.
        }
        pub(super) fn metadata(
            &self,
            _: Option<&str>,
            _: Option<&FileStamp>,
        ) -> Result<NativeMetadata> {
            bail!("native source ownership/permission metadata is unsupported on this platform")
        }
        pub(super) fn trusted_change_stamps(&self) -> Result<bool> {
            Ok(false)
        }
        pub(super) fn root_stamp(&self) -> Result<FileStamp> {
            bail!("native directory-root stamps are unsupported on this platform")
        }
    }
}

pub(crate) struct PinnedRoot {
    pub safe: SafeRoot,
    anchor: anchor::Anchor,
}

impl PinnedRoot {
    pub(crate) fn open(root: &ApprovedRoot) -> Result<Self> {
        root.validate()?;
        let anchor = anchor::Anchor::open(&root.path)?;
        ensure!(anchor.identity() == root.identity, AuthorityChanged);
        let safe = SafeRoot::open(&root.path)?;
        anchor.check()?;
        Ok(Self { safe, anchor })
    }

    pub(crate) fn check(&self) -> Result<()> {
        self.anchor.check()?;
        ensure!(self.safe.same_root(&self.safe)?, AuthorityChanged);
        Ok(())
    }

    pub(crate) fn metadata(
        &self,
        relative: Option<&str>,
        expected: Option<&FileStamp>,
    ) -> Result<NativeMetadata> {
        self.anchor.metadata(relative, expected)
    }

    pub(crate) fn is_inside(&self, base: &Self) -> Result<bool> {
        self.check()?;
        base.check()?;
        Ok(self.anchor.inside(&base.anchor))
    }

    pub(crate) fn root_stamp(&self) -> Result<FileStamp> {
        self.anchor.root_stamp()
    }
}

/// Filesystem qualification is additional to the caller's native watcher/gap
/// epochs. Unknown or cross-device semantics cannot reuse cached content hashes.
pub(crate) fn can_reuse_content_cache(roots: &[ApprovedRoot], previous: &Snapshot) -> Result<bool> {
    if !previous.content_captured {
        return Ok(false);
    }
    qualified_change_stamps(roots, previous)
}

pub(crate) fn qualified_change_stamps(roots: &[ApprovedRoot], previous: &Snapshot) -> Result<bool> {
    for root in roots {
        let pinned = PinnedRoot::open(root)?;
        if !pinned.anchor.trusted_change_stamps()? {
            return Ok(false);
        }
        if previous
            .nodes
            .values()
            .filter(|node| node.root_id == root.id)
            .any(|node| {
                node.stamp
                    .as_ref()
                    .is_none_or(|stamp| stamp.device != root.identity.device)
            })
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn approve_root_identity(
    path: &Path,
    policy: &TrackingPolicy,
    manual_leaves: bool,
) -> Result<RootIdentity> {
    check_policy(path, policy, manual_leaves)?;
    pin_identity(path)
}

#[derive(Clone, Copy)]
pub(crate) enum CandidateScope {
    Tree,
    SelectedLeaves,
}

/// Candidate identity/provenance only, NOT content/index/grant authority.
/// Every retained normalized root still requires check_policy()'s complete
/// native anti-alias proof before indexing or granting it.
pub(crate) fn pin_candidate_identity(
    path: &Path,
    policy: &TrackingPolicy,
    scope: CandidateScope,
) -> Result<RootIdentity> {
    check_policy_mode(
        path,
        policy,
        matches!(scope, CandidateScope::SelectedLeaves),
        false,
    )?;
    pin_identity(path)
}

fn pin_identity(path: &Path) -> Result<RootIdentity> {
    let anchor = anchor::Anchor::open(path)?;
    let safe = SafeRoot::open(path)?;
    anchor.check()?;
    ensure!(safe.same_root(&safe)?, AuthorityChanged);
    Ok(anchor.identity())
}

pub(crate) fn check_policy(
    path: &Path,
    policy: &TrackingPolicy,
    manual_leaves: bool,
) -> Result<()> {
    check_policy_mode(path, policy, manual_leaves, true)
}

fn check_policy_mode(
    path: &Path,
    policy: &TrackingPolicy,
    manual_leaves: bool,
    full_audit: bool,
) -> Result<()> {
    validate_absolute(path)?;
    for component in path.components() {
        if let std::path::Component::Normal(text) = component {
            ensure!(
                !is_secret_component(text.to_str().context("non-UTF8 root component")?),
                "repository/cache/credential/key roots are excluded"
            );
        }
    }
    let safe = PolicyRootFailure::new(
        path,
        None,
        InspectionSide::Selected,
        "pin_policy_selected_root",
    )
    .run(policy, || SafeRoot::open(path))?;
    let anchor = PolicyRootFailure::new(
        path,
        None,
        InspectionSide::Selected,
        "pin_policy_selected_anchor",
    )
    .run(policy, || anchor::Anchor::open(path))?;
    for denied in std::iter::once(&policy.data_dir).chain(policy.excluded_paths.iter()) {
        ensure!(
            !path.starts_with(denied) && (manual_leaves || !denied.starts_with(path)),
            ScopeGrantViolation(
                "selected root overlaps excluded QuickSave/repository/config/key material"
            )
        );
        if manual_leaves || !full_audit {
            // No recursive scan of unapproved siblings. The actual selected
            // leaves are opened as regular files only, never directories.
            let excluded = match PolicyRootFailure::new(
                path,
                Some(denied),
                InspectionSide::Protected,
                "pin_policy_protected_anchor",
            )
            .run(policy, || anchor::Anchor::open(denied))
            {
                Ok(excluded) => excluded,
                Err(error) if is_missing(&error) => continue,
                Err(error) => return Err(error),
            };
            ensure!(
                !anchor.inside(&excluded) && (manual_leaves || !excluded.inside(&anchor)),
                ScopeGrantViolation(
                    "selected native root/parent has a forbidden protected ancestor relationship"
                )
            );
            PolicyRootFailure::new(
                path,
                Some(denied),
                InspectionSide::Protected,
                "verify_policy_protected_anchor",
            )
            .run(policy, || excluded.check())?;
        } else {
            let excluded = match PolicyRootFailure::new(
                path,
                Some(denied),
                InspectionSide::Protected,
                "pin_policy_protected_root",
            )
            .run(policy, || SafeRoot::open(denied))
            {
                Ok(excluded) => excluded,
                Err(error) if is_missing(&error) => continue,
                Err(error) => return Err(error),
            };
            let overlap = PolicyRootFailure::new(
                path,
                Some(denied),
                InspectionSide::Both,
                "inspect_policy_overlap",
            )
            .run(policy, || safe.overlaps_for_approval(&excluded))?;
            ensure!(
                !overlap,
                ScopeGrantViolation("selected native root aliases an excluded root")
            );
        }
    }
    PolicyRootFailure::new(
        path,
        None,
        InspectionSide::Selected,
        "verify_policy_selected_anchor",
    )
    .run(policy, || anchor.check())?;
    Ok(())
}

fn stopped(stop: &AtomicBool) -> Result<()> {
    ensure!(!stop.load(Ordering::Acquire), "tracking worker is stopping");
    Ok(())
}

/// Hashes at most a fixed buffer at a time, checking stop and source identity.
#[cfg(test)]
pub(crate) fn capture(
    roots: &[ApprovedRoot],
    previous: Option<&Snapshot>,
    force_hash: bool,
    policy: &TrackingPolicy,
    stop: &AtomicBool,
) -> Result<Snapshot> {
    capture_index(
        roots,
        previous,
        force_hash,
        true,
        policy,
        stop,
        &IoCounters::default(),
    )
}

/// Metadata-only inventory never reads payload bytes. Content hashing is an
/// explicit capture operation, not a side effect of status or UI pagination.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_index(
    roots: &[ApprovedRoot],
    previous: Option<&Snapshot>,
    force_hash: bool,
    hash_content: bool,
    policy: &TrackingPolicy,
    stop: &AtomicBool,
    counters: &IoCounters,
) -> Result<Snapshot> {
    let mut snapshot = Snapshot {
        content_captured: hash_content
            || (!force_hash && previous.is_some_and(|previous| previous.content_captured)),
        ..Snapshot::default()
    };
    let mut path_bytes = 0_usize;
    let mut pinned = Vec::new();
    let mut tree_entries = Vec::new();
    for root in roots {
        stopped(stop)?;
        let handle =
            RootContext::approved(root, None, "pin_root").run(policy, || PinnedRoot::open(root))?;
        if let Some(leaves) = &root.allowed_files {
            for leaf in leaves {
                stopped(stop)?;
                let observed = if hash_content {
                    RootContext::approved(root, Some(leaf), "open_payload").run(policy, || {
                        handle
                            .safe
                            .read_file(leaf)
                            .map(|(file, stamp)| (Some(file), stamp))
                    })
                } else {
                    RootContext::approved(root, Some(leaf), "observe_file_metadata")
                        .run(policy, || {
                            handle.safe.file_metadata(leaf).map(|stamp| (None, stamp))
                        })
                };
                match observed {
                    Ok(opened) => {
                        add_file(
                            &mut snapshot,
                            &mut path_bytes,
                            root,
                            &handle,
                            leaf,
                            opened,
                            previous,
                            force_hash,
                            hash_content,
                            policy,
                            stop,
                            counters,
                        )?;
                    }
                    Err(error) if is_missing(&error) => {} // Absence is compared to the baseline.
                    Err(error) => return Err(error),
                }
            }
            tree_entries.push(None);
        } else {
            let mut metadata = RootContext::approved(root, None, "read_root_metadata")
                .run(policy, || handle.metadata(None, None))?;
            metadata.retain_read_time(
                previous.and_then(|snapshot| snapshot.root_metadata.get(&root.id)),
            );
            snapshot.root_metadata.insert(root.id.clone(), metadata);
            snapshot.root_stamps.insert(
                root.id.clone(),
                RootContext::approved(root, None, "read_root_stamp")
                    .run(policy, || handle.root_stamp())?,
            );
            counters.fs_walks.fetch_add(1, Ordering::Relaxed);
            let entries = RootContext::approved(root, None, "enumerate_metadata")
                .run(policy, || handle.safe.metadata_entries())?;
            counters
                .metadata_nodes
                .fetch_add(entries.len() as u64, Ordering::Relaxed);
            ensure!(
                entries.len() <= MAX_FILES.saturating_sub(snapshot.nodes.len()),
                "tracking entry bound exceeded"
            );
            for entry in &entries {
                stopped(stop)?;
                ensure!(
                    !entry.relative_path.split('/').any(is_secret_component),
                    "tracked tree contains excluded repository/cache/key material; select narrower roots"
                );
                match entry.kind {
                    EntryKind::File => {
                        let opened = if hash_content {
                            let (file, stamp) = RootContext::approved(
                                root,
                                Some(&entry.relative_path),
                                "open_payload",
                            )
                            .run(policy, || handle.safe.read_file(&entry.relative_path))?;
                            ensure!(
                                stamp == entry.stamp,
                                "file changed after native enumeration"
                            );
                            Some(file)
                        } else {
                            None
                        };
                        add_file(
                            &mut snapshot,
                            &mut path_bytes,
                            root,
                            &handle,
                            &entry.relative_path,
                            (opened, entry.stamp.clone()),
                            previous,
                            force_hash,
                            hash_content,
                            policy,
                            stop,
                            counters,
                        )?;
                    }
                    EntryKind::Directory | EntryKind::Symlink => {
                        reserve_path(&snapshot, &mut path_bytes, &entry.relative_path)?;
                        let link = if entry.kind == EntryKind::Symlink {
                            let link = entry
                                .link
                                .as_ref()
                                .context("native link lacks target evidence")?;
                            RootContext::approved(
                                root,
                                Some(&entry.relative_path),
                                "verify_link_metadata",
                            )
                            .run(policy, || {
                                handle.safe.verify_link(&entry.relative_path, link)
                            })?;
                            Some(link.clone())
                        } else {
                            ensure!(entry.link.is_none(), "directory has invalid link metadata");
                            None
                        };
                        let mut metadata = RootContext::approved(
                            root,
                            Some(&entry.relative_path),
                            "read_required_metadata",
                        )
                        .run(policy, || {
                            handle.metadata(Some(&entry.relative_path), Some(&entry.stamp))
                        })?;
                        metadata.retain_read_time(
                            previous
                                .and_then(|snapshot| {
                                    snapshot
                                        .nodes
                                        .get(&crate::file_id(&root.id, &entry.relative_path))
                                })
                                .and_then(|node| node.metadata.as_ref()),
                        );
                        let node = Node {
                            root_id: root.id.clone(),
                            path: entry.relative_path.clone(),
                            directory: entry.kind == EntryKind::Directory,
                            size: 0,
                            stamp: Some(entry.stamp.clone()),
                            hash: None,
                            link,
                            metadata: Some(metadata),
                        };
                        ensure!(
                            snapshot.nodes.insert(node.id(), node).is_none(),
                            "duplicate native node"
                        );
                    }
                }
            }
            tree_entries.push(Some(entries));
        }
        handle.check()?;
        pinned.push(handle);
    }
    // A second exact listing detects deletions/additions/renames during the pass.
    // Manual files never enumerate or read neighboring, unapproved files.
    for ((root, handle), entries) in roots.iter().zip(&pinned).zip(tree_entries) {
        stopped(stop)?;
        if let Some(before) = entries {
            counters.fs_walks.fetch_add(1, Ordering::Relaxed);
            let after = RootContext::approved(root, None, "verify_namespace")
                .run(policy, || handle.safe.metadata_entries())?;
            ensure!(after == before, "source tree changed during reconciliation");
            let metadata = RootContext::approved(root, None, "verify_root_metadata")
                .run(policy, || handle.metadata(None, None))?;
            ensure!(
                snapshot.root_metadata.get(&root.id) == Some(&metadata),
                "source root ownership/permissions changed during reconciliation"
            );
            let stamp = RootContext::approved(root, None, "verify_root_stamp")
                .run(policy, || handle.root_stamp())?;
            ensure!(
                snapshot.root_stamps.get(&root.id) == Some(&stamp),
                "source root namespace/timestamps changed during reconciliation"
            );
        } else {
            for leaf in root.allowed_files.as_ref().unwrap() {
                let id = crate::file_id(&root.id, leaf);
                if !snapshot.nodes.contains_key(&id) {
                    match RootContext::approved(root, Some(leaf), "verify_absent_manual_metadata")
                        .run(policy, || handle.safe.file_metadata(leaf))
                    {
                        Err(error) if is_missing(&error) => {}
                        Err(error) => return Err(error),
                        Ok(_) => bail!("manual file appeared during reconciliation"),
                    }
                }
            }
        }
        for node in snapshot
            .nodes
            .values()
            .filter(|node| node.root_id == root.id)
        {
            stopped(stop)?;
            if let Some(link) = &node.link {
                RootContext::approved(root, Some(&node.path), "verify_link_metadata")
                    .run(policy, || handle.safe.verify_link(&node.path, link))?;
            } else if !node.directory {
                let stamp = node.stamp.as_ref().context("file stamp is missing")?;
                verify_regular(root, handle, &node.path, stamp, hash_content, policy)?;
            }
            let metadata =
                RootContext::approved(root, Some(&node.path), "verify_required_metadata")
                    .run(policy, || {
                        handle.metadata(Some(&node.path), node.stamp.as_ref())
                    })?;
            ensure!(
                node.metadata.as_ref() == Some(&metadata),
                "source native ownership/permissions changed during reconciliation"
            );
        }
        RootContext::approved(root, None, "verify_root_identity").run(policy, || handle.check())?;
    }
    snapshot.validate(roots)?;
    // Establish the serialized-metadata bound before any service can enqueue a
    // capture which could never have a durable tracking baseline.
    snapshot.identity()?;
    Ok(snapshot)
}

fn reserve_path(snapshot: &Snapshot, path_bytes: &mut usize, path: &str) -> Result<()> {
    validate_relative(path)?;
    ensure!(
        snapshot.nodes.len() < MAX_FILES,
        "tracking entry bound exceeded"
    );
    *path_bytes = path_bytes
        .checked_add(path.len())
        .context("path count overflow")?;
    ensure!(
        *path_bytes <= MAX_PATH_BYTES,
        "tracking path-memory bound exceeded"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_file(
    snapshot: &mut Snapshot,
    path_bytes: &mut usize,
    root: &ApprovedRoot,
    handle: &PinnedRoot,
    relative: &str,
    (mut file, stamp): (Option<File>, quicksave_platform::FileStamp),
    previous: Option<&Snapshot>,
    force_hash: bool,
    hash_content: bool,
    policy: &TrackingPolicy,
    stop: &AtomicBool,
    counters: &IoCounters,
) -> Result<()> {
    reserve_path(snapshot, path_bytes, relative)?;
    ensure!(
        stamp.size <= policy.max_file_bytes,
        "file exceeds configured streaming bound"
    );
    let id = crate::file_id(&root.id, relative);
    let cached = previous
        .and_then(|s| s.nodes.get(&id))
        .filter(|old| !force_hash && old.stamp.as_ref() == Some(&stamp))
        .and_then(|old| old.hash.clone());
    let hash = if let Some(hash) = cached {
        Some(hash)
    } else if !hash_content {
        None
    } else {
        let file = file
            .as_mut()
            .context("actual content capture has no readable native file handle")?;
        let mut hash = blake3::Hasher::new();
        let mut buffer = [0_u8; 128 * 1024];
        let mut total = 0_u64;
        loop {
            stopped(stop)?;
            let read = file.read(&mut buffer).map_err(|error| {
                RootContext::approved(root, Some(relative), "read_payload").attach(error.into())
            })?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .context("source size overflow")?;
            ensure!(
                total <= stamp.size && total <= policy.max_file_bytes,
                "source grew during reconciliation"
            );
            hash.update(&buffer[..read]);
            counters
                .bytes_read
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        ensure!(total == stamp.size, "source shrank during reconciliation");
        counters.files_hashed.fetch_add(1, Ordering::Relaxed);
        Some(hash.finalize().to_hex().to_string())
    };
    verify_regular(root, handle, relative, &stamp, hash_content, policy)?;
    handle.check()?;
    let mut metadata = RootContext::approved(root, Some(relative), "read_required_metadata")
        .run(policy, || handle.metadata(Some(relative), Some(&stamp)))?;
    metadata.retain_read_time(
        previous
            .and_then(|snapshot| snapshot.nodes.get(&id))
            .and_then(|node| node.metadata.as_ref()),
    );
    let node = Node {
        root_id: root.id.clone(),
        path: relative.to_owned(),
        directory: false,
        size: stamp.size,
        stamp: Some(stamp),
        hash,
        link: None,
        metadata: Some(metadata),
    };
    snapshot.nodes.insert(id, node);
    Ok(())
}

fn verify_regular(
    root: &ApprovedRoot,
    handle: &PinnedRoot,
    relative: &str,
    before: &FileStamp,
    hash_content: bool,
    policy: &TrackingPolicy,
) -> Result<()> {
    RootContext::approved(
        root,
        Some(relative),
        if hash_content {
            "verify_payload_stamp"
        } else {
            "verify_file_metadata"
        },
    )
    .run(policy, || {
        if hash_content {
            handle.safe.verify_file(relative, before)
        } else {
            ensure!(
                handle.safe.file_metadata(relative)? == *before,
                "native metadata-only file identity/size/write/change stamp changed"
            );
            Ok(())
        }
    })
}

fn is_missing(error: &anyhow::Error) -> bool {
    crate::diagnostics::os_error(error) == Some(2)
        || error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        })
}

pub(crate) fn save_baseline(
    snapshot: &Snapshot,
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
    policy: &TrackingPolicy,
) -> Result<BaselineReference> {
    snapshot.validate_content(&record.roots)?;
    let name = format!("baseline-{}.json", uuid::Uuid::new_v4());
    let root = SafeRoot::open(&policy.baseline_dir())?;
    let mut hash = blake3::Hasher::new();
    root.write_new(&name, |file| {
        let writer = BoundedHashWriter {
            file,
            hash: &mut hash,
            written: 0,
        };
        serde_json::to_writer(writer, snapshot).context("write bounded tracking baseline")
    })?;
    let hash = hash.finalize().to_hex().to_string();
    let grant = store.issue_grant("tracking_baseline", &record.baseline_scope(&name, &hash))?;
    ensure!(
        store.verify_grant(
            "tracking_baseline",
            &record.baseline_scope(&name, &hash),
            &grant
        )?,
        "store did not issue an authenticated tracking baseline sidecar"
    );
    Ok(BaselineReference { name, hash, grant })
}

pub(crate) fn load_baseline(
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
    policy: &TrackingPolicy,
) -> Result<Option<Snapshot>> {
    let Some(reference) = &record.baseline else {
        return Ok(None);
    };
    validate_relative(&reference.name)?;
    ensure!(
        !reference.name.contains('/'),
        "invalid baseline sidecar reference"
    );
    ensure!(
        store.verify_grant(
            "tracking_baseline",
            &record.baseline_scope(&reference.name, &reference.hash),
            &reference.grant,
        )?,
        "tracking baseline authority is invalid or revoked"
    );
    let root = SafeRoot::open(&policy.baseline_dir())?;
    let (file, stamp) = root.read_file(&reference.name)?;
    ensure!(
        stamp.size <= MAX_BASELINE_BYTES,
        "tracking baseline exceeds metadata guard"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BASELINE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.size,
        "tracking baseline size changed"
    );
    ensure!(
        blake3::hash(&bytes).to_hex().as_str() == reference.hash,
        "tracking baseline integrity check failed"
    );
    root.verify_file(&reference.name, &stamp)?;
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    snapshot.validate_content(&record.roots)?;
    Ok(Some(snapshot))
}

struct BoundedHashWriter<'a> {
    file: &'a mut File,
    hash: &'a mut blake3::Hasher,
    written: u64,
}
impl Write for BoundedHashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("tracking baseline metadata size overflow"))?;
        if next > MAX_BASELINE_BYTES {
            return Err(std::io::Error::other(
                "tracking baseline exceeds metadata guard",
            ));
        }
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.written = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub(crate) fn root_request(root: &ApprovedRoot) -> Value {
    let mut value = root.authority();
    if let Some(source) = &root.source {
        value["source"] = source.clone();
    }
    value
}
