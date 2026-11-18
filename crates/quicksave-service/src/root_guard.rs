// SPDX-License-Identifier: GPL-3.0-only
//! Service-owned no-follow native directory handles, retained past admission.

use crate::interfaces::SourceGuard;
use anyhow::{ensure, Result};
use serde_json::Value;
use std::sync::Arc;

// Matches the persisted Tracker/WorkspaceStore root schema, not a UI page size.
const MAX_APPROVED_ROOTS: usize = 48;

pub fn pin(record: &Value) -> Result<Arc<dyn SourceGuard>> {
    #[cfg(unix)]
    {
        Ok(Arc::new(unix::Pinned::open(record)?))
    }
    #[cfg(windows)]
    {
        Ok(Arc::new(windows::Pinned::open(record)?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = record;
        anyhow::bail!("Owned native source identity pinning is not supported on this platform")
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use quicksave_platform::SafeRoot;
    use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
    use std::{
        os::fd::OwnedFd,
        path::{Component, Path},
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity(u64, [u64; 2]);
    struct Edge {
        fd: OwnedFd,
        name: Option<String>,
        identity: Identity,
    }
    struct Root {
        edges: Vec<Edge>,
        safe: SafeRoot,
    }
    pub(super) struct Pinned(Vec<Root>);

    fn identity(stat: &Stat) -> Result<Identity> {
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
            "Approved root is no longer a real directory"
        );
        #[allow(clippy::unnecessary_cast)]
        Ok(Identity(stat.st_dev as u64, [stat.st_ino as u64, 0]))
    }

    impl Root {
        fn open(record: &Value) -> Result<Self> {
            let text = crate::boundary::text(record, "path", 32_768)?;
            crate::boundary::absolute(text)?;
            let expected: quicksave_state::NativeFileStampID =
                serde_json::from_value(record["identity"].clone())
                    .map_err(|_| anyhow::anyhow!("Persisted root has no native identity"))?;
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let first = open("/", flags, Mode::empty())?;
            let stamp = identity(&fstat(&first)?)?;
            let mut edges = vec![Edge {
                fd: first,
                name: None,
                identity: stamp,
            }];
            for component in Path::new(text).components() {
                if let Component::Normal(name) = component {
                    ensure!(
                        edges.len() <= 128,
                        "Native root exceeds the ancestor handle limit"
                    );
                    let name = name
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("Native root is not UTF-8"))?;
                    let fd = openat(&edges.last().unwrap().fd, name, flags, Mode::empty())?;
                    let stamp = identity(&fstat(&fd)?)?;
                    edges.push(Edge {
                        fd,
                        name: Some(name.to_owned()),
                        identity: stamp,
                    });
                }
            }
            ensure!(
                edges.last().unwrap().identity == Identity(expected.device, expected.file_id),
                "Native root was replaced since approval"
            );
            let root = Self {
                edges,
                safe: SafeRoot::open(Path::new(text))?,
            };
            root.verify()?;
            Ok(root)
        }

        fn verify(&self) -> Result<()> {
            for (index, edge) in self.edges.iter().enumerate() {
                ensure!(
                    identity(&fstat(&edge.fd)?)? == edge.identity,
                    "Pinned native root identity changed"
                );
                if let Some(name) = &edge.name {
                    ensure!(
                        identity(&statat(
                            &self.edges[index - 1].fd,
                            name.as_str(),
                            AtFlags::SYMLINK_NOFOLLOW
                        )?)? == edge.identity,
                        "Native root namespace edge changed"
                    );
                }
            }
            ensure!(
                self.safe.same_root(&self.safe)?,
                "Pinned source root changed"
            );
            Ok(())
        }
    }

    impl Pinned {
        pub(super) fn open(record: &Value) -> Result<Self> {
            let roots = record["roots"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Approved roots are missing"))?;
            ensure!(
                !roots.is_empty() && roots.len() <= MAX_APPROVED_ROOTS,
                "Approved root count is invalid"
            );
            Ok(Self(
                roots.iter().map(Root::open).collect::<Result<Vec<_>>>()?,
            ))
        }
    }
    impl SourceGuard for Pinned {
        fn verify(&self) -> Result<()> {
            for root in &self.0 {
                root.verify()?;
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use quicksave_platform::{RootIdentity, SafeRoot};
    use std::path::Path;

    pub(super) struct Pinned(Vec<(SafeRoot, RootIdentity)>);
    impl Pinned {
        pub(super) fn open(record: &Value) -> Result<Self> {
            let roots = record["roots"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Approved roots are missing"))?;
            ensure!(
                !roots.is_empty() && roots.len() <= MAX_APPROVED_ROOTS,
                "Approved root count is invalid"
            );
            let mut pinned = Vec::with_capacity(roots.len());
            for root in roots {
                let path = crate::boundary::text(root, "path", 32_768)?;
                crate::boundary::absolute(path)?;
                let expected: RootIdentity = serde_json::from_value(root["identity"].clone())?;
                // SafeRoot uses retained native ancestor handles, rejects every
                // reparse component and preserves the full 128-bit file ID.
                let held = SafeRoot::open(Path::new(path))?;
                ensure!(
                    held.identity()? == expected,
                    "The approved native root was replaced"
                );
                pinned.push((held, expected));
            }
            Ok(Self(pinned))
        }
    }
    impl SourceGuard for Pinned {
        fn verify(&self) -> Result<()> {
            for (root, expected) in &self.0 {
                ensure!(
                    root.identity()? == *expected && root.same_root(root)?,
                    "The pinned native root or its namespace changed"
                );
            }
            Ok(())
        }
    }
}
