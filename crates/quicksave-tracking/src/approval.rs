// SPDX-License-Identifier: GPL-3.0-only
//! Server-only native consent handoff. Never accept `_approvedPaths` from JS.

use crate::model::{validate_absolute, ApprovedRoot, RootIdentity, MAX_ROOTS};
use anyhow::{ensure, Context, Result};
use quicksave_platform::{FileStamp, SafeRoot};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    path: PathBuf,
    kind: String,
    identity: RootIdentity,
    #[serde(default)]
    stamp: Option<FileStamp>,
    #[serde(default)]
    parent_identity: Option<RootIdentity>,
}

enum Pin {
    Directory {
        root: SafeRoot,
        identity: RootIdentity,
    },
    File {
        parent: SafeRoot,
        parent_path: PathBuf,
        parent_identity: RootIdentity,
        leaf: String,
        _file: File,
        stamp: FileStamp,
    },
}

/// Owns all newly opened native handles until the tracking grant is persisted.
pub(crate) struct PreparedPaths {
    entries: BTreeMap<PathBuf, Pin>,
}

impl PreparedPaths {
    pub(crate) fn from_input(input: &Value) -> Result<Option<Self>> {
        let Some(value) = input.get("_approvedPaths") else {
            return Ok(None);
        };
        let entries = value
            .as_array()
            .context("native approved paths must be an array")?;
        ensure!(
            !entries.is_empty() && entries.len() <= 4096 + 2 * MAX_ROOTS,
            "native approval path count is invalid"
        );
        let mut pinned = BTreeMap::new();
        for value in entries {
            let proof: Wire = serde_json::from_value(value.clone())
                .context("native approved path proof is invalid")?;
            validate_absolute(&proof.path)?;
            let pin = match proof.kind.as_str() {
                "directory" => {
                    ensure!(
                        proof.stamp.is_none() && proof.parent_identity.is_none(),
                        "directory approval contains file-only proof fields"
                    );
                    let root = SafeRoot::open(&proof.path)?;
                    ensure!(
                        identity(&root)? == proof.identity,
                        "native-approved directory identity changed"
                    );
                    Pin::Directory {
                        root,
                        identity: proof.identity,
                    }
                }
                "file" => {
                    let stamp = proof
                        .stamp
                        .context("native file approval lacks the exact file stamp")?;
                    let parent_identity = proof
                        .parent_identity
                        .context("native file approval lacks the parent identity")?;
                    ensure!(
                        stamp.device == proof.identity.device
                            && stamp.file_id == proof.identity.file_id,
                        "native file stamp and identity disagree"
                    );
                    let parent_path = proof
                        .path
                        .parent()
                        .context("approved file has no parent")?
                        .to_owned();
                    let leaf = proof
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("approved file has no UTF-8 leaf")?
                        .to_owned();
                    let parent = SafeRoot::open(&parent_path)?;
                    ensure!(
                        identity(&parent)? == parent_identity,
                        "native-approved file parent changed"
                    );
                    let (file, current) = parent.read_file(&leaf)?;
                    ensure!(
                        current == stamp,
                        "native-approved file identity or contents changed"
                    );
                    parent.verify_file(&leaf, &stamp)?;
                    Pin::File {
                        parent,
                        parent_path,
                        parent_identity,
                        leaf,
                        _file: file,
                        stamp,
                    }
                }
                _ => anyhow::bail!("native approved path kind is invalid"),
            };
            ensure!(
                pinned.insert(proof.path, pin).is_none(),
                "duplicate native approved path"
            );
        }
        let prepared = Self { entries: pinned };
        prepared.verify()?;
        Ok(Some(prepared))
    }

    /// Exact add_files request plus its already signed previous software scope.
    /// A directory proof is never a substitute for a newly selected file proof.
    pub(crate) fn files(
        &self,
        requested: &BTreeSet<PathBuf>,
        scope: &[ApprovedRoot],
    ) -> Result<()> {
        let expected: BTreeSet<_> = requested
            .iter()
            .cloned()
            .chain(scope.iter().map(|root| root.path.clone()))
            .collect();
        ensure!(
            expected == self.entries.keys().cloned().collect(),
            "native approved paths do not exactly cover the requested files and existing roots"
        );
        for path in requested {
            ensure!(
                matches!(self.entries.get(path), Some(Pin::File { .. })),
                "every requested file requires its own native file proof"
            );
        }
        for root in scope {
            self.directory(&root.path, &root.identity)?;
        }
        self.verify()
    }

    /// Verify a new software scope without widening retained manual allowlists.
    /// `retained` is supplied only after verifying the old signed tracking grant.
    pub(crate) fn roots(&self, roots: &[ApprovedRoot], retained: &[ApprovedRoot]) -> Result<()> {
        for root in roots {
            if let Some(leaves) = &root.allowed_files {
                ensure!(
                    self.parent_covered(root),
                    "manual file parent has no matching native approval"
                );
                for leaf in leaves {
                    let path = root.path.join(leaf);
                    if let Some(Pin::File {
                        parent_identity, ..
                    }) = self.entries.get(&path)
                    {
                        ensure!(
                            *parent_identity == root.identity,
                            "approved file parent differs from pinned tracking root"
                        );
                    } else {
                        let retained_leaf = retained.iter().any(|old| {
                            old.path == root.path
                                && old.identity == root.identity
                                && old
                                    .allowed_files
                                    .as_ref()
                                    .is_some_and(|old| old.contains(leaf))
                        });
                        ensure!(
                            retained_leaf,
                            "new manual file lacks its exact native file proof"
                        );
                    }
                }
            } else {
                // A file's parentIdentity must not become a whole-tree grant.
                self.directory(&root.path, &root.identity)?;
            }
        }
        for old in retained {
            if !roots.iter().any(|root| root.path == old.path) {
                ensure!(
                    self.parent_covered(old),
                    "previous scope root is missing from native approval"
                );
            }
        }
        for (path, pin) in &self.entries {
            match pin {
                Pin::Directory { identity, .. } => {
                    let expected = roots
                        .iter()
                        .find(|root| &root.path == path)
                        .or_else(|| retained.iter().find(|root| &root.path == path))
                        .context("native approval contains an unexpected directory")?;
                    ensure!(
                        *identity == expected.identity,
                        "native directory proof differs from tracked identity"
                    );
                }
                Pin::File {
                    parent_path,
                    parent_identity,
                    leaf,
                    ..
                } => {
                    ensure!(
                        roots.iter().any(|root| {
                            root.path == *parent_path
                                && root.identity == *parent_identity
                                && root
                                    .allowed_files
                                    .as_ref()
                                    .is_some_and(|leaves| leaves.contains(leaf))
                        }),
                        "native approval contains an unexpected selected file"
                    );
                }
            }
        }
        self.verify()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        for pin in self.entries.values() {
            match pin {
                Pin::Directory {
                    root,
                    identity: expected,
                } => {
                    ensure!(
                        identity(root)? == *expected,
                        "native approved directory was replaced"
                    );
                }
                Pin::File {
                    parent,
                    parent_identity,
                    leaf,
                    stamp,
                    ..
                } => {
                    ensure!(
                        identity(parent)? == *parent_identity,
                        "native approved file parent was replaced"
                    );
                    parent.verify_file(leaf, stamp)?;
                }
            }
        }
        Ok(())
    }

    fn directory(&self, path: &Path, expected: &RootIdentity) -> Result<()> {
        let Some(Pin::Directory { identity, .. }) = self.entries.get(path) else {
            anyhow::bail!("requested root is missing its native directory proof");
        };
        ensure!(
            identity == expected,
            "native directory approval differs from the newly pinned root"
        );
        Ok(())
    }

    fn parent_covered(&self, root: &ApprovedRoot) -> bool {
        if let Some(Pin::Directory { identity, .. }) = self.entries.get(&root.path) {
            return identity == &root.identity;
        }
        self.entries.values().any(|pin| match pin {
            Pin::File {
                parent_path,
                parent_identity,
                ..
            } => parent_path == &root.path && parent_identity == &root.identity,
            _ => false,
        })
    }
}

fn identity(root: &SafeRoot) -> Result<RootIdentity> {
    let actual = root.identity()?;
    Ok(RootIdentity {
        device: actual.device,
        file_id: actual.file_id,
    })
}
