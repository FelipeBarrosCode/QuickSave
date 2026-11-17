// SPDX-License-Identifier: GPL-3.0-only

use std::{io::Write, path::Path};

use anyhow::{ensure, Context, Result};
use quicksave_content::RepositoryKey;
use quicksave_platform::{FileStamp, SafeRoot};
use serde_json::{json, Value};

use crate::{
    capture::{tree_shape, TreeShape},
    format::*,
    repository::Repository,
};

pub(crate) fn restore(
    repository_path: &Path,
    snapshot_id: &str,
    destination_path: &Path,
    key: &RepositoryKey,
) -> Result<Value> {
    restore_with_write_hook(repository_path, snapshot_id, destination_path, key, || {
        Ok(())
    })
}

pub(crate) fn restore_with_write_hook(
    repository_path: &Path,
    snapshot_id: &str,
    destination_path: &Path,
    key: &RepositoryKey,
    after_preflight: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let repository_path = absolute_root(repository_path)?;
    let repository = Repository::open(&repository_path, key)?;
    // Identity authentication happens even before rejecting an invalid supplied
    // ID or touching a destination, so a wrong key is never a write-side probe.
    validate_uuid(snapshot_id)?;
    let destination_path = absolute_root(destination_path)?;
    reject_overlap(&repository_path, &destination_path)?;
    let destination = SafeRoot::open(&destination_path)
        .context("restore requires an existing approved directory")?;
    ensure!(
        !repository.root.overlaps(&destination)?,
        "repository and destination roots must not overlap, including native directory aliases"
    );
    ensure!(
        destination.entries()?.is_empty(),
        "restore destination must be empty; no existing entries were changed"
    );
    repository.entries()?;
    let commit = repository.load_commit(snapshot_id)?;

    // Complete preflight is intentionally conservative: authenticate every
    // required chunk and reconstruct each file's BLAKE3 before the first write.
    // Work is streaming per file, never a whole-payload buffer or unbounded
    // cross-file manifest/chunk cache.
    for node in &commit.nodes {
        if let Node::File {
            index, hash, size, ..
        } = node
        {
            let index = repository.load_index(index)?;
            ensure!(
                index.hash == *hash && index.size == *size,
                "file index does not match snapshot entry"
            );
            verify_file_content(&repository, &index)?;
        }
    }
    ensure!(
        destination.entries()?.is_empty(),
        "destination changed during preflight; no restore entries were created"
    );
    after_preflight()?;

    let operation_id = uuid::Uuid::new_v4().to_string();
    let mut attempted_writes = false;
    let result = (|| -> Result<()> {
        let mut directories: Vec<_> = commit
            .nodes
            .iter()
            .filter(|node| node.is_directory())
            .map(Node::path)
            .collect();
        directories.sort_by(|left, right| {
            left.split('/')
                .count()
                .cmp(&right.split('/').count())
                .then_with(|| left.cmp(right))
        });
        for directory in directories {
            attempted_writes = true;
            destination.create_dir(directory)?;
        }
        let mut stamps: Vec<(String, FileStamp)> = Vec::new();
        for node in &commit.nodes {
            let Node::File {
                path,
                index,
                hash,
                size,
            } = node
            else {
                continue;
            };
            let index = repository.load_index(index)?;
            ensure!(
                index.hash == *hash && index.size == *size,
                "file index changed after restore preflight"
            );
            attempted_writes = true;
            destination.write_new(path, |file| {
                let mut hasher = blake3::Hasher::new();
                let mut length = 0_u64;
                for chunk in &index.chunks {
                    let bytes = repository.load_chunk(chunk)?;
                    hasher.update(&bytes);
                    length = length
                        .checked_add(bytes.len() as u64)
                        .context("restore byte count overflow")?;
                    file.write_all(&bytes)?;
                }
                ensure!(
                    length == *size && format!("blake3:{}", hasher.finalize().to_hex()) == *hash,
                    "restored file length or BLAKE3 integrity check failed"
                );
                Ok(())
            })?;
            let (_, stamp) = destination.read_file(path)?;
            stamps.push((path.clone(), stamp));
        }
        let mut expected: Vec<_> = commit
            .nodes
            .iter()
            .map(|node| TreeShape {
                path: node.path().to_owned(),
                is_directory: node.is_directory(),
                size: match node {
                    Node::File { size, .. } => *size,
                    Node::Directory { .. } => 0,
                },
            })
            .collect();
        expected.sort_by(|left, right| left.path.cmp(&right.path));
        ensure!(
            tree_shape(&destination)? == expected,
            "destination tree changed during restore"
        );
        for (path, stamp) in stamps {
            destination.verify_file(&path, &stamp)?;
        }
        Ok(())
    })();
    if attempted_writes {
        result.with_context(|| {
            format!(
                "restore operation {operation_id} failed; partial new destination entries \
                 were retained for inspection; no pre-existing entries were overwritten or deleted"
            )
        })?;
    } else {
        result?;
    }
    Ok(json!({
        "operationId": operation_id,
        "id": snapshot_id,
        "snapshotId": snapshot_id,
        "repositoryId": repository.id,
        "createdAt": commit.created_at,
        "totalFiles": commit.summary.total_files,
        "totalDirectories": commit.summary.total_directories,
        "logicalBytes": commit.summary.logical_bytes,
        "state": "restored",
        "captureConsistency": CONSISTENCY,
        "preserved": "file-bytes-and-directory-tree",
        "destinationPolicy": "existing-empty-directory-no-overwrite",
    }))
}

fn verify_file_content(repository: &Repository<'_>, index: &FileIndex) -> Result<()> {
    let mut hasher = blake3::Hasher::new();
    let mut size = 0_u64;
    for chunk in &index.chunks {
        let bytes = repository.load_chunk(chunk)?;
        hasher.update(&bytes);
        size = size
            .checked_add(bytes.len() as u64)
            .context("restore preflight byte count overflow")?;
    }
    ensure!(
        size == index.size && format!("blake3:{}", hasher.finalize().to_hex()) == index.hash,
        "full-file BLAKE3 or length check failed during restore preflight"
    );
    Ok(())
}
