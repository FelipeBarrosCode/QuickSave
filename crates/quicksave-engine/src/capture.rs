// SPDX-License-Identifier: GPL-3.0-only

use std::{io::Read, path::Path};

use anyhow::{ensure, Context, Result};
use chrono::{SecondsFormat, Utc};
use quicksave_content::{chunk_reader, hash, RepositoryKey};
use quicksave_platform::{FileStamp, SafeRoot};
use serde_json::Value;

use crate::{format::*, repository::Repository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeShape {
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
}

pub(crate) fn tree_shape(root: &SafeRoot) -> Result<Vec<TreeShape>> {
    let entries = root.entries()?;
    ensure!(
        entries.len() <= MAX_TREE_ENTRIES,
        "source tree entry limit exceeded"
    );
    let mut tree: Vec<_> = entries
        .into_iter()
        .map(|entry| TreeShape {
            path: entry.relative_path,
            is_directory: entry.is_directory,
            size: if entry.is_directory { 0 } else { entry.size },
        })
        .collect();
    tree.sort_by(|left, right| left.path.cmp(&right.path));
    // Use exactly the same path and tree validation for capture and restore.
    let placeholder = format!("blake3:{}", "0".repeat(64));
    let nodes: Vec<_> = tree
        .iter()
        .map(|entry| {
            if entry.is_directory {
                Node::Directory {
                    path: entry.path.clone(),
                }
            } else {
                Node::File {
                    path: entry.path.clone(),
                    index: placeholder.clone(),
                    hash: placeholder.clone(),
                    size: entry.size,
                }
            }
        })
        .collect();
    validate_nodes(&nodes).context("source tree has unsupported paths or aliases")?;
    Ok(tree)
}

pub(crate) fn backup(repository: &Path, source: &Path, key: &RepositoryKey) -> Result<Value> {
    backup_with_validation_hook(repository, source, key, || Ok(()))
}

/// A private synchronization point makes source-change tests deterministic.
/// Production never accepts a callback from an untrusted caller.
pub(crate) fn backup_with_validation_hook(
    repository_path: &Path,
    source_path: &Path,
    key: &RepositoryKey,
    before_validation: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let repository_path = absolute_root(repository_path)?;
    let repository = Repository::open(&repository_path, key)?;
    let source_path = absolute_root(source_path)?;
    reject_overlap(&repository_path, &source_path)?;
    let source = SafeRoot::open(&source_path).context("cannot open approved source directory")?;
    ensure!(
        !repository.root.overlaps(&source)?,
        "repository and source roots must not overlap, including native directory aliases"
    );
    quicksave_platform::ensure_private_directory(&repository_path)
        .context("backup requires a private repository directory")?;
    let _writer = repository.lock_writer()?;
    repository.entries()?;
    let initial_tree = tree_shape(&source)?;
    let mut nodes = Vec::with_capacity(initial_tree.len());
    let mut stamps: Vec<(String, FileStamp)> = Vec::new();
    let mut summary = Summary::default();

    for entry in &initial_tree {
        if entry.is_directory {
            summary.total_directories += 1;
            nodes.push(Node::Directory {
                path: entry.path.clone(),
            });
            continue;
        }
        ensure!(
            entry.size <= MAX_FILE_BYTES,
            "source file exceeds capture size limit"
        );
        let (file, stamp) = source.read_file(&entry.path)?;
        let mut emitted = 0_usize;
        let (file_hash, size, chunks) =
            chunk_reader(file.take(MAX_FILE_BYTES + 1), |chunk, bytes| {
                emitted += 1;
                ensure!(
                    emitted <= MAX_CHUNKS_PER_FILE,
                    "per-file chunk index limit exceeded"
                );
                ensure!(
                    !bytes.is_empty()
                        && bytes.len() <= MAX_CHUNK_BYTES
                        && bytes.len() as u64 == chunk.size
                        && hash(bytes) == chunk.hash,
                    "content layer emitted an invalid chunk"
                );
                let published = repository.store_immutable(
                    &object_path(&chunk.hash)?,
                    "chunk",
                    &chunk.hash,
                    bytes,
                    MAX_CHUNK_BYTES,
                )?;
                if published == 0 {
                    summary.reused_chunks = summary
                        .reused_chunks
                        .checked_add(1)
                        .context("reused chunk count overflow")?;
                } else {
                    summary.new_chunks = summary
                        .new_chunks
                        .checked_add(1)
                        .context("new chunk count overflow")?;
                    summary.new_bytes = summary
                        .new_bytes
                        .checked_add(published)
                        .context("new byte count overflow")?;
                    summary.new_logical_chunk_bytes = summary
                        .new_logical_chunk_bytes
                        .checked_add(chunk.size)
                        .context("new logical chunk byte count overflow")?;
                }
                Ok(())
            })
            .with_context(|| format!("cannot capture source file {:?}", entry.path))?;
        ensure!(
            size == entry.size && size <= MAX_FILE_BYTES,
            "source file changed size during capture"
        );
        ensure!(
            chunks.len() == emitted && chunks.len() <= MAX_CHUNKS_PER_FILE,
            "content layer returned an inconsistent bounded index"
        );
        source
            .verify_file(&entry.path, &stamp)
            .with_context(|| format!("source file changed during capture: {:?}", entry.path))?;
        let index = FileIndex {
            format: FORMAT.to_owned(),
            version: VERSION,
            repository_id: repository.id.clone(),
            hash: file_hash.clone(),
            size,
            chunks: chunks
                .into_iter()
                .map(|chunk| ChunkRef {
                    hash: chunk.hash,
                    size: chunk.size,
                })
                .collect(),
        };
        validate_index(&index, &repository.id)?;
        let index_bytes = serialize_bounded(&index, MAX_INDEX_BYTES)?;
        let index_id = hash(&index_bytes);
        repository.store_immutable(
            &index_path(&index_id)?,
            "file-index",
            &index_id,
            &index_bytes,
            MAX_INDEX_BYTES,
        )?;
        nodes.push(Node::File {
            path: entry.path.clone(),
            index: index_id,
            hash: file_hash,
            size,
        });
        stamps.push((entry.path.clone(), stamp));
        summary.total_files += 1;
        summary.logical_bytes = summary
            .logical_bytes
            .checked_add(size)
            .context("logical byte count overflow")?;
    }

    before_validation()?;
    validate_source(&source, &initial_tree, &stamps)?;
    let commit = Commit {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: repository.id.clone(),
        snapshot_id: uuid::Uuid::new_v4().to_string(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        capture_consistency: CONSISTENCY.to_owned(),
        summary,
        nodes,
    };
    // Referenced chunks and per-file indexes are already synced, authenticated
    // immutable objects. This final native no-clobber publication is the commit
    // point; there is no mutable LATEST pointer or automatic generation deletion.
    repository.publish_commit(&commit)?;
    Ok(commit.summary_json())
}

fn validate_source(
    source: &SafeRoot,
    initial_tree: &[TreeShape],
    stamps: &[(String, FileStamp)],
) -> Result<()> {
    ensure!(
        tree_shape(source)? == initial_tree,
        "source tree changed during capture; no snapshot was committed"
    );
    for (path, stamp) in stamps {
        source
            .verify_file(path, stamp)
            .with_context(|| format!("source file changed before commit: {path:?}"))?;
    }
    Ok(())
}
