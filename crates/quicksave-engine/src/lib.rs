// SPDX-License-Identifier: GPL-3.0-only
//! Local, additive QuickSave repositories.
//!
//! This is a new QuickSave format, not a reader or writer of No Land repositories.
//! The content crate supplies the upstream-derived FastCDC/BLAKE3 algorithms.
//! Files are captured and revalidated individually, followed by an exact tree
//! check. This is **not** an application-atomic or volume snapshot.
//!
//! All repository, source, and destination I/O is through pinned `SafeRoot`
//! handles. Restores require an existing, approved empty directory. Failed
//! captures can leave unreachable immutable objects; failed restore writes are
//! retained for inspection, never cleaned up by deleting arbitrary paths.

#![forbid(unsafe_code)]

mod capture;
mod format;
mod repository;
mod restore;

use std::path::Path;

use anyhow::Result;
pub use quicksave_content::RepositoryKey;
use serde_json::Value;

/// Actual engine format/capture limits, independent of the platform walk limit.
///
/// These are bounded preview limits, not a throughput or platform-acceptance
/// claim. The metadata guard remains unchanged at 512 MiB.
pub fn limits() -> Value {
    serde_json::json!({
        "maxTreeEntries": format::MAX_TREE_ENTRIES,
        "maxTreePathBytes": format::MAX_TREE_PATH_BYTES,
        "maxCommitBytes": format::MAX_COMMIT_BYTES,
        "maxIndexBytes": format::MAX_INDEX_BYTES,
        "maxChunkBytes": format::MAX_CHUNK_BYTES,
        "maxFileBytes": format::MAX_FILE_BYTES,
        "maxChunksPerFile": format::MAX_CHUNKS_PER_FILE,
        "captureConsistency": format::CONSISTENCY,
    })
}

/// Initialize an empty local repository and return its new key.
///
/// This convenience API does not persist the key. Applications should generate
/// and durably save an external recovery key **first**, then call
/// [`initialize_with_key`], to avoid losing a newly initialized repository's key.
pub fn initialize(repository: &Path) -> Result<RepositoryKey> {
    let key = RepositoryKey::generate();
    initialize_with_key(repository, &key)?;
    Ok(key)
}

/// Initialize a new/empty repository with an already durably saved external key.
///
/// The key is never stored in the repository. Existing nonempty directories,
/// including No Land repositories, are refused. On failure, partial new entries
/// are retained rather than deleting user data.
pub fn initialize_with_key(repository: &Path, key: &RepositoryKey) -> Result<Value> {
    repository::initialize_with_key(repository, key)
}

/// Authenticate only the repository identity, without enumerating history or
/// accessing a source/destination. This does not mutate or grant another root.
pub fn verify_repository(repository: &Path, key: &RepositoryKey) -> Result<Value> {
    let path = format::absolute_root(repository)?;
    let repository = repository::Repository::open(&path, key)?;
    Ok(serde_json::json!({
        "id": repository.id,
        "repositoryId": repository.id,
        "format": format::FORMAT,
        "version": format::VERSION,
    }))
}

/// Capture a folder as a new immutable version. No source file is modified.
pub fn backup(repository: &Path, source: &Path, key: &RepositoryKey) -> Result<Value> {
    capture::backup(repository, source, key)
}

/// Read all authenticated immutable history commits, not a mutable latest pointer.
///
/// Returns a JSON array, ordered by creation time and snapshot ID. Each item has
/// `id`, `snapshotId`, `createdAt`, `totalFiles`, and `logicalBytes`.
/// Responses above 64 KiB fail explicitly; commits are never silently omitted.
pub fn snapshots(repository: &Path, key: &RepositoryKey) -> Result<Value> {
    repository::snapshots(repository, key)
}

/// Restore authenticated file bytes/directories into an existing empty directory.
///
/// All paths, indexes, and referenced chunks are authenticated and checked before
/// creating the first output entry. They are checked again during writing.
/// ACLs, extended attributes, original file modes, hardlink relationships,
/// application consistency, remote providers, and volume snapshots are not
/// implemented by this format.
pub fn restore(
    repository: &Path,
    snapshot_id: &str,
    destination: &Path,
    key: &RepositoryKey,
) -> Result<Value> {
    restore::restore(repository, snapshot_id, destination, key)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;
