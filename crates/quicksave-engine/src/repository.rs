// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use quicksave_content::{hash, open, seal, RepositoryKey};
use quicksave_platform::SafeRoot;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::format::*;

pub(crate) struct Repository<'key> {
    pub root: SafeRoot,
    pub id: String,
    pub key: &'key RepositoryKey,
}

/// The lock is acquired on a native handle opened by SafeRoot, never by a
/// path-based OpenOptions call. Engine code never replaces this lock inode.
pub(crate) struct WriterLock {
    file: File,
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub(crate) fn initialize_with_key(repository: &Path, key: &RepositoryKey) -> Result<Value> {
    // The legacy local format requires durable private directory operations.
    // Windows' desktop-native adapter is not acceptance of that separate engine.
    // Refuse before creating even an empty directory on unsupported hosts.
    ensure!(
        cfg!(any(target_os = "macos", target_os = "linux")),
        "legacy local repository initialization is unsupported on this platform"
    );
    let path = absolute_root(repository)?;
    quicksave_platform::ensure_private_directory(&path).context(
        "repository must be a native private directory (0700 on Unix), without symlinks",
    )?;
    let root = SafeRoot::open(&path).context("cannot open private repository root")?;
    ensure!(
        root.entries()?.is_empty(),
        "initialization requires an empty directory; existing/No Land repositories are never adopted"
    );
    // SafeRoot's directory creation is private and durable. We never create a
    // repository by following symlinks or by using create_dir_all on raw paths.
    root.create_dir(NAMESPACE)?;
    root.create_dir(OBJECTS)?;
    root.create_dir(INDEXES)?;
    root.create_dir(COMMITS)?;
    root.write_new(LOCK_PATH, |file| {
        file.write_all(LOCK_BYTES)?;
        Ok(())
    })?;

    let repository_id = uuid::Uuid::new_v4().to_string();
    let check = KeyCheck {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: repository_id.clone(),
        purpose: "repository-key-authentication".to_owned(),
    };
    let check_bytes = serialize_bounded(&check, MAX_IDENTITY_BYTES)?;
    let identity = Identity {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: repository_id.clone(),
        key_check: seal(
            key,
            &context(&repository_id, "repository-identity", &repository_id),
            &check_bytes,
        )?,
    };
    let bytes = serialize_bounded(&identity, MAX_IDENTITY_BYTES)?;
    // Identity is published last. Earlier failures leave visibly incomplete,
    // nonempty directories, which cannot accidentally be reinitialized.
    root.write_new(IDENTITY_PATH, |file| {
        file.write_all(&bytes)?;
        Ok(())
    })?;
    Ok(json!({
        "repositoryId": repository_id,
        "format": FORMAT,
        "formatVersion": VERSION,
        "initialized": true,
        "keyStoredInRepository": false,
        "captureConsistency": CONSISTENCY,
    }))
}

impl<'key> Repository<'key> {
    pub fn open(path: &Path, key: &'key RepositoryKey) -> Result<Self> {
        let root = SafeRoot::open(path).context("cannot open approved repository root")?;
        // Authentication deliberately precedes namespace enumeration, writer
        // locking, source/destination access, and every repository mutation.
        let bytes = read_bounded(&root, IDENTITY_PATH, MAX_IDENTITY_BYTES).context(
            "not an authenticated QuickSave repository; No Land repositories are unsupported",
        )?;
        let identity: Identity =
            serde_json::from_slice(&bytes).context("invalid QuickSave repository identity")?;
        ensure!(
            identity.format == FORMAT && identity.version == VERSION,
            "unsupported repository format; only QuickSave.Local.Encrypted/v1 is accepted"
        );
        validate_uuid(&identity.repository_id)?;
        ensure!(
            identity.key_check.len() <= MAX_IDENTITY_BYTES,
            "oversized repository key check"
        );
        let plain = open(
            key,
            &context(
                &identity.repository_id,
                "repository-identity",
                &identity.repository_id,
            ),
            &identity.key_check,
        )
        .context("repository key authentication failed (wrong key or damaged identity)")?;
        ensure!(
            plain.len() <= MAX_IDENTITY_BYTES,
            "oversized decrypted key check"
        );
        let check: KeyCheck =
            serde_json::from_slice(&plain).context("invalid authenticated repository key check")?;
        ensure!(
            check.format == FORMAT
                && check.version == VERSION
                && check.repository_id == identity.repository_id
                && check.purpose == "repository-key-authentication",
            "authenticated repository identity mismatch"
        );
        Ok(Self {
            root,
            id: identity.repository_id,
            key,
        })
    }

    pub fn lock_writer(&self) -> Result<WriterLock> {
        let (file, stamp) = self.root.read_file(LOCK_PATH)?;
        FileExt::try_lock_exclusive(&file)
            .context("repository has an active writer, or native exclusive locking failed")?;
        let mut guard = WriterLock { file };
        let mut bytes = Vec::new();
        (&mut guard.file)
            .take((LOCK_BYTES.len() + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes == LOCK_BYTES,
            "repository writer lock file is invalid"
        );
        self.root.verify_file(LOCK_PATH, &stamp)?;
        Ok(guard)
    }

    /// Refuse foreign root-level namespaces, including old No Land metadata.
    /// Immutable objects and operation-private publication temporaries remain
    /// beneath `quicksave/`; readers ignore uncommitted ones.
    pub fn entries(&self) -> Result<Vec<quicksave_platform::Entry>> {
        let entries = self.root.entries()?;
        for entry in &entries {
            validate_relative(&entry.relative_path)?;
            ensure!(
                entry.relative_path == IDENTITY_PATH
                    || entry.relative_path == NAMESPACE
                    || entry.relative_path.starts_with("quicksave/"),
                "foreign repository metadata is forbidden; No Land metadata is unsupported"
            );
        }
        Ok(entries)
    }

    pub fn load_commit(&self, id: &str) -> Result<Commit> {
        let path = commit_path(id)?;
        let commit: Commit = self.load_json(&path, "snapshot-commit", id, MAX_COMMIT_BYTES)?;
        validate_commit(&commit, &self.id, id)?;
        Ok(commit)
    }

    pub fn load_index(&self, id: &str) -> Result<FileIndex> {
        let path = index_path(id)?;
        let plain = self.load_record(&path, "file-index", id, MAX_INDEX_BYTES)?;
        ensure!(hash(&plain) == id, "file index content identifier mismatch");
        let index: FileIndex =
            serde_json::from_slice(&plain).context("invalid authenticated per-file index")?;
        validate_index(&index, &self.id)?;
        Ok(index)
    }

    pub fn load_chunk(&self, chunk: &ChunkRef) -> Result<Vec<u8>> {
        ensure!(
            chunk.size > 0 && chunk.size <= MAX_CHUNK_BYTES as u64,
            "invalid referenced chunk length"
        );
        let path = object_path(&chunk.hash)?;
        let plain = self.load_record(&path, "chunk", &chunk.hash, MAX_CHUNK_BYTES)?;
        ensure!(
            plain.len() as u64 == chunk.size && hash(&plain) == chunk.hash,
            "chunk length or BLAKE3 integrity check failed"
        );
        Ok(plain)
    }

    pub fn load_record(
        &self,
        path: &str,
        kind: &str,
        id: &str,
        plain_limit: usize,
    ) -> Result<Vec<u8>> {
        ensure!(
            plain_limit <= MAX_METADATA_BYTES,
            "record limit exceeds global guard"
        );
        let envelope_limit = plain_limit
            .checked_add(MAX_ENVELOPE_OVERHEAD)
            .context("record limit overflow")?
            .min(MAX_METADATA_BYTES);
        let encrypted = read_bounded(&self.root, path, envelope_limit)?;
        let plain = open(self.key, &context(&self.id, kind, id), &encrypted)
            .with_context(|| format!("record authentication failed for {path}"))?;
        ensure!(
            plain.len() <= plain_limit,
            "decrypted record size limit exceeded"
        );
        Ok(plain)
    }

    fn load_json<T: DeserializeOwned>(
        &self,
        path: &str,
        kind: &str,
        id: &str,
        plain_limit: usize,
    ) -> Result<T> {
        let plain = self.load_record(path, kind, id, plain_limit)?;
        serde_json::from_slice(&plain).context("invalid authenticated metadata")
    }

    /// Returns ciphertext bytes published, or zero for verified existing data.
    pub fn store_immutable(
        &self,
        path: &str,
        kind: &str,
        id: &str,
        plain: &[u8],
        plain_limit: usize,
    ) -> Result<u64> {
        ensure!(
            plain_limit <= MAX_METADATA_BYTES,
            "record limit exceeds global metadata guard"
        );
        ensure!(plain.len() <= plain_limit, "record exceeds plaintext limit");
        match self.root.read_file(path) {
            Ok(_) => {
                let existing = self.load_record(path, kind, id, plain_limit)?;
                ensure!(
                    existing == plain,
                    "immutable content is corrupt or does not match its protected identifier"
                );
                return Ok(0);
            }
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(error).context("cannot safely inspect immutable object"),
        }
        let encrypted = seal(self.key, &context(&self.id, kind, id), plain)?;
        ensure!(
            encrypted.len() <= plain_limit.saturating_add(MAX_ENVELOPE_OVERHEAD)
                && encrypted.len() <= MAX_METADATA_BYTES,
            "encrypted record size limit exceeded"
        );
        self.root.write_new(path, |file| {
            file.write_all(&encrypted)?;
            Ok(())
        })?;
        Ok(encrypted.len() as u64)
    }

    pub fn publish_commit(&self, commit: &Commit) -> Result<()> {
        validate_commit(commit, &self.id, &commit.snapshot_id)?;
        let plain = serialize_bounded(commit, MAX_COMMIT_BYTES)?;
        let encrypted = seal(
            self.key,
            &context(&self.id, "snapshot-commit", &commit.snapshot_id),
            &plain,
        )?;
        ensure!(
            encrypted.len() <= MAX_COMMIT_BYTES + MAX_ENVELOPE_OVERHEAD,
            "commit envelope exceeds bounded size"
        );
        let path = commit_path(&commit.snapshot_id)?;
        self.root.write_new(&path, |file| {
            file.write_all(&encrypted)?;
            Ok(())
        })
    }
}

pub(crate) fn snapshots(repository: &Path, key: &RepositoryKey) -> Result<Value> {
    let path = absolute_root(repository)?;
    let repository = Repository::open(&path, key)?;
    let mut summaries = Vec::new();
    let mut response_bytes = 2_usize; // JSON array brackets.
    for entry in repository.entries()? {
        let Some(name) = entry.relative_path.strip_prefix(&format!("{COMMITS}/")) else {
            continue;
        };
        if !name.ends_with(".qscommit") {
            // SafeRoot publication temporaries and uncommitted objects are not
            // history. Only the final protected commit extension is visible.
            continue;
        }
        ensure!(
            !entry.is_directory && !name.contains('/'),
            "invalid immutable commit entry"
        );
        let id = name.strip_suffix(".qscommit").expect("suffix checked");
        // Drop each complete manifest immediately. History does not retain all
        // versions' file trees in memory or return them to the backend/webview.
        let summary = repository.load_commit(id)?.summary_json();
        let encoded = serialize_bounded(&summary, MAX_HISTORY_RESPONSE_BYTES)?;
        response_bytes = response_bytes
            .checked_add(encoded.len() + usize::from(!summaries.is_empty()))
            .context("history response length overflow")?;
        ensure!(
            response_bytes <= MAX_HISTORY_RESPONSE_BYTES,
            "snapshot history exceeds the 64 KiB response limit; all immutable commits \
             are retained; paginated history is not implemented"
        );
        summaries.push(summary);
    }
    summaries.sort_by(|left, right| {
        left["createdAt"]
            .as_str()
            .cmp(&right["createdAt"].as_str())
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });
    Ok(Value::Array(summaries))
}

pub(crate) fn read_bounded(root: &SafeRoot, relative: &str, limit: usize) -> Result<Vec<u8>> {
    let (mut file, stamp) = root.read_file(relative)?;
    let length = file.metadata()?.len();
    ensure!(length <= limit as u64, "input record exceeds bounded size");
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .context("record allocation failed")?;
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "input record grew beyond bounded size"
    );
    ensure!(
        bytes.len() as u64 == length,
        "input record changed length while being read"
    );
    root.verify_file(relative, &stamp)?;
    Ok(bytes)
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
    })
}
