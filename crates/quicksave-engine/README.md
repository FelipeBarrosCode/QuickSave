# QuickSave local engine

Original GPL-3.0-only orchestration using `quicksave-platform` native handles and
`quicksave-content` encryption, compression, BLAKE3, and upstream-derived FastCDC.
No engine source was copied from No Land. See the content crate's provenance
notice for its derived algorithms and the original snapshot's license ambiguity.
This is an incompatible **QuickSave** repository format.

## Public interface

- `initialize(path) -> RepositoryKey` generates but does not persist a key.
- `initialize_with_key(path, key) -> Value` is preferred: the caller durably
  saves a private, external recovery-key file **before** initializing.
- `verify_repository(path, key) -> Value` authenticates only the repository
  identity and returns its ID/format/version without walking history, mutating,
  or accessing/granting any source/destination root.
- `backup(repository, source, key) -> Value` publishes an immutable version.
- `snapshots(repository, key) -> Value` returns a JSON array of summaries.
- `restore(repository, id, existing_empty_directory, key) -> Value` restores.
- `limits() -> Value` reports actual engine entry/path/document/chunk limits
  independently of the platform tree-walk limit.

Every operation authenticates the self-describing identity before source or
destination access, writer locking, or repository mutation. Identity, chunk,
per-file index, and snapshot-commit contexts are domain-separated and bound to
the random public repository ID. Keys are never stored in repository settings,
metadata, logs, or operation summaries.

## Layout and commit semantics

```
quicksave.repository.json          public identity + encrypted key check
quicksave/writer.lock              persistent native flock/LockFile lock inode
quicksave/objects/<hex>.qsobj       immutable authenticated compressed chunks
quicksave/indexes/<hex>.qsidx       immutable encrypted per-file chunk indexes
quicksave/commits/<uuid>.qscommit   immutable encrypted complete tree commits
```

Hashes in authenticated documents use `blake3:<hex>`; filesystem names use only
validated lowercase hex. Reuse verifies existing authenticated plaintext; corrupt
objects are not accepted, repaired, or overwritten. Deduplication is local to the
same repository/key. The native writer lock is acquired on a `SafeRoot` file
handle, not a separate unsafe path open.

Objects and indexes are durably published first. Files' native stamps and the
exact source tree are revalidated before publishing the final commit through
`SafeRoot::write_new`. There is no mutable `LATEST` pointer. History reads final
commits, and every old version remains addressable. Failed capture can leave
unreachable immutable objects; there is **no automatic GC, retirement, or deletion**.
An error after a native publication/durability check can leave a complete new
entry; errors are never converted into successful durability claims.

## Restore safety

The destination must already exist and be empty. Nonempty targets are rejected
without writing. All manifest paths, parent/type relationships, portable device
names, case/Unicode-normalization aliases, indexes, referenced chunk hashes,
lengths, AEAD tags, and reconstructed full-file BLAKE3 hashes are preflighted
before output. Content is reauthenticated while writing. Native create-new
publication refuses clobbering even if another process races the preflight.

There is no overwrite/rollback feature. If a later write fails, only private
staging entries are cleaned by the platform. Already published new destination
entries are retained for inspection and the operation returns a failure with its
ID; engine code does not delete user files. A successful restore rechecks the
output tree and file stamps.

## Explicit limits and nonfeatures

- Metadata's inherited global guard remains **512 MiB**, never increased.
  Commits are at most 64 MiB; each file's separate index is at most 16 MiB.
- At most 250,000 file/directory entries, 32 MiB aggregate relative-path bytes,
  64 path components, 4,096 path bytes, and 255 bytes per component.
- Chunk bounds and maximum chunks/file follow the content crate (1/4/8 MiB
  FastCDC; at most 65,536 chunk references). No whole-file payload buffering.
- Deserialization bounds node/chunk sequence counts and validates strings before
  retaining them. The tree-node decoder streams fields instead of buffering
  arbitrary internally-tagged enum content. Escaped JSON still uses bounded
  serde_json scratch space; this is not a claim of a 512 MiB process-memory cap.
- Operation results are summaries, not manifests. Complete history summaries
  exceeding 64 KiB fail explicitly; paginated history is not implemented and no
  versions are silently hidden or deleted.
- `newBytes` counts newly published **encrypted chunk-object** bytes, excluding
  metadata. `newLogicalChunkBytes` is their unencrypted logical length.
  `reusedChunks` counts verified reused chunk references, including repeats.
- Repository paths are native no-symlink private directories (`0700` on Unix);
  existing nonprivate directories are refused, never silently chmodded.
- Root `..` components, repository/source or repository/destination overlap,
  symlinks, reparse points, special files, and unportable paths are unsupported.
  Before payload writes, conservative normalized/case-folded component checks
  are followed by `SafeRoot::overlaps` native root/ancestor identity checks to
  reject native directory aliases as well as ordinary lexical ancestors.
- History uses no writer lock and never interprets publication staging as a
  commit. A native consistent tree walk can fail explicitly if a concurrent
  writer changes directory entries while they are being enumerated.
- Captures are validated **stable-file capture, not application-atomic**.
  Files can still be modified after their last check; no VSS, application
  profiles, quiescing, or volume snapshots are claimed.
- Restores preserve bytes and directory structure, not original modes, ACLs,
  ownership, extended attributes, sparse layout, or hardlink relationships.
- No remote provider, daemon, native key vault, No Land repository compatibility,
  automatic retention, packaging, signing, Windows/Linux acceptance, or
  application-profile implementation is claimed.

Tests create isolated native temporary roots only. Native mutation/roundtrip
tests are gated to macOS/Linux; unsupported platforms test explicit failure.
The synthetic 186,735-file regression serializes/deserializes one owned tree at
a time under the unchanged 64 MiB commit bound, then exercises count overflow.
It creates no physical file tree and makes no I/O throughput/acceptance claim.
