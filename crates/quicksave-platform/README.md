# QuickSave native platform boundary

Original QuickSave implementation, licensed `GPL-3.0-only`. No No Land source
was copied into this crate.

## API

The `SafeRoot`, `FileStamp`, `Entry`, `capabilities()`, and `app_directories()`
interfaces follow `docs/IMPLEMENTATION-CONTRACT.md` exactly. `FileStamp` and
`Entry` derive serde, `PartialEq`, and `Eq`.

Additional helper:

```rust
pub fn ensure_private_directory(path: &std::path::Path) -> anyhow::Result<()>;
pub fn verify_private_file(file: &std::fs::File) -> anyhow::Result<()>;
impl SafeRoot {
    pub fn overlaps(&self, other: &SafeRoot) -> anyhow::Result<bool>;
    pub fn contains_file_identity(&self, stamp: &FileStamp) -> anyhow::Result<bool>;
    pub fn same_root(&self, other: &SafeRoot) -> anyhow::Result<bool>;
}
```

`same_root` compares only final native directory IDs, with both roots revalidated
before and after. It is cheap, does not enumerate contents, and returns false
for distinct parent/child roots. It is appropriate for binding native approvals
to an already-open root, not for establishing that two trees are disjoint.

`overlaps` compares final directory IDs against pinned ancestor IDs in both
directions, then, if necessary, scans both bounded trees and intersects **all**
native directory IDs. It does not rely on textual path prefixes or assume bind
mounts/firmlinks retain every physical ancestor in a pathname. Shared descendants
are detected even if neither selected final root is a native ancestor of the
other. Directory identities and entry sets are rechecked while scanning; both
roots are revalidated before and after. Invalid entries fail rather than
producing a potentially false negative. The scan opens directory handles and
inspects metadata, never file contents. It is deliberately conservative and
potentially expensive, not a performance or atomic-namespace-lock claim.

`contains_file_identity` scans the same bounded tree, opens regular files whose
enumerated lengths match the supplied stamp, and compares **only** native
device/file IDs. It detects an external recovery-key inode reachable under a
different namespace (including hard links); equal bytes in a different file do
not match. Timestamps are intentionally ignored for alias detection. It does not
read file bytes or replace independent key-length/content/stability checks.
Directory overlap and individual file aliases are separate guards. Both APIs
need rechecking before commit/mutation when namespaces can change.

On supported Unix systems this creates missing components at `0700` through
pinned parents, flushes new directories and parents, and requires the final
directory to have mode `0700` and the effective user's ownership. Existing
ancestors may be system-owned, shared, or sticky. It never chmods/chowns existing
directories. Existing nonprivate final directories are errors.

Private means more than mode bits. `verify_private_file` requires the effective
user's ownership, mode exactly `0600`, regular-file type, one native hard link,
and **no extended ACL**. It checks metadata before/after handle-based ACL
inspection. Callers must use it before reading external recovery-key bytes;
ordinary source `read_file` is intentionally not restricted to private files.
This descriptor privacy check does not replace no-follow path opening through
`SafeRoot`.

On macOS, native `acl_get_fd_np(ACL_TYPE_EXTENDED)`/`acl_get_entry` reject every
ACE, including benign/inherited entries. Empty/no ACL is accepted only on native
APFS/HFS when the native descriptor API reports ACL absence. Explicit empty ACL
objects are also rejected rather than guessing their inheritance flags;
unsupported filesystem ACL models fail explicitly. On Linux, native
`fgetxattr` checks for both POSIX access ACLs and directory default ACLs. Every
present ACL is rejected; only `ENODATA` proves absence, while `ENOTSUP` and other
inspection errors fail. Supported Linux private ACL models are ext2/3/4, XFS,
Btrfs, tmpfs, F2FS, and overlayfs; NFS, CIFS, FUSE, and unknown filesystem models
are unsupported rather than treated as private from mode bits alone.

These checks apply to private directories, newly created directories, and both
staging directories/files **before the writer is invoked** and again before
publication. ACLs are never silently stripped or changed. Failed private
directory creation can leave a new empty directory but never reports success or
writes recovery-key bytes into it. Windows private-file ACL verification is
unsupported and explicitly errors, consistent with its private-write capability.

`create_dir` creates one component beneath the root (parents must already exist);
it accepts an existing verified real directory. `write_new` never accepts an
existing final entry, including symlinks, directories, or broken symlinks.

## Implemented native safety

**macOS / Linux:** `openat`, `fstatat(AT_SYMLINK_NOFOLLOW)`, `O_NOFOLLOW`,
`O_DIRECTORY`, native device/inode identity, mtime and ctime. Every root ancestor
is pinned and rechecked. Relative parent edges are also checked before and after
operations. File descriptors never reopen a source through an unchecked path.
Nonblocking opens ensure a replacement FIFO cannot hang a read.

Writes use a random, operation-private `0700` staging directory and a `0600`
create-exclusive file. The writer callback must complete all content verification
successfully. File-handle swaps, name replacements, privacy changes, unexpected
hard links, and metadata changes after callback verification fail explicitly.
File and directory sync errors propagate. Native `linkat` publishes without
replacement, then staging is removed, file metadata and the destination directory
are flushed again. Filesystems without the required hard-link or directory-flush
support fail rather than receiving a path-based fallback.

Callback errors clean up only operation-owned staging entries, with identity
checks. Cleanup failures are reported. Panic unwinding attempts staging cleanup
but cannot report cleanup errors. Abrupt process termination may leave an
uncommitted private staging directory; there is no automatic scavenging/deletion.
An error after publication may leave the complete new target present: this is
not a rollback/overwrite API.

As with normal Unix filesystem security, another process with the same UID,
ptrace access, or elevated filesystem privileges must not tamper with private
staging names or open handles. Directory identity revalidation detects namespace
replacement; it is not a kernel-wide namespace lock against an adversary moving
directories between individual system calls. This is stable-file capture, not
an application-atomic snapshot or protection from a compromised local account.

**Windows:** real `NtCreateFile` parent-relative handles with
`FILE_OPEN_REPARSE_POINT`, `OBJ_DONT_REPARSE`, native volume/128-bit file IDs,
length/last-write/change times, and native `NtQueryDirectoryFile` enumeration.
Every ancestor is opened without `FILE_SHARE_DELETE`, preventing rename/deletion
while pinned. Reparse points, device/UNC roots, device names, alternate streams,
and non-Unicode names are rejected.

Windows durable writes, directory creation, and private ACL creation are
**unsupported and return errors before creating anything or running a writer**.
Their capability fields are false; there is no racy `std::fs` fallback.
Windows implementation is not a claim of Windows native acceptance.

## Bounds and paths

Walks are deterministic and fail on any invalid entry instead of skipping it.
Limits: 1,000,000 entries, depth 128, 32,768 bytes per relative path, and 128 MiB
of aggregate path bytes. Discovery also charges pending names to the global
entry/path budget, bounding recursive enumeration memory. All source names must
be UTF-8 and ordinary directory/regular-file names; symlinks and special files
are explicit errors. Relative paths use `/` and reject empty, `.`/`..`, NUL,
backslash, colon, and overlong components. Hard-linked regular source files are
permitted; their individual names and native identities are validated.

`app_directories()` returns `data`, `config`, `cache`, `state`, `logs`, and
`runtime` strings under the QuickSave namespace. Discovery uses native account
home plus Apple layouts on macOS, XDG plus native account fallback on Linux, and
`SHGetKnownFolderPath` without `KF_FLAG_CREATE` on Windows. It never creates
directories or reads application state.

## Validation

`tests/safe_root_unix.rs` exercises stable reads, serde, native file/root/ancestor
replacement, symlink escapes, traversal rejection, FIFO/non-UTF8 rejection,
ordered repeatable walks, depth limits, private modes, verification-before-
publication, callback failures/panics, concurrent create-new writers, overwrite
refusal, file-handle swaps, and private-directory helpers. Windows-specific tests
cover native reading, source-name pinning, device paths, and fail-closed writes.

Native tests and cross-target compilation must be reported separately. Merely
compiling a target does not establish Windows/Linux acceptance or native
packaging acceptance.
