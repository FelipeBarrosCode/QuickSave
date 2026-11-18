# QuickSave native platform boundary

Original QuickSave implementation, licensed `GPL-3.0-only`. No No Land source
was copied into this crate.

## API

### Directory-identity approval (not capture)

```rust
impl SafeRoot {
    pub fn overlaps_directory_identities(&self, protected: &SafeRoot)
        -> anyhow::Result<bool>;
}
pub enum DirectoryIdentityInspectionSide { Selected, Protected }
#[non_exhaustive]
pub enum DirectoryIdentityInspectionStage {
    ValidatePinnedRoot,
    RecordDirectories,
    VerifyDirectories,
    RevalidateRootIdentity,
    RevalidatePinnedRoot,
    UnsupportedPlatform,
}
pub struct DirectoryIdentityInspectionFailure {
    pub side: DirectoryIdentityInspectionSide,
    pub stage: DirectoryIdentityInspectionStage,
    pub relative_path: Option<std::path::PathBuf>,
    // Private construction; also implements std::error::Error + Display.
}
```

Tracker's root-identity approval may use this new purpose-specific method. The
receiver is the **selected** root and the argument is the **protected** root;
errors identify the side, native operation and relative directory. Callers should
add their approved root/path label as error context. This is not a payload
readability or capture receipt.

Every error from this method carries `DirectoryIdentityInspectionFailure` as
typed `anyhow` context. Stable public field names are **`side`**, **`stage`** and
**`relative_path`**; construction is private. Downcast through caller context:

```rust
let failure = error.downcast_ref::<DirectoryIdentityInspectionFailure>();
let failed_side = failure.map(|failure| failure.side);
```

The native cause remains downcastable as well (for example `std::io::Error`).
`relative_path` is `None` for root/global failures or unavailable location;
otherwise it is the inspected directory (possibly a containing directory),
relative to that side's root. Unix non-UTF-8 bytes are preserved, not parsed from
display text. `stage` is a non-exhaustive enum; callers must not parse its Display
text. A protected-side permission or topology failure is **not** evidence that
the selected app root is missing/unavailable. An error without this context
(from another API) must not be silently classified as selected-side failure.
Generic capture errors are unchanged; no string-based whitelist or new
`UnsupportedNativeCaptureEntry` classification is introduced.

- The ancestor-ID fast path and intersection of **all real directory IDs** still
  catch same-root, containment, shared-descendant bind/firmlink aliases and case
  aliases. A descendant matching the protected root already proves overlap and
  avoids inspecting that subtree again. Negative results never come from
  lexical prefixes or blind ancestor-only checks.
- Native handle-relative enumeration classifies entry kinds without following
  links. Unix uses no-follow `fstatat` for kind (directory-entry type hints are not
  alias authority). Windows uses byte-bounded extended native directory records
  and verifies both halves of each directory's 128-bit handle ID.
- No regular-file handles, payload reads, or symlink target-text reads occur.
  Files, sockets/FIFOs and known symlinks are excluded from the directory census,
  including absolute/escaping symlinks. Windows directory junctions and unknown
  directory reparse tags fail explicitly, never as disjointness.
- Directory before/open/after edges, retained parents, native identities, and
  directory-only children are rechecked. A second deterministic census verifies
  the recorded topology without allocating another inventory. File sizes,
  timestamps and file-name sets are not compared; ordinary file churn does not
  invalidate approval. A vanished **known directory**, changed directory set,
  alias cycle, inaccessible directory or exhausted bound still fails.
- Each census bounds total enumeration work by the existing 1,000,000-entry /
  128 MiB summed-name limits. Its retained directory inventory additionally
  allows at most 131,072 directories including the root, with 32 MiB summed
  relative directory paths. Existing depth/path limits still apply. No retries,
  permission repair, elevation, or "unknown means safe" fallback is installed.

**Topology/performance limitation:** native ancestor IDs are positive overlap
evidence, not a disjointness proof. No trusted cross-platform OS proof excluding
interior bind/firmlink aliases is implemented here; a mount-table or lexical
prefix comparison alone would not establish one on macOS. Otherwise both
directory trees are inspected, with the above precise failure diagnostics. This
does not promise to eliminate protected-directory enumeration per application.
Do not cache a negative census as a permanent mount/namespace authorization.

`overlaps()`, `entries()`, `metadata_entries()`, `read_file()`, and the parent's
`file_metadata()` / Unix native-filename changes are preserved. Generic overlap
and capture continue to reject unsupported/escaping links; identity approval
does not authorize their capture or relax source/root guards. Like the existing
overlap guard, this is a validated census, not an atomic namespace/mount lock.

Synthetic tests: `tests/directory_identity_overlap_unix.rs`, common inventory
unit tests and Windows native/parser regressions. The real shared-descendant
Linux bind-alias fixture is **ignored by default**; it requires explicitly
selected native capability acceptance and creates a private, non-propagating
mount namespace in a subprocess, never in the test runner. No mounts, native
apps, protected accounts, vaults or repository trees were probed by this agent.
Parent-owned serialized Cargo/native validation is required; these new tests
have not been run by the assigned agent.

Assigned-agent static checks (not compilation/native acceptance):

```sh
rustfmt --check --edition 2021 \
  crates/quicksave-platform/src/lib.rs \
  crates/quicksave-platform/src/overlap.rs \
  crates/quicksave-platform/src/unix.rs \
  crates/quicksave-platform/src/unix/overlap.rs \
  crates/quicksave-platform/src/windows.rs \
  crates/quicksave-platform/src/windows/overlap.rs \
  crates/quicksave-platform/tests/directory_identity_overlap_unix.rs \
  crates/quicksave-platform/tests/safe_root_unix.rs \
  crates/quicksave-platform/tests/safe_links_unix.rs \
  crates/quicksave-platform/tests/safe_root_windows.rs
git diff --check -- crates/quicksave-platform
```

### Additive native metadata / state contract (2026-11)

```rust
pub enum EntryKind { File, Directory, Symlink }
pub struct NativeLinkStamp {
    pub stamp: FileStamp,
    pub target: String,
    pub target_is_directory: Option<bool>,
}
pub struct MetadataEntry {
    pub relative_path: String,
    pub kind: EntryKind,
    pub stamp: FileStamp,
    pub link: Option<NativeLinkStamp>,
}
impl SafeRoot {
    pub fn open_directory(&self, relative: &str) -> anyhow::Result<std::fs::File>;
    pub fn clone_root_directory_handle(&self) -> anyhow::Result<std::fs::File>;
    pub fn metadata_entries(&self) -> anyhow::Result<Vec<MetadataEntry>>;
    pub fn read_link(&self, relative: &str) -> anyhow::Result<NativeLinkStamp>;
    pub fn verify_link(&self, relative: &str, before: &NativeLinkStamp) -> anyhow::Result<()>;
    pub fn create_new_relative_symlink(
        &self, relative: &str, target: &str, target_is_directory: Option<bool>,
    ) -> anyhow::Result<NativeLinkStamp>;
}
```

`open_directory` requires a nonempty ordinary relative path and returns a real
read-only no-follow directory handle after before/open/after identity and pinned
parent checks. `clone_root_directory_handle` is the explicit root-only operation;
it performs a fresh handle-relative `.` open for an independent enumeration
cursor. `""`, `"."`, and traversal are never root aliases. Callers doing a bounded
one-level enumeration retain the returned handle and re-open through the same
`SafeRoot` afterward to compare native IDs. Windows consumers query full native
128-bit IDs from the handle, not Rust's legacy 64-bit metadata index.

The metadata walk never traverses a link. Unix link text is retained exactly;
Windows native separators are normalized to `/` in this logical-root API. Text
must be bounded UTF-8 and lexically confined to the selected logical root: `..` is
allowed only while it remains within that root. Absolute, drive/NT namespace,
backslash, NUL, stream, and escaping targets fail. Dangling internal links do not
cause target reads. Existing strict `entries()` and `read_file()` APIs retain
their no-symlink behavior. A link stamp binds no-follow native identity, length,
write/change times, link text and (on Windows) the directory-link bit.

Windows-only state adapter (available under `cfg(windows)`):

```rust
pub struct PrivateDirectory; // pinned, protected current-user-SID namespace
pub struct PrivateLock;      // scoped LockFileEx lock, persistent lock inode
pub struct PrivateFileVersion; // complete native identity + content/change stamp
pub fn flush_native_directory(directory: &File) -> anyhow::Result<()>;
impl PrivateDirectory {
    pub fn open(path: &Path) -> anyhow::Result<Self>;
    pub fn lock(&self, name: &str) -> anyhow::Result<PrivateLock>;
    pub fn read(&self, name: &str, limit: usize)
        -> anyhow::Result<Option<(Vec<u8>, PrivateFileVersion)>>;
    pub fn replace(&self, name: &str, bytes: &[u8], observed: Option<&PrivateFileVersion>)
        -> anyhow::Result<()>;
    pub fn flush(&self) -> anyhow::Result<()>;
}
impl PrivateLock { pub fn check(&self) -> anyhow::Result<()>; }
```

Replacement is exclusively for caller-approved private configuration, not
arbitrary user-data overwrite. Callers hold the scoped lock across read/replace.
The Windows durability boundary is local NTFS/ReFS, protected user-only DACL,
native handle-based publication, and a successful actual filesystem/volume
flush. Unsupported filesystem, flush privileges or OS semantics return errors;
an error after publication is not rollback. No Windows acceptance is implied.

Standalone fork coordination: `noland-snapshot/src/source.rs` declares
`native_metadata.rs`; the parent owns the `lib.rs` exports and `metadata.rs`
integration. Its Windows metadata must retain `NativeIdentity { volume,
file_id: [u64; 2] }`, raw creation/access/write/change FILETIME ticks, attributes,
link count, and the checked symlink tag. Never substitute Unix UID/GID or a
truncated 64-bit file index.

Concrete snapshot integration hook: `SourcePath::metadata()` on Windows calls
`SourceMetadata::from_windows(&WindowsMetadata) -> SourceMetadata`. The parent
must add that constructor in its owned `metadata.rs`, retain the supplied native
metadata, and make stable comparisons ignore access-time-only changes. Available
fields are `identity`, `size`, `creation_time`, `last_access_time`,
`last_write_time`, `change_time`, `attributes`, `number_of_links`, `reparse_tag`,
and `kind: NativeEntryKind`. `WindowsMetadata::from_file(&File)` performs native
handle queries and rejects unsupported reparse tags. `modified()` converts the
raw native write time without pretending its epoch is Unix.

Snapshot native boundary helpers are additive: `native_identity()`,
`parent_native_identity()`, `new_beneath_native(path, boundary, NativeIdentity)`,
`native_link_stamp()`, and
`create_new_relative_symlink(target, logical_relative, target_is_directory)`.
The legacy `(device, inode)` boundary APIs intentionally fail on Windows, rather
than truncating a 128-bit identity. Parent exports should include `NativeIdentity`,
`NativeEntryKind`, `SourceLinkStamp`, and (on Windows) `WindowsMetadata`.

`SourceMetadata::from_file(&File)` is already implemented in the new module.
Standalone database/restore adapters can use
`native_metadata::{identity_from_file, flush_directory, verify_private_file,
verify_private_directory, ScopedFileLock}`. `ScopedFileLock::lock(&File)` is a
real scoped `LockFileEx`/`flock` lock on the verified private inode; callers also
validate its parent/name. `flush_directory` uses the same real Windows volume
barrier rather than `File::sync_all` on a directory. `WindowsMetadata` supplies
checked `mtime_ns()`/`ctime_ns()` and `same_file_state()` (ignoring access time).
`apply_file_metadata(&File, mode, mtime_ns, uid, gid)` is Windows-only: exact native
100ns mtime is supported, while requested Unix mode/UID/GID explicitly fails.
Windows `SourcePath::move_new_to` is handle-based no-replace; its
`move_new_to_checked(target, expected)` variant additionally binds the opened
source to a frozen `SourceMetadata`.
All handles denying delete-sharing must close before a Windows publication/move;
sharing violations are real failures, never a reason to use a racy path fallback.

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

On Unix, private means more than mode bits. `verify_private_file` requires the effective
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
writes recovery-key bytes into it. Windows requires local NTFS/ReFS, current-user
SID ownership, a protected DACL with exactly one explicit full-access allow ACE
for that SID, and one hard link for private files. Null/default/inherited DACLs,
additional ACEs, extra hard links and unverifiable ACL models are errors.

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
while pinned. Strict reads reject reparse points; the separate metadata API
accepts only checked relative `IO_REPARSE_TAG_SYMLINK` data without traversing it.
Junctions, unknown reparse tags, device/UNC roots, device names, alternate streams,
and non-Unicode names fail explicitly.
Content reads reopen the already checked native inode with deny-write/delete
sharing, refusing ordinary concurrent write handles instead of trusting Windows
timestamps that can be deferred until writer close. Metadata-only indexing is
separate from a successful stable-content capture. This is not VSS or an
application-wide atomic/mapped-memory snapshot; applications requiring that
consistency need a separate supported quiescence/snapshot mechanism.

Windows creation uses `NtCreateFile(FILE_CREATE)` with an explicit protected
current-user descriptor. Staging handles and names are checked around the entire
writer; `NtSetInformationFile(FileRenameInformation)` publishes atomically without
replacement. Private configuration replacement is separate and requires an
observed prior version. `LockFileEx`/`UnlockFileEx` provide scoped persistent-inode
locking. Native file data is flushed and the final writer is closed while the
random private staging name is still unpublished. A sealed, read-only DELETE
control handle denies ordinary writers and namespace replacement across rename,
verification and `FlushFileBuffers` on the actual volume. Timestamp finalization
is thus not a race with an application opening the newly published name.
A volume GUID root is pinned and checked against the selected native
volume ID. NTFS/ReFS and successful actual volume flush are mandatory, including
a preflight flush before the writer. Windows may require elevation for that
handle; denial is an error, not a pretend durable fallback. Link creation also
requires the authenticated directory-link kind and enabled native
`SeCreateSymbolicLinkPrivilege` (never silently enabled). Windows native acceptance
and ordinary-user durability acceptance are still pending.

## Bounds and paths

Walks are deterministic and fail on any invalid entry instead of skipping it.
Limits: 1,000,000 entries, depth 128, 32,768 bytes per relative path, and 128 MiB
of aggregate path bytes. Discovery also charges pending names to the global
entry/path budget, bounding recursive enumeration memory. All source names must
be UTF-8. Strict walks accept ordinary directory/regular-file names only;
metadata walks additionally retain confined symlinks and never follow them.
Special files are errors. Relative paths use `/` and reject empty, `.`/`..`, NUL,
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
refusal, file-handle swaps, and private-directory helpers. `safe_links_unix.rs`
adds 16 synthetic framework/confinement/no-follow/link-stability cases.
Windows-specific tests cover protected ACLs, native hard links, reparse reads,
source-name pinning, device paths, real barrier denial, and privileged durable
configuration replacement/no-overwrite acceptance.

Native tests and cross-target compilation must be reported separately. Merely
compiling a target does not establish Windows/Linux acceptance or native
packaging acceptance.

### This native-boundary revision

Only formatting/static whitespace validation was run by its assigned agent;
Cargo builds/tests, commits and additional agents were expressly prohibited.
New test names above are coverage to run, not passing native acceptance evidence.

Executed checks (both passed):

```sh
rustfmt --check --edition 2021 crates/quicksave-platform/src/lib.rs crates/quicksave-platform/src/unix.rs crates/quicksave-platform/src/windows.rs crates/quicksave-platform/tests/safe_links_unix.rs crates/quicksave-platform/tests/safe_root_windows.rs crates/quicksave-state/src/state_file.rs shared-storage/crates/noland-snapshot/src/source.rs shared-storage/crates/noland-snapshot/src/windows.rs shared-storage/crates/noland-snapshot/src/native_metadata.rs
git diff --check -- crates/quicksave-platform crates/quicksave-state/src/state_file.rs shared-storage/crates/noland-snapshot/src/source.rs shared-storage/crates/noland-snapshot/src/windows.rs shared-storage/crates/noland-snapshot/src/native_metadata.rs
```

The parent must integrate the snapshot metadata constructor/exports and native
restore/database callers before Windows compilation. Native Windows tests,
elevated NTFS/ReFS flush acceptance (including ignored tests), enabled-privilege
symlink creation, power-loss/fault durability, and platform packaging remain
unvalidated. No No Land reference checkout or live app/provider/vault state was
accessed. New `windows/*.rs`, standalone `windows.rs`/`native_metadata.rs`, and link
tests are original GPL-3.0-only native boundary code using SDK ABI declarations;
the parent provenance ledger should separately record the changes to the derived
active-fork `source.rs`.
