# Agent integration contract

This document fixes the first vertical-slice APIs. It is not a claim of full platform acceptance.

## Platform crate (agent-owned)

Use `anyhow::Result`.

```rust
pub struct FileStamp { /* serializable comparable native identity + length/mtime */ }
pub struct Entry { pub relative_path: String, pub is_directory: bool, pub size: u64 }
pub struct SafeRoot { /* private pinned native directory handle */ }
impl SafeRoot {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self>;
    pub fn entries(&self) -> anyhow::Result<Vec<Entry>>;
    pub fn read_file(&self, relative: &str) -> anyhow::Result<(std::fs::File, FileStamp)>;
    pub fn verify_file(&self, relative: &str, before: &FileStamp) -> anyhow::Result<()>;
    pub fn create_dir(&self, relative: &str) -> anyhow::Result<()>;
    pub fn write_new(&self, relative: &str, writer: impl FnOnce(&mut std::fs::File) -> anyhow::Result<()>) -> anyhow::Result<()>;
    pub fn same_root(&self, other: &SafeRoot) -> anyhow::Result<bool>;
    pub fn overlaps(&self, other: &SafeRoot) -> anyhow::Result<bool>;
    pub fn contains_file_identity(&self, stamp: &FileStamp) -> anyhow::Result<bool>;
}
pub fn capabilities() -> serde_json::Value;
pub fn app_directories() -> anyhow::Result<serde_json::Value>;
pub fn ensure_private_directory(path: &std::path::Path) -> anyhow::Result<()>;
pub fn verify_private_file(file: &std::fs::File) -> anyhow::Result<()>;
```

All source and output operations must stay pinned beneath the approved root. `write_new` refuses overwrites, syncs data, and does not publish unverified bytes; writer errors clean up only that operation's new entry. Root opening rejects symlink ancestors. Native unsupported APIs error, never silently downgrade. Directory traversal, non-UTF8 names, special files, symlinks and reparse points may be explicitly rejected for the initial capability level. Maximum tree size/depth must be bounded.

Root comparisons use native identities, including aliases which skip lexical ancestors; string prefixes alone are insufficient. Private staging must reject unsafe native ACLs before the writer receives a file. Recovery-key reads verify native privacy, ownership and link count before reading bytes.

## Content crate (agent-owned)

Pure native-independent content layer derived from upstream algorithms, using `anyhow::Result`.

```rust
pub struct RepositoryKey { /* no Debug/Serialize, zeroize on drop */ }
impl RepositoryKey {
    pub fn generate() -> Self;
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32]; // explicit key export only
}
pub struct Chunk { pub hash: String, pub size: u64 }
pub fn chunk_reader(reader: impl std::io::Read, emit: impl FnMut(&Chunk, &[u8]) -> anyhow::Result<()>) -> anyhow::Result<(String, u64, Vec<Chunk>)>;
pub fn seal(key: &RepositoryKey, context: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>>;
pub fn open(key: &RepositoryKey, context: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>>;
pub fn hash(bytes: &[u8]) -> String;
```

Maintain existing FastCDC boundaries/constants where possible and document fixture equivalence. AEAD and HKDF must come from reviewed cryptographic libraries or unmodified upstream code, never bespoke crypto. Enforce per-record bounds. Format is explicitly QuickSave, not a claim of existing Noland repository compatibility.

## Engine crate (agent-owned)

Use safe platform/content crates. Expose:

```rust
pub fn initialize(repository: &Path) -> anyhow::Result<RepositoryKey>;
pub fn initialize_with_key(repository: &Path, key: &RepositoryKey) -> anyhow::Result<serde_json::Value>;
pub fn verify_repository(repository: &Path, key: &RepositoryKey) -> anyhow::Result<serde_json::Value>;
pub fn limits() -> serde_json::Value;
pub fn backup(repository: &Path, source: &Path, key: &RepositoryKey) -> anyhow::Result<serde_json::Value>;
pub fn snapshots(repository: &Path, key: &RepositoryKey) -> anyhow::Result<serde_json::Value>;
pub fn restore(repository: &Path, snapshot_id: &str, destination: &Path, key: &RepositoryKey) -> anyhow::Result<serde_json::Value>;
```

New encrypted QuickSave namespace; repository identity authenticated; dedup content by hash only within same repository/key; additive immutable commit per snapshot; last commit publication only after all referenced content. No automatic retention/deletion. Local repository first, existing Noland repo refused. Recovery-key file is external to repository and source. Initial restore into an approved empty directory only; fail before writing on nonempty targets. No pretending that rollback-overwrite is implemented. Revalidate source identities and tree sets before commit; if unavailable say "stable-file capture, not application-atomic". Reject repository/source overlap. Metadata is bounded (global guard not raised).

## Desktop API (parent backend, UI agent)

Tauri invoke commands:

- `authorize_operation({kind, repository, keyFile, source?, destination?, snapshotId?})` => opaque one-use native approval ID
- `get_capabilities` => JSON platform object
- `get_directories` => JSON platform directories
- `initialize_repository({repository, keyFile, approvalId})` => summary
- `backup_folder({repository, source, keyFile, approvalId})` => operation ID summary
- `list_snapshots({repository, keyFile, approvalId})` => snapshot array (or documented object)
- `restore_snapshot({repository, snapshotId, destination, keyFile, approvalId})` => operation ID summary
- `operation_status({operationId})` => `{id, kind, state, startedAt, finishedAt, result, error}`
- `operation_history` => bounded local operation receipts, never automatic retry authority
- `discover_applications` => bounded read-only discovery, not backup permission

Key files selected through a native dialog; key bytes never enter the webview.
The backend's native confirmation authorizes the exact action and path scope and
pins identity proofs. An HTML confirmation or path string alone is not authority.
Approvals are opaque, one-use, expire after ten minutes, and are bounded to 32
pending entries. Changing action/paths/snapshot requires a fresh approval.

Backend serializes conflicting mutations, enforces one active mutation at first,
and runs engine, admission/receipt, and history work off the UI thread. Read-only
execution and native dialogs have separate bounded admission. Quit handlers must
not wait on a filesystem-held mutex. Worker lifetime is owned; this foreground
preview does not install an independent background daemon or local RPC service.
Backend reports unsupported features honestly. UI does not fake
progress/events/data. No web/network fallback, mock repository, cloud deletion,
remote-machine controls or production state access.

## CLI (parent-owned)

Expose capabilities/directories, init with external key-file, backup, list, restore. No source or cloud deletion commands. No plaintext key in stdout/arguments.
