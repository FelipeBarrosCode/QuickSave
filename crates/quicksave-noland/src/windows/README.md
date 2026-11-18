<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Windows engine integration contract

This is the Windows composition of the audited No Land portable libraries, not a
port of its Linux collector, daemon, provisioning or lifecycle. New code is
GPL-3.0-only. Protocol references are the active fork derived from No Land
`e81238a7536aae201540956ce76981364fd36595`; upstream notices remain unchanged.

## Composition wiring

`quicksave-noland` Windows dependencies: `blake3`, `chrono`, `uuid`, `tokio`
(`sync`, `rt-multi-thread`, `time`, `process`, `io-util`, `macros`), `sha2`,
`hmac`, `async-trait`, `bytes`, `noland-state-core`, `noland-state-db`,
`noland-crypto`, `noland-cas`, `noland-pack`, `noland-storage`,
`noland-rclone-adapter`, `noland-restore`, `noland-snapshot`. **No `noland-state-agent`,
`noland-observer`, Linux collector or eBPF dependency.**

`noland-state-db` Windows dependencies additionally require `anyhow` (for the
platform adapter's error type) and `quicksave-platform`; no Windows SDK dependency
is needed in that crate because its admission VFS delegates native I/O to SQLite
and the protected-DACL platform implementation. A narrow `kernel32` query reads
the full ID from each pinned metadata-only handle.

`windows-sys` requires `Win32_Foundation`, `Win32_Storage_FileSystem`,
`Win32_System_LibraryLoader`, `Win32_System_Threading`, `Win32_System_IO`.

`Cargo.toml` now has Unix-only StateAgent/RPC dependencies and separate portable
Unix-or-Windows / Windows-native dependency groups. `lib.rs` exports
`windows::{NativeEngine, SourceRuntime, native_capture_root_token}` and reexports
`windows::capture as capture_control` under Windows. `unsupported` is selected
only by `not(any(unix, windows))`; Unix child/source symbols and the public
`catalog_control` / `operation_control` modules remain unchanged. No Windows
export brings `noland-state-agent`, an observer, or eBPF into that target's graph.

Public engine methods retain the original Unix bridge signatures:
`open`, `register`, `preflight`, `probe`, `health`,
`catalog`, `catalog_page`, `catalog_projection`, `files`, `software_files`,
`upload_guarded`, `retry_guarded`, `verify_capture_completion`,
`preview_restore`, `restore_preview_scope`, `download_guarded`,
`restore_recovery_scope`, `restore_recovery_available`, `recover_restore_local`,
`retry_restore_guarded`, `preview_delete`, `delete`, `status`, `recent`, `cancel`,
`retry`, `reattach`. Unguarded `download` explicitly rejects missing frozen
preview/consent instead of using a separate create-only fallback.
`shutdown` additionally drains and joins native work.
The one-pass native path also supplies `upload_captured_guarded` with the same
controller trait/scope/node/receipt facade as Unix, including the Rust-only
`NativeFullScopeAuthority` / `FullScopeBinding` callback. Widen the service's current
Unix-only capture dispatch/imports to Unix-or-Windows when wiring it. To resume
metadata-captured work, call `reattach_captured(access, id, original_controller)`
then `retry_guarded`; plain `reattach` explicitly rejects that work instead of
silently falling back to predicted hashes. The original native tracker must still
own its frozen scope/accepted receipt; after loss of that authority, start a new
approved work item rather than manufacturing a controller.

The native service factory is also identical:
`with_workspace(self, quicksave_state::WorkspaceStore) -> anyhow::Result<Self>`.
It lazily composes current provider authority, device-key operation/recovery
HMACs and the shared operation-bound `NativeProviderLifecycle`. The module cfg is
now Unix-or-Windows. Windows uses `prepare_native_provider_context` to recover
retained app-owned handoffs and reacquire fresh native access without changing the
original provider/account/root/key/authority scope. No source No Land vault is
read. Registrations are invalidated only after real workers/session finalization
have stopped, never while a child might still need its checked token handoff.
Operation/recovery signing and retained-document verification use
`operation_mac_existing` / `recovery_mac_existing`. Missing existing device
authority fails rather than creating a replacement key. The consent/vault owner
creates that key at its existing grant boundary, not during recovery.

The SQLite `src/windows.rs` is selected as `store::native` under Windows.
`StateDb.native_files` and all writer/browse lock guard checks now use
Unix-or-Windows cfgs; only other platforms get the explicit unsupported
`open_native`. Its Windows-only
dependency on `quicksave-platform` uses the repository path
`../../../crates/quicksave-platform`. The main file/sidecars must use protected
current-user DACLs, real 128-bit IDs, and real flushes. WAL + FULL is verified,
not inferred from successful configuration.
Source data handles intentionally deny write sharing. SQLite/engine-owner pins
therefore use metadata/ACL-only handles with read/write sharing but no delete
sharing; retaining a source `read_file` handle would block their legitimate writes.

## Shared native seams

* Platform: `SafeRoot` pinned identities/metadata/read/create-new,
  `ensure_private_directory`, `verify_private_file`, `PrivateDirectory`
  lock/read/replace/flush as published in `quicksave-platform/README.md`.
* Disk admission now uses `GetDiskFreeSpaceExW` on the final pinned directory's
  actual `\\?\Volume{GUID}\...` path, not C:, a drive-letter guess or total free
  space. It returns quota-aware caller-available bytes and the actual native
  64-bit volume ID, retains/checks all full 128-bit ancestor IDs, bounds paths and
  handle count, and rejects traversal, DOS devices, streams, mapped/UNC drives,
  reparse points and non-NTFS/ReFS filesystems. Missing descendants use the nearest
  verified existing directory; access errors do not become absence. Unix
  accounting/reservation behavior is unchanged.
* Portable pack: `pack_chunk_files` (actual FastCDC/NLPK v2 pipeline). The shared
  FS adapter owns Windows CAS/pack creation, confinement, stable-handle metadata
  and actual durability. The original Unix `File::open(dir)` flush cannot be used
  as a Windows success fallback.
  `noland-cas::{CasLease, CaptureSegments}` likewise must retain:
  protected native creation and native directory barriers must cover `.leases`,
  sealed `.segments`, CAS object publication and owned-lease release.
* Restore: the restore agent owns `noland_restore::native` and the portable
  authenticated selective-restore executor. This module consumes that interface,
  never the Unix restore transaction implementation.
  The engine consumes the exported `NativeRestorePreview`,
  `NativeRestoreControl`, `NativeRecoveryAuthority`, `recover_native_restore`,
  and `RestorePlan::into_shared().with_native_control(...)` APIs.
  Windows directory-link type is retained without traversal in
  `manifest.environment.windowsSymlinkMetadata` entries
  `{logicalRoot, relativePath, targetIsDirectory}` (also indexed by the logical
  file ID in `native_symlink_directory_hints`). The Windows restore backend must
  consume the exact matching hint when recreating a native directory symlink;
  a dangling link's type must not be guessed from its target.
* Transport: source guarded rclone session/configuration and packaged executable
  resolver; OAuth refresh sinks are private Rust callbacks, never JSON/IPC.
  Credentials must be reattached from native state for retry and never persisted
  in operation rows, frozen plans, or diagnostics.
  The compiled trusted SHA-256 pin authenticates held bytes; their BLAKE3 is then
  passed to `pin_native_rclone_resource` before any version/flag command. The
  shared source independently checks the exact full ID and compatible PE type.
  Helper input is bounded to 128 MiB. There is no PATH/download fallback.
  Pack upload/download observers check native authority before transport retries
  and completion; ordinary progress/chunks use only the atomic cancellation bit.
* Publication: the service's native `Arc<dyn Fn() -> anyhow::Result<()> +
  Send + Sync>` is checked at admission and every metadata commit/publication
  boundary. It must reload device-HMAC authorization, not trust a cached enabled
  bit. UI monitoring never invokes that callback. Historical publication and
  current Tracker cleanliness are separate.

Additional native wiring methods:

```rust,ignore
type NativeAuthorityGuard = Arc<dyn Fn(&str, bool) -> anyhow::Result<()> + Send + Sync>;
type NativeOperationAuthority = Arc<dyn Fn(&[u8]) -> anyhow::Result<[u8; 32]> + Send + Sync>;
engine.install_authority_guard(guard)?;
engine.install_operation_authority(device_operation_mac)?;
engine.install_recovery_authority(Arc<dyn noland_restore::NativeRecoveryAuthority>)?;
engine.bind_credential_sink(provider_id, noland_storage::NativePrivateCredentialSink)?;
engine.shutdown().await?; // joins all actual native owners
```

The authority guard receives `(provider_id, requires_write)`. Read-only health,
catalog and restore also require current provider authority, not cached
credentials. Upload's existing operation-specific publication guard is checked
in addition. Retry consumes one fresh, bounded-lifetime `reattach`. Failed work
retains no access cache. Successful captured uploads retain bounded original
completion-only access as described below; it cannot authorize transport/retry.
Prefer `with_workspace` over these manual injection seams in production.

Read-only catalog/probe access performs no repository mutation. A restore needs
the source repository's authenticated maintenance/read-lease writes; a truly
read-only remote/profile cannot bypass this admission fence. The engine reports
that actual permission failure rather than inventing a safe concurrent restore.

## Implemented optimized paths

* Complete approved application graphs retain full `AppIdentity`/Steam/launcher
  metadata and the native role classifications (including exact-file-only
  `installer`, which never runs an installer). The parent's authenticated
  `captureSource.selectionKind:"full_scope"` AND the actual installed Rust
  `NativeFullScopeAuthority` are required for complete mode;
  `"selected_nodes"`/missing coverage remain custom even if all visible rows
  were selected. Exact current metadata is verified, including confined link
  type bits. UID/GID are absent and IDs are not synthesized from `fs::Metadata`.
  Held-handle checks use `SourceMetadata::from_file`.
  Canonical source IDs (e.g. `steam:480`) remain the No Land catalog/manifest app
  ID; tracker installation IDs such as `steam:480@native-install-id` are frozen
  separately as `software_instance_id`. Several actual instances may share one
  canonical product, with independent root IDs, publication bindings and status.
  The opaque workspace software ID is a third identity; Tracker evidence
  `softwareId` binds that record, while `trackingScope.appId` binds installation.
  Full-scope evidence uses the tracker's original raw lowercase 64-hex digest
  schema; it is not prefix-stripped, normalized or re-signed. Native root and
  complete inventory checks are independent of the browser index. Genuine empty
  scopes require the original live authority, exact roots/stamps and empty native
  inventory; `Some([])`, missing nodes, unknown reparse entries, read failures or
  a coverage marker alone never grant empty/wildcard authority. Authenticated
  parent omissions must match signed baseline/deleted-node evidence; tombstones
  retain the actual parent bundle and do not delete local or cloud history.
  The authenticated `quicksave_native_root_layouts` frame and receipt
  `sourceRootLayouts` retain actual kind/leaf/role and canonical app vs instance.
  Root fingerprints use the shared v3 kind/leaf/role contract with full 128-bit
  native identities. Windows currently registers real directory anchors, with
  manual files confined by exact leaf allowlists; it never fabricates a file-root
  identity from its parent.
* Small files share 1,024-file native capture/receipt groups and actual leased
  CAS segments; they do **not** each get a remote pack transfer. Large files emit
  bounded waves into the same FastCDC/CAS/NLPK-v2 zstd pipeline. Source capture,
  packing and adaptive provider transfers overlap within shared CPU/memory,
  process-count and ciphertext-byte budgets.
* Authenticated per-wave and grouped stable-file receipts plus SQLite transfer
  completion records resume original pack IDs without rehashing complete
  captures. Same-stamp, tracker-hash-verified unchanged files reuse authenticated
  live pack references; watcher silence is not proof. History is additive.
  Metadata-only capture takes hashes from this actual CAS pass, then hands an
  engine-private receipt to the native tracker before any COMMITTED/LATEST.
  Reuse on that path additionally requires the same opaque tracker instance/gap
  epoch, software instance and exact root bindings; a restart/overflow/None epoch
  forces content capture. Publication checks do not run per chunk or on UI polls.
  Every local receipt (including prepared manifests, frozen reuse maps and
  upload preparation records) has a single create-new frame containing both the
  device HMAC and original No Land metadata envelope. A repository key alone
  cannot manufacture captured hashes on retry. Receipt caches use weak references.
  Supported mtimes are converted with checked signed nanoseconds (including
  negative boundaries); an out-of-range time fails rather than becoming None.
* `catalog_projection(&ProviderAccess)` uses the shared rich projection of the
  actual authenticated `CatalogDocument`, pending full-deletion plans and real
  freshness. Provider/metadata I/O metrics are separate private diagnostics,
  never extra Service projection fields or revision/hash inputs.
  Heads, modes, instances, source/parent
  lineage and pending identities are revision-bound. Cached details come only
  from authenticated manifests read during explicit file/restore requests or
  COMMITTED readback, never history-wide per-bundle reads on polling.
  Original deletion selections have a native device-MAC binding where known;
  unknown/foreign selections and dependencies remain `None`, never guessed.
  Projection/cache accounting is capped at 32 MiB aggregate and 100,000 entries;
  shared storage's independent bounded metadata-decode limits still apply.
  Only overlapping refreshes coalesce; there is no TTL-cached "latest".
  `catalog_page` clones only its requested bundle slice with revision-bound
  cursors; large app/instance/pending metadata appears only on the first page.
  All projections have `authoritativeForExecution:false`.
  `status` uses SQLite monitoring projections, never grant/vault callbacks,
  full-tree rescans or credential serialization.
* `verify_capture_completion(original_id, binding)` accepts only the real compact
  Tracker binding (128 KiB maximum). The worker reads the genuine COMMITTED UUID
  and shared AEAD-decoded manifest before persisting device-MAC/No Land-envelope
  `capture-committed.enc`; `capture-drained.enc` is created only after transfers,
  session finalization and credential-registration invalidation have succeeded.
  The barrier requires the original plan/repository/access, actual WorkspaceStore
  `tracking_capture_receipt` MAC, source expected-manifest envelope and both
  receipts. A forged `COMPLETED` row or prepared manifest is insufficient.
  The user authorized fresh native grant-nonce checks at this explicit one-time
  barrier, including revocation; it fetches no provider credentials/repository
  keys and performs no provider/network/helper access or live-source file scan.
  Completion access is held in original Rust `Arc`s, at most 128 entries / 64 MiB
  of session strings, cleared on clean shutdown. Missing/evicted access or proof
  requires explicit reconciliation, not a Saved fallback. This method never
  calls `mark_saved`; confirming older immutable bytes cannot clean newer local
  mutations. A cached proof still requires fresh current grant/revocation checks.
* A nonblocking native `LockFileEx` owner and scoped repository admission fence
  join all actual work before shutdown. Prepared plans have both No Land envelope
  authentication and a separate workspace device-HMAC receipt.
  A failed session/credential finalization is sticky: new admission and clean
  shutdown confirmation fail until native recovery/restart, even if the Rust
  queue is empty. Unconfirmed native reaping is not reported as clean shutdown.
* Native restore workspaces use real UUID attempt directories and the source
  `restore-native.v1.{json,log}` authenticated journals, not the legacy path
  journal. Verified recovery retains old journals and can start a fresh bounded
  attempt of the same frozen selection; retained/unverifiable artifacts block
  rather than authorize cleanup.
* Rich restore uses the same `NativeRestorePreview` / `NativeRestoreControl` /
  `restore_pipelined` / authenticated native journals, not another file loop.
  Preview freezes the authenticated revision, selection, shared native layout,
  conflicts and full-ID destination. Spend accepts only the original ticket,
  separate exact overwrite acknowledgement and exact native path proof. Incoming
  destination/file/mapping edits are rejected. The same control `Arc` remains in
  the joined worker; payload/freshness and clean committed completion are checked
  by the shared engine. No giant preview clone is made for durable serialization.
  Provider binding uses the real `EphemeralRcloneSession::storage_identity()`,
  `ProviderAccess` ID/read-only policy, native authority revision and repository
  key fingerprint, never token/config bytes.
* A separate native-private, bounded, create-new device-MAC recovery document
  binds the complete original preview and provider scope. Scope and UI-hint
  queries perform metadata-only reads, no vault/provider/rclone calls. Local
  recovery authenticates the existing device key at spend, uses only the original
  operation UUID's recorded native attempt/journal, and owns cleanup synchronously
  under an expiring native consent lease. Shutdown cannot claim clean while that
  local owner is active. No recorded workspaces means **not recovered**, never
  fabricated success. The two clean native journals remain additive audit history.

The native Windows tests use temporary fixtures for SQLite WAL/FULL/ACL
admission, nonblocking engine ownership, cached file paging, and actual shared
small-file CAS/NLPK deduplication. Additional fixtures cover canonical Steam IDs
versus multiple installations, metadata-only full-ID stamps, actual CAS-produced
hashes, device-MAC receipt forgery/AAD rejection, publication-key classification,
retry/cancellation callback boundaries, and SQLite clone/VFS/WAL ownership.
`full_scope_tests.rs` adds raw digest, actual empty-root, native-owner revocation,
manual sibling confinement, independent completeness and high-ID/metadata proof
fixtures. Its authority is explicitly synthetic; the parent's real Tracker/
service controller fixture is still required. `completion_tests.rs` additionally
composes real Tracker/WorkspaceStore/MemoryVault, CAS/NLPK and LocalStorage
COMMITTED formats, with distinct three-way IDs, forged completion/envelope
rejection and nonce-only/no-current-file barrier assertions; these latest
fixtures have not been executed. `catalog_tests.rs` covers typed source history,
authenticated pending plans, unknown versus device-bound requested scope,
revision changes, paging and aggregate cache bounds. `restore_tests.rs` adds exact
acknowledgement/ticket/digest/full-ID tests and a helper/provider/key-free local
scope/recovery fixture, including missing existing device authority.
Disk fixtures cover existing/missing descendants, real volume identity, existing
file parents, aggregate same-volume requests and invalid/remote path rejection.
The reparse fixture is explicitly ignored unless native symlink privilege /
Developer Mode is provided; it is not an acceptance pass.
Portable plan/crypto tests are in `plan.rs`; the parent can include that module
under host `cfg(test)` after adding `hmac` and `sha2` test dependencies.
No test or benchmark has been run by this agent; only Rust formatting/syntax
parsing has run. No speed result is claimed.

Still requiring parent/shared-agent validation before Windows acceptance:
the shared native filesystem/restore/credential runtime behavior, service capture
dispatch, the real Tracker/source-controller fixture, latest bridge target
compilation and isolated native fixtures. The parent reported GNU cross-checking
the shared platform/snapshot/CAS/pack/DB/storage/restore libraries successfully;
that is **not** a native execution result or a pass for these latest bridge edits.
Windows `SourceRuntime::discover` expects the packaged
`resources/rclone.exe` plus the build-time trusted
`QUICKSAVE_WINDOWS_RCLONE_SHA256` digest; a missing pin is a packaging error, not a
PATH/download fallback. Actual NTFS/ReFS volume flush permission may require
elevation; failures propagate.

The materialized `ServiceObservationSource`/application graph remains an
untransferred Windows integration gap; API parity here does not establish whole
Windows feature acceptance. Runtime capability/acceptance fields remain explicit
about that gap and pending full-scope/native validation.

Shared-restore integration note: manual-leaf root captures intentionally have
`allowedFiles` and `metadata:null`, not fabricated parent ownership/metadata.
The actual signed `rootCaptures` now include
`metadataScope:{version:1,kind:"manual_leaves_only",sourceRootId,sourceRootIdentity,allowedFilesDigest}`.
The identity retains the device and both file-ID words; the digest is raw lowercase
BLAKE3 of the sorted nonempty JSON allowlist. Null alone is not authority.
Manual deletion-only revisions require actual prior authenticated deleted IDs
and source-parent lineage; they cannot publish an invented empty parent.
Whole-revision restore handoff preserves those tombstones as history, not local
deletion consent. Shared parser/runtime interop still needs owner validation:
the producer's workspace ID is not its installation ID, and provider identity
is on the original full proof, not `trackingScope`. The service must count real
root changes separately in empty-root conflict summaries, not invent file rows.

The parent's strict Windows snapshot comparison intentionally rejects
`SourceMetadata::from(&fs::Metadata)` (it cannot supply a full Windows ID).
Shared CAS/pack/transport adapters must use `SourceMetadata::from_file` / native
file-state helpers rather than weakening that comparison or filling in a
synthetic high ID word. This engine's live-source comparisons use `from_file`
and check agreement with the platform's native 128-bit stamp.

## Static checks performed

No Cargo, target build, test execution, package-cache mutation, lockfile edit,
staging, commit, live provider/vault access or packaged-helper execution was run.

* Parsed both edited Cargo manifests and resolved all 14 explicit path
  dependencies inside QuickSave (the DB platform dependency is
  `../../../crates/quicksave-platform`, **three** parent components).
* Walked the Windows x86_64 local path-dependency closure from TOML: 12 packages,
  no StateAgent/RPC/observer/eBPF path. This is a static graph review, not Cargo
  target resolution or compilation.
* Ran explicit `rustfmt --edition 2021 --config skip_children=true` over assigned
  Rust paths; child modules owned by other agents were not formatted.
* Final `rustfmt --check` and scoped staged/unstaged `git diff --check` are the
  allowed syntax/whitespace validation. Added fixtures remain unexecuted.

## Safety / acceptance

Local plans are authenticated, versioned, bounded and bind provider, operation,
exact selected logical paths, native root identities, expected stamps/sizes and
original bundle/commit IDs. Legacy prehashed work also binds expected hashes;
metadata-only work binds the real hashes in device-authenticated capture receipts.
Retrying resumes that plan; it never replaces it by a fresh selection.
Windows metadata retains volume + **both** 64-bit halves of the
128-bit ID; UID/GID are absent, not synthetic Unix values. Source data is never
removed. History remains additive. Explicit full deletion calls the original
authenticated closure/receipt protocol under repository admission.

Only native Windows tests with isolated temporary fixtures can establish Windows
filesystem behavior. A macOS build, target check or portable test is not Windows,
Linux, provider, signing or packaging acceptance. This agent runs no Cargo jobs,
real accounts, production key-vault entries, network probes or remote provisioning.
