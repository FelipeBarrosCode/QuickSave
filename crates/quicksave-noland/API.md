# Native engine handoff

The binding scope is `docs/FULL-SHARED-STORAGE-CONTRACT.md`.
`ProviderAccess` comes directly from `quicksave_state`. Private keys, provider
sessions and native authority objects never cross renderer IPC.

- `open(data_dir, home)` creates only `data_dir/shared-storage/{state,run}`.
  No live No Land state, OS vault, RPC listener, discovery or process launcher.
- `register(software)` accepts
  `{id,appId?,name,roots:[{id?,path,role?,identity?,allowedFiles?}]}`.
  Call only with the service's native-approved, persisted root identities.
  The service must re-register persisted approved software after opening.
  `identity:{device,fileId:[low,high]}` is checked against the pinned actual root;
  the second Windows file-ID word must not be discarded.
  `allowedFiles:null` means the approved whole tree; a nonempty array means
  **only those parent-directory leaves**, without enumerating siblings. The
  allowlist is included in the frozen root fingerprint and does not change the
  stable root ID when a new native grant adds a leaf.
- `upload_captured_guarded(access,selection,guard,controller)` is the production
  service path. `selection` is the original metadata-only Tracker work;
  `controller` pages real frozen nodes and receives an actual source-produced
  `PreparedCaptureReceipt`. The source performs stable capture, hashing, chunk/
  pack reuse, compression, encryption and publication. The service never hashes
  the tree first to predict that receipt. See [`PUBLICATION-GUARD.md`](PUBLICATION-GUARD.md).
  Whole/empty snapshots require a typed full-scope owner, exact baseline/omission
  grants and pinned roots. An empty JSON array alone grants nothing.
  `upload_guarded` is retained for legacy prehashed work, not as a service fallback.
- `verify_capture_completion(operation_id,binding)` is a once-per-completion Saved
  barrier. It verifies the real device-bound capture and authenticated post-
  `COMMITTED` result after worker drain. A completed DB row or prepared receipt
  alone cannot acknowledge Tracker work. Ordinary status does not fetch credentials
  or contact a provider.
- `preview_restore(access,{bundleId,appId,destination,fileIds?,mode})` freezes
  authenticated content, root layouts, destination identities and conflicts.
  `restore_preview_scope(id)` exposes its exact native consent scope.
  `download_guarded` spends only `{restorePreviewId,overwriteAcknowledgement}`
  plus native-held operation/path proofs; it does not accept replacement paths
  or file selections. Existing bytes and root metadata require exact conflict
  approval. Real root changes are not counted as fictitious files.
  Native layouts can reconstruct package directories/resources/confined links;
  readiness stays `files_only` or `reconstruction_unverified`, never an invented
  Runnable/signature/dependency result. Original absolute source hints are ignored.
- `catalog_projection` returns bounded native catalog evidence for the service's
  revision-bound apps/history/instances/pending-deletion cache. `files` takes
  `{bundleId,appId,cursor?,limit?}` and returns `{files,nextCursor}`. For local
  files call `software_files({softwareId,cursor?,limit?})`.
- `preview_delete` takes `{bundleId,appId}` and returns a sanitized frozen
  `{previewId,dependentBundles,...}`. `delete` takes
  `{previewId,acknowledgeDependencies}`. Native confirmation remains the
  service/ticket layer's responsibility; dependency acknowledgement is checked
  separately against the frozen source preview.
- `status`, `recent`, `cancel` return bounded Activity DTOs. A terminal DB row is
  projected as finalizing while the actual worker still owns the operation.
  Receipt-backed recovery uses an authenticated `NativeFrozenWork`, original
  source submission/checkpoint/receipt and fresh native publication authority;
  never a new capture under an old work ID. Missing legacy frames fail explicitly.
  Ordinary `retry_guarded` must not substitute for that recovery protocol.
  Deletion reattachment loads only the existing authenticated pending
  `FullDeletionPlan`; it requires the original persisted dependency
  acknowledgement and never expands a new plan automatically. If no frozen plan
  was published before interruption, a new preview/native confirmation is needed.
- `SourceRuntime::discover().await` / `NativeEngine::preflight().await` verifies
  an absolute installed rclone executable, version >=1.76 and required flags.
  No PATH modification. Missing/old tools are explicit errors.
- `probe(&ProviderAccess).await` (alias `health`) returns
  `{providerId,canList,canRead,repositoryAccessible,repositoryEmpty,keyVerified,
  observedAt,evidence,error}`. It performs the actual source rclone root listing,
  catalog-head stat and authenticated source catalog read. Without a head, all
  source repository namespaces must have no objects; a missing head with
  existing objects is recovery-required, not an empty/new repository.
  No probe writes,
  creates a repository or acquires a write lease. Empty repository:
  `canList=true`, `repositoryAccessible=true`, `repositoryEmpty=true`, but
  **`canRead=false` and `keyVerified=false`**: no encrypted object exists to prove
  read/decryption. Never describe that as a verified key/backup read.
  Service/store connection-state rule:
  `canList && repositoryAccessible &&
  (repositoryEmpty === true || (canRead && keyVerified))`.
  An optional `authenticated` field should mean the existing encrypted-catalog
  proof (`canRead && keyVerified`), **not** merely a configured/empty provider.
  Preserve `evidence` and `observedAt` when recording the report.

## Tracker/service selection contract

Bridge file IDs are now exactly `quicksave_tracking::file_id(root.id, relative)`,
including the `file-` prefix and length-prefixed BLAKE3 input. A new source
`$NOLAND_CUSTOM_ROOT:quicksave-v1-<hex appId>-<hex rootId>` stores those stable IDs
in the **existing No Land custom-root mechanism**, not a new storage format.
For imported original No Land logical roots, the logical token is the root ID.
Cloud `FileItem.rootId` remains the source logical token; its `id` is the same
tracker-compatible identity for native-created bundles.

Pass `Tracker::root_authority` / `prepare_upload_scope` approved root objects intact,
including `identity` and `allowedFiles`, to `register`. Do not project them to
`{path}`. Keep the private software ID, installation `appId` and canonical
`sourceIdentity.app_id` distinct. Pass original work/file IDs unchanged to
`upload_captured_guarded`; no retry widens to newly appearing files.
Call Tracker `complete_upload` for the original work/generation only after real
authenticated committed completion. Older immutable bytes may be saved while
newer local changes remain dirty.

Uploads/downloads/deletion are the real source managed operations. An accepted
submission returns `{operationId}`. Poll `status`; submission is not completion.
Progress and errors are allowlisted, not raw engine detail/diagnostic JSON.
Windows has a separate native host over the same storage/CAS/pack/restore
libraries; it does not link the Linux StateAgent/collector. Cross-compilation is
not Windows runtime or whole-feature acceptance. See `src/windows/README.md`.

## Native restore recovery safety gate

Native boot **never invokes** upstream path-based restore recovery, including
forged/legacy v3 journals with no operation record. It retains all artifacts and
marks unfinished restore operations interrupted, not completed. Native failure/
cancellation retains outputs and artifacts when ownership cannot be proved.
`restore_recovery_scope(original_id)` and
`recover_restore_local(selection,consent_gate)` use authenticated original journals
and exact destination ownership. Recovery is local-only: no provider connection,
helper, repository key or new download. A successful rollback does not turn the
original failed download into completed. Retained/unverifiable artifacts remain
visible and block unsafe cleanup/retry.

Native partials are precreated/journaled before plaintext is written. Their open
ownership is tracked separately from first assembly admission: unfinished-file
counters equal the count/sum of started, incomplete files, including zero-byte
placements. Checked transitions reject inconsistent/overflowed counters rather
than saturating them, and successful completion requires both counters to be
zero. Existing handle, hasher and verification/publication budgets are unchanged.

## Native SQLite admission and durability

Native boot uses `StateDb::open_native`, not the upstream named-path default.
The main DB is precreated/pinned as an owned single-link 0600 regular file below
a pinned private 0700 directory. Existing main, `-wal`, `-shm` and `-journal`
paths must pass native no-follow type/ownership/mode/link/identity checks before
SQLite I/O. Main writer and read-only monitoring connections use
`SQLITE_OPEN_NOFOLLOW`; native receipts require actual WAL + `synchronous=FULL`.
Directory/file pins are rechecked across initialization and DB lock admission.
The bridge additionally checks its held root identities and native file privacy
before/after boot. Existing insecure files (including 0644 DBs) fail explicitly;
there is no global umask change or chmod repair.

On Unix this is **not a custom SQLite VFS**. SQLite still opens/manages named sidecars;
pre/post checks do not prove every hostile concurrent rename race impossible.
The private directory and single-native-engine lock remain required. Sidecar
replacement/removal during admission fails closed, even if recovery would
otherwise have been possible. Non-native source `open` retains its original
NORMAL-synchronous/default-opening behavior. No new platform/power-loss
acceptance claim follows from these flags.

Windows instead uses the audited native VFS admission with full file IDs,
current-user ACLs, pinned main/sidecar handles and checked WAL/FULL durability.
No fallback to an unprotected default VFS is allowed.

## OAuth rotation safety gate

OAuth storage requires the installed native refresh/CAS/recovery authority.
Explicit session finish reads back rotated credentials before private cleanup,
checks the original provider/account/generation and propagates vault failures.
An uncertain finish remains failure with retained recovery artifacts, never
success from a best-effort Drop callback. Revocation/disconnection cannot be
undone by a late refresh. `preflight` reports the actual installed capability;
PKCE tokens or an available adapter alone do not establish a connected account.

No live provider account, production key-vault entry, remote operation or native
Windows/Linux packaging acceptance was exercised in development.
