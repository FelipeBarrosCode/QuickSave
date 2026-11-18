<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Source/API provenance: No Land e81238a7536aae201540956ce76981364fd36595. -->
# Whole Shared Storage: optimization parity and executable gates

**Whole optimized Shared Storage is the requirement. Passing a folder-copy or
QuickSave-local-format test is not evidence of that requirement. Optimization
parity is not claimed by this document.** The binding scope is
[FULL-SHARED-STORAGE-CONTRACT.md](FULL-SHARED-STORAGE-CONTRACT.md).

Reference: the read-only pinned source
[`upstream/no-land/docs/shared-storage-dev-optimizations.md`](../upstream/no-land/docs/shared-storage-dev-optimizations.md),
including its unchanged/one-save capture, streaming restore, finalization,
query-only browsing, observation-gap and resource-admission sections. Its
historical cloud/debug timings are **not QuickSave measurements** and are not
copied into this benchmark.

## What the new gate actually runs

[`native_optimized_pipeline.rs`](../shared-storage/crates/noland-testkit/tests/native_optimized_pipeline.rs)
uses the active source fork, not a reimplementation:

```text
fresh private temporary root
  -> explicit AgentConfig(native_host=true, converge_complete_backups=false)
  -> StateAgent::native_register(pinned, approved synthetic roots)
  -> frozen metadata-only NativeSelection + installed native capture sink
  -> native_set_publication_guard (separate from source receipt/root revalidation)
  -> backup::run_backup(Custom selected nodes / authorized full scope, Automatic)
  -> source FastCDC/BLAKE3/CAS/pack/upload/commit/checkpoint/claim-release
  -> source read_committed_manifest + read_pack_index
  -> prepare_restore + native_restore_roots
  -> NativeRestorePreview + NativeRestoreControl
  -> restore_pipelined + independent byte/hash verification
```

`NativeLocalStorage` is an explicit **test alias of
`noland_storage::LocalStorage`**, not a new transport or file format.
`NoLandNativeConfig` is a **test-local config builder** around the actual
`AgentConfig`; it never searches for a production data directory. The counting
provider delegates actual reads, writes, fsyncs, immutable checks, exact
repository-claim cleanup, streaming and targeted-upload capabilities to that
source provider. It does not invoke rclone or install a fake executable.

All app, HOME, source-native data-root, CAS, provider and restore paths are
synthetic, disjoint children of one newly created private directory. No account,
No Land state, system credential vault, remote machine, process launch, Linux
observer/BPF start, provisioning code or production rclone configuration is used.
Consent and recovery authority are fixture-owned native objects; they are never
decoded from incoming JSON. Recovery uses an independently generated test key.
Publication, expected-content, no-follow, root-identity, admission and durability
checks remain enabled. Only exact authenticated activity claims may be cleaned;
there is no payload/history retirement.

### Workload and ceilings

- Default: **64 MiB / 1,000 files**. Three quarter-payload assets include an
  independently generated duplicate and compressible content; remaining saves
  mix distinct and compressible small files.
- Explicit upper limits: **256 MiB / 4,096 files**. Generation streams through one
  **64 KiB** buffer. No existing game/app tree is copied and no 34 GB workload is
  inferred from a file count.
- Conservative scratch admission: `8 × payload + 256 MiB` available space. This is
  an admission estimate, **not** a measured process disk peak or a general storage
  quota. Owned temporary trees are removed only if their original identity holds.
- First, unchanged, bounded-prefix-changed and one-file-subset captures; original
   all-selected-file restore, identical restore, and selective restore from a multi-pack
  revision. Old revisions remain authenticated/readable.
- The first ordered restore requests one stream so zero extra readback is a
  deterministic algorithmic gate, not a scheduling lottery. Native CPU/memory and
  provider admission can reduce, never raise, requested worker/queue bounds.
- A separate simulation exercises the **real** `AdaptiveConcurrency::for_streams`
  controller: four concurrent admitted jobs, rate-limit feedback reducing new
  admissions to two, retained in-flight permits, and complete drain. It is labeled
  `simulation: true`; it measures no provider/network throughput.
- A DB-only stress test stores **250,000** server-only plan entries once, then
  runs 100 actual `operation_monitoring_snapshot` reads. Replies remain at most
  4 KiB, acquire no writer lock, and cause zero source reconciliations. This is
  not a claim that QuickSave's entire JS IPC plan boundary has passed acceptance.

## Execute without concurrent Cargo builds

The coordinating parent owns **all Cargo execution**. Build/run commands below
are acceptance instructions, not a record of builds performed by this subtask.
Use one build lane and isolated synthetic fixtures:

```sh
cargo test --locked --manifest-path shared-storage/Cargo.toml \
  -p noland-testkit --features noland-state-agent/native-host \
  --test native_optimized_pipeline --no-run --message-format=json
```

Take `executable` from that test's compiler-artifact record. The runner deliberately
requires an **already-built integration-test binary**, so it cannot start another
Cargo build or accidentally select `quicksave-cli`'s local format:

```sh
python3 scripts/bench_native_shared_storage.py \
  --binary /absolute/path/to/native_optimized_pipeline-<build-hash>
```

The runner clears the inherited environment, sets synthetic HOME/XDG/app-data/run
paths, bounds both subprocess pipes to 2 MiB, accepts exactly one bounded JSON
sentinel, and measures elapsed time with a monotonic clock. Its 30-minute runaway
guard is not a speed/performance pass threshold. Output from failing subprocesses
is withheld instead of copying possible private diagnostics.

To record the currently guarded full-rehash baseline while receipt wiring is
incomplete, make that limitation explicit:

```sh
python3 scripts/bench_native_shared_storage.py \
  --binary /absolute/path/to/native_optimized_pipeline-<build-hash> \
  --allow-revalidation-baseline
```

This reports `optimizedParity: false` with a specific gap. **Without that flag,
full rehashing on unchanged/one-file-change capture fails the optimization gate.**
The flag cannot waive incorrect bytes, missing durability, marker-order failure,
unbounded resources, lost chunk reuse, repeated/unrelated pack downloads, or
no-event-clean safety regressions. An explicit larger run uses `--mib 256`;
larger requests are rejected.

Small normal regressions, and the expensive opt-in workload, are separate tests:

```sh
cargo test --locked --manifest-path shared-storage/Cargo.toml \
  -p noland-testkit --features noland-state-agent/native-host \
  --test native_optimized_pipeline -- --test-threads=1

python3 -m unittest discover -s tests -p test_native_bench_helpers.py -v
```

## Metrics: observed, estimated, unavailable

### Recorded isolated run

The parent reran the default 64 MiB / 1,000-file ignored workload using the freshly
built actual source integration-test binary through the bounded isolated runner.
It passed in **46.57 s** of measured fixture work (**46.85 s** runner time). The
raw receipt is
[`artifacts/native-shared-storage-benchmark-latest.json`](../artifacts/native-shared-storage-benchmark-latest.json).
The earlier 42.13 s checkpoint is retained separately, not overwritten or averaged.

| Phase | Seconds | Files rehashed/reused | New/downloaded packs |
| --- | ---: | --- | --- |
| First capture | 6.31 | 1,000 / 0 | 2 new |
| Unchanged capture | 2.36 | 0 / 1,000 | 0 new |
| One changed file | 3.57 | 1 / 999 | 1 new |
| First ordered restore | 18.58 | 1,000 published | 2 downloaded |
| Identical restore | 5.38 | 1,000 reused | 0 downloaded |
| Selective restore | 0.25 | 1 published | 1 of 3 downloaded |

Ordered restore reported zero post-assembly readback. Query-only monitoring
returned at most 451 bytes across 100 polls over 250,000 stored entries, with zero
reconciliations. This does **not** establish whole-service IPC performance, physical
read volume, RSS, live-provider throughput, power-loss recovery or native Windows/
Linux acceptance. The limiter rate-limit test is explicitly a simulation.

The report is structured JSON with source provenance and per-phase metrics.
There is no fabricated throughput or assumed zero for missing instrumentation.

| Field | Meaning / limitation |
| --- | --- |
| `bytesRead` on capture | Source `OperationMetrics.bytes_hashed`: logical input consumed by native content hashers. **Not physical read syscalls**, staging-copy reads, cache traffic or tracker prehash reads. |
| `sourceFilesReused`, `filesRehashed` | Actual native operation fast-identity reuse/hash counters. Zero new packs alone does not establish source-read reuse. |
| `captureMetadataCounters` | Actual source-coordinator page fetches, metadata-only file opens, directory-pin validations, full-scope inventory nodes, recorded/reused proofs, proof-checkpoint bytes read and accepted receipts. It is an O(1) status snapshot, not a physical syscall counter or an inventory/revalidation poll. |
| `chunksReused` | Authenticated manifest chunk references whose pack mapping points to packs actually uploaded before this capture. `hashWorkerChunksReused` separately retains the engine's hash-worker counter. |
| `newPacks` | Actual payload pack upload completions through the source provider. Metadata writes are excluded, not hidden. |
| `remoteBytes` | Actual uploaded/downloaded filesystem-provider object payload bytes, including separate pack and stream buckets. Not internet bytes or protocol overhead. |
| `bytesRead` / `readback` on restore | Actual post-assembly verifier reads. Preview/preflight destination hashing is **not instrumented** and is explicitly null. |
| `fixtureHashReadBytes`, `fixtureVerificationBytes` | Extra fixture expected-content/post-restore verification work, reported separately rather than silently charged to or omitted from the engine's readback count. |
| `peakBuffers` | Measured capture codec/upload/reservation peaks and restore assembly-handle/hasher/unpublished-file/worker peaks, alongside their actual admission ceilings. Queue/reader capacity and estimated working set are explicitly limits/estimates; unexported queue/reader peaks and RSS peak are null. |
| `fullScans`, `filesScanned` | Actual reconciliation counter delta and engine scan count. An unchanged complete capture can still reconcile a namespace even when it avoids content hashing. |
| `durableCompletion` | Capture returned successfully **and** its operation is `COMPLETED`, repository claim is `RELEASED`, and committed metadata authenticates. Restore returned with `verify_native_completion()?.is_clean_committed()` and all expected entries published/reused. Authenticated metadata-only recovery receipts may intentionally remain in staging; unknown/plaintext artifacts cannot pass. Upload EOF/100% pack bytes are insufficient. |
| `elapsedSeconds` | Real monotonic elapsed time; worker/stage durations can overlap and must not be added. Restore post-run independent verification is outside its engine elapsed time. |

Stable pass/fail criteria are counts, integrity and read-amplification/resource
ratios: zero unchanged payload uploads; retained FastCDC chunks after a prefix
edit; ciphertext payload minus the actual 16-byte AEAD tag never larger than
plaintext; actual zstd use for compressible records; no unrelated/repeated pack
downloads; zero new pack downloads for an identical destination; no more than one
post-assembly readback pass; and source ceilings of 32 assembly handles, 128 active
hashers, 256 unpublished files / 64 MiB unpublished bytes, and admitted worker
limits. The controlled ordered case additionally requires zero readback.

The admission/capture fault path performs a same-inode, same-size,
restored-mtime write **without any watcher event** after freezing expected bytes
but before stable capture. Publication must be refused.
A change **after completed stable capture**, during upload/finalization, may
publish the old verified generation: it is not app-wide atomic consistency.
Exact newer mutations must stay pending, and tracking completion must compare
current metadata/epochs instead of marking the changed bytes saved. Replacing an
approved native root still revokes publication authority.
A separate failure before the actual bundle `COMMITTED` write leaves ordinary
metadata present but the bundle invisible and its operation non-completed.
Successful bundle/index/catalog marker order and post-claim-release completion
are independently checked.

## Exact source/API parity matrix and adapter loss points

Paths below are relative to `shared-storage/crates/` unless prefixed otherwise.
“Source retained” means the algorithm exists in the active fork, **not** that its
optimized QuickSave service path has passed acceptance.

| Required source optimization | Actual source entry points / implementation | Where a QuickSave adapter can lose it; required acceptance |
| --- | --- | --- |
| FastCDC + BLAKE3, bounded source reads | `noland-cas/src/lib.rs`: `ChunkFileReader::{chunk_open_file,capture_small_file}`, `chunk_reader_with`, `fastcdc_offsets`; `noland-state-agent/src/backup.rs`: `hash_one_file` | Never prehash the entire tree once per layer, then hash it again for every upload. Account tracker/bridge/source content reads separately. |
| Unchanged-file identity reuse | `backup.rs`: `fresh_preflight`, fast-identity branch, `finish_backup_evidence`; `native_capture::prove_reuse`; DB `FileStateRecord`/capture generations | Native reconciliation still invalidates ordinary size/mtime trust. Only a previous actual source proof, matching complete native stamp and parent chunk hashes, canonical app/roots/software-instance binding and unchanged native uncertainty epoch independently prove scoped reuse. Do not remove reconciliation or treat event silence as proof. |
| Dirty/gap/restart/concurrent-write preservation | `StateAgent::recover`, `process_events`; `StateDb::{mark_dirty,capture_generation,finish_backup_mutations}`; versioned app mutations | Propagate monotonic dirty/uncertainty epochs through tracking, frozen selection, upload and completion. Writes during upload must remain pending. Never acknowledge “whatever is current” instead of the captured generation. |
| One authoritative prepared native revision | `backup.rs`: `PreparedBackup`, `write_prepared_backup`, `read_prepared_backup`, `finish_prepared_backup`; `native_host.rs`: `NativeSelection`, `native_check_publication` | Prepared backup helpers are private source implementation, not an existing public split-capture API. Parent must expose/wire the actual pipeline rather than fabricate a receipt from tracker hashes. Keep source handles, authenticated metadata, selection/provider/key binding and publication guard alive. |
| Bounded metadata-to-receipt bridge | `crates/quicksave-tracking/src/receipt.rs`: `NativeCaptureReceipt::{evidence,revalidate}`, `Tracker::{prepared_node_listing,accept_capture_receipt,verify_capture_receipt}` | These are native Rust capabilities, not incoming JS authority. Page native metadata once, accept actual source evidence once, and retain its owner. Do not serialize 250k expected-file records at every poll or instantiate a fake successful receipt. |
| Scoped authenticated chunk index / dedup | `backup/{cache,scoped_index}.rs`, `ScopedIndex`, 4,096-entry cache / 256-hash prefetch; `LocalCas` / `CasLease` | Reuse repository-and-vault-key-bound authenticated mappings. Recreating adapters per file/chunk loses the cache, leases and common transfer budget. Same content in another repository is not authority. |
| zstd no-expansion packs and locality | `noland-pack/src/lib.rs`: `PackWriter`, `ChunkCompressor`, `PackIndexEntry`; `backup/packing.rs`: `plans`, `group_sources` | Preserve compression flags, chunk offsets, plaintext/ciphertext lengths and launch/path/offset ordering. Do not repack each selected file independently. The benchmark opens the actual source authenticated index and checks stored lengths. |
| Capture/pack/upload overlap, bounded staging | `backup/capture_pipeline.rs`, `capture_pipeline/streaming{,/scheduler,/durability}.rs`, `backup/{preparation,packing}.rs`; `PackUploadSession`, `RollingUploadWindow` | Keep one operation and shared resource/transfer admission. Serial per-file provider calls, whole-tree staging copies, repeated session/vault acquisition, or independent nested pools defeat it. Active/retry leases are not a hard CAS-cache size guarantee. |
| Adaptive provider-aware concurrency | `noland-storage/src/adaptive.rs`: `AdaptiveConcurrency::{for_uploads,for_downloads,for_streams,acquire_slots,record_error}`; `TransferTuning`, `WorkerResources` | Preserve raw connection ceilings; `cat` is one stream, not divided by `copyto` multistream width. Group transfers must reserve all internal slots. Local fixture limiter simulation is not an actual provider benchmark. |
| Immutable staged/batch metadata, marker last | `SharedStorageProvider::put_metadata_batch`, `MetadataBatch`; `commit_bundle_with_pack_index_for_operation`, `CatalogStore`, `RcloneStorage` metadata implementation | Do not equate payload completion with saved state. Retain index/manifest-before-marker, catalog commit-before-pointer, checkpoint/index persistence and exact claim-release barriers. This fixture tests the real LocalStorage/default batch path, not rclone's provider-specific staging implementation. |
| Selective streaming pack retrieval | `noland-restore::{prepare_restore,restore_pipelined}`, pipeline `pack_jobs`; `SharedStorageProvider::{supports_streaming_downloads,download_stream_observed}` | A wrapper must forward streaming capability, not accidentally use the scratch-pack fallback. Plan by **unique selected pack IDs**, not one whole-pack download/copy per file. Metadata reads still occur for unchanged destinations. |
| Ordered assembly, inline hashes, bounded verification | `noland-restore/src/pipeline.rs`, `pipeline/{decode,scheduler,verification}.rs`; `PipelineOptions`, `PipelineIoMetrics` | Keep record authentication before assembly and whole-file verification before publication. Out-of-order/hash-evicted files must retain mandatory readback. Do not drop verification for zero-readback numbers or create an unbounded hasher/file-handle map. |
| Shared plans + overlapped verified flush/publication | `RestorePlan::into_shared`, `SharedRestorePlan::with_native_control`, `NativeRestorePreview`, `NativeRestoreControl`, `restore_pipelined` | Passing legacy `&RestorePlan` clones large metadata; use shared ownership. Native preview/conflict/identity authority must remain intact. Preview/preflight duplicate destination reads need separate measurement; this fixture does not claim their elimination. |
| Authenticated journal/retry/recovery | Prepared captures/pack receipts; `NativeRestoreControl`, `NativeRecoveryAuthority`, `recover_native_restore` | Preserve frozen app/file/child operation IDs, ciphertext, authenticated ownership and exactly approved recovery mappings. A checkpoint-file existence test or replayed JSON plan is not recovery authority. This fixture is not process-kill/power-loss acceptance. |
| Query-only browsing and status | `StateDb::operation_monitoring_snapshot`, `noland-state-db/src/monitoring.rs`; RPC `GetOperationStatus` with `projection:"progress"` | `NativeEngine::status` uses the source progress projection. Audit the service/JS response too. Never call full `get_operation`, parse result/retry JSON, unlock a vault or rescan roots just to display progress. |
| Indexed/revision-bound inventory pagination | Source index + committed query-only connection; QuickSave `NativeEngine::{software_files,local_files}` and `page` | **Loss point at review:** `local_files` reconciles and builds the full `Vec<Value>` before paging; `software_files` calls it. A small returned page does not bound work. Browse the validated native index by revision/cursor; do not revalidate/capture on every UI poll. |
| Full application graph and exact roots | Source discovery/attribution/classification/runtime binding plus `native_register`, pinned approved roots and actual bounded index | Optimizing only a manually chosen folder does not fulfill whole-app capability parity. Do not replace evidence-backed software with placeholder bundles, duplicate superseded runtime payloads, or suppress necessary saves/config/control records. Platform/application reconstruction needs its own acceptance. |

### Native capture coordinator handoff

New source integration is in
`shared-storage/crates/noland-state-agent/src/native_capture.rs`, with the
in-process bridge in `crates/quicksave-noland/src/capture_control.rs`.

- Parent declares the modules and adds
  `pub(crate) captures: crate::native_capture::NativeCaptures` to `NativeBindings`.
- `install(agent, operation, app, scope, sink)` reads frozen native metadata in
  500-node pages once and returns exact logical keys. `NativeCaptureScope` carries
  `version`, `workId`, `metadataIdentity`, `nodeCount`, and optional `fullScope`.
  `fullScope` is a compact `NativeFullScopeBinding` with `version`,
  `evidenceHash`, `rootCount`, `deletedCount`. It does not accept predicted content
  hashes. `validate_selection` binds that scope, those keys and the native roots
  fingerprint to the installed operation-owned Rust sink. Scoped selections also
  require `software_instance_id`; source reuse partitions by canonical source
  AppId, root fingerprint, software instance and uncertainty epoch.
- Native root fingerprints use v3 and explicitly bind actual source kind and
  basename in addition to canonical app, role, path, native IDs and allowlists.
  `Installer` is an approved capture-only `ReconstructableApp/AppContent` role;
  nothing in this path executes an installer or launches/signs an application.
- The actual partial/streaming pipelines persist complete **pre-read** stamps in
  their authenticated capture state and record them only after the real stable
  before/after checks pass. Missing legacy stamps cannot become native provenance.
  A bounded encrypted native-proof checkpoint is durably published before local
  stream receipts are cleaned; replay never invents captured stamps from a later
  filesystem observation.
- Parent calls `accept_prepared(agent, operation, manifest, master)` after
  capture/pack/upload and before first `COMMITTED`/`LATEST`. The callback receives
  a source-owned receipt: actual file hashes/chunk-list digests, exact frozen
  stamps and a real source-crypto encrypted/authenticated manifest binding.
  `verify_prepared` belongs at each subsequent publication barrier.
- `NativeCaptureReceipt::revalidate` has no service/publication callback. It checks
  source authentication, immutable captured-proof binding, cancellation and
  pinned root/workspace identities, avoiding both a tracker → source receipt →
  service guard → tracker recursion/deadlock and a repeated live-leaf stat walk.
  It does **not** require app data to remain unchanged throughout a long upload.
  Actual before/after capture checks and existing pack/immutable-upload receipts
  remain mandatory; later writes belong to a dirty/pending next generation.
- Optional `prove_reuse` requires a previously minted actual source proof, the
  same content/chunk-list digest, an exact complete current stamp, root binding,
  and the same trusted controller-supplied reuse epoch. The default epoch is
  absent and **disables reuse**. The native tracker must change its opaque epoch
  after restart/overflow/observation loss; a JS flag or event silence is not proof.
  The source's own observer-loss generation independently fences reuse even if a
  controller accidentally supplies a stale epoch. It does not revoke an already
  completed, immutable stable capture.
- `record_metadata` supports anchored directory and confined-relative-link
  observations, retaining full native entry stamps while logical size stays
  zero. Directory evidence has no invented content hash; link evidence binds
  actual target-text hashes and never follows the target. Source selection and
  actual directory/link capture call these hooks; full service/platform acceptance
  remains a separate gate.
- Proof documents reuse the source's existing 512 MiB authenticated metadata
  ceiling; it is not raised. Relative paths have a separate aggregate bound,
  selected nodes/registrations/root handles remain independently bounded.
- The measured workload now installs the metadata-only source coordinator and
  supplies an explicitly fixture-owned restart/gap epoch. Separate small tests
  retain the legacy expected-hash/no-clean-proof guard, verify source crypto,
  publish old verified bytes while retaining a later mutation, and refuse a
  replaced approved root after capture.
  Actual Rust execution and full service/IPC acceptance remain parent-owned gates.

### Additive full-scope and empty/deleted generations

`NativeCaptureSink::full_scope_authority(scope)` defaults to `None`, not successful
omission authority. A full scope requires a retained native
`Arc<dyn NativeFullScopeAuthority>` with required `evidence() -> Result<Value>` and
`revalidate() -> Result<()>`. The service adapter must use
`Tracker::full_scope_evidence(work_id)` and verify the **original** full-capture,
tracking/provider and baseline grants. No IPC document implements this trait.
`NativeFullScopeBinding::from_evidence` computes a compact binding; a hash or a
nonempty grant-shaped JSON object is not authority.
The bridge exports its own platform-neutral `NativeFullScopeAuthority` trait,
`NativeCaptureController::full_scope_authority`, and both associated
`CaptureScope::full_scope_from_evidence` and free `full_scope_from_evidence`
helpers. It retains the original native owner and forwards evidence/revalidation
to the source, rather than turning the compact header into authority. The
Windows facade still needs its owner's matching forwarding implementation.

The source independently:

- Opens every approved root with real no-follow native identities, including
  roots with no indexed children and direct-file approvals.
- Verifies all whole-root frozen metadata and performs one bounded,
  descriptor-anchored inventory, including actual directories and confined links.
  Unknown/special entries, unreadable directories, omitted nodes, root replacement
  and unexpected extra nodes fail explicitly. Manual allowlists never enumerate
  unrelated parent files.
- Binds exact signed live/deleted ID hashes, canonical source AppId, software
  instance and all approved root IDs. Zero nodes are accepted **only** for this
  whole-scope Rust capability. `Some(empty)` in legacy/selected upload requests
  remains invalid.
- Before inheritance filtering, checks every authenticated source-parent key's
  fate: present in the new frozen inventory or in its exact authenticated deleted
  set. Each deletion must match the actual source parent's kind, content/link
  identity and captured Unix metadata. Watcher deletes cannot authorize omissions.
  An incompatible/missing parent is an explicit failure, not an empty bundle.
- Emits ordinary native `ManifestTombstone` entries **exactly** for that frozen
  deletion set, without cloud payload/history deletion or generation retirement.
  A later unchanged empty generation has zero payload packs and no fabricated
  tombstones. Older source manifests/packs remain authenticated and restorable.
  A native config that accidentally enables automatic history convergence is
  rejected before provider I/O; it cannot silently retire older generations.
- Authenticates the complete captured-proof/history digest as well as the actual
  source manifest and regular-file proofs. Actual root metadata is recorded in
  `environment.quicksave_native.full_scope.rootCaptures`, not synthetic file
  entries. Existing NLNE/NLPK formats and metadata mode fields are retained.

Optional `sourceBaseline: {sourceSnapshotId, manifestHash}` in the native evidence
must match the actual authenticated source parent. `manifestHash` is the source
receipt's manifest digest, not a differently reordered JSON reserialization.
Non-latest or incompatible tracker/source baselines currently fail explicitly;
they are not silently merged into deletion authority.

The separate small source-native tests cover one-file deletion, all files and
structural directories deleted, an initially empty real root, unchanged-history
payload reuse, no-Rust-authority/legacy empty rejection, revoked grants, mismatched
source baselines, unreadable/changed directories and selected-file disappearance.
The measured benchmark still selects regular-file fixture nodes in **Custom**
mode; it does not certify full `.app` reconstruction or empty-root restore.
Tombstone application requires a separate native acknowledgement; ordinary
fixture `approve()` explicitly refuses tombstone-bearing manifests. Pure empty
root reconstruction and zero-byte complete-head presentation remain restore/
parent catalog integration gates.

### Authenticated reconstruction layout

Source-native manifests with a software-instance binding contain
`environment.quicksave_native_root_layouts`:

```text
{version:1, platform, app_id, software_instance_id,
 roots:[{logical_root, root_id, role, source_kind, leaf_name}]}
```

`StateAgent::native_root_layouts(app, instance)` derives descriptors from actual
held `NativeRootBindings`. Captures project them to selected logical roots for
Custom coverage; full captures retain every approved root, including genuinely
empty roots with actual root metadata. The descriptor contains no absolute source
path, HOME guess, relative-parent guess or UI-supplied mapping. Basenames use the
shared portable single-component validator and layout root/metadata limits; an
unsupported name/count fails explicitly. Native publication and source receipt
acceptance compare the frame against those held roots, and the real source AEAD
binds its digest plus the entire prepared manifest/proof.

`native_restore_roots` uses the shared
`noland_state_core::native_layout::{native_restore_layout,logical_root_map}`.
Installation-directory roots map to the explicitly chosen destination plus their
actual basename (for example `destination/Isolated Layout.app`), not an opaque
hash folder or host `Applications`. Other roles remain in confined role/root
namespaces. A present malformed descriptor fails; only descriptor-absent legacy
manifests use the files/tombstones-only opaque fallback. Native exact-key restore
selection validates the original descriptor before projecting it.

The synthetic `.app` regression checks actual named-root reconstruction, canonical
AppId versus software-instance binding, forged-frame rejection and preservation
of Custom coverage/no new complete head. It is not discovery, real application
launch/liveness, code-signing or packaging acceptance. Empty-root token validation
and metadata reconstruction still require the coordinated core/restore changes;
neither an empty file list nor a layout descriptor is app-ready authority.

`native_capture_tests.rs` additionally exercises actual
`AgentRpc.handle(StartBackup {mode:"custom", ...})`, managed worker completion,
authenticated committed metadata and absence of a complete head. It runs a child
test harness with a pinned sandbox-local fake helper, synthetic guarded local
session and an in-memory test master key. This is **RPC-mode admission coverage**,
not a provider durability/performance benchmark. Source unit tests require
`noland-storage = { workspace = true, features = ["native-test-runtime"] }` as a
test-only dependency. Child environment, output, object sizes and deadlines are
bounded; no real helper/account/configuration fallback is allowed.

### Actionable integration priorities

1. Wire source capture preparation to the tracker receipt boundary and service
   publication guard. The strict benchmark should then show zero **source**
   rehash bytes for proven unchanged files and only the changed file's bytes for
   a selective change. Keep a negative no-proof/no-event test alongside it.
2. Remove duplicate content hashing across tracker/service/bridge **by consuming
   actual source receipts**, not by relaxing evidence requirements. Add counters
   for the tracker/bridge and staging physical reads; current source logical hash
   counters cannot prove total read amplification.
3. Make browse/status/frozen-plan handles opaque and revision-bound end to end.
   Extend the 250k DB-only test through the real service/IPC adapter; the source
   projection passing does not certify that adapter.
4. Run the parent-owned Rust tests and benchmark after wiring, plus source
   resource/cancellation/retry/fault suites. Measure provider-specific metadata
   batching/streaming only in a separately authorized isolated provider fixture.
5. Preserve the pinned upstream snapshot and original notices. New files here
   are GPL-3.0-only pending the existing GPL/MIT owner/license review. Update
   active-fork provenance accounting through the coordinator, not the reference.

## Recorded validation status

- Python benchmark-helper unit tests exercise containment, bounded output,
  provenance/schema checks and counter gates. Their synthetic report dictionaries
  are explicitly test data, **not native performance results**.
- No Cargo command or native workload was executed by this documentation/benchmark
  subtask; Rust compilation, normal regressions and the opt-in measured workload
  are parent-owned pending gates.
- No live-provider speedup, total physical-read reduction, peak RSS, source-native
  Windows/Linux acceptance, native packaging, code-signing, launch reconstruction
  or full optimized product completion is claimed.
