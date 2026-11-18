# Full Shared Storage port — binding implementation scope

The requested product is **No Land's whole optimized Shared Storage feature,
running natively**, not a replacement folder copier or a UI over planned
capabilities. The local-only preview and workspace-v2 checkpoint are historical
increments, not completion of this scope.

## User requirements

- Overview, Backup and Restore are the only navigation pages.
- Every displayed software bundle is backed by a real native identity, verified
  roots and an actual bounded file index. Never generate `discovered-*` software
  placeholders, fake counts, fake tracking, or a successful empty bundle.
- Native app discovery, runtime/process evidence, classification and learned
  associations feed the source application graph. Include installation, saves,
  configuration, runtime/private workspace, dependencies and exact control files
  where supported by evidence. Names are not ownership proof.
- A native-approved automatic tracking policy can enroll validated applications
  within its exact identity/root rules. Discovery itself is not content authority.
  Unresolved identities/permissions are diagnostics, not pretend bundles.
- Import No Land finds `state.json` automatically. The authoritative identifier is
  **`com.noland.connect`**, using the native application-data directory, not the
  QuickSave identifier or an arbitrary checkout. One valid source is selected
  automatically; multiple sources use a chooser. Manual picking is an advanced
  fallback, not the normal flow.
- Import is read-only at source and copies only the necessary storage material
  into QuickSave's own vault. No source migration getter, permission repair,
  source write, or unapproved credential read.
- Whole-app, selected-app, all-app and individual-file operations use actual
  source capture/pack/commit/restore algorithms and authenticated frozen plans.
  Partial bundles must not be advertised as complete applications.
- Preserve catalog heads, history, source/completeness/parent information, pending
  deletions, freshness, exact deletion dependency identities and revision-bound
  pagination.
- Persist non-secret operation bindings and exact parent/child plans. Restart,
  cancellation, retry and reattachment must not duplicate work or widen selection.
- Complete provider lifecycle: connection, real health verification, private
  authentication/refresh, checked token rotation, disconnection, import and
  recovery-key handling. A configured adapter is not a connected account.
- Restore includes native mappings, conflicts, selected files, verified metadata,
  identity-bound recovery and original supported application reconstruction.
  Existing bytes are never overwritten/deleted without exact native authority.
- Autosave is opt-in, keeps local data, reconciles gaps/restart, preserves changes
  during uploads and records additive deletion-state snapshots without physical
  cloud deletion.

## Optimizations are required, not optional polish

Keep the source's FastCDC/BLAKE3, deduplication and unchanged-file/chunk reuse,
zstd packs, bounded adaptive provider concurrency, immutable batch/staged metadata
publication, selective pack retrieval, ordered streaming assembly, bounded
hashers/handles, overlapped verified flush/publication and resumable journals.

Do not introduce full content scans on UI refresh/status polling, duplicate
whole-tree hashing in each adapter, one config/vault call per chunk, serial
per-file remote transfers, whole-pack copies per restored file, giant IPC file
lists, or relaxed integrity/resource limits.

Reuse validated native indices/capture receipts and propagate dirty/gap epochs.
An optimization may reuse unchanged data only with its real change/identity proof;
event silence is not proof. Benchmark/counter evidence must distinguish bytes
read, hashes, filesystem walks, pack/network bytes, readback, memory and final
durable completion. Do not invent speed measurements.

## Native coordination

New primary service operations:

| Operation | Native behavior |
| --- | --- |
| `enable_app_tracking` | Approve/persist identity- and native-base-bound enrollment policy, then materialize actual source-backed bundles |
| `refresh_app_tracking` | Reconcile actual native application/evidence/index generations |
| `app_tracking` query | Real enrollment/scanning/index progress and bounded diagnostics |
| `discover_noland_import` | After native consent, inspect only authoritative standard data locations and retain candidate file proofs |
| `import_noland {sourceId}` | Use the opaque, pinned discovered source; retain advanced `stateFile` only as an explicit fallback |
| `upload_all` / selected-app upload | Freeze an exact native plan set and durable child IDs; never forward an unguarded raw `*` |
| `preview_restore` | Freeze source/destination mappings, conflict inventory, mode and recovery authority |
| `download` / `recover_restore` | Spend the exact approved plan and validate ownership before every publication/rollback step |

Server-only fingerprints/path proofs remain inaccessible as incoming JS authority.
All large inventories/plans use bounded native handles and pagination. Source
publication guards, authenticated retries and metadata ceilings remain mandatory.

## Mandatory safety differences and acceptance

No automatic local deletion or cloud convergence/retirement; history is additive.
Explicit deletion remains separately previewed, authenticated and confirmed.
No remote Linux provisioning/SSH/lifecycle service is part of this native app.
Do not execute source binaries/installers merely to infer app ownership.

Native filesystem/OS permissions, platform acceptance, compatible executable
formats, licensing and distribution are separate factual gates. Implement real
paths and disclose actual permission/entitlement failures; never substitute a
placeholder or claim acceptance from a Mac build.

Development validation uses synthetic app roots, injected vaults/observations and
isolated provider fixtures only. Do not test on live No Land state, credentials,
machines or repositories.
