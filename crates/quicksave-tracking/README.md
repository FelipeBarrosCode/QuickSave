# QuickSave native tracking

Original GPL-3.0-only implementation. No upstream code is copied.

## Native materialized-bundle API (parent handoff)

```rust,ignore
Tracker::materialize_bundles(candidates: &[Value], authority: &Value) -> Result<Value>;
Tracker::bundles() -> Result<Vec<Value>>;             // sanitized real indexes only
Tracker::bundle_listing(cursor: Option<&str>, limit: usize) -> Result<Value>;
Tracker::bundle_record(software_id: &str) -> Result<Value>; // native-only authenticated record
Tracker::disable_automatic_tracking() -> Result<Value>;
Tracker::automatic_tracking_status() -> Result<Value>;
Tracker::observe_application(event: &Value) -> Result<Value>; // native ownership callback
Tracker::freeze_metadata_index(software_id: &str) -> Result<Arc<NativeMetadataIndex>>;
NativeMetadataIndex::header(&self) -> Result<Value>;
NativeMetadataIndex::node_page(&self, offset: usize, limit: usize) -> Result<Value>;
NativeMetadataIndex::revalidate(&self) -> Result<()>;
Tracker::scan_metadata(software_id: &str) -> Result<Value>;
Tracker::prepare_upload_scope(software_id, provider_id, file_ids) -> Result<Value>;
Tracker::prepared_node_listing(work_id, cursor: Option<&str>, limit: usize) -> Result<Value>;
Tracker::accept_capture_receipt(work_id, Arc<dyn NativeCaptureReceipt>) -> Result<Value>;
Tracker::verify_capture_receipt(work_id) -> Result<Value>; // source publication barrier
Tracker::capture_completion_binding(work_id: &str) -> Result<Value>; // native COMMITTED-verifier input, not a verdict
Tracker::capture_reuse_epoch(work_id: &str) -> Result<Option<String>>;
Tracker::full_scope_evidence(work_id: &str) -> Result<Value>; // native-only frozen full-scope authority
Tracker::mark_unknown_dirty(software_id: &str) -> Result<Value>; // native-only recovery transition, no live-source I/O
Tracker::original_work(software_id: &str, work_id: &str, generation: u64,
    tracking_scope_hash: &str) -> Result<Arc<NativeFrozenWork>>;
Tracker::resume_pending(original: Arc<NativeFrozenWork>,
    receipt: Arc<dyn NativeCaptureReceipt>) -> Result<Value>;
Tracker::performance_counters() -> Value;
```

`candidates` are the trusted integrations provider's `bundlePlans`, not UI
payloads. `sourceRoots` must be `verified_candidate` with exact native identities
and nonempty ownership evidence. The service authenticates the complete batch;
neither `trackingAuthorized` nor a candidate's display name is authority.
Only an approved native scope followed by successful native metadata indexing and
durable authenticated index/manifest sidecars enters `bundles()`. Rejected apps
produce bounded `diagnostics`, not zero-count or discovered-app placeholders.
Real empty roots have a real empty index, not fabricated file counts.
The metadata index has real node kinds, sizes, pinned native stamps, ownership/
permission metadata and link text. File content hashes remain explicitly absent
until capture, never zero/fabricated hashes. `contentState` distinguishes this
index from a frozen content-verified capture.
The provider report's `protectedSourceRoots` must be copied into the sealed
policy's `excludedPaths` by the native service. Report-wide protected paths are
not silently discarded because candidates are passed separately.

Exact duplicates and compatible installation parent/child roots are indexed
once, preserving authenticated child evidence and roles. Container boundaries
yield to independently verified child roots; omitted container siblings remain
explicit partial-coverage diagnostics. Unsupported aliases fail. A new
candidate with some independently indexable real roots can retain those roots as a **partial**
bundle and record unavailable roots as diagnostics; all-root failure never
creates a zero-count placeholder. An unavailable previously indexed root cannot
silently disappear from a refreshed scope or its confirmed baseline.

Metadata indexing does not test payload readability. Whole-tree enumeration
uses native enumeration stamps; manual leaves and regular-file rechecks use
`SafeRoot::file_metadata` (pinned parents, no-follow regular-file enforcement,
complete native ID/length/write/change stamp, **no READ_DATA open**). Required
Unix/Windows metadata remains native and stamp-bound. A read-denied regular file
can therefore be `metadata_indexed` with absent content hashes and
`payloadReadability:"not_established"`. Actual capture still opens/reads the real
file and validates its complete pre/post stamps; read denial cannot become Saved.
Existing hash reuse still requires the existing full native stamp and qualified
watcher/uncertainty proof.

Per-root failures are all-or-nothing, never partial subtrees. Native
`diagnostics[].rootDiagnostics` and authenticated `autoEnrollment.unresolvedRoots`
retain exact root ID/path/role, operation `stage`, optional `relativePath`,
native `osError`, and the actual bounded error reason. Error text is at most
1024 UTF-8 bytes; batch diagnostics are capped at 256 entries / 4 MiB with an
explicit omitted count. An initial independent-root partial bundle cannot mint
full-scope capture/omission/head authority (`fullScopeCaptureBlocked:true`);
only explicit selected-node partial capture remains available until a genuine
successful reindex of the failed roots. A failed refresh scan retains prior
roots/index/baseline and forces reconciliation. Revocation, policy rejection,
invalid native identity, unsafe entries and resource bounds are not downgraded
to successful availability omissions.

On Unix, exact native file/link names may contain literal `:` and `\\`; those
bytes are not separators or rewritten. NUL, absolute paths, slash traversal,
empty/dot components and existing bounds remain rejected. Windows keeps its
strict punctuation rules. App/provider identity validation and raw-path
`file_id` derivation are unchanged.

Automatic candidates first receive **identity pins only**: exact native identity,
base/role/ownership proof, lexical exclusions and positive native-ancestor denies.
`pin_candidate_identity(..., CandidateScope::{Tree,SelectedLeaves})` does not
authorize a tree, index, or grant. Normalization may discard a broad container
in favor of independently evidenced owned child scopes without ever traversing
the discarded Desktop/Downloads scaffold. No unknown container siblings are
inferred to belong to the child; the container omission remains authenticated
partial coverage and blocks a full-scope head.

After normalization, **every retained root** must pass `check_policy`'s full
native selected/protected overlap proof via
`SafeRoot::overlaps_directory_identities`, and retained root pairs must pass their
full anti-alias audit, before metadata indexing or grant issuance. Absence of
positive ancestor containment is never treated as disjointness. A protected
root inspection failure fails policy approval, not an omittable app root.
Directory-only approval does not impose capture link semantics on protected
repository/state trees or grant readability of their files. Actual metadata
capture, payload reads and the strict `SafeRoot::overlaps` API remain unchanged.
Root diagnostics distinguish `inspectionSide`, `selectedRootPath` and
`protectedRootPath`. Native overlap errors are downcast through caller context
to `DirectoryIdentityInspectionFailure`; typed side refines pair attribution,
and typed stage appears as the stable `nativeInspectionStage` code. No English
message is used for classification. Known relative directory text is retained
exactly up to 32 KiB, without separator/Unicode normalization. Over-bound or
non-UTF-8 native paths produce `relativePath:null` with an explicit
`relativePathUnavailableReason`, never a lossy guessed path.
An unattributed pair error reports `path:null` /
`inspectionSide:"undetermined"` rather than guessing the app was unreadable.
Native missing protected paths retain the existing lexical protection; failed
opens other than real NotFound cannot silently disappear behind `Path::exists`.

### Cached software-root display projection

Sanitized materialized software includes `roots:[{id,path,role,roles?}]` from its
approved record. Tracking/policy grants are checked before UI projection. The
list is bounded by `MAX_ROOTS` (48, below the UI's 64-root ceiling); each exact
approved UTF-8 path retains the existing 32 KiB bound. Paths are not truncated,
resolved again, or replaced by guessed discovery paths. Unmaterialized records
or invalid/revoked tracking/policy grants produce `tracked:false` and an empty
display-root list.

Optional extra `roles` come only from automatic enrollment's authenticated
normalized app-evidence binding; unsigned manual source/display labels do not
add roles. Root display objects contain no native identities, grants, leaf
allowlists, baseline/sidecar paths, or per-root counts. Actual indexed root
counts remain in the separate sanitized `bundle.roots` metadata. Producing this
projection uses no source pin, filesystem traversal or content hash.

### Native immutable index handoff to the actual source graph

`quicksave_tracking::NativeMetadataIndex` has private fields and no JSON
constructor/`Deserialize` implementation. `freeze_metadata_index` requires an
actual materialized cached index with authenticated index/manifest references,
the current tracking grant and (for automatic enrollment) policy/discovery
grants. It rejects pending placeholders, absent canonical source identities,
and unconfirmed `quicksave.observed:` identities. There is no fallback from
display name, installation instance ID, or a raw UI path.

`header()` returns bounded native-only metadata:

```json
{
  "version": 1,
  "softwareId": "<record.id>",
  "appId": "<exact canonical sourceIdentity.app_id>",
  "instanceId": "<record.appId>",
  "revisionId": "<bundleIndexSource.revisionId>",
  "snapshotIdentity": "<authenticated cached index identity>",
  "trackingScopeHash": "<exact approved tracking scope digest>",
  "nodeCount": 0,
  "metadataOnly": true,
  "fileStateTrust": "VERIFY_REQUIRED",
  "payloadReadability": "not_established",
  "reconciliationRequired": true,
  "coverageTrusted": false,
  "complete": false,
  "saved": false,
  "cloudWrite": false
}
```

`nodeCount` is the actual cached node count, not merely regular-file count.
`node_page(offset, limit)` accepts `1..=500` and returns
`{nodes,offset,nextOffset,nodeCount,revisionId,metadataIdentity,metadataOnly:true,
fileStateTrust:"VERIFY_REQUIRED",reconciliationRequired:true,saved:false}`.
Nodes have exactly the same shape and ID order as `prepared_node_listing`:
`{id,rootId,path,kind,size,stamp,metadata,linkTargetHash}`. Directory/link nodes
are included. `stamp` is the actual complete native `FileStamp`, preserving
both file-ID words and write/change timestamps. File content hashes are never
projected, even if a prior real capture populated them in the cached index.
Link-target digests describe actual previously indexed confined link text.
Offset equal to `nodeCount` returns an empty terminal page; a larger offset
fails rather than silently fabricating a complete index.

The owner retains `Arc<Snapshot>`, not a cloned node tree. A sparse checkpoint
every 500 IDs makes each arbitrary-offset page a BTree lookup plus at most 999
visited nodes, rather than a repeated full-prefix walk. Repeated freezing of
the same revision reuses the existing owner. Retained distinct snapshot Arcs
are bounded globally to 250k nodes, 32 MiB path/link text and 128 MiB serialized
metadata, including separately charged owner bindings/checkpoints. At most 4096
owners remain live; dead weak entries are reclaimed at the next freeze. This
is bounded serialized-metadata accounting, not an exact allocator/RSS claim.
Individual page serialization is bounded to 32 MiB. Excess retention fails
explicitly until native consumers release obsolete owners.

Freeze performs a bounded in-memory metadata identity/size check once. It does
not reread sidecars, traverse/open source roots, hash content, issue a capture
grant, prepare/upload data, log another application, or alter confirmed history.
`header` and both sides of page serialization revalidate the current cached
revision/snapshot binding, exact original roots/leaf allowlists/source identity,
and tracking/policy/index/manifest grants. They do not rescan an index per page.
Revocation, replacement revisions, lost materialization and Tracker shutdown
fail explicitly.

A startup index or an index with pending reconciliation is still usable as
authenticated **historical metadata**, always with source `VERIFY_REQUIRED`.
Neither a quiet watcher nor this API grants current-content trust or clears
Tracker dirtiness. The service's `NativeIndexOwner` must separately recheck
current native root authority/protected file identities before the real source
DB imports pages, map Tracker IDs to source logical IDs exactly as for prepared
capture nodes, and never reenter its owning source engine from the callbacks.
This index is not capture/restore/overwrite authorization.

### Content I/O and native receipt optimization

Counter assertions around asynchronous integration fixtures must control native
scheduling rather than suppress required audits. `TrackingPolicy::new` uses a
real monotonic `Instant`; `with_clock(Arc<dyn TrackingClock>)` is an optional
Rust-only host/test dependency (`TrackingClock: Debug + Send + Sync`,
`fn now_millis(&self) -> u64`). A fixture may hold elapsed time at zero while
asserting cached UI/index import counters, then explicitly advance it through
the quiet/audit threshold. This never disables native watchers, discards hints,
changes production intervals, or asserts that a missed-event gap was clean.
In particular, the first watch registered **after** indexing still requires a
real reconciliation; a slower live-clock polling test can legitimately overlap
that independent worker audit. Frame/receipt JSON writes in the private bundle
directory do not increment source `fsWalks`/`metadataNodes` counters.

`software`, `bundles`, and `file_listing` do **no source I/O**. Initial bundle
materialization and `scan_metadata` walk metadata only. They do not hash app
installations simply to populate a dashboard. `performance_counters` reports
`bytesRead`, `filesHashed`, `fsWalks`, and `metadataNodes` for test/diagnostic
verification. Cached content hashes are reused only with matching complete
native stamps and valid watcher/uncertainty epochs; overflow/restart remains
unknown until a real capture/full reconciliation.
Full-scope comparison includes the approved root directory's native timestamps:
returning identical file bytes does not erase an actual root metadata change.
An unchanged returning subtree can become clean only after a real verified
comparison against its authenticated confirmed baseline.
The cache additionally qualifies native filesystem semantics: local APFS or the
implemented fine-grained Linux filesystem set, with unchanged native device IDs.
Unknown, cross-device, network/FUSE, HFS, ext-family precision and overlay cases
remain conservative. These gates are not platform-native acceptance claims.
`fsWalks`/`metadataNodes` count tracker index traversals/nodes, not individual OS
syscalls; platform exclusion/alias inspections and source-engine pack/network
I/O have their own boundaries and are not claimed in these counters.

Use `bundle_listing` and `file_listing` for bounded (1..=500), revision-bound UI
pages. Neither constructs a 250k-node JSON tree. The optimized work queue carries
exact IDs plus a compact `captureSource.metadataSelection` work token, not a
duplicate JSON stamp list. `prepared_node_listing` exposes the frozen native
stamps to native adapters in bounded pages only.

The optimized native-only upload path is `prepare_upload_scope`, then the
engine's actual prepare/chunk/capture **once**, then `accept_capture_receipt`.
The latter accepts an owned Rust `NativeCaptureReceipt` adapter, **not** webview
JSON. Its `evidence()` returns the source's actual prepared expected-files,
stable stamps, exact selection binding and `sourceExpectedManifestAuth`;
`revalidate()` must revalidate the real owned source prepare/publication guard.
The tracker freezes those hashes, seals a receipt, and returns publication
evidence. The parent must call `verify_capture_receipt` at the source publication
barrier; it rechecks the owned source callback and exact tracking authority.
Completion of receipt-backed work never rehashes file contents: it validates the
receipt and reconciles metadata/epochs. Legacy `begin_upload` remains supported
for callers without a native receipt and uses the original conservative hashing.
Neither callback nor an event can manufacture an engine capture proof or mark
data durable before actual engine confirmation.

```rust,ignore
pub trait NativeCaptureReceipt: Send + Sync + 'static {
    fn evidence(&self) -> anyhow::Result<Value>;
    fn revalidate(&self) -> anyhow::Result<()>;
    fn immutable_prepared_capture(&self) -> bool { false }
}
```

`evidence()` returns `{workId,metadataIdentity,sourceSnapshotId,
sourceExpectedManifestAuth:{...},nodes:[{id,rootId,path,kind,size,stamp,
fileHash?,linkTargetHash?}]}`. `kind` is `file`, `directory` or `symlink`;
`stamp` is the complete snake_case platform `FileStamp`. Regular `fileHash`
may be raw lowercase BLAKE3 hex or `blake3:<hex>`. Link target hashes are raw
BLAKE3 of the exact UTF-8 link text, not target contents. Node size is regular
file bytes, zero for directory/link metadata. The adapter must authenticate its
actual source manifest, not populate this object from tracker predictions.
Methods cannot reenter Tracker or perform cloud writes. Source handles and the
real source publication guard remain owned by the adapter until completion.
`accept_capture_receipt` returns a `captureSource` patch; merge it into the
original work rather than discarding dirty generation/selection/authorization.
Receipt bytes/source proof are retained in a create-new authenticated sidecar.
Original metadata-stage queued work remains verifiable after receipt acceptance;
the regular authority monitor does not walk receipt files.

Override `immutable_prepared_capture` **only** once the source authenticates a
completed stable capture and its immutable prepared manifest/bytes/ciphertext
independently of live-file changes. The native-only result is cached at receipt
acceptance, never taken from JSON. Then ordinary events/gaps after acceptance may
publish a valid older immutable generation, but completion does not mark newer
or uncertain local data clean. Default adapters retain conservative aborts.
Initial acceptance still enforces exact frozen metadata/stamps/selection and
stable preparation epochs; this is not application-atomic capture.

`capture_reuse_epoch` is called once per native capture. It returns an opaque
instance/gap/authority/provider partition tag only with verified root pins,
qualified native stamps, frozen event epochs and healthy registered watches.
Fresh instance nonces, monotonic gap epochs and acknowledged watcher resets
prevent restart/overflow/watch-error proof reuse. A first capture can receive a
fresh epoch without existing content hashes. The tag never authorizes hash/chunk
reuse by itself: the actual source must authenticate its parent, exact complete
native file stamps, hash/chunk references and prepared manifest.

Every automatic generation is a **whole approved-scope manifest**, even for a
one-file change. The worker never emits a changed-only custom patch as a complete
app generation; source-native deduplication/reuse limits actual hashing/packing
to changed/uncertain data. Explicit manual file selections remain partial.
The global current-index and baseline path budgets include link-target text,
not merely file counts, across all 4096 software slots.

### Frozen full-scope/omission handoff

`full_scope_evidence(work_id)` is a trusted Rust callback, not an IPC approval
payload. It rejects selected-node work and returns the original
`expectedFullScope:{scope,grant}`, frozen `authorization` and `roots`, exact
`deletedFileIds` plus ID-sorted `deletedNodes:{id,rootId,path,kind,size,stamp,
fileHash?,linkTargetHash?,metadata}`, frozen `rootMetadata`/`rootStamps`, and
authenticated `baseline:{kind,snapshotIdentity,reference,scope}` information.
It also retains the native enrollment policy/discovery grants when applicable.
The outer binding is `{version:1,workId,softwareId,providerId,generation,
metadataIdentity,fullScope:true,keepsVersionHistory:true}`. Nothing is inferred
from an empty list, unreadable directory or a caller boolean. A missing/replaced
approved root still fails its native guard. Call once at native capture setup;
the normal authority monitor never rebuilds this expanded evidence.

The callback does **not** enable engine capabilities. Composition must set
`supports_deletion_snapshots`/`supports_metadata_snapshots` only after real source
fixtures validate additive full-scope omission, directories/links and an
authenticated empty full manifest. Both flags remain false by default.

### Lost-work recovery transition

`mark_unknown_dirty(software_id)` is native-only. The service first compares
current roots/tracking grant/source identity/app ID against its signed frozen
plan. Tracker then verifies the current tracking/policy MACs without opening a
source root, bumps checked dirty/per-software unknown/event generations, requires
reconciliation and forces uncertain capture. It persists real status and returns
`{softwareId,dirty:true,dirtyGeneration,unknownGeneration,
lastConfirmedUploadedGeneration,reconciliationRequired:true,status,
trackingScopeHash,trackingGrantHash,pendingWorkId,authorityUnchanged:true,
keepsVersionHistory:true}` for the parent's device-MAC group digest.

This does not reapprove a missing/replaced root, clear the confirmed baseline,
alter grants/providers/history, delete data, or recapture files. Unsigned/revoked
records fail. Existing pending work is retained as an older generation and can
never acknowledge the new unknown generation as saved. The caller must drain
its actual source owner before recovery; this API does not cancel/release it.
Normal source verification is still required before any new clean baseline.

### Durable original native work / source checkpoint recovery

State adapters **must preserve** optional private software field
`pendingWork: Option<Value>` (camelCase), bounded to 64 KiB. Its only payload is
`{version:1,name,hash,bytes,scope,grant}`, never a plaintext secret or source file
contents. No UI DTO includes it. `TrackingStore::read_record(software_id)` may be
overridden with one bounded native state view; the default is a bounded list
read. It is used for admission/readback boundaries, never per node or chunk.

Every optimized native `prepare_upload_scope` persists and reads back a private,
create-new `SafeRoot` work frame **before** returning source-admissible work.
The `tracking_frozen_work` grant binds the exact frame hash/name/byte length,
original work ID/generation, tracking/provider/autosave/instance/source identity,
original metadata identity, unknown generation, policy-bound authorization,
selection/deletion IDs, full-scope proof, original baseline reference and
accepted-receipt lineage. Optional authority values hash canonical JSON
(`None -> null`); `Some(null)` is rejected, not normalized into approval.

The frame retains the exact queued request, original authenticated metadata
snapshot (including directory/link/root stamps and any previously known hashes),
original policy/record and original epoch partition. It does not capture today's
tree or reissue a different work ID. Only 64 active software-frame references and
128 MiB aggregate active frame bytes are permitted; each frame is bounded by
`MAX_BASELINE_BYTES`. Create-new superseded/orphaned/corrupt files are retained,
never physically deleted as an automatic recovery step.

Current index/manifest grants are verified **when creating** the independent
frame. Recovery authenticates that historical snapshot/record with the frame's
own device grant and exact private-file hash, then checks its original metadata
identity and scope bindings. It must not require the old **current-index**
nonces to remain valid: a real newer metadata scan or accepted capture can
legitimately rotate them. No old grant, stamp, metadata identity or frame is
rewritten/re-signed to compensate. Fresh current tracking/provider/autosave/policy
authority, no-follow root identities, full-scope/baseline proofs and actual
accepted source-receipt/envelope authentication remain mandatory. The separate
`NativeMetadataIndex` API still verifies its genuinely current index grants.

When a real source receipt is accepted, a new immutable frame links the original
frame and the existing authenticated `tracking_capture_receipt` seal/sidecar.
Original metadata identity/stamps/selection are unchanged. Actual prepared hashes
come only from that source evidence, not a new metadata scan or predicted hash.
Accepted receipt sidecars are re-read and authenticated once on recovery; frame
and source evidence reads are bounded, without raising existing document limits.

`NativeFrozenWork` is exported but has no public fields, JSON constructor,
`Deserialize` or successful default authority. Its native-only API is:

```rust,ignore
NativeFrozenWork::record(&self) -> Result<Value>; // exact ORIGINAL private record/policy
NativeFrozenWork::work(&self) -> Result<Value>;   // exact ORIGINAL queued request
NativeFrozenWork::header(&self) -> Result<Value>;
NativeFrozenWork::node_page(&self, offset: usize, limit: usize) -> Result<Value>;
NativeFrozenWork::full_scope_evidence(&self) -> Result<Value>;
NativeFrozenWork::accepted_receipt(&self) -> Result<Option<Value>>; // locator/seal, NOT authority alone
NativeFrozenWork::revalidate(&self) -> Result<()>;
```

Node pages use the same actual metadata DTO as `prepared_node_listing`, bounded
to 500 selected nodes and 32 MiB, with numeric `nextOffset`. Pages/work/evidence
are immutable in-memory reads, not per-node vault/frame lookups. Call
`revalidate` at source admission/publication; it verifies current original
authority and no-follow root identity without walking a source tree or reading
live content. The loader verifies the frame grant once and caches its owned
handle. A restart persists a checked dirty/unknown generation advance; it cannot
reuse the original zero-valued event partition as cleanliness.

The parent drains the actual source owner first, loads `original_work` using the
exact signed plan's work ID/generation/tracking-scope hash, and asks the source
engine to reload its **actual authenticated immutable preparation checkpoint**.
Only that real native `NativeCaptureReceipt` may enter `resume_pending`. Metadata
JSON, a receipt sidecar alone, a database `completed` flag, and an absent legacy
frame cannot construct a recovered receipt or authorize a new attempt. Changed
root identities, policy/tracking grants, provider selection/writability or source
keys fail before a recovered Pending is installed.

`resume_pending` returns a `captureSource` patch to merge with `work()`; retain the
original generation, authorization, selection and full-scope proof. It installs
only that older Pending, never substitutes today's index or recaptures files.
The source may resume that original unfinished operation or acknowledge an
already-COMMITTED child; never rerun a completed child.

`NativeCaptureReceipt::verify_committed() -> Result<()>` deliberately defaults to
an error. The real source adapter must override it by verifying a durable
COMMITTED cryptographic manifest bound to the same `evidence()`/immutable
preparation. Recovered completion refuses to update any baseline without that
native check, even if the completion caller passes `success:true`.

Authenticated recovered completion updates the **historical** baseline using
the exact original full manifest or selected-node patch over the original
baseline; full-scope omissions retain version history. It does not advance
`lastConfirmedUploadedGeneration`, `lastSavedAt`, or replace/confirm today's
index. Dirty/reconciliation/force-hash remain set, so changed local data requires
real follow-up verification/capture. The result explicitly distinguishes
`historicalBaselineConfirmed:true` from `currentGenerationConfirmed:false`.
Terminal frame authority is revoked and the active reference removed only after
the historical state is persisted; original frame/receipt/baseline files remain.
This is a bounded durable design, not a power-loss acceptance claim.

Terminal retirement writes explicit `pendingWork:null`, including through
patch-preserving state adapters. An explicitly failed/drained work item that
never accepted a source receipt may retire its own **metadata-only** temporary
authority without acknowledging Saved or deleting any frame/history/payload.
Accepted prepared receipts and uncertain source success remain recoverable and
block creation of replacement work until real COMMITTED recovery/finalization;
they are not canceled merely to make a new generation fit.

### Native COMMITTED finalization binding (single / autosave / batch)

Call `capture_completion_binding(work_id)` **before** `complete_upload` removes
Pending. It requires a real accepted owned receipt, current tracking/autosave
authority, the original provider and native roots, and a valid
`tracking_capture_receipt` MAC. Metadata-only work and missing receipts fail;
there is no JSON/status-derived successful fallback.

The entire serialized result is bounded to 128 KiB:
`{softwareId,appId:<canonical sourceIdentity.app_id>,softwareInstanceId,
providerId,workId,generation,metadataIdentity,captureReceipt:{scope,grant},
sourceExpectedManifestAuth}`. There is no canonical-ID/display-name fallback.
The compact source envelope is copied from actual `evidence()` once at receipt
acceptance and bound to `scope.sourceExpectedManifestAuthHash`; the accepted
frozen frame preserves it. Resume authenticates the actual receipt sidecar and
checks that compact field against both the original scope and reloaded real
source proof. Finalization never requests another full node-vector `evidence()`
or rereads a large sidecar body. It validates the sidecar reference/hash/MAC;
private sidecar body corruption is checked when that body is actually loaded
for recovery, not by adding payload reads to finalization/status paths.

This method returns **verifier input**, not `verified:true`, saved state, or a
COMMITTED assertion. The native service must pass it to the real source engine's
post-COMMITTED cryptographic manifest/submit-HMAC verifier, including for singles
and autosave, before calling `complete_upload`. A database row whose status says
completed, a prepared receipt alone, or an unverified returned JSON object must
never mark data Saved. Older immutable work can supply a valid binding while
newer local data remains dirty; its original identity/generation is unchanged.

The parent-only authority JSON is:

```text
{
  policyScope: {
    version: 1, policyId: <opaque id>, rolePolicyVersion: 1,
    source: "verified_native_discovery", enabled: true,
    baseDirectories: [{
      id, path, identity: {device,fileId:[u64,u64]},
      allowedRoles: ["installation","save","config","runtime"],
      ownershipRules: ["native_installation_handle", ...exact permitted evidence kinds...]
    }],
    appIdentityPolicy: {
      allowedAppIds: [<exact ids>], allowNewVerifiedApps: <bool>,
      allowedEvidenceKinds: [<exact permitted identity-evidence kinds>],
      allowNativeInstallationOnly: <bool>
    },
    excludedPaths: [<native approved exclusion paths>],
    providerId: <optional selected provider id>
  },
  policyGrant: TrackingStore.issue_grant("app_tracking_policy", policyScope),
  discoveryScope: {
    version: 1, source: "verified_native_discovery",
    policyHash: blake3(serde_json::to_vec(policyScope)).hex(),
    candidatesHash: blake3(serde_json::to_vec(candidates)).hex()
  },
  discoveryGrant: TrackingStore.issue_grant("bundle_discovery", discoveryScope)
}
```

Issue these grants only after one-use native consent and a trusted native
discovery-provider result, never for arbitrary webview JSON. Consent may allow
future verified apps only inside the exact pinned base directories and explicit
ownership/identity/role rules. A home-directory base, drive root, vault/cache/
QuickSave/No Land path or an unowned root is not an implicit wildcard grant.
Base IDs/identities are revalidated through no-follow native handles; every
source root records its granting policy/base/evidence hashes. Revoking the
policy or discovery attestation invalidates auto-enrolled authority too.
`policyScope.providerId` selects a provider, not autosave permission; use the
existing separate native-consented autosave grant.
`/Applications` is a permitted **base**; its directory contents are not a grant.
Sources must be strict descendants with the individually verified native IDs.
Unknown/native-only installations require `allowNativeInstallationOnly`; that
never permits guessing their data roots.

The full `sourceIdentity` (No Land `AppIdentity`, original snake_case payload)
is preserved in native records/manifests/work and bound in tracking scopes.
Automatic primary roles are native `installation/save/config/runtime`;
container/group/data map to `save`, with original classifications/multi-role
provenance retained in authenticated root `source` metadata.

Tracking HMAC scope is `{version:1,softwareId,appId,roots:[{id,path,role,identity,
allowedFiles}],sourceIdentity?,autoEnrollment?}`. Automatic binding fields are
`policyHash`, `discoveryHash`, `appEvidenceHash`, `candidateHash`, `coverageHash`.
Hash encoding is BLAKE3 of exact JSON serialization, with sorted JSON object keys.
`appEvidenceHash` hashes `{appId,identityEvidence,roots:[root_request...]}`;
`coverageHash` hashes `{rootsComplete,unresolvedRoots,unresolvedReasons}`.
Prefer the exact `root_authority().scope` for native verification; never strip
these fields by reconstructing the old manual-only scope.

The returned object contains `bundles`, `diagnostics`, and `incomplete`.
`bundle_record` contains actual immutable `revisionId`, `bundleIndexSource`
(manifest/index file references, content hashes, and authenticated sidecars),
root roles/counts/bytes, coverage derived from real roots/evidence, and private
native authority. Never send this raw record or sidecar paths/grants to a webview.
The list DTO exposes revisions/counts/coverage but no native paths or grants.
Complete coverage means complete **approved evidenced scope**, never all data
used by an app or app-wide atomicity. Failed/omitted scopes cannot contribute
counts or a clean baseline. Previously indexed revisions remain additive.
Disable revokes policy/tracking/autosave authority and marks automatic records
`tracked:false`; it never deletes data/indexes/manifests/history or manual scopes.
The service owns global enabled-policy status before any actual bundle exists.

`observe_application` accepts `{softwareId,appId,kind:"app_open"|"app_close"|
"change_hint",rootIds:[...],scope,grant}`. The service issues `"tracking_observation"`
for `scope` `{version:1,softwareId,appId,kind,rootIds:<sorted IDs>,
trackingScopeHash}` after verifying observation ownership.
Events merely advance dirty/reconciliation epochs; no watcher/observer callback
writes cloud data or marks a source saved.

## Canonical upload evidence (service/bridge handoff)

Every work item, **including whole-software work**, has exact `fileIds`
(up to 250,000 internally; UI selection limits are separate). Match the actual
prepared manifest against this frozen evidence **before cloud commit**:

```ts
captureSource: {
  changedDirty: boolean,
  dirtyGeneration: number,
  lastConfirmedUploadedGeneration: number,
  snapshotIdentity: string, // tracker index identity, NOT proof of engine capture
  consistency: "validated_stable_files_not_application_atomic",
  keepsLocalCopy: true,
  expectedFiles: Array<{
    id: string,             // tracker file_id(rootId, path)
    size: number,
    fileHash?: string,      // lowercase regular-file BLAKE3-256 hex
    kind?: "file" | "directory" | "symlink", // absent means regular file
    linkTargetHash?: string // required for symlink; no fileHash for metadata
  }>
}
```

`expectedFiles` is ID-sorted, includes **only** selected current native nodes,
and must have exactly the same IDs as `fileIds`. Empty full-root and deletion-only
omission captures require actual native writer support. `expectedFiles` is absent
in metadata-only work until the actual native receipt has been accepted.
Never substitute a UI scan or only compare `snapshotIdentity`.
Native inventory/manifest IDs must use the same tracker identity, or a lossless
mapping held by the bridge. Exact ID algorithm:
`"file-" + blake3("QuickSave logical file v1\0" || u64_le(rootId byte length) ||
rootId UTF-8 || relativePath UTF-8).lowercase_hex()`.
The domain ends in one NUL byte, not the characters backslash and zero.
Map `(rootId,path)` losslessly into the engine's native logical roots. For manual
roots, expand only `allowedFiles` into native bindings; never register the parent
as whole-tree authority. Actual prepared file set/size/hash mismatch must abort
before publishing cloud data. Native stable-file pre/post checks supply ordinary
capture identity; full stamps are separate initial individual-file consent.
Continue revalidating native grants and
source handles at the bridge's publication barrier. Legacy completion's later
rehash is additional dirty-state protection, not an engine commit authorization;
receipt-backed completion uses real source revalidation without that second hash.

Set `TrackingPolicy.supports_metadata_snapshots` only when the native writer and
guard support typed directories/links and genuine empty full-root captures. Set
`supports_deletion_snapshots` only when authenticated full-root omission is an
immutable additive version. Whole work includes
`captureSource.expectedFullScope:{scope,grant}` with grant kind
`"tracking_full_capture"`, binding exact root IDs, metadata identity, generation,
provider, selected/deleted ID hashes, and authenticated `baselineKind` (`none`,
`partial`, `full`). Selected-only deletion cannot masquerade as whole-root
omission; autosave promotes deletion captures to full scope. Physical disappearance
or replacement of the approved root itself still fails native identity checks;
it is not treated as an empty tree or authority over a replacement root.

This evidence can exceed the UI's 1 MiB request limit; the compact form plus IDs
fits 186k ordinary entries under 64 MiB. Use an exact serialized-byte counter for
native metadata, not a UI string-escaping estimate. Preserve the engine's 512 MiB
metadata guard, the 250k entry bound, and 32 MiB total file-path bound. Do not send
evidence to the webview or clone it into unbounded queues.

## Service integration boundary

```rust,ignore
pub type Enqueue = Arc<dyn Fn(Value) -> anyhow::Result<()> + Send + Sync>;
pub trait TrackingStore: Send + Sync + 'static {
    fn load_records(&self) -> anyhow::Result<Vec<Value>>;
    fn save_record(&self, record: &Value) -> anyhow::Result<()>;
    fn issue_grant(&self, kind: &str, scope: &Value) -> anyhow::Result<Value>;
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value)
        -> anyhow::Result<bool>;
    fn revoke_grant(&self, kind: &str, scope: &Value) -> anyhow::Result<()>;
    fn provider_writable(&self, provider_id: &str) -> anyhow::Result<bool>;
    // Optional metadata-only override, permitting read-only provider selection:
    fn provider_known(&self, provider_id: &str) -> anyhow::Result<bool>;
}
```

Implement this trait around `WorkspaceStore`. Grants **must** be authenticated
with its native-vault device key and support persistent revocation. There is no
production in-memory or plaintext-boolean authority fallback. `save_record`
must atomically preserve every field, including private tracking fields. Return
only `Tracker::software()` / `file_listing()` output to the webview, not raw
persisted records, grants or source paths from enqueue requests.
Load all records with tracking-grant fields, including `tracked:false` approvals
awaiting their first index; filtering by the unsigned boolean loses valid pending
consent. Only successful authenticated index persistence sets `tracked:true`.

`Tracker::open(store, enqueue, TrackingPolicy::new(data_dir))` starts a joined
native worker. Include repository/key/cache/config directories in
`policy.excluded_paths`; QuickSave's entire `data_dir` is excluded automatically.
The policy's baseline directory stores bounded, authenticated-reference,
create-new sidecars; these are not stored inside tracked user roots.

Public entry points use `anyhow::Result` and camelCase JSON:

- `software() -> Vec<Value>`
- `approve_software(&Value) -> Value`
- `add_files(&Value) -> Value`
- `set_provider(software_id, provider_id: Option<&str>) -> Value`
- `configure_autosave(software_id, provider_id, enabled) -> Value`
- `file_listing(software_id, cursor: Option<&str>, limit) -> Value`
- `scan(software_id) -> Value`
- `root_authority(software_id) -> Value` (native service only, never a webview DTO)
- `begin_upload(software_id, provider_id, file_ids: Option<&[String]>) -> Value`
- `complete_upload(work_id, generation, success) -> Value`
- `verify_autosave_work(&Value) -> Value` (recheck queued authority before admission)
- `shutdown() -> ()`

`approve_software`, `add_files`, `set_provider`, and `configure_autosave` are
backend-only **already-native-consented** entry points. Never expose them as
unprotected IPC. `approve_software` accepts `softwareId?`, `appId?`, `name`,
`providerId?`, and `roots:[{id?,path,role?,source?}]`. Roles are `installation`,
`save`, `config`, `runtime` or `manual`; source metadata alone is never authority.
An existing root ID is preserved for the exact same pinned native root; changing
its allowlist requires fresh consent/grants, not a new logical root ID.
`add_files` accepts `softwareId?`, `name?`, `paths`, and `providerId?`;
it pins parent directories but reads/watches only explicitly allowlisted leaves.
Neither display name nor executable basename establishes ownership. Supply
save/config candidates from integrations only after native root approval.
`add_files` assigns a stable `quicksave.manual.<digest>` app ID to the manual
group; it does not infer ownership by any installed executable.

Production IPC supplies server-only `_approvedPaths` from the native ticket.
Both entry points pin their own handles and compare exact native identities
before creating any grant/record. Directory proofs are `{path,kind:"directory",
identity:{device,fileId}}`; file proofs additionally carry the exact snake_case
`quicksave_platform::FileStamp` and `parentIdentity`. A newly selected file cannot
fall back to a directory proof. Proofs must cover exactly selected paths plus
the previously authenticated scope roots; missing/extra/wrong-kind proofs fail.
Original file proofs survive `add_files`' inner root approval, and handles stay
owned through grant persistence. Direct already-trusted native unit callers may
omit this field; untrusted IPC must never be allowed to supply it.

The enqueue callback must promptly enqueue, not synchronously upload or reenter
the tracker. A request contains `workId`, `softwareId`, `providerId`, `generation`,
`fileIds` (exact selection even for whole-software work), approved `roots`, and `captureSource`
including `changedDirty`, `snapshotIdentity`, and consistency. Preserve this
exact selection on retries. Call `complete_upload` only after durable engine
confirmation for that exact work/generation; partial or failed work is not
success. Manual uploads must use either prepare/receipt/complete or legacy
`begin_upload`/`complete_upload`; skipping
them cannot establish a confirmed baseline. Concurrent upload requests for the
same software fail, including manual-vs-autosave.

`captureSource.changedDirty` compares against the last **confirmed** baseline,
not the preceding UI scan. Completion rehashes/revalidates the source before
publishing a baseline. Changes/events during upload stay pending; ambiguous
completion intentionally causes another stable capture. A partial upload merges
only selected files and cannot clear other dirty files. Deleted-file snapshots
are disabled by default; unsupported deletion returns an explicit error and
stays dirty. Set `supports_deletion_snapshots` only if the integrated engine
actually supports additive full-scope omission snapshots. This crate never deletes user files or
physical cloud objects.

Native `notify` uses FSEvents on macOS and the native recommended Unix backend.
Events are hints; bounded overflow, startup, watch errors and periodic audits
force reconciliation. No events is not evidence of a saved version. The worker
exists for the application lifetime, including hidden UI; no OS login service is
installed. Windows platform durability/native handles/notify now exist, but this
crate now has a Windows tracking anchor/metadata adapter using the audited fork's
safe native `SourcePath`/`WindowsMetadata` primitives. It retains complete 128-bit
IDs, raw FILETIMEs, attributes/link counts and checked symlink tags instead of Unix
mode/UID/GID placeholders. Native ancestor IDs prove containment; accesses do not
follow reparse points. Atime-only observations do not churn cached revisions.
Windows reuse remains `None` without a real journal/change-proof integration;
the separate source capture/receipt feature gates still apply. No Linux/Windows packaging/native
acceptance follows from a macOS build.

Windows adapter provenance: the target-specific dependency calls only the safe
native metadata/path API in `shared-storage/crates/noland-snapshot/src/
{source.rs,windows.rs,native_metadata.rs}` (the audited active fork derived from
No Land `e81238a7536aae201540956ce76981364fd36595`). No snapshot-copy fallback,
remote provisioning/lifecycle function, or upstream reference file is invoked or
modified. New tracking code remains GPL-3.0-only; original notices are preserved.

## Verification

Parent owns serial Cargo builds (`jobs=1`, shared target). Unit tests use a fake
authenticated/revocable store and isolated temporary roots only. Scheduler tests
advance integer milliseconds; no sleep-loop timing assertions or real vault/
provider access. Large-source coverage uses logical counters/streaming, not a
34 GB or 186k-file test fixture. Baseline hashing is streaming and listings return
at most 500 items; the bounded scan index is not sent wholesale to the UI.
