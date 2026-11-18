# Native service hookup (actual materialized records only)

No ambient startup. Call only after an explicit authenticated native app-tracking
policy was enabled and the Tracker has a real materialized index. This is a
backend function, **never** an operation accepting renderer paths, records,
grants, app IDs, or a `tracked: true` boolean. The adapter rejects missing or
unsigned materialization, disabled/revoked policy, changed roots/native IDs,
unselected sibling executables, changed source IDs, and leaf-scope widening.

## Implemented native service owner

`crates/quicksave-service/src/observation.rs` implements the owned manager, not
just this example. The parent adds `mod observation`, owns the field in native
tracking, activates it after consent/materialization, merges `status()` into
metadata, and calls `shutdown()` **before** shutting down Tracker. No other
service file was edited by this assignment.

Native-only API:

```rust
ObservationSession::start(store, tracker, policy, excluded_paths) -> Result<Self>
ObservationSession::start_if_enabled(store, tracker, policy, excluded_paths, enabled) -> Result<Self>
ObservationSession::start_with_graph(store, tracker, policy, excluded_paths, graph_sink) -> Result<Self>
ObservationSession::start_with_protected_files(
    store, tracker, policy, excluded_paths, already_pinned_marker_and_key_ids, graph_sink,
) -> Result<Self>
// Unix source DB composition, after actual Engine.register/materialization:
ObservationSession::start_with_source_engine(
    store, tracker, policy, excluded_paths, already_pinned_marker_and_key_ids, engine,
) -> Result<Self>
// Also: disabled(), status(), watermark(), request_reconcile(), shutdown().
// ObservationManager is an alias for ObservationSession.
```

`store` is a `WorkspaceStore`, `tracker` is `Arc<Tracker>`, and `policy` is a
`TrackingPolicy`. The protected IDs are `Vec<NativeFileIdentity>` from already
pinned native handles, not renderer IDs or permission to read excluded secrets.
The simpler startup variants cannot discover unknown hard-link aliases of a
key/marker; use the protected-file variant when the native owner has those IDs.

The parent must use `disabled()` or `enabled=false` in isolated development.
Production startup is excluded under `cfg(test)`; the service file's inline
tests use an injected-source constructor and MemoryVault, never ambient
enumeration. Startup does not resolve a default provider or contact an account.
It rejects missing/unverified policy before determining a native principal or
constructing any native process source.

One immutable scope/worker spans actual materialized records. Bounds are 4096
apps, 4096 logical roots, 16 MiB retained authority metadata, 16384 selected
leaves, 16 MiB scope path strings, 64 MiB serialized scope and 256 diagnostics.
Limits fail the observer inactive with diagnostics rather than dropping roots
or pretending coverage. A missing canonical executable remains unconfirmed;
there is no launcher/PATH/sibling guess. The exact derived request is checked
against the current signed global policy and each real tracking MAC around
polling. No per-session vault-purpose registry is created.

`SourceGraphSink` receives `(Arc<ObservationSnapshot>,
Arc<[TrackerBundleBinding]>)` on the owned native worker. It is the parent's
StateDB bridge seam for real APP_USES_PATH facts and uncertainty, not authority
to create ownership/grants. It must be bounded, non-reentrant, and must not join
or destroy its observation owner. These raw native values must never go to JS.
No StateDB integration is asserted when the optional sink is unbound.

### Actual No Land graph bridge

The expanded assignment adds ONLY
`crates/quicksave-noland/src/observation_control.rs`, a child of `native.rs`.
Parent-owned glue is required:

```rust
// native.rs:
#[path = "observation_control.rs"]
pub(crate) mod observation_control;
// NativeEngine field and constructor initializer:
observation: Mutex<observation_control::EngineObservationState>
// ... observation: Mutex::new(Default::default()),
// lib.rs Unix re-export (now supplied by parent):
pub use native::observation_control;
```

No parent `native.rs`/`lib.rs` or shared-storage implementation was edited here.
After materialization/startup reconciliation and before starting the worker, the
parent calls the implemented synchronous service helper:

```rust
materialize_source_indices(
    store.clone(), tracker.clone(), engine.clone(), protected_native_file_ids,
) -> Result<serde_json::Value>
```

It uses real `Tracker::freeze_metadata_index`, validates the exact native header,
then performs `engine.register_materialized(&record)` immediately followed by
`native_materialize_index(record, owner)` for each individual installation.
Registration works **without a provider/rclone**, calls real `db.upsert_app`,
`add_known_root` and native root registration, and does not enumerate contents.
Per-app diagnostics are bounded to 256 and failed imports are not counted.

New synchronous native engine APIs:

* `native_materialize_index(record: Value, owner: Arc<dyn NativeIndexOwner>)`
  imports actual immutable metadata pages via source `upsert_scanned_paths`,
  acknowledges actual persisted associations, and writes only `VerifyRequired`
  file states with no content hashes. It never walks/hashes the source.
* `native_observe_application(event: Value)` rechecks the bound WorkspaceStore's
  `source_native_observation` MAC, current global policy, discovery/tracking
  grants and materialized attestations. Exact actual instance/root/leaf bindings
  must match that instance's retained real pinned registration evidence.
* `native_observation_scope(record, root_authority, observation)` constructs the
  bounded exact scope for native signing, without issuing a grant.
* `native_observation_status(software_id)` is cached metadata only.

`NativeIndexOwner` has four mandatory methods:

```rust
fn root_authority(&self, scope: &NativeIndexScope) -> Result<Value>;
fn verify_current(&self, scope: &NativeIndexScope) -> Result<()>;
fn protected_file_ids(&self) -> Result<Vec<(u64, [u64; 2])>>;
fn node_page(&self, scope: &NativeIndexScope, offset: usize, limit: usize)
    -> Result<Vec<quicksave_noland::capture_control::FrozenCaptureNode>>;
```

`NativeIndexScope` binds software ID, canonical source app ID, installation ID,
revision, snapshot identity, tracking-scope hash and exact node count (regular
files + directories + symlinks). Pages are at most 256 nodes, with full stamps;
no predicted hash is accepted. The service's `SourceMetadataIndexOwner` retains
the real `Arc<quicksave_tracking::NativeMetadataIndex>` and implements all four
callbacks. It uses the delivered `header()`, `node_page(offset, limit)` and
`revalidate()` APIs, not sanitized UI listings. Pages preserve full original
stamps including change times, directories and symlinks. Roots-only or failed
imports retain `sourceIndexMaterialized:false`, not a full file graph.
Explicit reimport releases only this bridge's transient frozen read lease
before freezing the new revision, avoiding exhaustion of Tracker's retained-index
budget. No source rows, history, pinned registration evidence or capture bindings
are deleted or retired.

Use `start_with_source_engine` (or `native_source_graph_sink` with
`start_with_graph`) to get the working signed callback, not plain `start`.
The sink sends bounded actual file-use proofs to the real engine, which writes
source `AppSession` rows and original `PathAssociation`/`Evidence` rows.
`NativeOwnedRootEvidence` is inspectable native reason data inside the source's
existing `KnownAppRoot` evidence; classification reuses `NativeRootRole`.
File use is `APP_USES_PATH`, not inferred ownership, reads or writes.
Multiple processes using one path share one actual path association with
distinct source-session use evidence.

The original schema has no portable full-generation process-event column or
standalone process-edge table. Full PID/UID/start/namespace/image proofs stay in
private per-engine observation records and file-use evidence. Source UUIDs are
new observation session IDs, never hashed/truncated native start times. Session
timestamps are receipt times, not fabricated OS-start/exit times. No Linux
collector, `/proc` recovery, fake `Exec`/`FilesystemEvent`, machine process or
daemon is invoked. Old PID-only sessions after engine restart fail closed when
their full generation cannot be recovered.

The source capture registry still has one active root-binding set per canonical
app. Graph import retains each installation's independent native root handles
and exact verified registration/layout/role/file-selection evidence. Graph writes
for an earlier instance reverify current MACs and both retained/current root
identities against that record-scoped evidence, not the historical DB or another
installation's active capture fingerprint. Missing/changed/revoked evidence fails
explicitly. Polling never registers again, switches capture roots, or aggregates
permissions. Capture stays bound per attempt by the parent's exact registration.
The bridge never mixes permissions or rewrites `steam:480@…` into canonical
`steam:480` ownership.
Source canonical DB apps and Tracker installation counts are different measures.

Graph operations use bounded nonblocking admission; busy/changed authority is an
error, not success. Limits include 4096 index owners, 250k nodes per immutable
index (the Tracker/source minimum), 1 million aggregate nodes, 4096 retained
registration roots, 64 MiB registration metadata, 64 MiB
path text, 8192 retained full process proofs/observer cursors, 64 MiB process
proof metadata, 16 recent native use edges per path, and 16 MiB input-document
budget. Unsupported native ID/timestamp representations fail without u64 hashes
or narrowing casts. No loss/absence can clear dirty state, mark coverage trusted,
invent content hashes or report saved. Windows source-graph admission is not
claimed by this Unix child module.

The adapter validates current records/roots and frozen process proof generations
before signing `tracking_observation` and calling `Tracker::observe_application`.
Real source gaps without a generation become only signed `change_hint` events
with explicit unknown reasons, never a fabricated app open/close.
**Tracker currently exposes no public overflow-invalidation method.** These gap
events request reconciliation and advance its event epoch; they are **not**
represented as a forced full-hash/unknown-generation API. The cached service
status exposes that limitation. The parent must retain Tracker's independent
filesystem/capture/receipt loss fences; polling cannot supply completeness.

Replace a changed session by stopping/joining the old worker **before** calling
the service startup constructor again. Shutdown waits for in-flight native calls
and the callback; no hard-cancellation guarantee is made.

## Standalone crate-level hookup

The example uses the existing `WorkspaceStore::{verify_grant,issue_grant}` and
`Tracker::{bundle_record,root_authority,observe_application}` APIs. It is not run
by this crate or its tests. `exact_executable` must come from the real native
source/index or an explicitly approved exact native mapping, not basename
matching, PATH/Exec expansion, a guessed install parent, or process arguments.

```rust
use anyhow::{ensure, Result};
use quicksave_observation::{
    integration::TrackerBundleBinding, native_source, NativeFileIdentity,
    ObservationEngine, ObservationLimits, ObservationScope, ObservationWorker,
    ScopeRequest, WorkerConfig,
};
use quicksave_state::WorkspaceStore;
use quicksave_tracking::Tracker;
use std::{path::{Path, PathBuf}, sync::Arc};

fn start_indexed_observer(
    tracker: Arc<Tracker>, store: Arc<WorkspaceStore>,
    software_id: &str, exact_executable: &Path, approved_uid: u32,
    protected_paths: Vec<PathBuf>, marker_and_key_ids: Vec<NativeFileIdentity>,
) -> Result<ObservationWorker> {
    // These native APIs refuse placeholders/unmaterialized or revoked records.
    let record = tracker.bundle_record(software_id)?;
    let authority = tracker.root_authority(software_id)?;
    let verify = |kind: &str, scope: &serde_json::Value, grant: &serde_json::Value|
        store.verify_grant(kind, scope, grant);
    let binding = TrackerBundleBinding::from_native_records(
        &record, &authority, exact_executable, &verify,
    )?;
    let mut request = ScopeRequest::new(
        format!("observation:{software_id}"), approved_uid, vec![], vec![],
    );
    binding.append_to_scope(&mut request)?; // exact roots/allowedFiles, not bases
    request.excluded_paths = protected_paths;
    request.excluded_native_files = marker_and_key_ids;

    // ONLY the already-consented native policy owner may issue this purpose.
    // No user/root/executable selection is added by the observer.
    let sealed = serde_json::to_value(&request)?;
    let observation_grant = store.issue_grant("application_observation", &sealed)?;
    let policy = record["autoEnrollment"]["policyScope"].clone();
    let policy_grant = record["autoEnrollment"]["policyGrant"].clone();
    let tracking = authority["scope"].clone();
    let tracking_grant = authority["grant"].clone();
    let consent_store = store.clone();
    let consent = Arc::new(move |candidate: &ScopeRequest| {
        Ok(serde_json::to_value(candidate)? == sealed
            && consent_store.verify_grant("application_observation", &sealed, &observation_grant)?
            && consent_store.verify_grant("app_tracking_policy", &policy, &policy_grant)?
            && consent_store.verify_grant("tracking", &tracking, &tracking_grant)?)
    });
    let scope = ObservationScope::approve(request, consent)?;
    let context = scope.context(); // opaque native scope/generation context
    let source = native_source(&scope)?; // first native process adapter admission
    let engine = ObservationEngine::new(scope, source, ObservationLimits::default())?;
    ObservationWorker::start(engine, WorkerConfig::default(), Arc::new(move |snapshot| {
        if let Some(hint) = binding.hint(&snapshot, &context)? {
            // hint() checks immutable process generation, executable stamp,
            // scope fingerprint, exact record appId/root IDs and allowedFiles.
            let current = tracker.bundle_record(binding.software_id())?;
            let current_authority = tracker.root_authority(binding.software_id())?;
            binding.validate_current(&current, &current_authority,
                &|kind: &str, scope: &serde_json::Value, grant: &serde_json::Value|
                    store.verify_grant(kind, scope, grant))?;
            let grant = store.issue_grant("tracking_observation", hint.scope())?;
            let result = tracker.observe_application(&hint.into_event(grant))?;
            ensure!(result["reconciliationRequired"] == true, "native hint was not admitted");
        }
        Ok(())
    }))
}
```

For several materialized bundles, prepare a binding per actual record, append
their exact selections to **one** request, and use one worker. Identical root
IDs must have identical paths, native identities, observation kinds and allowlists; no
union/promotion is performed. Per-app root ownership is indexed in the approved
scope, including separate signed IDs for shared physical roots. The service
retains bindings and validates each before issuing a compact signed hint.
Ambiguous executable-to-app mappings fail rather than attributing by title.

`sourceIdentity.app_id` and record `appId` are not interchangeable: e.g.
`steam:480` may have materialized record appId `steam:480@<native-install-id>`.
The helper emits the latter verbatim so `Tracker::observe_application` matches
the actual indexed owner. XDG `desktop:Org.Exact-CASE.desktop` stays exact.

File roots keep their exact `allowedFiles` sets even though their native handle
pins a parent directory. Adding a sibling, changing `Some(leaves)` to `None`,
or deriving an executable parent is not supported. Unknown
`quicksave.observed:*` identities are diagnostics; this bridge never enrolls
them, issues tracking grants, enables autosave, or expands signed root grants.

Polling gaps, missed polls, restart/overflow, permission failures and observed
process disappearance never publish a clean/saved/application-atomic result.
`app_close` is only an observed disappearance of a previously proven generation,
not an OS exit guarantee. Every emitted event remains a dirty reconciliation
hint. Intrinsic polling limitations remain visible without repeatedly signing
change hints or triggering whole-app content scans on idle status polls.
