# Native application observation

Parent integration contract (not a webview API):

* `ObservationScope::approve(ScopeRequest, Arc<dyn ScopeConsent>)` checks a native
  consent verifier, then pins the exact approved roots and executable stamps.
  The verifier is retained and rechecked around each bounded poll; revocation
  during a poll discards that batch. File descriptors do not cause vault/config
  calls or repeated whole-scope signature work.
  Root IDs/identities and exact application IDs must come from the native
  service. Observation approval does **not** issue tracking/autosave grants.
  Supply both `excluded_paths` and native `excluded_native_files` for root
  markers/private keys; native-ID exclusions also reject hard-link aliases.
  `approve_with_limits` accepts an explicit larger limit (up to 4096 logical
  roots and 4096 apps); the default 64 roots is a rejection bound, never a silent
  truncation. Physical handles are shared only for identical native roots, while
  root IDs and file selections remain separate.
* `native_source(&scope)` returns the host's bounded native polling adapter.
  `EvidenceSource` is injectable; tests never enumerate actual processes or
  inspect actual user data.
* `integration::TrackerBundleBinding::from_native_records` consumes only private
  `Tracker::bundle_record` and `Tracker::root_authority` output. It verifies the
  enabled native policy, tracking/discovery and materialized sidecar grants,
  then pins one explicitly selected executable's metadata in the exact approved
  installation/runtime selection. No parent-directory or PATH inference.
  `append_to_scope`, `ScopeRequest::add_exact_root` and
  `add_native_application` never union file leaves or broaden a parent grant.
* `ObservationEngine::new(scope, source, limits)`, `reconcile(now_ms)`, and
  `snapshot()` produce per-app run/session/open-file evidence, dirty generations,
  unknown epochs, and root candidates. Snapshots are shared native
  `Arc<ObservationSnapshot>` values, not duplicate full inventories.
* `ObservationWorker::start(engine, config, callback)` owns notify and the
  bounded command queue. `shutdown()` releases watchers and joins its worker.
  Callback receives `Arc<ObservationSnapshot>`; the parent may use its capture
  triggers to request its own separately approved stable-file reconciliation.
  Known identities still require exact native policy validation; unknown
  identities require manual review. Neither kind grants authority. UI file
  listings use revision-bound `ObservationSnapshot::evidence_page`, not the
  whole native snapshot.
  Page `observation:…` evidence IDs are not tracking file IDs and cannot select
  capture/upload files; the parent's validated native index owns those IDs.

The parent owns workspace/dependency wiring and serialized Cargo validation.
The expanded assignment also implements the native owned service adapter in
`crates/quicksave-service/src/observation.rs`; no other service file is owned.
The source-graph expansion additionally owns only the new
`crates/quicksave-noland/src/observation_control.rs`. It writes actual source DB
sessions/associations through existing APIs, with signed native admission and
VerifyRequired metadata. Parent wiring and the frozen index owner are described
in `INTEGRATION.md`; no roots-only registration is called a full source index.

`AppObservation` is **diagnostic evidence, not a displayed software bundle**.
The parent still needs a validated native source/index and an exact enrollment
policy before materializing a bundle. `ObservationRootKind::Installation`
explicitly permits both executable and data metadata within one pinned install
root; it never expands observation or backup permission automatically.

`ObservationWorker::watermark()` exposes pending event/loss state immediately,
including events queued during a parent upload. Compare it around native
capture work; a matching watermark never proves complete polling coverage.

Worker polling backs off from 2s to at most 30s on idle evidence, resets on actual
activity, and coalesces event storms behind the minimum poll interval. There are
no filesystem walks or content hashing here. Repeated intrinsic polling gaps
stay unknown but do **not** advance dirty generations, invoke the callback or
cause Tracker to hash the whole app every two seconds. Actual new loss/recovery,
native session/file-evidence changes and approved root hints remain actionable.
Status/UI reads use the cached snapshot, not a scan.
Executable and exact-leaf/ancestor routes are indexed. Polls revalidate touched
evidence roots, rather than auditing all inactive app roots every two seconds.
An untouched root's continued presence is not asserted; it is rechecked before
use. Scope appends roll back on error without cloning the accumulated allowlists.

## Shared application IDs

`stable_app_id(&AppIdentity)` matches integrations' current **SourceAppIdentity**:
`mac-bundle:<CFBundleIdentifier>`, `steam:<number>`, or
`desktop:<exact-case-desktop-file-id>`. It never uses the old placeholder
`mac_bundle_identifier:*` / `steam_app_id:*` / `desktop_entry_id:*` convention.

For materialized bundles use the adapter: `NativeApplicationSpec.app_id` is
copied verbatim from the actual Tracker **record.appId**, which can contain an
installation-specific `@native-identity` suffix. Its `source_app_id` separately
retains `sourceIdentity.app_id`, including exact XDG case. Emitted proofs and
callback events therefore match the actual record appId, not a reconstructed
plan/product ID. Root IDs remain the actual signed Tracker root IDs.

Unknown executables get
`quicksave.observed:<native-identity-hash>`, require manual review, and do not
masquerade as a discovered application. Display titles/basenames are not IDs.

The compact native service hookup is in [`INTEGRATION.md`](INTEGRATION.md).
Scope updates rebuild the exact request from current private records, approve
the new sealed scope, and shutdown/join the previous worker before replacement.
There is deliberately no ambient mutable "add whatever path was observed" API.
The service adapter exposes an inert isolated-development constructor,
native-only policy-gated production startup, bounded diagnostic status, an
optional native source-graph sink, capture watermarks and joined shutdown.

## Security and completeness contract

No file payloads, argv, environment, credentials, provider state, No Land state,
helper installation, remote lifecycle/provisioning or network calls are used.
Only approved executable/metadata/data paths may be retained. Pinned handles
reject symlinks/reparse points and changed namespace edges. Exclusions, native
root-marker names and private-key paths are checked before file metadata opens.
Native-ID marker/key aliases are rejected before metadata is retained/emitted.
Application files use metadata handles, never payload reads; the Linux probe
reads bounded kernel-generated proc metadata, and Security.framework may inspect
approved bundle signing metadata as detailed in `CAPABILITIES.md`.

Polling cannot see short-lived opens or complete process lifecycles. A healthy
poll is **not** a complete event stream and never clears the unknown epoch or
declares files clean/saved. A run-close transition is an observed disappearance,
not proof the app was cleanly closed or a promise of application consistency.
Notify/FSEvents/ReadDirectoryChangesW are root hints, not process attribution.
Only a process-generation + executable stamp + native descriptor/file-identity
match attributes an open file, and that is evidence of use, not ownership.

## Provenance

Original GPL-3.0-only QuickSave implementation, informed by immutable No Land
snapshot commit `e81238a7536aae201540956ce76981364fd36595`:

* `state-agent/crates/noland-observer/src/lib.rs`: process-generation proofs,
  open-file recovery, loss fencing.
* `state-agent/crates/noland-observer/src/host_path.rs`: PID/starttime and native
  file/namespace identity, rejection of remounts and deleted replacements.
* `state-agent/crates/noland-attribution/src/lib.rs`: generation-bound sessions,
  unresolved evidence, conservative loss epochs.
* `state-agent/crates/noland-discovery/src/{lib,runtime}.rs`: stable application
  identity and explicit unresolved/manual-review discovery.

No upstream files or active shared-storage files are modified. No No Land code,
remote agents, provisioning, production accounts, or credential stores execute.
Original upstream notices and root licensing ambiguity remain untouched.

Native-platform implementation/acceptance details are in `CAPABILITIES.md`.
