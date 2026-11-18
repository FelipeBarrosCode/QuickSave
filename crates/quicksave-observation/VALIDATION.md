# Validation handoff

Executed, without Cargo or native process probes:

```sh
rustfmt --edition 2021 crates/quicksave-observation/src/lib.rs
rustfmt --edition 2021 --check crates/quicksave-observation/src/lib.rs
rustfmt --edition 2021 crates/quicksave-service/src/observation.rs
rustfmt --edition 2021 --check crates/quicksave-service/src/observation.rs
rustfmt --edition 2021 crates/quicksave-noland/src/observation_control.rs
rustfmt --edition 2021 --check crates/quicksave-noland/src/observation_control.rs
python3 -B -c 'import pathlib,tomllib; p=pathlib.Path("crates/quicksave-observation/Cargo.toml"); d=tomllib.loads(p.read_text()); assert d["package"]["name"] == "quicksave-observation"; assert d["package"]["license"]["workspace"] is True; print("Observation manifest TOML syntax and inherited license OK")'
git status --short -- crates/quicksave-observation crates/quicksave-service/src/observation.rs crates/quicksave-noland/src/observation_control.rs
git diff --check -- crates/quicksave-observation crates/quicksave-service/src/observation.rs crates/quicksave-noland/src/observation_control.rs
```

Formatting/parser checks and manifest validation passed. These are **not** Rust
type checking, linking, test execution, native permission acceptance, or
packaging acceptance. Scoped status includes the newly assigned service file.
Pre-existing/parent staging was not changed or reset by this agent.

The parent owns workspace/member dependency tables, module/field/start/stop
wiring and authorized serialized builds/tests. Only the observation crate and
the newly assigned `quicksave-service/src/observation.rs` and
`quicksave-noland/src/observation_control.rs` were edited. No lockfile,
unassigned crate file, upstream snapshot,
remote repository, credential store, provider account, live No Land state, or
actual application state was changed or exercised by this agent.

Injected tests cover native-use evidence vs authority, PID reuse, FD swap/close,
exec/image-stamp change, namespace change, root replacement/remount,
unverified bundle ID, stable/unknown app IDs, exact-leaf and private/marker
exclusions, native-ID hard-link exclusions, symlink rejection, revocation before
probing, root-hint non-attribution, bounded descriptor scans, overflow/restart/
missed-poll epochs, unavailable and permission-denied sources, run-close and
uncertain sessions, stale immutable proofs, sanitized revision-bound pages,
Windows path-only evidence, bounded worker backpressure, and joined shutdown.
Linux stat parsing and macOS FFI layout tests do not query actual OS processes.

Native limitations and permission gates are enumerated in `CAPABILITIES.md`.

Integration revision additionally covers canonical `steam:` / `mac-bundle:` /
exact-case `desktop:` IDs, explicit materialized record appId preservation,
authenticated Tracker index/policy headers, singleton file-scope preservation,
rejected root/leaf widening and missing materialization, idle backoff, and
suppression of repeated intrinsic-gap dirty callbacks. `INTEGRATION.md` contains
the parent service construction/signing snippet. These tests remain unexecuted;
no Cargo command or actual-process probe was run.

The expanded service assignment adds isolated inline fixtures using actual
Tracker materialization and a MemoryVault-backed WorkspaceStore. They exercise
inert/no-policy startup without vault unlock or source construction, unknown
executables remaining diagnostic, installation-specific app/root IDs on accepted
native MACs, exact selected-file non-expansion, protected native executable
exclusion, mid-poll global policy revocation discarding all proofs/signatures,
source-permission gaps without invented lifecycle, cached sanitized status and
joined shutdown. Crate regressions additionally exercise atomic append rollback
and explicit scopes over 64 logical roots with shared physical handles.
These tests are written but **not executed or type-checked**.

Known integration limitation: Tracker has no public overflow-invalidation API;
the service forwards real observer gaps as authenticated reconciliation hints
with explicit unknown reasons and reports the missing stronger API, rather than
claiming it forced a full hash/unknown-generation fence. The optional StateDB
sink still requires parent wiring. Native permissions and platform/packaging
acceptance remain unvalidated.

The source-graph revision adds real source DB fixtures under the new No Land
child file: actual app/root registration, metadata-index path associations,
VerifyRequired/no-hash states, full-generation source sessions/PID reuse,
per-process use evidence sharing a single actual path, unknown polling without
fake exits or trust upgrades, signed-frame tamper/replay/revocation rejection,
retired observer scopes, and lossless native ID rejection. Source runtime
preflight remains uninitialized and the Linux observer queue stays unused.
All are isolated temporary directories, MemoryVault and injected observations.
They remain **unexecuted and un-type-checked by this agent**.

The parent has supplied the engine control-state/module exports and the Tracker
owner API. The service now implements `materialize_source_indices` with the real
`NativeMetadataIndex` header/page/revalidation methods and synchronous per-record
`register_materialized`. New service fixtures exercise actual frozen-owner
mapping/full change stamps, exact leaves, actual source import acknowledgments,
reimport, and unchanged Tracker walk/hash/read counters.
The source bridge retains independently pinned registration evidence per instance;
a new fixture checks that observing an earlier installation does not switch the
later installation's active capture roots. Source rows, history and root
authorization remain intact when an obsolete transient read owner is released.
All new fixtures remain unexecuted/type-unchecked by this agent; parent-run
results are separate. Legacy PID-only session limitations still fail explicitly.
No multi-instance/source-graph/platform acceptance is claimed by formatting.

Parent-reported service execution subsequently found a counter assertion racing
the real Tracker startup audit (`fsWalks` 2→4, `metadataNodes` 2→4, while
`filesHashed`/`bytesRead` stayed zero). Reviewing the call path found no Tracker
scan/refresh request in the frozen reader or source-import adapter. Native watch
rebuild independently requires initial reconciliation after the 1.5s quiet
period. The service observation fixture now uses a bounded, nonblocking
`save_record` notification to await that real dirty/metadata-only audit before
the two counter tests measure work, with periodic audits moved to the validated
one-hour fixture interval. It does not clear reconciliation or fabricate saved,
complete or trusted state. Full counter equality remains asserted for both
initial import and reimport. The revised tests require parent rerun; no child
Cargo command was executed.

The subsequent parent combined run reported only the lifecycle notification
test failing: an older, genuine `Running` frame was queued before the requested
not-running frame. The test now transports the real snapshot epoch with each
state, records an epoch fence before flipping the injected process flag, and
consumes notifications until a newer `NotObservedRunning` frame arrives. Waiting
uses one absolute monotonic 10s deadline and at most 64 events, not per-message
timeout renewal or sleep polling. New pure channel regressions preload multiple
Running frames plus a stale matching state and check the deadline/event bounds.
The native worker and its evidence remain unchanged; selected-file guards and
the final actual Tracker `appRunning:false` assertion are retained. Parent rerun
is pending; no child Cargo, staging or commit was performed.
