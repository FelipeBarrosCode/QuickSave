# Full Shared Storage — integration checkpoint

This is **not a completion/acceptance record**. The binding scope remains
[FULL-SHARED-STORAGE-CONTRACT.md](FULL-SHARED-STORAGE-CONTRACT.md), including the
original optimizations. The older workspace-v2/folder preview is not parity.

## Normal-mode macOS follow-up

### Directory-approval correction

A subsequent user refresh localized failures to `approve_directory_identity`.
That approval had reused strict capture metadata enumeration for overlap checks
against protected roots. It could reject an unrelated selected app because of
protected-side file/link metadata or regular-file churn.

The replacement overlap check uses bounded, no-follow directory-identity censuses,
not payload opens or link-target reads. It still checks shared descendants and
fails on inaccessible/replaced directories or exhausted limits; disjoint checks
still inspect both directory trees. This is not an OS-level topology lock or a
new capture capability. Capture's stricter traversal remains unchanged.

Candidate identities are pinned before root normalization; only retained roots
receive full anti-alias audits before indexing/grants. Omitted container scaffolding
remains explicitly partial rather than following links into unrelated home data.
Final typed failure-side integration passed **297 tests** (67 platform, 116
service, 114 tracking). Windows platform tests cross-compile; 103 Python tests
and repository verification also pass. Desktop rebuild passed and the updated
normal-mode process is PID 75326, with a PID-bound visible-window receipt in
`artifacts/native-normal-window.json`. The prior exact process received only a
normal quit request. No permissions, settings or tracking/provider operations
were changed by the relaunch; live refresh acceptance remains pending.

Real user interaction subsequently reported OS permission denials, a rejected
native filename in iMovie, and unresolved installation identities. The checkpoint
below predates this follow-up; these reports are not native workflow acceptance.
Development investigates them only with isolated synthetic fixtures.

- Metadata-only indexing was requesting payload read access. A new native
  `SafeRoot::file_metadata` observes full identities/timestamps without payload
  access; actual capture still requires real readable native handles.
- POSIX filename handling needs exact native names rather than blanket Windows
  portability rules or backslash-to-slash normalization. Cross-platform restore
  must reject incompatible target names before mutation.
- No Land/QuickSave are now excluded by canonical macOS bundle ID before
  executable/app-data enrollment. Unresolved apps retain their concrete native
  reason in the diagnostic projection.
- Platform regression tests passed **56 tests**; Windows platform tests
  cross-compile. Integrations passed **52 tests**. The combined follow-up passed
  **304 tests** (115 service, 108 tracking, 81 state), including five actual-source
  interoperability cases. Source core/snapshot/restore passed **187 tests** and
  the optimized pipeline passed **21 regressions**, including exact native-name
  backup/restore, reuse and additive history. Frontend tests passed **156** and
  Python tests **103**.
- Failed scans retain existing baseline/index authority. Initial enrollment may
  retain complete independently verified roots with explicitly partial coverage;
  it never omits unknown descendants inside a claimed complete root. Partial
  coverage cannot advance complete-application heads.
- Native root diagnostics now survive the service/UI projection with bounded
  friendly names, failure stage and approved path. The updated desktop build
  passed and was relaunched in normal mode (PID-bound visible-window receipt:
  `artifacts/native-normal-window.json`). Only the prior exact QuickSave process
  received a normal quit request; no force termination, settings reset or
  permission repair was used. Tests/window visibility are not live-app permission
  acceptance.

See [macOS tracking diagnostics](MACOS-TRACKING-TROUBLESHOOTING.md). No source
permission repair, `sudo`, real-app repro, automatic upload, or vault probe is
part of this investigation.

## Current validated checkpoint

- **620 Rust workspace tests passed**, two opt-in tests ignored.
  Log: `artifacts/native-workspace-tests.log`.
- **449 tests passed in the combined shared-library run**: 32 CAS, 12 pack, 132 restore,
  8 snapshot, 40 core and 225 storage; eight opt-in tests ignored.
  Log: `artifacts/native-shared-libraries-tests.log`.
  The subsequent restore rerun passed **133 tests**, including the exact
  three-namespace Windows manual-leaf metadata contract, with three opt-in
  workloads ignored (`artifacts/native-restore-tests.log`).
- **20 actual-source pipeline regressions passed**; the separate bounded
  64 MiB / 1,000-file benchmark also passed. The latest raw receipt is
  `artifacts/native-shared-storage-benchmark-latest.json`.
- The **five real Tracker → source interoperability tests passed**, including
  full/custom/empty/additive history, changed-during-upload dirt, original
  encrypted-proof reload after restart and same-length sidecar tamper rejection.
  Recovery authenticates the independently signed original frame, not a revoked
  historical *current-index* nonce, and never recaptures today's files.
- Frontend typecheck, **155 tests**, production build and **103 Python tests**
  passed. Actual WebKit geometry checks passed on Overview/Backup/Restore at
  1320-, 880- and 360-pixel widths, preserving the main scroll and modal position.
  The WebKit fixture has synthetic IPC and rejects every native mutation.
- Windows **service, bridge and their tests cross-compile**:
  `cargo check -p quicksave-service -p quicksave-noland --tests --target x86_64-pc-windows-gnu`.
  This is not native Windows test execution. Linux integration/control target
  compilation also passed; full Linux/native workflow acceptance is separate.
  A full Linux service target check stopped at bundled SQLite because this host
  lacks `x86_64-linux-gnu-gcc`; no toolchain download/install was attempted.
- Repository verification passed: **227 immutable upstream files**, 242 active-
  fork files, 116 recorded deltas, 33 manifests and 13 workspace members. Original
  notices are preserved; owner/license review remains required before distribution.

The latest benchmark measured 46.57 s fixture work / 46.85 s runner time.
Unchanged capture rehashed **0 files**, reused 1,000 and created **0 packs**.
One-file capture rehashed one, reused 999 and created one pack. Identical restore
downloaded **0 packs**; selective restore downloaded **1 of 3**. Ordered assembly
performed **0 post-assembly readback bytes**. Physical source reads, preview reads,
RSS and some queue peaks are uninstrumented; limiter fault feedback is simulated.
These are isolated filesystem-provider measurements, not live-provider throughput.

The native desktop also built and was launched with a fresh synthetic home and
memory vault; the PID-bound visible-window receipt is separate from workflow
acceptance. Native launch/build receipts are in `artifacts/native-latest-*`.

## Integrated in the parent

- Removed discovered-name placeholder software rows.
- Added consent-backed native enrollment, actual metadata-index materialization,
  bounded scan status, pinned policy bases and persistent policy revalidation.
- Connected automatic No Land source discovery and opaque source IDs to native
  tickets. Advanced file selection is a fallback, not the normal import route.
- Isolated development uses a memory vault and synthetic home/data locations,
  including the No Land finder; it must not inspect real source vault entries.
- Preserved full source application identities and installation/save/config/
  runtime/container roles through source registration and classification.
- Added metadata-only prepared upload scopes and a Rust-only actual-source
  capture receipt handoff. The engine supplies file hashes and complete native
  stamps; neither the tracker nor the bridge predicts content hashes.
- Kept native receipt verification at actual publication barriers, not in UI
  polling. Cached software/file listing does not invoke content capture.
- Routed selected native uploads to the existing compatible `custom` backup mode,
  rather than falsely advancing a complete-application head.
- Registered operation-bound credential refresh/CAS and source transfer policy;
  explicit session finalization participates in completion. No live account
  acceptance has occurred.
- Updated native request validation for frozen restore IDs and separate overwrite
  acknowledgement; removed the frontend's legacy direct-download fallback.

## Still open — do not call the whole port complete

- Full native workflow acceptance beyond the now-passing real cross-layer
  full/empty/additive capture, batch, original-receipt recovery and source graph
  fixtures. Legacy/missing original frames remain explicitly unrecoverable.
- Complete user-facing standalone receipt-backed retry/reattachment coverage.
  Typed original recovery and batch wiring are not proof that every restart
  action is available through the desktop.
- Explicit local deletion-state/tombstone acknowledgement. Default restores keep
  local originals and do not treat cloud tombstones as local deletion permission.
- Runnable application/signature/dependency acceptance. Authenticated `.app`
  placement, package/resource/link reconstruction and exact native mappings are
  tested; readiness remains `files_only` or `reconstruction_unverified`.
- Windows native observation/source-graph and all-app/recovery composition.
  Process polling is incomplete evidence, never a complete kernel trace or
  cleanliness proof, on every platform.
- Finish whole-workflow performance acceptance. Receipt-backed epoch reuse and
  complete-manifest autosave are wired; source and tracker regressions pass.
- Native Windows/Linux, real provider/vault, packaging and power-loss acceptance.
  No trusted installed rclone/helper or live account was used here. Cross-target
  checks and a visible macOS window do not establish those outcomes.

## Historical isolated checkpoints (superseded by the current checkpoint)

Earlier serialized core run:

```sh
env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-service -p quicksave-noland -p quicksave-state -p quicksave-tracking --no-fail-fast
```

**228 passed**: 54 service, 39 bridge, 65 state, 70 tracking; one installed-rclone
integration test remains ignored. This includes actual temporary-file enrollment,
the cross-crate coverage/source-identity MAC binding, full-manifest autosave,
dirty follow-up after older immutable captures, and authenticated restore fixtures.

The source `native_optimized_pipeline` integration binary compiles. Its regular
run now has **17 passing regressions and one ignored bounded benchmark**. It
checks actual source capture/pack/commit behavior, exact additive omissions,
genuine empty roots, authenticated root layouts, source-loss reuse fencing,
relative-link metadata and older immutable generations. Restore completion is
verified using its authenticated clean-commit receipt, not by incorrectly
requiring all recovery metadata directories to disappear. The explicit 64 MiB /
1,000-file local benchmark also passed, in 42.13 seconds of measured fixture
work. Its raw receipt is
[`artifacts/native-shared-storage-benchmark.json`](../artifacts/native-shared-storage-benchmark.json).
Unchanged capture rehashed zero files and created zero packs; one changed file
reused 999 files, rehashed one and created one pack. Identical restore reused all
1,000 files and downloaded zero packs. Ordered streaming restore had zero
post-assembly readback. These are isolated filesystem-provider results, not
live-provider throughput, RSS, physical-read or platform acceptance.

The latest platform/control/observation run passed 49 macOS filesystem tests,
25 control tests and 29 injected observation tests. Windows-gated tests did not
run on this host.

Subsequent isolated native checks: **51 integrations, 51 filesystem, 73 state,
82 tracking, 26 control, 155 frontend and 95 Python tests passed** at their
recorded checkpoints. A subsequent source-library run passed **211 tests**:
32 CAS, 12 pack, 119 restore, 8 snapshot and 40 core. Three opt-in restore
workloads were not run. The bridge rerun passed **50 tests**, with one
installed-rclone fixture ignored.

An intermediate combined run failed on bridge fingerprints, immutable fixture
kinds, batch handoffs and the real full-scope digest boundary. Those failures
were fixed; the current full workspace and interoperability runs above pass.

Additional integration now connects authenticated frozen Tracker metadata pages
to the actual source DB and native process/file-use evidence, with joined
observer shutdown before Tracker. The current combined run includes its tests
and real Tracker → source-capture fixtures. A bounded four-Hz revocation check
now carries small native grant envelopes, not a cloned 250k-node work inventory;
exact capture receipts remain mandatory at real publication barriers.

The desktop's exposed commands/permissions are now only the three workspace
gateway commands. The obsolete local-format/discovery IPC fallback is no longer
registered; the separate CLI/library is retained.

Cross-target compilation is distinct from native acceptance:

- `cargo check -p quicksave-integrations -p quicksave-control --target x86_64-unknown-linux-gnu`
  passed.
- `cargo check -p quicksave-noland --target x86_64-pc-windows-gnu` now passed the
  complete Windows native engine bridge, including frozen restore/full-scope
  capture handoffs and shared libraries. Platform tests also **cross-compile**
  with `cargo check -p quicksave-platform --tests --target x86_64-pc-windows-gnu`.
  No Windows test binary, native workflow or package was executed. Service-level
  target integration is checked separately.

Read-only provenance checks confirmed all **227 immutable upstream files** and
**33 Rust manifests / 13 QuickSave workspace members**. The audited Windows-only
SQLite → local platform-library edge is explicit; unrelated reverse edges remain
rejected. The reviewed active-fork delta ledger was subsequently refreshed and
verified as recorded above.

An earlier supporting host suite: **235 passed** (26 control, 51 integrations,
31 observation, 54 filesystem/browser-validation, 73 state); frontend typecheck,
155 tests and production build passed, as did 101 Python tests. The service/
Tracker integration run compiled and exercised its expanded suites, but is
then failed: 95 service / 94 tracking tests passed with six/two failures,
respectively. Remaining failures cover fixture software-vs-instance identity,
scan-counter isolation, retained-frame retirement and one explicit history retry.
Those were corrected without dropping the safety/performance assertions.

Parent commands so far include:

```sh
env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-control -p quicksave-integrations --no-fail-fast
env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-observation -p quicksave-control
env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p quicksave-service
npm run typecheck
npm test -- --run
python3 -m unittest tests.test_native_bench_helpers
```

At their recorded checkpoints: 25 control, 43 integrations, 23 observation,
107 frontend and 12 benchmark-helper tests passed. Later edits still require
reruns; the benchmark-helper tests are not provider throughput measurements.

Earlier state/tracking/service integration runs exposed Box fixture policy,
unsafe-link fixture setup, and cross-crate enrollment grant/coverage binding
regressions. Those were fixed and the core suites rerun as recorded above.
Source restore work also temporarily broke compilation while its new metadata
helpers were being added. The current full-workspace pass is recorded at the top.

All exercised data was synthetic and isolated. No real No Land state, account,
credential vault entry, cloud upload/restore/delete, remote machine, repository
merge/release, signing identity or paid resource was used.
