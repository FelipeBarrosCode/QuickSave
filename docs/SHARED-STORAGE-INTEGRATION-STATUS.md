# Full Shared Storage — integration checkpoint

This is **not a completion/acceptance record**. The binding scope remains
[FULL-SHARED-STORAGE-CONTRACT.md](FULL-SHARED-STORAGE-CONTRACT.md), including the
original optimizations. The older workspace-v2/folder preview is not parity.

## Normal-mode macOS follow-up

### User-directed NSWorkspace / Launch Services discovery

Replaced production macOS installation-folder enumeration with linked public
NSWorkspace application URLs/Launch Services identifier resolution and scoped
Spotlight application-bundle metadata gathering. The primary retained-base
planner and legacy read-only discovery endpoint both use this path. No shell
commands, private registry dumps or application launches are involved.

See [MACOS-NATIVE-APP-DISCOVERY.md](MACOS-NATIVE-APP-DISCOVERY.md) for bounds,
source coverage, fixtures and the unchanged identity/permission requirements.
Native records are hints, not data-root grants; no source permissions, exclusions,
autosave, keys, remote history or tracking policy bases are widened. Unsupported
or partial native inventory never falls back to crawling folders or fake bundles.
Different native installations remain ambiguous; alternate spellings of one
installation are deduplicated using actual native identities.

The linked Foundation/AppKit bridge and production Rust path compile on macOS.
**62 integration tests and 126 service tests passed** (188 total), including
candidate injection, no folder-crawling fallback, outside-policy rejection,
native case aliases, absent bundle identity, malformed response bounds and a
linked C argument guard that returns before any native application query.
The service tests retain actual capture/history/source-index regressions.
No tests inspected real running-app records, private application data, credential
vaults or No Land state. Real native gathering and permissions are separate
acceptance gates; an OS-native discovery source does not promise every installed
app has a verified data-root mapping or complete backup coverage.

The native desktop build passed with the linked Objective-C bridge. Windows
integration/service test sources and Linux integration test sources cross-checked
successfully; these checks did not link or execute Windows/Linux applications.
Repository verification and `git diff --check` passed.

The user approved a normal relaunch: PID 62151 accepted normal quit, and the new
normal-mode build launched as PID 66342. Its visible native window was verified
at `2026-11-19T13:02:04Z`; receipts are
`artifacts/native-nsworkspace-launch.json` and
`artifacts/native-nsworkspace-window.json`. No settings reset, permission change,
credential import, tracking approval or upload was performed by the agent.
Actual native inventory gathering remains for the user's explicit refresh.

Validation commands for this change:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p quicksave-integrations
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-integrations -p quicksave-service --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --target x86_64-pc-windows-gnu -p quicksave-integrations -p quicksave-service --tests
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --target x86_64-unknown-linux-gnu -p quicksave-integrations --tests
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml --bin quicksave-desktop
python3 scripts/verify_repository.py
git diff --check
```

### Protected-root and paused-approval recovery, November 19

Addressed the next reported retry failures, without a configuration reset or
permission changes:

- Added the narrow [boot APFS Data namespace proof](MACOS-APFS-APPROVAL-PROOF.md).
  Explicit native volume capabilities, physical no-firmlink directory ancestry,
  pinned mount parents/roots and a bounded stable mount snapshot can establish
  disjointness without enumerating protected descendants. Unsupported layouts
  still require the complete census; denied/incomplete proof remains an error.
  Fixtures reproduce a mode-000 synthetic `protected/id_rsa` directory: the
  census fails while the supported native proof and actual owned-child indexing
  succeed, with zero selected payload bytes/hashes.
- Explicit **Refresh app tracking** now rechecks a paused approval and reconciles
  metadata before lifting its denial latch. A typed deferred legacy authority
  can be renewed only for a never-captured metadata-only enrollment with unchanged
  exact roots/source identity and no baseline, history, receipt or pending work.
  Background materialization cannot do this. Real encrypted-state/MemoryVault
  integration verifies that refresh reads only the active aggregate vault item,
  not old credentials; revocation and unavailable historical authority remain
  blocked.
- Zero selected roles/owned children is an intentional-omission diagnostic, not
  a fabricated permission error or placeholder bundle. Simple errors are no
  longer repeated twice.
- Idle/terminal Activity stops polling. Accepted user actions and explicit
  resumption have a bounded status round and share in-flight requests. Missing
  unfinished work is retained even against a full 128-row response; absence is
  never a completion/cancellation receipt. Idle status refresh is not a source
  scan or automatic retry.

Final isolated validation passed **616 workspace Rust tests**, with one rclone
integration test intentionally ignored, plus **6 native gateway tests**
(**622 Rust tests total**), **184 frontend tests**, and the frontend/native
desktop builds. The gateway fixture now canonicalizes its private temporary
parent rather than traversing macOS's `/var` symlink.

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-platform -p quicksave-tracking -p quicksave-service -p quicksave-state -p quicksave-control -p quicksave-noland -p quicksave-integrations -- --test-threads=1
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --bin quicksave-desktop -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --target x86_64-pc-windows-gnu -p quicksave-platform -p quicksave-state -p quicksave-tracking -p quicksave-service --tests
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --target x86_64-unknown-linux-gnu -p quicksave-platform --tests
npm --prefix apps/desktop test -- --run
npm --prefix apps/desktop run build
CARGO_TARGET_DIR="$PWD/target" CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml --bin quicksave-desktop
python3 scripts/verify_repository.py
git diff --check
```

Windows test-source and Linux platform test-source checks passed; neither links
or executes those platforms. The full Linux service cross-build is not newly
established: `x86_64-linux-gnu-gcc` is still unavailable. Repository verification
passed: 227 immutable reference files, 243 fork files, 117 recorded fork deltas,
33 manifests and 13 workspace members. No engine optimization or provenance
requirement was relaxed.

After explicit user approval, the prior PID 35711 accepted normal quit; the
rebuilt normal-mode app was launched as PID 57737 with existing configuration.
The launch request is recorded separately at
`artifacts/native-tracking-recovery-launch.json`; prior launch receipts remain
untouched. No force quit, configuration reset, permission repair, credential
import, tracking approval or upload was requested by the agent.
A visible native window owned by that exact new PID was verified at
`2026-11-19T11:01:34Z` (`artifacts/native-tracking-recovery-window.json`).
Window visibility and the user's actual refresh results are separate evidence;
no live tracking/credential/backup acceptance is claimed here.
Safari/Zed identity gaps and apps with no verified selected child roots remain
explicitly unresolved, not silently converted to complete applications.

### Cross-ruleset audit after reported app errors

See [TRACKING-RULESET-AUDIT.md](TRACKING-RULESET-AUDIT.md) for rule coverage,
exact validation commands, and unresolved protection constraints.

Confirmed/corrected the real producer `mac_os` versus fixture/consumer `macos`
mismatch that bypassed the narrower data-only container branch. A service test
now serializes the actual discovery enum and rejects broad scaffold capture.
Also separated intentional incomplete coverage from OS errors, made executable
registration metadata-only, grouped shared protected-rule failures, added
redacted source-index failure stages, isolated pending-app status, and serialized
execution-time tracking verification against cooperating metadata updates.
No grant, alias, payload readability, completeness, or Saved requirement was
relaxed.

Final serialized isolated run passed: 146 state, 124 tracking, 123 service, and
63 native-adapter tests, with one explicitly ignored rclone integration test.
The integration rules suite passed 57 tests; the frontend passed 179 tests.
Seven platform unit tests and seven real native overlap-fixture tests also
passed (including unreadable payloads, denied directories, aliases and root
replacement): 527 Rust tests passed in the scoped review overall.
Windows state/tracking/service test sources cross-checked successfully with
`cargo check --target x86_64-pc-windows-gnu ... --tests`; this did not link or run a
Windows application. Native Windows/Linux acceptance is still outstanding.
Repository provenance verification passed with the immutable snapshot/fork
unchanged. Earlier attempts found a temporary-directory fixture failure and the
metadata-projection race; they are not counted as successful validation.

**Still unresolved:** a denied census inside a protected directory can prevent
tree disjointness from being established. The shared `.ssh` blocker was not
bypassed or represented as fixed by diagnostic grouping. No actual SSH/app data,
native vault entries or cloud account were inspected for this review. The app was
not relaunched and live configuration/permissions were not reset or modified.

Subsequent user-approved relaunch: frontend and native desktop builds passed
using the existing root Cargo cache. The prior process accepted a normal quit;
the audited build launched in normal mode as PID 35711 (receipt:
`artifacts/native-normal-launch.json`). No configuration reset or agent-initiated
credential import/upload was performed. The protected-tree overlap blocker
remains unresolved; this is build/launch evidence, not backup acceptance.

### Local-first tracking review, November 18

- Added a separate native-ticket local setup: inventory QuickSave account
  attributes, import only the existing local signing key, and defer old cloud
  values inside an authenticated pending manifest. Deferred reads fail explicitly;
  writes/deletes atomically retire pending entries. Later exact remaining-only
  import preserves newer grants and deletion decisions. No legacy item is changed.
- Added noninteractive single-item readiness and explicit single-item native
  authorization. Setup does not enable tracking, connect providers, or upload.
- Saves/settings are the default tracking roles; installation/runtime remains
  opt-in. Data-only macOS roots omit whole-container scaffolding, retaining
  independently verified owned children with explicit partial coverage.
- Temporary authority failures retain references/history behind a persisted
  denial latch. Pending apps are not verified bundles or Saved. Informational
  protected-product exclusions no longer mark inventory incomplete.
- Cloud-history initialization failures no longer block the local dashboard:
  history is explicitly unavailable, existing work is retained, and new data
  operations remain blocked.

Validation used synthetic vaults and isolated temporary source/provider fixtures:
179 frontend tests and production frontend build passed; 145 state, 123 tracking,
57 integration, and 28 control tests passed. The 118-test service suite passed
serially. A selected-capture metadata projection race failed in earlier runs and
passed on focused and serial reruns; this must not be represented as proven
race-free acceptance.

Native desktop gateway compilation was interrupted by timeout/disk exhaustion;
generated desktop/service Cargo caches were cleaned to recover space. No updated
native app was launched, no real vault migration was performed, and native
Keychain/Windows/Linux acceptance remains outstanding. The existing running app
was not reset, replaced, or relaunched.

Subsequent user-approved rebuild/relaunch: the frontend production build and
native desktop build passed using the existing repository-root Cargo target
cache. The old process accepted a normal quit and the local-first build launched
in normal mode as PID 24906 (receipt: `artifacts/native-normal-launch.json`).
No configuration reset, credential import, tracking approval, or upload was
performed by the agent. Build/launch evidence does not establish real Keychain
or backup acceptance; native gateway tests remain unexecuted for this revision.

### User-approved encrypted state vault

The user subsequently confirmed native `-25293`: unconditional suppression
prevented reading old items. Explicit pre-worker migration now uses a PRIVATE
authorization-capable backend, constructed only after a spent native approval.
All native vault operations share a process-wide interaction mutex; UI is restored
to false before release on success/error/cancellation/unwind. Reset failure blocks
further native access. The migration backend cannot write old accounts, delete
items, or read foreign namespaces. Ordinary/background access stays noninteractive.

This correction passed **133 state tests + 27 control tests**, **170 frontend
tests**, desktop build/four gateway tests, and Windows state test-source checking.
The corrected app was normally relaunched as PID 16258; real OS authorization and
successful migration still require the user's native approvals and are not claimed
by synthetic tests. The user's requested config reset was separately backed up;
Keychain items and backup history were not deleted. Tracking must be opted into
again after that reset. No migration was started automatically.

Subsequent user migration failed behind an overbroad native error message. The
failure has **not yet been diagnosed against a real native operation**. A follow-up
adds typed migration phases, redacted numeric native OS status, distinct
already-encrypted/recovery messages, and removes irrelevant Windows wording from
the generic native failure. No account names, key material, raw backend bodies or
private paths are forwarded/logged. The follow-up passed **128 state/vault tests**
and **170 frontend tests**; desktop build and gateway tests passed. Direct macOS
Security.framework dependencies now match keyring's actual major version so
numeric status downcasts are exercised by a synthetic error-construction test.
The updated app was normally relaunched as PID 7631, with a visible-window receipt.
No real migration was retried automatically. The 701-test checkpoint below
predates this diagnostic follow-up.

Implemented authenticated encrypted `state.json` secrets, one active native
key/rollback-anchor item, and explicit startup migration before workers launch.
Old native items remain unchanged; missing aggregate entries and rolled-back
legacy state never fall back to them. Two ciphertext slots preserve independently
durable revocations across failed outer metadata updates. Public service snapshots
strip encrypted payloads, and non-secret metadata operations remain vault-free.

The startup gate uses the existing three IPC commands and a spent native ticket,
binding generation/native workspace identity again under the state lock. Native
status/approval bypass service initialization so locked tracking startup cannot
prevent an explicit migration attempt. Isolated host/service flows share their
injected synthetic vault; production tests do not access OS entries.

- Final expanded Rust workspace: **701 tests passed**, zero failures, two ignored,
  using `--test-threads=1`. A stale Unix fingerprint test was corrected to accept
  the literal filename `CON` while still rejecting NUL; Windows target-name
  preflight remains strict.
- Real source capture/additive empty-history/optimization regression also passed
  after encrypted-state migration. Provider/repository keys, tracking/autosave
  grants and historical baseline preservation are covered after migration/reopen.
- Desktop native gateway: **4 tests**; frontend **170 tests**, typecheck and
  production build passed. Python **103 tests** passed.
- Windows state/service/control test sources cross-compile. **Windows legacy
  inventory/migration is explicitly unsupported**, not a guessed partial import.
- Linux inventory type-checks against pinned real libdbus Rust declarations for
  `x86_64-unknown-linux-gnu` without linking/executing native calls. Full Linux
  cross-check is blocked by missing `x86_64-linux-gnu-gcc`; native Linux tests,
  Secret Service availability/unlock and native Windows acceptance remain open.
- Existing locked/unapproved legacy items can prevent migration. The main
  process remains noninteractive; this is not a guarantee of an OS-level
  one-password unlock across existing items or changing development identities.

Details: [encrypted workspace vault](ENCRYPTED-STATE-VAULT.md). No real credential
migration, legacy deletion, provider connection, upload or permission repair was
performed during development. The final native desktop build, four desktop
gateway tests, and latest Windows state/service/control test-source cross-check
passed. The binary is ready for a user-directed restart; it has not been launched
or used to migrate real credentials by this validation.

### Keychain prompt storm (not single-authorization acceptance)

At the user's subsequent request to remove the prompts, macOS native vault
operations now disable interactive Keychain Services for this process before
using the legacy `keyring` backend. Locked/unapproved items fail explicitly rather
than displaying dialogs. No credential is reclassified as missing, replaced,
deleted or exported by this change. This is a no-dialog policy, **not** acceptance
of a usable one-password vault migration; unavailable credentials can still block
features. The updated state/vault suite passed **85 tests** and the native desktop
build passed. No live credential/vault operation or no-dialog workflow acceptance
was performed; the updated binary has not been launched by this validation.

The user's screenshots identify `quicksave.desktop-secrets.v1` access dialogs
while startup is pending and activity reports exhausted read workers. Same-service
dialogs can refer to distinct accounts; Always Allow does not grant every account
or guarantee trust survives development rebuilds.

Startup background reads now wait for a loaded dashboard and stay paused after
startup failure. Native vault operations are serialized and fail closed for the
rest of a session after a failed request; restart is the explicit retry boundary.
Fresh authority/revocation reads and native write read-back remain intact; no
successful authorization cache, ACL change, global Keychain unlock or plaintext
login password is introduced. The guards passed **158 frontend tests** and
**84 state/vault tests**, including concurrent denied requests.

The updated frontend production build and desktop rebuild passed.
QuickSave is left closed to avoid further live prompts. Consolidating existing
per-scope items and stable signed application trust remain unaccepted; these
guards must not be described as the requested one-password solution.

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
