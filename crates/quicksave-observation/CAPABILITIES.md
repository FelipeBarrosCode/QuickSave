# Exact runtime capabilities and gaps

No native-platform acceptance has been performed by this agent. No Cargo build
or test command is authorized for this task. The fixtures in `src/tests.rs` are
injected and do not call live process APIs, actual application data, vaults,
provider accounts, or No Land state. The parent must run and review them.

`SourceCapabilities` reports the adapter and its latest runtime admission state.
Real native permission errors change that state to `needs_native_permission`;
whole-source failures report `unavailable`. Individual gaps retain uncertainty
even when some other processes were successfully observed. Support flags do not
mean the entire OS/account scope was accepted or observed completely.

## macOS

Implemented adapter: same-UID, unprivileged `proc_listpids(PROC_UID_ONLY)`,
`proc_pidpath`, `proc_pidinfo(PROC_PIDTBSDINFO/PROC_PIDLISTFDS/
PROC_PIDREGIONPATHINFO)`, `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`.

* The generation includes PID, UID and native start seconds/microseconds.
* The running executable's mapped vnode device/inode must match a no-follow,
  handle-pinned approved executable's full `FileStamp`.
* Mapped-image lookup examines at most 64 regions. Denial, missing vnode
  information or exceeding this bound is an explicit unknown observation, not a
  fallback to pathname/basename identity.
* Registered Mac bundle IDs are compared with the native running code's signing
  identifier, obtained with Security/CoreFoundation APIs after native
  `SecCodeCheckValidity` with `kSecCSNoNetworkAccess`. This requires macOS 11.3+
  for the documented no-network flag on running code. No publisher/notarization,
  trusted-anchor or online revocation claim is made. Unsigned/unverifiable apps,
  unusual bundles whose signing ID differs from CFBundleIdentifier, and
  permission failures require manual review and do not receive a product join.
  The adapter checks bounded native OS-version metadata before using that flag.
  Ambiguous/older OS versions do not call Security validation. An explicit
  executable/installation observation root must cover the complete bundle and
  its Info.plist metadata; a narrow executable-file-only grant is insufficient
  for native bundle signature metadata inspection.
* Open vnode paths and native device/inode IDs are bracketed by descriptor,
  process-generation, mapped-image and approved-root revalidation. A detached,
  replaced, symlinked or no-longer-present leaf cannot borrow its previous name.
* Security.framework may inspect the running app's code-signature metadata;
  the observer does not parse/read application payloads, Info.plist, argv,
  environment or saves. Native Security validation is not app-data capture.

The optional EndpointSecurity adapter is **not bound**. The status API returns
`needs_native_entitlement`, with both complete-stream flags false. This code
does not request an entitlement, install a system extension/helper, or claim
polling is equivalent to EndpointSecurity.

## Linux

Implemented adapter: local procfs only, verified with procfs filesystem magic.
Same-UID, same-mount-namespace process generation comes from bounded kernel
`/proc/<pid>/stat` data (start ticks plus proc directory inode), mount namespace
identity, and the native executable magic-link identity.

`/proc/<pid>/fd` is bounded, FD paths are filtered before file metadata is
requested, and the descriptor's native inode/device must match the no-follow
approved host leaf. Both ends and the process are revalidated. Deleted files
are gaps, never live-path replacements. Foreign mount namespaces/chroots that
cannot match an approved host native file are rejected; no runtime-home,
AppImage argv, Proton prefix, name-matching or canonicalization escape fallback
is used. Kernel-generated proc stat is the only explicit metadata-content read;
no application-file payload is read.

The optional eBPF native bridge is **not bound**. Its status is
`needs_native_permission`; a future binding requires explicit local permission,
verified local code/object and native loss accounting. No No Land agent,
libbpf remote provisioning, privileged subprocess, capability escalation or
remote lifecycle code executes.

## Windows

Implemented adapter: bounded Toolhelp process enumeration, same native SID
verification with token APIs, `GetProcessTimes` creation time and
`QueryFullProcessImageNameW`. Approved paths use QuickSave's no-reparse pinned
native handles and `FileStamp`s.

This is expressly `process_image_path_and_pinned_stamp_only`: it does **not**
prove the running image section's native file ID. The source reports
`running_image_native_identity: false` and `native_open_file_identity: false`.
The collector therefore emits **no Windows open-file attribution**, and adds
`native_file_source_unavailable`. Source permission failures remain unknown.
Path-only samples do not join a registered product identity or prove that
product absent. They remain separate, unconfirmed manual-review process
diagnostics; a known application's execution status remains unknown.
Windows scopes set `uid: 0` as an explicit API placeholder while the adapter
actually binds the current Windows SID. UNC/device and case/spelling aliases
not accepted by the pinned root/lexical scope are not guessed or expanded.

The Kernel-File/Process ETW adapter is **not bound** and reports
`needs_native_permission`; it cannot report an available stream based only on
an administrator token. No ETW session, service or driver is secretly started.
The notify hint route uses its native ReadDirectoryChangesW backend, but those
events carry no usable PID attribution. No Windows packaging/acceptance claim
is made.

## Root hints and worker

The worker owns `notify::RecommendedWatcher` (FSEvents on macOS, inotify on
Linux, ReadDirectoryChangesW on Windows) with symlink-following disabled.
Registrations are **non-recursive** so Linux's backend cannot implicitly
walk/stat private or explicitly excluded child directories. Nested approved
files can still be observed through native open FDs. Descendant-only mutations
can miss root hints; missing them is covered by the polling unknown contract.
The parent can explicitly approve additional subdirectory observation roots.
Nothing automatically broadens a signed observation or tracking grant.

Callbacks discard outside/private/oversized path payloads. The worker receives
bounded root IDs, not untrusted source paths or payloads. Queue overflow,
watcher rescan/error, missed poll, restart, callback failure and events arriving
during reconciliation are loss/unknown epochs. The snapshot exposes current
open evidence, bounded historical manual-review candidates, run/exec-change/
observed-disappearance sessions, and capture triggers for the parent's separate
stable-file reconciler. A closed FD or disappeared process is never “clean”.

All worker commands and OS enumerations have hard bounds. Snapshot/session/
candidate memory is bounded. `shutdown` stops, releases native watchers, and
joins the owned thread; no remote process/thread is launched or detached on
normal lifetime paths. Callbacks must be bounded, non-reentrant, and must not
destroy their worker owner or call its joined shutdown from inside themselves.
Shutdown waits for native calls and callbacks; no fictitious hard cancellation
guarantee is made. An exit fence marks snapshots unknown even after a panic.

## Parent integration requirements

1. Verify native consent over the exact `ScopeRequest` in `ScopeConsent`. It is
   retained in an `Arc` and rechecked before/after bounded polling batches;
   verification errors fail closed. Use an authenticated cached native lease and
   cheap revocation checks, not a vault/config read or a new prompt per file.
   Per-FD metadata pinning does not reserialize/reverify the whole signed scope.
   Do not expose this interface to the UI.
2. Include actual state, repository, root-marker and externally held recovery-key
   locations in `excluded_paths`, and their already-pinned native marker/key
   identities in `excluded_native_files` to reject hard-link aliases. The
   observer never discovers a key by reading it. Built-in exclusions are a
   conservative extra guard, not discovery of where an external key is stored.
3. Translate `AppObservation`/`RootCandidate` into proposals only. Never create
   `SourcePath`s, issue tracking grants, or expand an approved root because the
   observer found a file.
4. Keep the tracking engine's stable-file validation, payload integrity and
   upload-generation checks. This metadata-only observer is neither a content
   scanner, a snapshotter, nor application-wide atomic consistency.

The materialized-record bridge and explicit native app-ID/root binding API are
documented in `INTEGRATION.md`. Quiet polling backs off (default 2–30 seconds),
coalesces hints behind the minimum interval, updates cached snapshots, and does
not invoke service callbacks for repeated intrinsic polling gaps. This avoids
periodic force-hashing in Tracker without treating silence as completeness.

The implemented native service owner is
`crates/quicksave-service/src/observation.rs`. Startup remains an explicit parent
action after signed policy activation; disabled/isolated startup is inert, and
unit tests cannot select the ambient process source. It can bind a parent
StateDB sink but does not assert that bridge is connected when absent.
Scope admission verifies the exact native-derived request and current real
tracking/global-policy MACs around polls. Protected native file IDs come only
from the owner's already-pinned marker/key handles.

The service's real-gap fallback delivers an authenticated `change_hint` with
unknown reasons. Tracker has no public overflow-invalidation method at present;
no stronger forced-hash/unknown-generation behavior is claimed. Cached status
reports this limitation, actual bound/prepared/unconfirmed counts and bounded
diagnostics, never native path lists or grants.

The further Unix source-graph adapter is the new
`quicksave-noland/src/observation_control.rs`. Its source-engine service sink
performs actual DB session/path association writes, retains full native
generation/image proofs, and never injects source Linux process/FS events.
Metadata index import requires a native frozen Tracker owner and preserves
VerifyRequired/no-content-hash states. Missing owner/registration, busy admission,
instance/root mismatch, unrepresentable source IDs, or lost legacy PID generation
proof are explicit limitations. Source graph/platform acceptance remains pending
parent module/state/index-owner wiring and serialized validation.
