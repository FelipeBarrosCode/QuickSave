# Workspace service integration handoff

Original GPL-3.0-only QuickSave orchestration. No upstream code is copied.

## Public gateway API

```rust,ignore
pub async fn WorkspaceService::open(data_dir: &Path, home: &Path)
    -> anyhow::Result<Arc<WorkspaceService>>;
pub async fn query(&self, name: &str, params: Value) -> anyhow::Result<Value>;
pub async fn execute_authorized(&self, action: &str, params: Value)
    -> anyhow::Result<Value>;
pub async fn confirmation_details(&self, action: &str, params: &Value)
    -> anyhow::Result<Value>;
pub async fn approval_scope(&self, action: &str, params: &Value)
    -> anyhow::Result<Value>;
pub fn shutdown_blocked(&self) -> bool;
pub async fn shutdown(&self) -> anyhow::Result<()>;
```

The parent must retain opaque single-use tickets containing exact native-approved
parameters. `execute_authorized` is **not an IPC command**. A JSON `approved` flag
does not authorize anything and is rejected. `confirmation_details` never starts
deletion. It only retrieves the stored frozen preview, including dependencies.

`approve_provider_writes {providerId}` (`authorize_provider_writes` accepted as an
alias) is a separate native-confirmed action,
required before uploads/deletes/autosave on imported read-only providers.
`verify_provider {providerId}` explicitly retries real read-only health with the
retained native credentials, never a cache-only success. Failed verification
stays an error without deleting encryption keys; disconnected profiles require
a fresh connection/reimport because their credentials were removed.
`connect_oauth` uses `quicksave_oauth::authorize` with private native PKCE for
Google Drive, OneDrive and Dropbox; other kinds explicitly fail. A registered
public/native client ID is required. Tokens go directly into the native
vault-backed store's exact `o_auth2` shape, never into IPC/state/history. Real
engine provider health must succeed after authorization before connected.
Before any browser, vault read, master-key creation or token acquisition,
`connect_oauth` checks native engine preflight and requires
`available:true, oauthRefreshPersistence:true`. The bridge reports whether its
operation-bound native refresh/CAS/recovery authority is actually installed.
Session finish must durably hand off rotated credentials before cleanup; vault
or ambiguous finish errors remain failures, not connected/Saved state. Protocol
implementation is not live-account acceptance. Missing rclone is reported first
when native preflight cannot run.
`open_oauth_browser` is exported for parent integration: fixed OS-owned browser
opener, allowlisted HTTPS authorization URL as an argument, no shell, no output,
three-second bounded launch wait. Tests inject `ServiceOAuth` instead.
The `native-oauth` feature is enabled by default and uses the path dependency's
published `OAuthRequest`/`OAuthTokens`/`authorize` API. A deliberately disabled
feature build explicitly rejects OAuth rather than faking a connection.

Operations return `{operationId}` immediately after bounded service admission,
with `queued/preparing` until the real native journal accepts the same operation.
No transfer progress is invented before native admission.
Service-owned asynchronous monitors retain shutdown/admission counters until
engine terminal state **and** durable tracker finalization. Watcher callbacks
only use a bounded `try_send`, never cloud I/O. Queue/submission failures release
the tracker work with `success=false`, retaining dirty/pending state.

## Sibling coordination needs

- State: uses `WorkspaceStore::document` (no vault access), `update_software`
  (direct lossless tracker records), `issue_grant`/`verify_grant`/`revoke_grant`,
  `verify_tracking_grant`, `verify_autosave_grant`, `provider_writable`,
  `grant_provider_write`, `record_provider_health` and the contract methods.
  Every manual tracking/root/leaf scope is signed even without autosave.
- Engine: uses `health(&ProviderAccess)` and preserves actual `providerId`,
  `canList`, `canRead`, `repositoryAccessible`, `repositoryEmpty`, `keyVerified`,
  `evidence`, and `observedAt`. Empty repository list + absent-head evidence
  allows connection without inventing successful read/decryption.
- Engine: upload must consume tracker-approved `roots`/`captureSource` and exact
  selected file identities without widening; tracker and engine file IDs must
  agree or have an explicit lossless conversion. Selection is passed unchanged
  with the assigned operation ID.
- Tracker: use its published `TrackingStore`, `Tracker`, `TrackingPolicy`,
  `begin_upload`, `complete_upload`, file listing, native root approval and grant
  validation plus `root_authority`/`verify_autosave_work`. An engine submission
  error calls `complete_upload(..., false)`.
- Whole-software and selected work carry frozen explicit `fileIds`, metadata
  identity and native-only immutable node owners. Production capture is paged
  through `CaptureController`; actual source receipts supply hashes, never a
  duplicate tracker content scan. Full/empty scope requires signed native
  baseline/omission evidence. Custom subsets do not advance complete-app heads.
- Uploads use the typed trusted `PublishGuard` with
  `NativeEngine::upload_captured_guarded`. Receipt-backed recovery reloads only
  authenticated original work and actual source checkpoints/receipts; no new
  capture is substituted under the original ID.
  It checks connected/native write authority, frozen signed manual root/provider
  scope, and autosave enabled/grant/work validity immediately before publication.
  The monitor cancels on revocation too; terminal completion cannot acknowledge
  revoked authority. Older immutable captures may publish without clearing newer
  dirt. Saved requires an authenticated actual committed result after owner
  drain, never an unsigned terminal DB row. Guard functions never cross IPC.
- Native operation submission errors must mean definitive admission failure.
  Ambiguous acceptance must return an operation ID so close protection remains
  active while the actual journal is monitored.

Test construction injects service Store/Engine/Tracking/Discovery interfaces;
synthetic tests never invoke a native vault, live account, or No Land state.
Only the parent runs serial Cargo verification with the shared target.

`approval_scope` never reads credentials or newly selected source/destination/
import paths. Its provider/software/deletion summary includes a deterministic
`scopeFingerprint`. Parent retains this with the ticket and compares immediately
before execution, or supplies it as native-only `_scopeFingerprint` (not accepted
from JS). The service checks that value before admission. Persisted native root
identity/grant checks are repeated by the owned operation worker.
Parent-only `_approvedPaths` are structurally bounded, excluded from approval
fingerprints, and forwarded intact to tracker/import/download workers. They are
never discarded and recomputed against replacement paths. JS must not supply
either private field.

The deletion context is `{deletion:{previewId,summary,...}}`: the single-line
summary contains exact backup/application IDs, item and byte counts and dependent
backup count. Its frozen-plan fingerprint is retained for equality checking.
Preparing/looking up this context never calls engine deletion.

Native source handles are retained through async terminal journal confirmation
and durable tracker completion. A worker panic/abort or failed durable completion
leaves shutdown blocked, never reports a clean generation, and never silently
releases unknown native work.

`shutdown_blocked` reads a single atomic outstanding-work counter, avoiding a
false idle observation while a queued job becomes active. Shutdown first stops
new admission, waits for a queue barrier, rechecks work, then joins tracker and
service workers. Failed durable finalization/join remains explicitly blocked.

Production tracking is lazy for manual-only workspaces: open/idle/dashboard do
not touch the native vault or manually tracked roots. Existing autosave records
initialize and verify their signed authority before watches start; explicit
native-approved mutations/source browsing initialize other tracking. Unverified
manual records do not masquerade as granted tracked roots.

Missing rclone, unsupported platform and read-only failures use fixed public
messages only; arbitrary provider/subprocess/error bodies never reach IPC.

## Verification / explicit limits

Agent command run: `rustfmt --edition 2021 src/lib.rs src/interfaces.rs
src/boundary.rs src/native.rs src/root_guard.rs src/oauth.rs src/tests.rs`.
No Cargo command, live account, installed-tool probe, real vault access, browser
launch, No Land user state, cloud operation, repository commit or packaging
acceptance was performed by this agent. Parent owns serial workspace tests.

Tests inject store/engine/tracker/OAuth/discovery, plus a synthetic native
filesystem/MemoryVault adapter round-trip. They cover signed-authority denial,
read-only imports/native write grants, exact retries, captured dirty/partial
completion, pre-publication revocation, bounded queues/cursors/errors,
shutdown handoff/barrier, OAuth readiness-before-browser, and native pin transport.

Restore uses frozen preview IDs, separate exact overwrite acknowledgement and
authenticated native ownership journals. Explicit original-ID local recovery
needs no provider/helper/repository key and never turns a failed download into
completed. Retained/unverifiable artifacts block unsafe cleanup/retry.
Box PKCE remains unsupported. Windows materialized observation/all-app integration
and native Windows/Linux/package/provider acceptance remain separate open gates.
