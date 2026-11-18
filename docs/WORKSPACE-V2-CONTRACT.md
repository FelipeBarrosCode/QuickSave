# Software/provider workspace v2 integration contract

User-directed product revision: **Overview, Backup, Restore only**. Connect
providers in an Overview sheet/dialog (not another sidebar page). No capability
screen, no repository/key-file setup form in the normal flow, no giant help cards.
State is `state.json` containing references/settings only; secrets remain native.

## Execution and safety

- Agent development/tests use synthetic isolated repositories and injected
  credential stores. Do not read actual No Land state or keychain while coding.
- Runtime No Land import is an explicit, native-confirmed READ-ONLY import into
  QuickSave's own vault/state. Never write, migrate or delete No Land vault items.
- `upstream/no-land/` remains unmodified. `shared-storage/` is the active,
  provenance-tracked library fork, NOT a remote agent deployment. Never run its
  provisioning/systemd/lifecycle code. The native bridge is its only caller.
- Reuse No Land's crypto, format, packs, provider adapter, capture/restore,
  admission, receipts, frozen deletion previews, cancellation and retry rules.
  No hand-written "compatible" cipher or bypassed generation/metadata guards.
- QuickSave disables automatic post-upload cloud convergence/retirement. Explicit
  cloud deletion requires a fresh exact preview, native confirmation and separate
  dependent-backup acknowledgement. Autosave never deletes local data or
  automatically physically deletes cloud objects.
- No Linux executable portability claim. Imported Linux bundles may be downloaded
  as files; native launchability remains separate.
- Source/selected-file scope must not widen on retry, restart or an overflow.
  Imported profiles default read-only until a separate native write grant.
- One shared Cargo build target, jobs=1/debug=0; parent runs final builds. Agents
  must not compile in separate target directories.

## Frontend IPC

New UI uses **three** gateway commands:

```ts
workspace_query({query, params?: {}}): Promise<unknown>
workspace_prepare({action, params?: {}}): Promise<{ticketId: string}>
workspace_execute({ticketId}): Promise<unknown>
```

`prepare` performs native confirmation for new authority (connect/import, tracked
roots, autosave, transfers/deletion as appropriate), binds server-held exact
parameters/proofs, and returns an opaque one-use ticket. `execute` never accepts
replacement parameters. Root/key/provider inputs are not authority by themselves.
Do not put master-key bytes in a webview or `state.json`.

The gateway also injects two **native-only** fields after consuming a ticket:
`_scopeFingerprint` (the prepared service authority fingerprint) and
`_approvedPaths` (pinned native directory IDs or selected-file stamps/parent IDs).
Neither is accepted in a webview request. Service code excludes these fields
when rederiving the public request fingerprint, but carries their proofs into
owned workers. Initial tracking, individual-file grants, import reads, and
download admission compare their newly pinned handles to these prepared IDs
before publishing authority or accessing data. Reopening the same pathname and
silently accepting a replacement identity is not a valid handoff.

Queries:

- `dashboard` => Dashboard below (only sanitized state)
- `provider_types` => available provider definitions with field schema
- `software` => `{software: Software[]}` (discovered + tracked, no false grants)
- `software_files` `{softwareId, cursor?, limit?}` => `{files: FileItem[], nextCursor?}`
- `bundles` `{providerId, cursor?}` => `{bundles: Bundle[], nextCursor?}`
- `bundle_files` `{providerId, bundleId, appId, cursor?, limit?}` => `{files: FileItem[], nextCursor?}`
- `activity` => `{activity: Activity[]}`
- `operation` `{operationId}` => Activity
- `noland_import_preview` => sanitized counts/profile names, no credential reads
  before native consent; an initial "choose state file" response is acceptable.

Actions:

- `connect_provider` `{kind, name, bucket?, prefix?, fields?, credentials?}`
  (manual provider credentials are transient inputs, not settings; OAuth/keychain
  tokens and encryption keys never return to JS)
- `connect_oauth` `{kind,name,clientId?,clientSecret?,fields?}`
- `disconnect_provider` `{providerId}` (does not remove encryption keys/backups)
- `verify_provider` `{providerId}` (explicit read-only connection/metadata recheck;
  never treats retained configuration as successful authentication)
- `import_noland` `{stateFile?,profileIds?}`
- `track_software` `{appId?,name,roots:[{path,role?}],providerId?}`
- `add_files` `{paths:string[],providerId?}` (native-picked individual files)
- `set_provider` `{softwareId,providerId}`
- `set_autosave` `{softwareId,providerId,enabled}` (explicit persistent scope)
- `upload` `{softwareId,providerId,fileIds?:string[]}` (absent list = whole approved software)
- `download` `{providerId,bundleId,appId,destination,fileIds?:string[]}`
- `preview_delete` `{providerId,bundleId,appId}` => frozen deletion preview
- `delete_cloud` `{providerId,previewId,acknowledgeDependencies:boolean}`
- `cancel` / `retry` `{operationId}` (retry only the original authenticated plan)

If an action starts asynchronous work, return `{operationId}`. Connection/import
or tracking/state changes may return an updated sanitized Dashboard directly.
The UI should refresh state after completion, never optimistically claim success.
Unimplemented/unsupported actions return explicit errors, never fake results.

## UI DTOs (all camelCase)

```ts
type Provider = {
  id:string; name:string; kind:string;
  status:'connected'|'connecting'|'disconnected'|'error';
  origin?:'quicksave'|'noland'; readOnly?:boolean; error?:string|null;
}
type Software = {
  id:string; appId?:string; name:string; tracked:boolean; providerId?:string|null;
  status:'needs_backup'|'saved'|'checking'|'uploading'|'error'|'not_tracked';
  autosave:boolean; dirty?:boolean; lastSavedAt?:string|null;
  fileCount?:number|null; logicalBytes?:number|null; error?:string|null;
}
type Bundle = {
  id:string; appId:string; name:string; providerId:string;
  createdAt?:string|null; fileCount?:number|null; logicalBytes?:number|null;
  platform?:string|null; format?:string; compatibility?:string;
}
type FileItem = {
  id:string; name:string; path:string; directory:boolean; size:number;
  status?:string; rootId?:string;
}
type Activity = {
  id:string; kind:'upload'|'download'|'delete'|'connect'|'autosave';
  name:string; providerId?:string; softwareId?:string;
  state:'queued'|'running'|'completed'|'failed'|'cancelled'|'interrupted';
  phase?:string; completedBytes?:number; totalBytes?:number;
  completedFiles?:number; totalFiles?:number; error?:string|null;
  canCancel?:boolean; canRetry?:boolean; startedAt?:string; finishedAt?:string|null;
}
type Dashboard = {
  providers:Provider[]; software:Software[]; activity:Activity[];
  summary:{needsBackup:number;autosaveEnabled:number;connectedProviders:number};
}
```

Names/IDs from untrusted metadata are validated and rendered as text. `fileIds`
bind logical-root + relative-path identities, not unrestricted absolute paths.
Lazy paginated file browsing; do not mount a 186k-entry DOM tree. No fake progress.

## Rust state/provider crate (agent-owned `quicksave-state`)

Use `anyhow::Result`, JSON at the cross-agent boundary; expose a cloneable store:

```rust
pub struct WorkspaceStore { /* native state + injected/OS vault */ }
impl WorkspaceStore {
  pub fn open(data_dir:&Path) -> Result<Self>;
  pub fn sanitized(&self) -> Result<Value>; // providers/software/settings only
  pub fn provider_types(&self) -> Value;
  pub fn connect_provider(&self, input:&Value) -> Result<Value>;
  pub fn disconnect_provider(&self,id:&str) -> Result<()>;
  pub fn import_noland(&self, input:&Value) -> Result<Value>; // caller native-consented
  pub fn provider_access(&self,id:&str,operation_id:&str) -> Result<ProviderAccess>;
  pub fn update_software(&self,record:&Value) -> Result<Value>;
  pub fn software(&self) -> Result<Vec<Value>>;
}
pub struct ProviderAccess {
  pub provider_id:String,
  pub session:Value,          // private No Land EphemeralRcloneSession JSON
  pub repository_key:[u8;32], // never Debug/Serialize or sent to webview
  pub read_only:bool,
}
```

Also expose state mutation for provider selection/autosave/dirty status through
typed validated methods or a documented transaction closure. Publish exact APIs
to parent/service/tracking agents early. Preserve platform file identities in
tracked roots and HMAC/sign persistent auto-upload grants using a native-vault
device key, not editable JSON as write authority. Add native `state.json` atomic
replacement under private scoped locking; never overwrite No Land state.

## Shared engine bridge (agent-owned `quicksave-noland` + `shared-storage`)

```rust
pub struct NativeEngine { /* private local No Land engine instance */ }
impl NativeEngine {
  pub fn open(data_dir:&Path,home:&Path) -> Result<Self>;
  pub async fn register(&self,software:&Value) -> Result<()>;
  pub async fn catalog(&self,access:&ProviderAccess) -> Result<Value>;
  pub async fn files(&self,access:&ProviderAccess,bundle:&Value) -> Result<Value>;
  pub async fn upload(&self,access:ProviderAccess,selection:Value) -> Result<Value>;
  pub async fn download(&self,access:ProviderAccess,selection:Value) -> Result<Value>;
  pub async fn preview_delete(&self,access:&ProviderAccess,selection:Value) -> Result<Value>;
  pub async fn delete(&self,access:ProviderAccess,selection:Value) -> Result<Value>;
  pub async fn status(&self,id:&str) -> Result<Value>;
  pub async fn recent(&self) -> Result<Vec<Value>>;
  pub async fn cancel(&self,id:&str) -> Result<Value>;
  pub async fn retry(&self,id:&str) -> Result<Value>;
}
```

Same upstream wire formats and shared key. Rclone executable/version/flags must
be preflighted; no secret argv or raw subprocess logs. Selected-file upload
cannot capture other files; selected download confines target mappings, not
absolute source hints. Default keep-history retention is an explicit QuickSave
policy difference, not a weakened deletion protocol. Windows unsupported library
paths must be reported clearly until actually ported; never use remote Linux.

## Tracking/autosave (agent-owned `quicksave-tracking`)

Expose `Tracker` + pure testable scheduling state:

- Track only explicitly approved roots, including manual files.
- Native `notify` events + bounded queue, coalescing and quiet-period debounce.
- Overflow, permission loss, restart/remount => reconciliation required, never
  falsely "clean". Compare a durable baseline; changed means changed after the
  last confirmed snapshot, not merely after the last UI scan.
- One upload per software at a time. Changes during upload remain pending and
  trigger another stable capture. Backoff offline/unstable sources; no flood.
- Save original local files unconditionally. Local deletion produces a new
  snapshot state if supported; no automatic local/cloud physical deletion.
- Persist provider choice, opt-in setting, authority signature, dirty generation
  and last confirmed version through WorkspaceStore. Native-consented autosave
  is bound to software/root identities/provider; changed settings invalidate it.
- Worker ownership is joined and shutdown-safe. UI-hidden background is supported;
  separate OS login-service acceptance must not be invented.

Use callback `Arc<dyn Fn(Value) -> Result<()> + Send+Sync>` to enqueue an autosave
request into the service, not direct unknown cloud writes from a watcher callback.
No source tracing may infer ownership from an executable basename alone.

## Service (agent-owned `quicksave-service`)

Integrate the above into a single `WorkspaceService` with:

```rust
pub async fn open(data_dir:&Path,home:&Path) -> Result<Arc<Self>>;
pub async fn query(&self,name:&str,params:Value) -> Result<Value>;
pub async fn execute_authorized(&self,action:&str,params:Value) -> Result<Value>;
pub fn shutdown_blocked(&self) -> bool;
```

Parent supplies native preparation/ticket authorization and calls
`execute_authorized` only with the exact server-held approved plan. Service
validates persisted tracking/autosave grants and source identities too; it must
not trust a caller's `"approved":true`. Provider metadata browsing after an
authorized connection does not need a new OS prompt per refresh. Storage
operations use the real shared engine journal for status, cancellation, retry.
# Current integration scope

The historical v2 contract below is superseded where it conflicts with
[`FULL-SHARED-STORAGE-CONTRACT.md`](FULL-SHARED-STORAGE-CONTRACT.md). Runtime
integration and outstanding acceptance gates are recorded in
[`SHARED-STORAGE-INTEGRATION-STATUS.md`](SHARED-STORAGE-INTEGRATION-STATUS.md).

The current native gateway additionally validates:

- `enable_app_tracking`, `refresh_app_tracking`, and the `app_tracking` query;
- consent-backed `discover_noland_import`, followed by `import_noland {sourceId}`;
- `preview_restore` followed by `download {restorePreviewId,
  overwriteAcknowledgement}` only;
- frozen all-app plan handles and original-operation restore recovery requests.

Validation is not an implementation/acceptance claim for unfinished handlers.
No caller-supplied scope, file stamp, grant, callback, or JSON approval flag
creates native authority.
