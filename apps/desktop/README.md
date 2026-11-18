# QuickSave desktop workspace

Original GPL-3.0-only React / TypeScript frontend. The normal interface has only
**Overview, Backup, Restore**. Its sage/cream theme is retained without capability
pages, repository/key-file setup, or large help panels.

## Local checks

```sh
npm run typecheck
npm test
npm run build
```

`npm run dev` is a browser-only preview on `127.0.0.1:1420`: native actions are
disabled, with no mock data or browser storage/network fallback. `dev:native` and
`build:native` belong to native integration; frontend checks do not establish
packaging, signing, filesystem safety, or Windows/Linux acceptance.

## Native interface

`docs/WORKSPACE-V2-CONTRACT.md` defines the camelCase DTOs and three commands:

1. `workspace_query({query, params})` reads sanitized metadata.
2. `workspace_prepare({action, params})` obtains exact native consent.
3. `workspace_execute({ticketId})` consumes that one-use ticket only.

Parameters are captured before consent. Execute cannot replace a root, selected
file list, destination, provider, or deletion acknowledgement. Tickets are never
cached, logged, shared, or automatically retried. The backend remains authoritative
for filesystem identities, confinement, provider verification and all safety.

- Provider definitions load dynamically when the connection sheet opens.
  Native definitions are the No Land array (`kind`, `label`, `isOauth`,
  `credentialType`, fields with `key`, `fieldType`, `required`, `credential`).
  Manual credentials use its exact `{type, value}` shape; bucket/prefix remain
  top-level and OAuth client fields are passed to the native OAuth action.
  Credential fields are private, transient, cleared when submitting, and never
  stored by the frontend. OAuth is a native action; tokens/keys never return to JS.
- Import first prepares/executes `discover_noland_import {}`. Its bounded
  `{candidates:[{id,label,path,modifiedAt?,profileCount?}],selectedId?}` response
  auto-imports one candidate (or a native-selected ID) using
  `import_noland {sourceId}`. Only unresolved multiple candidates need a chooser;
  none is an explicit error. A JSON picker remains under **Advanced import** as
  `import_noland {stateFile}`. JS never searches or reads the source filesystem.
- Read-only connections expose a distinct `authorize_provider_writes` action with
  `{providerId}`. Selecting a provider or enabling autosave never updates the UI
  optimistically; only returned/refreshed native state can do that.
- Existing connected/error profiles offer `reauthorize_provider`. OAuth sends
  only `{providerId}` and reuses the native registered client/browser flow;
  no token/client replacement fields are exposed. Static providers use only
  credential fields from that existing kind's native definition, as
  `{providerId,credentials:{type,value}}`. Bucket, prefix, kind, root, key and
  client edits are not part of reauthorization. Transient fields are cleared at
  submission and native errors cannot reflect credentials back into the UI.
  Imported profiles remain read-only; old autosave approvals are not assumed valid.
- `export_recovery_key {providerId,destination}` uses the native **Save** dialog
  to choose a new external private file, followed by a separate native ticket.
  No key bytes enter the UI. Only a `{written:true,keyMaterialReturned:false}`
  receipt produces an export notice; existing-file/native failures never cause
  an overwrite fallback. Export remains available for disconnected profiles.
- App tracking is opt-in via native consent for `enable_app_tracking` with
  `{enabled:true,defaultProviderId?,roles:['installation','save','config','runtime']}`.
  `app_tracking` supplies `{enabled,scanning,completedApps,totalApps,diagnostics?}`;
  `refresh_app_tracking {}` requests native exact-scope reconciliation. The
  existing `Software` DTO is retained, with optional actual `roots[]`
  (`id,path,role?,roles?,fileCount?,logicalBytes?`). Only tracked native inventory
  renders as rows; untracked metadata and diagnostics never become fake bundles.
  Expanding a row lazily loads native `software_files`, including actual root
  IDs/roles. Counts remain unknown when not supplied by native code.
- Individual transfer IDs never derive from arbitrary path inputs. File pages
  contain at most 100 rows; replacing pages keeps the DOM bounded. A selection is
  limited to 512 IDs; discovered software renders 20 rows per page.
- All-app and selected-app uploads first prepare/execute
  `preview_upload_all {providerId,softwareIds?}`. **All** omits `softwareIds`:
  the backend chooses all actual approved instances bound to that provider,
  irrespective of the UI's filter/page. Selected apps retain at most 512 exact
  software IDs across display pages. The response requires
  `{planSetId,providerId,softwareCount,summary?}`; bounded native `sampleNames`,
  `jobCount`, `selection`, and optional file/byte totals are displayed when known.
  File/byte totals remain unknown otherwise: roots/identities are frozen, while
  each original child's metadata capture occurs when it starts. A separate
  **Upload frozen app set** confirmation sends only `upload_all {planSetId}`.
  No wildcard, per-row fallback, automatic submission or automatic retry exists.
- Cloud pages retain original `appId`, bundle/commit/parent/source-instance IDs,
  `mode`, `completeness`, `captureScopeLabel`, current/per-mode head flags,
  `readiness`, incremental bytes and deletion-state counts. A complete-mode head,
  mode label or file count never upgrades partial/unknown coverage into a whole
  application. Unknown catalog freshness and reconstruction readiness are explicit.
  **View app history** queries `history {providerId,appId,cursor?,limit:100}`;
  pending summaries load only when opened through
  `pending_deletions {providerId,cursor?,limit:100}`. Names/summary counts are not
  deletion authority, and unknown dependencies stay unknown. Both lists replace
  pages rather than append; stale-cursor refresh starts from page one. No
  pending-plan execution/retry capability is invented.
- Cloud deletion requires an authenticated frozen preview, a separate dependent
  backup checkbox when needed, then fresh native prepare/execute. A submitted
  preview cannot be reused from the dialog, even after failure.
  Service previews use `previewId`, `providerId`, `bundleId`, `appId`,
  `dependentBundleCount`, bounded `dependentBundles[]`, `items`, `logicalBytes`,
  `physicalBytes`, and `packCount`. Dependency counts and selected scope are
  validated before displaying a usable preview.
- Restore first prepares `preview_restore` with the exact
  `{providerId,bundleId,appId,destination,fileIds?,mode}` plan; `mode` is
  `create_new`, `merge`, or `replace`. A usable native response requires
  `{previewId,files,bytes,conflicts:[{path,reason?}],requiresOverwriteAcknowledgement}`.
  Optional total `conflictCount` is distinct from the bounded conflict sample;
  native `blockingConflicts` cannot be resolved by checking overwrite approval.
  The final `download` contains only
  `{restorePreviewId,overwriteAcknowledgement}`, through a fresh native ticket.
  Missing/unsupported preview APIs never fall back to direct downloads. Submitted
  previews are not reused after failures. `recover_restore` and `retry` send only
  an original `operationId`, and controls require actual `canRecover`/`canRetry`
  flags. Historical bundle IDs and optional `sourceBundleId`/`sourceAppId` are
  preserved, not collapsed into a latest-only row.
- Activity uses actual native metrics only. Two-second polls are serial and stop
  after 600 requests or three consecutive failures, with explicit resumption.
  App-tracking polls are similarly bounded, serial, and stop on native completion.
  Pausing UI checks never claims that native work stopped.
- Batch status uses `batch_status {planSetId}` after a native accepted
  `operationId`, or a native Activity `planSetId` for restart reattachment. Its
  actual response is an Activity envelope with `operationId`, `planSetId`,
  capability flags and nullable `batch` containing `softwareCount`, `jobCount`,
  per-state counts, phase/unit `progress`, and `closeBlocked`. Initial null totals
  are unknown, not zero. Checks are finite/serial, stop only after native drain,
  and never query remote catalogs or rebuild selections. Cancel/retry require
  explicit clicks and send the original native-returned `operationId`.
  Local `recover_restore` rollback reports are not converted into completed
  replacement downloads.

The fixed shell has one main vertical scroll with `min-height: 0`; the provider
sheet has its own stable-gutter content scroll and focus trap. Long paths/names
truncate within bounded flex/grid cells. Layout supports an 880×680 desktop window
and a 360px browser viewport without an overall horizontal scroll.

Tests mock the native gateway; one inventory fixture indexes only newly created,
isolated temporary roots, never installed apps or user data. They verify command sequence,
scope capture, malformed/cancelled authorization, privacy, dynamic fields, import,
read-only grants, non-optimistic autosave, transfer subsets, lazy pagination,
restore/deletion acknowledgements, finite app tracking, activity polling and scroll CSS. They do not access
provider accounts, real No Land state, actual vault entries or user file data.
Source-only cross-boundary tests read the actual synthetic Rust catalog fixtures
and native projection field names. They do not execute Rust serialization or
native IPC and do not establish whole-feature, provider, packaging or OS acceptance.
