# QuickSave desktop interface

Original GPL-3.0-only React 18 / TypeScript / Vite 7 frontend. This app is separate
from No Land and does not load its state or support its repository format.

## Local commands

Requires Node 20.19+ or 22.12+ and npm. Dependencies are exactly pinned in
`package.json` and `package-lock.json`.

```sh
npm ci
npm run typecheck
npm test
npm run build
```

`npm run dev` serves **only a browser preview** on `127.0.0.1:1420`, with a strict
port. It does not mock native commands, repositories, keys, or snapshot history.
To run the desktop app with the parent-owned Rust backend, use `npm run dev:native`
(or `npm run tauri -- dev`) after installing the relevant Tauri prerequisites.
`npm run build:native` builds native artifacts; this alone does not establish
signing, installer, filesystem, or cross-platform acceptance.

## Native integration

- Tauri 2 `@tauri-apps/plugin-dialog` provides folder selection and recovery-key
  open/save dialogs. No filesystem plugin, key import into JavaScript, network,
  local-storage persistence, or web upload fallback is used.
- Base command names and camelCase path fields follow `docs/IMPLEMENTATION-CONTRACT.md`:
  `get_capabilities`, `get_directories`, `initialize_repository`,
  `backup_folder`, `list_snapshots`, `restore_snapshot`, `operation_status`.
  The native-authorization extension below is now required before all four
  filesystem commands.
- **Native authorization is mandatory for each filesystem request.** The four
  wrappers first invoke `authorize_operation` with the exact scope shown below.
  Rust displays the authoritative native confirmation, pins root proofs, and
  returns an opaque approval string. Native cancellation/rejection or a malformed
  approval prevents the filesystem invoke. The UI preview and its complete path
  summary remain a separate, non-authoritative confirmation.

  | Wrapper | Authorization scope | Filesystem invoke after approval |
  | --- | --- | --- |
  | `api.initialize` | `{kind: "initialize", repository, keyFile}` | `initialize_repository({repository, keyFile, approvalId})` |
  | `api.backup` | `{kind: "backup", repository, keyFile, source}` | `backup_folder({repository, keyFile, source, approvalId})` |
  | `api.snapshots` | `{kind: "list", repository, keyFile}` | `list_snapshots({repository, keyFile, approvalId})` |
  | `api.restore` | `{kind: "restore", repository, keyFile, snapshotId, destination}` | `restore_snapshot({repository, keyFile, snapshotId, destination, approvalId})` |

  Each call captures only its explicit scope fields before awaiting authorization.
  Caller mutation or an injected `approvalId` cannot change the approved scope.
  Approvals must be nonblank strings bounded to 4,096 characters and 4,096 UTF-8
  bytes, are never exposed in UI state/logs/storage, and are used only once by
  that call. They are not cached, shared across scopes, or retried. Rust enforces
  single use, the ten-minute expiry, and its maximum of 32 outstanding approvals.
  Every subsequent request requires fresh native consent, including the automatic
  snapshot refresh after a successful backup; the UI does not dismiss native
  dialogs. Cancelling that refresh does not mark the successful backup failed.
  Passive `get_capabilities`, `get_directories`, `operation_history`, and
  `operation_status` calls are unchanged.
- The parent backend's `operation_history` extension is read on launch. Active
  jobs resume tracking; interrupted jobs are displayed and never retried
  automatically. If native history cannot be checked, mutations fail closed until
  an explicit successful retry.
- Snapshot responses accept either an array or `{ snapshots: [...] }`, with
  `snapshotId` / `id`, `createdAt`, `totalFiles` / `files`, and `logicalBytes`.
  Missing counts display as unknown, not zero. At most 10,000 snapshots are
  accepted; restore history is paginated.
- Writes require the native report to confirm local folder backups and safe,
  durable file/directory and private-directory creation. Unsupported Windows
  durable writes remain disabled. Read capability is evaluated separately.
- Backup, restore, and repository creation require confirmation. Native
  validation remains authoritative for path confinement, identity, external-key
  placement, repository compatibility, destination emptiness, and overwrite
  refusal.
- One mutation is owned at a time, including paused tracking. Polls do not
  overlap, run every 1.5 seconds, and stop after 600 requests, three consecutive
  errors, terminal status, or component unmount. Pausing never means a native job
  was cancelled or failed. The interval is cleared on unmount; late responses
  cannot update the unmounted UI. Tracking can be explicitly resumed.
- The interface displays actual running, completed, failed, or interrupted
  receipts. There is no percentage progress, speculative success, automatic
  deletion, remote machine control, key reset, or in-place rollback.

## Layout and validation boundaries

Designed for the native window at **1320 × 900** and **880 × 680** minimum.
Responsive layouts cover roughly 360px through wide desktop widths; keyboard
navigation, focus-visible controls, a skip link, labelled native pickers,
screen-reader status/error regions, modal focus trapping, Escape/cancel, and
reduced-motion preferences are supported.

Tests run against isolated in-memory native responses only. They exercise invoke
arguments and native authorization order/scope/cancellation/token bounds, parsers
and bounds, capability gating, status polling and cleanup,
mutation exclusion, interrupted-history recovery, native open/save selection,
confirmation dialogs, and safe error rendering. They do **not** validate native
dialogs, native filesystem safety, installers, or Windows/Linux execution.
Frontend checks do not replace those acceptance tests.
