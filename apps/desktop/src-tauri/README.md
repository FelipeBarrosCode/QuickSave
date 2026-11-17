# Native backend approval and worker contract

Development-preview backend; this is not native packaging acceptance.

## IPC

All fields below use Tauri's **camelCase** invoke names. No key bytes cross IPC.

First call:

```ts
const approvalId = await invoke<string>("authorize_operation", {
  kind: "backup", // "initialize" | "backup" | "list" | "restore"
  repository,
  keyFile,
  source,
  // destination and snapshotId only for restore; omit unused fields
});
```

Then invoke **once**, passing the same request fields plus `approvalId`:

| Command | Required fields in addition to `approvalId` | Result |
| --- | --- | --- |
| `initialize_repository` | `repository`, `keyFile` | Initialization summary after completion |
| `backup_folder` | `repository`, `keyFile`, `source` | Operation receipt/ID |
| `list_snapshots` | `repository`, `keyFile` | Engine snapshot listing |
| `restore_snapshot` | `repository`, `keyFile`, `destination`, `snapshotId` | Operation receipt/ID |

Authorization field sets are exact: initialize/list cannot include source,
destination or snapshot; backup requires only source; restore requires only
destination and snapshot. Unused optional fields may be omitted or `null`.
Cancellation rejects the promise; it does not return a usable token. A webview
boolean or a previous file-picker selection cannot replace native confirmation.
An approval cannot be transferred to another action, path, key or snapshot.

`get_capabilities`, `get_directories`, `discover_applications`,
`operation_history`, and `operation_status({ operationId })` need no approval.
`get_capabilities` includes `engineLimits` from the shared client.

## Authorization boundary

- Validate all untrusted strings at a 4096-UTF-8-byte limit. Reject relative paths,
  traversal, controls and bidi/line display controls. UUIDs must be nonzero,
  lowercase, hyphenated UUID strings (36 characters).
- Normalize absolute paths with `quicksave_client::literal_path`, **not**
  canonicalization. Scope equality uses these exact normalized literal paths;
  a differently spelled case alias needs a new approval.
- Before confirmation, do not open the selected paths, read keys, inspect
  repository contents, initialize operation history or call the engine.
- Show the exact action and every normalized path/snapshot in a native warning
  dialog with OK/Cancel, on a bounded background lane.
- Only after OK, pin `SafeRoot` proofs for repository/source/destination and key
  parent. For existing keys, retain the original file handle and `FileStamp`,
  require 32 bytes, and call native `verify_private_file` (including ACL checks).
- Store opaque random UUID tokens in native memory only: at most 32, one use,
  monotonic 10-minute lifetime. No persistence or job replay. Expired proofs are
  discarded on the next approval-store operation or process exit.
- Consume and compare exact scope **before filesystem IO**. A mismatched attempt
  also spends the token. Recheck `SafeRoot::same_root`, existing key stamp and
  privacy immediately before client execution; keep proofs alive through the call.
- Initialization pins the new key's existing parent, not an absent file. The
  shared client's exclusive `write_new` still refuses any occupied key name.
- Key exclusion, authenticated repository checks, overlap checks, stable capture,
  no-overwrite publication and engine bounds remain enforced by client/engine/
  platform, not weakened or replaced by a dialog.

The native proof API assumes the documented private-account ownership model.
This is not protection against hostile same-UID namespace control. Windows
operations fail explicitly while native durable writes/private key protection
are unsupported.

## Worker and shutdown policy

Admission uses nonwaiting semaphore permits: **2 read workers**, **1 native
authorization-confirmation worker**, and **1 mutation-admission worker**. Excess calls fail
busy rather than accumulating an unbounded queue. The client's owned
`OperationManager` separately admits only one engine mutation.

Directory discovery, application discovery, history loading/status/history
cloning, proof checks, receipt fsync and engine admission all run off the GUI
thread. History initialization is coalesced behind a background-only lock; the
manager cache lock protects only Arc clones/publication and never covers IO.
History reads do not create missing application state.

Each invocation awaits its background result. Its native worker owns an atomic
activity ticket and lane permit, so cancellation of the invoking future does not
release the permit, drop application state or allow normal quit while the native
call still runs. Close/exit handlers use `try_lock`, refuse conservatively on
contention, and consult both tracked workers and the client's nonblocking atomic
mutation flag. Successful shutdown closes further worker admission.

`build.rs` declares every application command through `AppManifest::commands`.
`capabilities/main.json` explicitly allows those commands only for local `main`
window content. No remote origins are authorized. Existing open/save picker
permissions are not operation authority.

## Validation handoff

**Not run during this change:** Cargo, Rust tests, native dialogs or packaged UI
tests (shared-target/disk constraint). The existing backend compile result predates
these changes and must not be treated as validation of them.

Passed during this change: direct `rustfmt --check --edition 2021` over
`build.rs`/`src/main.rs` and their modules; a read-only Python JSON/TOML check
matching all 10 registered commands to build-manifest commands and local-only
capability permissions, plus the UUID lock entry and Tokio sync feature.
These are source/configuration checks, not compilation or native acceptance.

The authorization and admission implementation now lives in the reusable
`crates/quicksave-control` crate (`approval.rs` and `runtime.rs`). The desktop
uses that exact policy; the native dialog itself remains in this backend.
Its 10 unit tests do not require linking a second GUI executable. They cover
lexical validation, action/field matching, complete confirmation text, token
one-use/mismatch/expiry/capacity, lane limits, caller cancellation, unwinding,
shutdown admission and nonblocking lock-contention handling. They perform no
filesystem or application-state IO; the generic approval-store tests do not
fabricate production path proofs.

When the parent authorizes serial Cargo work with sufficient disk:

```sh
cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml -- --check
cargo test --locked -p quicksave-control
cargo check --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Native acceptance still needs:

- OK versus Cancel, visible complete scope text, busy second dialog, and no
  selected-path/history IO on cancellation.
- Missing, wrong-kind, wrong-path/key/snapshot, expired, and replayed tokens.
- Root/ancestor replacement and key replacement/privacy changes after approval,
  using isolated synthetic directories only.
- Responsive history loading/fsync, read-lane saturation, normal close and Cmd-Q
  during dialog/list/admission/engine execution, and canceled invoke tracking.
- IPC denial from unauthorized window/remote-origin content.
- Separate native Windows/Linux and packaged acceptance; cross-compilation is
  not that evidence.
