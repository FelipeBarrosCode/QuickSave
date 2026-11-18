# Native credential and runtime handoff

New native modules are GPL-3.0-only. Original No Land storage code/notices and
manifest licensing are preserved; this is not a claim that the snapshot is MIT.
Source interoperability references are No Land e81238a7536aae201540956ce76981364fd36595
and the read-only desktop provider-profile/OAuth code listed in quicksave-state.

## Parent integration

`quicksave-noland/src/provider_lifecycle.rs` provides:

```rust,ignore
prepare_native_provider_context(store, &access, operation_id, run_root)
    -> Result<NativeProviderContext { access, lifecycle }>;
register_native_provider_lifecycle(store, &access, operation_id)
    -> Result<NativeProviderLifecycle>;
lifecycle.checkpoint() -> Result<()>;
lifecycle.invalidate() -> Result<()>; // stopped worker + explicit reauth/recovery only
```

The first factory finishes this provider's retained checked handoffs before
reminting private access. It refuses changed key/read-only/root/backend/client/
authority scopes. Retain the context's lifecycle with native operation access,
including asynchronous workers and retries. Do not recreate it for each chunk,
metadata object or progress poll. Keep the original source COMMITTED/catalog
LATEST authorization guard and native root/session/operation-ID checks intact.

Every rclone attempt snapshots a private token fingerprint. Actual token changes
invoke `NativePrivateCredentialSink` before return/retry/error completion.
The bridge verifies routing/operation coordinates and uses the expected original
vault generation plus read-back. A concurrent stale refresh cannot overwrite a
newer rotation. Callback/parse/persistence failures are sticky across the owning
registration, even after its guard drops.

The parser accepts at most 2 MiB, one expected remote, unique keys and a validated
bearer token/expiry. Every non-token config entry must remain unchanged, including
backend/root/client identifiers. No arbitrary endpoint, config path, routing field
or executable option can be introduced by a refresh. Tokens/fingerprints/configs
are native-private, never logged or exposed through public operation/state DTOs.
Only the private recovery artifact serializes the original session.

`EphemeralSessionGuard::finish()` is checked and **must be propagated on success
and error** after all children are reaped. A failed persistence retains the
private credential artifacts. Drop is best-effort teardown, not successful
finalization. New UUID directories and pinned, no-follow directory handles keep
nested readers' ownership separate. Config replacement is atomic within the held
directory, never an inode truncate/wipe; cleanup unlinks known owned leaves only.
Teardown seals further command admission. A successfully retired config is skipped
by later lifecycle checkpoints, even while an old storage handle is still held.
An unconfirmed child reap poisons its handoff and retains credentials instead of
making the directory eligible for cleanup. Progress records are framed with a
256 KiB bound before allocating a whole line; framing remains cancellation-safe.
An uncertain OS reap also sets a process-lifetime fail-closed latch: dropping the
last handoff reference cannot accidentally enable recovery or a retry. Confirm
stopped helpers before restart; no in-process override pretends they exited.

Visibility writes use the same config with only an already-vault-committed access
token, temporarily omitting refresh capability until the short COMMITTED/LATEST
helper is reaped. The original publication barrier still applies. Ordinary pack
transfers keep shared guarded sessions, immutable staging, batching, adaptive
bounded concurrency, provider flags, classification, retry ownership, checksum
and native progress behavior. No per-file request uploader replaces the source.

`NativeTransferPolicy` carries original resolved `TransferTuning` plus approved
upload/download ceilings. Registrations are operation/session scoped and bounded;
source-created storage objects preserve this policy when automatic tuning is
applied. No global config/credential env variables or per-progress vault reads.

## Crash recovery and helpers

Startup cleanup retains OAuth/unknown artifacts rather than erase an unpersisted
rotation. `retained_credential_sessions` excludes currently owned live sessions;
`finish_retained_credential_session` checks original/current/vault scope before CAS
and cleanup. An independently newer vault token cannot be replaced with an older
crashed worker's rotation. Such conflicts require explicit native reauthorization.
The factory uses the scope-bound sink APIs. A workspace/device MAC over the
provider ID and protected authority revision is retained in private `session.json`;
the vault-only credential generation is not exported. Recovery rejects an old or
missing authority proof even when a later explicit sign-in reused the same token
text. The original/current/vault comparison runs on the same stable config read
used by finalization, not a separate pre-validation path read. Legacy unbound
artifacts are not silently upgraded to a scoped native-host registration.
After explicit reauthorization, stale artifacts stay quarantined. The parent must
stop/invalidate their old lifecycle and obtain native approval for known-leaf
cleanup of the exact retained execution IDs (`shred_ephemeral_session`), then
attach fresh access. Do not repeatedly reauthorize or silently erase a conflict.
This cleanup concerns private run credentials only, never cloud versions/data.

Inventory canonicalizes only the caller's trusted run root (including macOS's
`/var` alias), then uses no-follow/pinned owned paths. Live guarded directories
and configurations with active children are excluded. The raw shred API rejects
a live directory too.

The native scope comparator handles SFTP/WebDAV's randomized rclone-obscure IVs
by bounded, zeroizing comparison using the public format compatibility key from
the active adapter (`noland-rclone-adapter/src/providers.rs`). That constant is not
a production/client/repository/device key. This comparison is only between two
native vault-minted sessions; the running guard still rejects **every** non-token
config mutation. Public upstream `potato` vectors and randomized sessions have
synthetic tests. No plaintext password is logged, returned to JS, or placed in argv.

`resolve_rclone(&[TrustedRcloneResource { path, blake3 }])` prefers a digest-verified
app resource, then known installed Unix locations. Windows uses trusted digest-
pinned NativePaths/app resources only. Digests must come from trusted build
metadata, never a writable adjacent checksum, JS or env. Parent still checks the
same executable's version/flags and installs its pinned native runtime.
There is no product download, PATH injection or source provisioning execution.

Only explicit `native-test-runtime` enables
`install_native_rclone_for_local_tests(executable, private_sandbox)`. It refuses
non-local/out-of-sandbox sessions and unguarded transports. Parent may supply a
verified official helper in an isolated temporary directory for actual local
transport tests; this is not provider-account or packaging acceptance.

## Validation ownership

Added synthetic tests for fake HTTP, injected vault CAS, real private config replacement,
callback failure, stale parallel rotations, nested/retry cache behavior, finalization,
startup artifacts, reauthorization scope replay, bounded/cancelled progress framing,
provider discovery and native file proofs. This agent ran no
Cargo builds/tests or real provider/keychain/No Land-state operations. Parent owns
serialized compilation and full native integration/acceptance commands.

Suggested parent checks, **not executed by this agent**, run serially from the
QuickSave root:

```sh
CARGO_BUILD_JOBS=1 cargo test -p quicksave-state -p quicksave-tracking -p quicksave-oauth -p quicksave-noland -- --test-threads=1
CARGO_BUILD_JOBS=1 cargo test --manifest-path shared-storage/Cargo.toml -p noland-storage --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 cargo test -p quicksave-service native_enrollment_persists_real_index_and_polling_never_hashes_app_data -- --test-threads=1
```

The storage manifest adds direct `aes` and `base64` dependencies for the existing
public obscure format; the parent owns resulting lockfile updates. Bridge
platform selection/manifests remain parent-owned. Windows implementation and
permission/resource gates are recorded in [`WINDOWS-NATIVE.md`](WINDOWS-NATIVE.md);
no Windows/Linux/native-package or real-account acceptance is claimed.
Request-scoped workspace snapshots do not replace fresh publication checks or
create a cross-request cache. The synchronous metadata trait-forwarding frame
is documented in `crates/quicksave-state/METADATA-VERIFICATION.md`.

Formatting command used for the owned Rust files (no `state_file.rs`, upstream
snapshot or other bridge/service files):

```sh
rustfmt --edition 2021 --config skip_children=true \
  crates/quicksave-oauth/src/lib.rs \
  crates/quicksave-oauth/src/callback.rs \
  crates/quicksave-oauth/src/onedrive.rs \
  crates/quicksave-oauth/src/providers.rs \
  crates/quicksave-oauth/src/transport.rs \
  crates/quicksave-oauth/src/tests.rs \
  crates/quicksave-state/src/lib.rs \
  crates/quicksave-state/src/model.rs \
  crates/quicksave-state/src/grant.rs \
  crates/quicksave-state/src/discovery.rs \
  crates/quicksave-state/src/import.rs \
  crates/quicksave-state/src/lifecycle.rs \
  crates/quicksave-state/src/provider.rs \
  crates/quicksave-state/src/vault.rs \
  crates/quicksave-state/src/tests.rs \
  crates/quicksave-noland/src/provider_lifecycle.rs \
  shared-storage/crates/noland-storage/src/lib.rs \
  shared-storage/crates/noland-storage/src/native_credentials.rs \
  shared-storage/crates/noland-storage/src/native_runtime.rs \
  shared-storage/crates/noland-storage/src/native_transfer_policy.rs \
  shared-storage/crates/noland-storage/src/rclone.rs \
  shared-storage/crates/noland-storage/src/rclone/upload.rs \
  shared-storage/crates/noland-storage/src/rclone/fetch.rs \
  shared-storage/crates/noland-storage/src/rclone/native_credential_tests.rs
```

The same file list passed `rustfmt --check --edition 2021 --config skip_children=true`.
Manifest syntax only was also checked successfully (not compilation/tests):

```sh
python3 -c 'import pathlib, tomllib; paths = ["crates/quicksave-oauth/Cargo.toml", "crates/quicksave-state/Cargo.toml", "shared-storage/crates/noland-storage/Cargo.toml"]; print("TOML syntax OK:", ", ".join(tomllib.loads(pathlib.Path(path).read_text())["package"]["name"] for path in paths))'
```
