# Workspace state API

Original QuickSave code, GPL-3.0-only. See `PROVENANCE.md` for the read-only
No Land wire-format references.

`WorkspaceStore` is cloneable. `open(&Path)` never reads the credential vault;
`open_with_vault(&Path, Arc<dyn CredentialVault>)` injects all vault access.
Tests MUST use `MemoryVault`. No default test constructor touches native accounts.

The v2 contract methods are `sanitized`, `provider_types`, `connect_provider`,
`disconnect_provider`, `import_noland`, `provider_access`, `software`, and
`update_software`. Cross-component records are `serde_json::Value`.

Additional service/tracker APIs:

- `transaction(|document: &mut WorkspaceDocument| -> anyhow::Result<R>)` reloads
  current state under the process/OS lock, validates the whole typed document,
  increments `generation` only when changed, and durably atomically replaces
  `state.json`. `WorkspaceDocument`, `StateSoftware`, and `StateRoot` are public
  non-secret types. Closures are trusted native code, NEVER webview callbacks.
- `software_record(id) -> Result<Value>` returns the internal non-secret record.
  `software()` likewise retains roots, dirty generations, and grants for workers;
  `sanitized()` emits only the contract's UI fields.
- `set_software_provider(software_id, provider_id)` invalidates autosave authority.
- `set_autosave(software_id, provider_id, enabled)` seals the current exact
  software/app/root identities and provider scope. **Enable only after native
  consent**. `verify_autosave_grant(software_id, provider_id)` returns `Result<bool>`.
- `grant_seal(scope) -> Result<Value>` / `grant_verify(scope, grant) -> Result<bool>`
  expose domain-separated HMAC for a native caller's exact bounded JSON scope.
  A caller must rederive scope from pinned native roots, not trust a JSON flag.
  `issue_grant(kind,scope)`, `verify_grant(kind,scope,grant)`, and
  `revoke_grant(kind,scope)` match the tracking adapter directly.
  `grant_revoke(scope)` is the generic counterpart. Wrapping
  `{kind,scope}` is equivalent to the typed calls. Grants include a native-vault
  nonce registry slot per software/purpose; revocation/reissue persists across
  restart and invalidates rolled-back JSON/signatures. These are not stateless
  HMACs that an old settings file could reactivate.
- `mark_dirty(id) -> Result<u64>` advances the dirty generation.
  `mark_saved(id, captured_generation, version, saved_at)` only clears dirty when
  the generation still matches. It preserves changes arriving during upload.
  It does not clear Tracker's reconciliation requirement or substitute for
  actual native source receipt/index verification.
- `record_provider_health(id, report)` accepts the native bridge's actual probe:
  `canList` + `repositoryAccessible`, and either `repositoryEmpty:true` with
  `canRead:false,keyVerified:false` (real list + absent head), or actual
  `canRead:true,keyVerified:true` for a nonempty repository. No `authenticated`
  field is required or fabricated. Configuration/import alone returns
  `connecting`, never fake health. UI errors are deliberately opaque.
- `grant_provider_write(id)` is a **separate native-consented** grant, stored in
  QuickSave's vault; editing `readOnly` in JSON cannot grant write access.
  `grant_provider_writes(id)` and `authorize_provider_writes(id)` are aliases.
  `provider_writable(id)` requires connected health plus the native-vault binding.
- `update_oauth_credentials(provider_id, credentials: &Value) -> Result<()>` is
  native-only and accepts exactly
  `{type:"o_auth2",value:{access_token,refresh_token?,expires_at}}`. The native
  refresher must prove the same provider account/client; token ownership cannot
  be inferred from opaque strings. No root/field/key/read-only changes are
  accepted. Rotation is verified in **QuickSave's** vault, never the source
  No Land vault. Omitted/null refresh tokens preserve the previous native token;
   a nonempty new token replaces it. A different account requires explicit native
   reauthorization/new authority; removing refresh capability requires disconnect.
  State bytes/generation, sanitized DTOs, health, client fields, and all grants
  remain unchanged. All persistence errors are opaque. A failed or non-atomic
  backend write is not treated as a successful refresh; read-back must match.
  No compensating rollback can resurrect an already-rotated old token.
- `seal_tracking_grant(software_id)` seals/persists exact manual tracking authority;
  `verify_tracking_grant(software_id)` verifies it before browsing or capture.
  Enable tracking only after native consent, even when autosave is disabled.

Root JSON: `{id,path,role?,identity:{device,fileId:[u64,u64]},stamp?,directory?,allowedFiles?,source?}`.
`identity` is a `NativeFileStampID`; an optional full platform `FileStamp` may be
stored as `stamp`. Identity is the authoritative native ID; path strings alone
never form a tracking/autosave grant. `allowedFiles` is either null (whole approved
tree) or a fixed bounded set of parent-directory leaves; manual-file grants bind
this allowlist too. Root/app/provider changes invalidate the relevant grants.
`update_software` is a validated merge patch, not whole-record replacement:
omitted tracking, baseline and grant fields survive coalesced status updates.
The tracker-compatible `lastConfirmedUploadedGeneration` field is preserved.
Generic `grant_seal`/`grant_verify` automatically bind a scoped `providerId` to
the current provider kind/bucket/prefix/credential/key references, not just its ID.
`ProviderRecord.public_scope` serializes as `publicScope` (default `{}`) and carries
only allowlisted, bounded non-secret destination fields: endpoint/URL, host/port/
public host keys, remote path/folder, drive ID/type, region/account ID and
bucket/space/container aliases. Client IDs/secrets, access/refresh tokens,
passwords and credential values are never projected. Endpoint URLs with embedded
credentials, query parameters or fragments are rejected rather than persisted.
This metadata is for exact native destination prompts, not dense normal UI content.
Native access compares it to the identical projection of protected provider
fields; editing the display map cannot misrepresent the destination. Grant
fingerprints include the map. An old profile missing relevant public fields fails
access until a native-consented reconnect; open/queries never read the vault to
silently migrate it. Profiles whose private fields have no relevant attributes
remain compatible with the default empty map.

Provider definitions use the UI normalizer's string `fieldType` values
`text|password|select|number|toggle`, with unique `key`, boolean `credential` and
`required`, and the exact No Land `credentialType`. OAuth client ID/secret fields
remain native authorization inputs; the service owns native OAuth availability
and registered-client normalization. This crate does not run a browser flow:
the OAuth service persists its private native tokens through `connect_provider`
or `update_oauth_credentials`, never the UI.

`ProviderAccess` deliberately implements neither `Debug`, `Clone`, nor
`Serialize`; its contract fields (`provider_id`, private-to-native `session`,
`repository_key`, `read_only`) are accessible to the native bridge only. Drop
zeroizes session strings and the key. Do not pass it to a webview, logger,
subprocess argv, or persistent generic operation JSON. The shared adapter creates
the exact No Land `EphemeralRcloneSession` JSON. The bridge owns guarded 0600
temporary config creation under a 0700 directory and must not use global rclone
configuration.

`import_noland({sourceId,profileIds?})` is the normal flow after native consent.
`stateFile` remains an advanced native-confirmed fallback, not a mandatory picker.
It opens the explicitly selected file read-only with native no-follow handles,
projects only storage profiles/profile fields/repository keys, reads selected
No Land vault items read-only, and writes only QuickSave's namespace. It never
calls No Land's migrating `secure_store::get`. Null vault tombstones suppress all
fallbacks. Import is read-only by default and does not perform provider health
checks. An import preview reads no credentials.
An already-imported source profile is rejected while **any** previous matching
record is connecting, connected, or error. After every previous match has been
explicitly disconnected, a fresh native-consented import creates a **new** UUID,
read-only profile and new credential/key references. Disconnected records, keys
and history remain additive. Software assignments and old grants are never
reattached or re-enabled for the new provider; uploads/autosave need fresh,
separate native authority. An error profile can retry health using its retained
QuickSave credentials without importing or reading the No Land source vault.

The gateway's native-only `_approvedPaths` handoff is enforced when present:
exactly one matching `{path,kind:"file",identity,stamp,parentIdentity}` is required.
Both identities use `{device,fileId}`; `stamp` uses the platform `FileStamp`'s
default snake_case fields. The opened parent native ID, file native ID, and full
file stamp must match **before any source bytes, JSON, or vault entries are read**.
Missing, malformed, duplicate, or mismatched proofs fail closed, never silently
repin a replacement. A second stable-file check precedes JSON parsing. Trusted
native standalone callers without this field retain the existing behavior;
the gateway must reject this private key from webview inputs and supply its own
server-held proof.

Durable replacement/locking is implemented locally under `src/state_file.rs`;
no platform crate edits are required. Unsupported native durability fails
explicitly. Only the parent runs workspace compilation/tests using the shared
target with jobs=1.

## Automatic No Land import (native gateway)

```rust,ignore
store.discover_noland_sources() -> Result<Value>;
store.discover_noland_sources_in(&KnownDataDirs { bases: Vec<PathBuf> }) -> Result<Value>;
store.noland_source_proof(source_id) -> Result<Arc<NativeNolandSourceProof>>;
store.noland_import_source_scope(source_id) -> Result<Value>; // NATIVE ticket only
proof.state_file() -> &Path;
proof.approved_path_handoff() -> Result<Value>;
```

After initial native discovery consent, inspect only
`<native application-data base>/com.noland.connect/state.json`: macOS Application
Support, Windows Local/Roaming KnownFolders, Linux XDG data with native account-home
fallback. No home/disk recursion, checkout path, capture-home override, source JSON,
vault access, chmod or source write. No Land's actual writer can create 0644 files;
discovery permits owner-owned, non-writable-by-others, single-link regular files,
pins file/full stamp/parent and never follows symlinks. Advanced manual policy is
separate. Exactly one candidate gets `selectedSourceId`; multiple require a native
chooser; none returns `hasData:false` and a real error, never imported profiles.
UI receives opaque IDs and redacted names/path summaries only.

IDs are store-bound and expire after 10 minutes. `noland_import_source_scope`
contains the exact native path/proof for the one-use ticket and must never be an
IPC response or accepted as incoming JavaScript authority. Import resolves the ID
again and checks the same proof before any source content/vault read.
`open_with_vault` disables default native discovery; isolated tests must inject
`KnownDataDirs`. `open` is the actual native-account product constructor.

## Checked credentials, reauthorization and external recovery

- `oauth_credential_generation_for_access(&ProviderAccess)` validates the complete
  original private session against the protected profile.
- `update_oauth_credentials_cas(id, expected_generation, credentials) -> u64` and
  typed `update_oauth_tokens_cas(...) -> u64` commit only token changes after
  generation CAS and checked vault read-back. Generations live only in the vault.
  An old parallel refresh or disconnected worker cannot overwrite/resurrect it.
  The legacy non-CAS updater is for already-serialized native callers, not rclone.
- `oauth_reauthorization_profile(id)` is a non-serializable native client profile.
  `provider_credential_generation(id)` supplies a private native CAS ticket.
  `complete_provider_reauthorization(id, expected_generation, credentials)` works
  for all fourteen providers. `complete_oauth_reauthorization` enforces OAuth.
  Explicit reauthorization preserves routing/client/key/read-only fields, requires
  new live health, revokes autosave, and advances protected `authorityRevision`
  so old request/grant scopes cannot silently move to another account. This is
  distinct from automatic token rotation, which leaves state/grants unchanged.
- `export_recovery_key(&NativeRecoveryExport { provider_id, destination,
  parent_identity })` writes a NEW external private 32-byte key file, checks
  durable creation/privacy/read-back, rejects protected/capture destinations and
  all `com.noland.connect` application-state destinations, and returns a sanitized
  receipt only. Native capture directories remain forbidden even for allowlisted
  partial capture. Never return a master key through IPC.
- `recovery_mac(&[u8])` and separate `operation_mac(&[u8])` return domain-separated
  HMAC-SHA256 using the cached **device** vault key and pinned data-root identity.
  Message bytes are borrowed, bounded to 512 MiB and streamed into the MAC; no
  JSON normalization, full copy, repository key or device-key export.
  `recovery_mac_existing` and `operation_mac_existing` use those identical
  domains/workspace bindings with `device_key(false)`: missing authority is an
  error and never creates a new key. Use existing-only APIs for recovery/journal
  verification; the creating APIs are for native-consented seal/preview work.
  Missing-vault failures retain journals rather than authenticate with a new key.

## Tracker records and efficient native metadata reads

Settings accept Tracker's exact `appTracking:{policyScope,policyGrant}` through
`set_app_tracking_policy`; `app_tracking_policy` revalidates authority and
`clear_app_tracking_policy` persistently revokes it. The typed policy preserves
absent versus explicit-null `providerId`, so serialization never changes the MAC.
No unsigned enabled flag is authority.

`StateSoftware` losslessly preserves `sourceIdentity`, `autoEnrollment`,
`bundleIndexSource`, `previousBundleManifest`, `captureReceipt`,
`baselineFullScope`, `appRunning`, and existing fields. Root tracking MACs match
Tracker exactly: full source identity plus BLAKE3 policy/discovery/app/candidate
and coverage binding (including ordered unresolved-root/reason arrays).
Canonical `sourceIdentity.app_id` (for example `steam:480`) and installation
`appId` (`steam:480@native-installation`) are distinct identities, not aliases
required to be equal. Each retains its bounded validation; the tracking grant
binds the instance `appId` AND the entire unchanged `sourceIdentity`. Native
enrollment verifies their evidence/path relationship. Filename-safe software/
provider ID rules remain unchanged and do not admit these app identity strings.
Pending approved roots may persist without claiming a materialized bundle.
Tracker's `unknownGeneration` is a lossless `u64` with legacy default zero. A
new uncertainty partition marks current data dirty/reconciliation-required and
invalidates only the current saved confirmation. Historical baseline, full-scope
marker, index/manifest/receipt, saved version/time and signed grants are retained.
The counter cannot roll backwards through merge updates and is never included as
new tracking/write authority. Missing application roots do not prevent persistence
of a genuine MAC-validated unknown-dirty transition.
`confirmedGeneration` is CURRENT metadata, derived during merge only when
`tracked`, `status:"saved"`, `dirty:false`, `reconciliationRequired:false`, and
matching nonzero `lastConfirmedUploadedGeneration == dirtyGeneration` all hold.
The reconciliation flag is preserved from Tracker, never inferred false from
counters, a baseline, or an upload. Dirty/reconciliation-pending results clear
current confirmation without deleting history. A later actual native-verified
receipt/index can restore it with the same nonzero `unknownGeneration`; the
counter is not a permanent clean-state ban. A caller-supplied confirmation is
ignored. These flags are not authority: the native Tracker/source still verifies
the actual receipt, exact scope/epoch, signed index, MAC and vault nonce before
accepting source data or publication.
Unknown fields still fail. Counts/roles/coverage are metadata-only projections;
sidecar paths, grants, receipts and private identities are not UI DTOs.
`pendingWork` is an optional, private, losslessly retained native-frame reference;
legacy absence/null means no reference. Its exact `trackingresume::write_frame`
envelope/scope/grant schema is checked before persistence: one `work-*.json` leaf,
matching name/hash/byte fields, fixed digest-only scope, raw 64-hex MAC/nonce, and
the `tracking_frozen_work` kind/registry slot. Unknown fields, inline frame JSON,
absolute reference paths and references over 64 KiB fail. Referenced frames are
bounded to 128 MiB and aggregate state is limited to 64 references / 128 MiB.
These are structural checks, not native authority or an actual-file size proof.
Tracker still authenticates the actual device MAC, persistent nonce, original
parent grants, exact frame content and SafeRoot identities before source admission.
State read/validation never opens a frame, reads a vault, creates a key/grant or
rotates a nonce. `sanitized()` never emits `pendingWork` or its scope/grants.
Merge omission preserves a retained reference; adapters must send explicit
`pendingWork:null` on native retirement rather than rely on Tracker's skipped
`None` serialization. Clearing a locator never removes baseline/history or files.
Native grant scopes are bounded to 2 MiB; prefer fixed digest/root scopes for
large restore/operation plans instead of duplicating inventories.

`read_snapshot() -> WorkspaceReadSnapshot` loads/validates state once for one
native metadata request. Its `verify_grant`, `verify_tracking_grant` and
`is_current` avoid an O(apps²) whole-state read loop while preserving actual MAC
and vault nonce checks. It is not a generation-only or cross-request cache and
must never replace fresh publication guards. A future cross-request cache must
use a locked native file stamp/ctime identity, not JSON's generation field.

For Tracker's existing per-record trait forwarding, wrap ONLY synchronous
`software`/`file_listing` DTO projections in
`with_metadata_verification_snapshot(|| ...)`. It uses a thread-local, exact-Inner
frame and restores it with RAII; real MAC/nonce checks remain unchanged. Writes,
provider reads and non-metadata grant kinds remain fresh, and a fresh end read
must match the actual decoded document. A changed projection is discarded via
`MetadataProjectionChanged`; replay is caller-owned and bounded. Never wrap
prepares, receipts, worker operations or publication/write guards. See
[`METADATA-VERIFICATION.md`](METADATA-VERIFICATION.md).
