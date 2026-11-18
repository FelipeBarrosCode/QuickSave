# QuickSave integration boundary

Public entry points:

```rust
pub fn discover_applications() -> anyhow::Result<serde_json::Value>;
pub fn discover_software_bundles() -> anyhow::Result<serde_json::Value>;
pub fn discover_software_bundles_in_scope(
    scope: &BundleInventoryScope,
) -> anyhow::Result<serde_json::Value>;
pub fn discover_software_bundles_with_approved_bases(
    scope: &BundleInventoryScope,
    proofs: &[ApprovedDiscoveryBase],
) -> anyhow::Result<serde_json::Value>;
pub fn discover_software_bundles_with_backend(
    backend: &mut dyn SoftwareBundleBackend,
    scope: &BundleInventoryScope,
    limits: BundlePlanLimits,
) -> anyhow::Result<serde_json::Value>;
pub fn integration_capabilities() -> serde_json::Value;
```

### Native tracking-policy boundary (service entry point)

```rust
pub struct ApprovedDiscoveryBase; // private fields; Clone, not Deserialize
impl ApprovedDiscoveryBase {
    pub fn from_pinned(
        path: std::path::PathBuf,
        root: std::sync::Arc<quicksave_platform::SafeRoot>,
        expected: quicksave_platform::RootIdentity,
    ) -> anyhow::Result<Self>;
}
```

The service must first obtain/verify its persisted native tracking-policy MAC,
then retain the exact `SafeRoot` objects and expected directory IDs from that
native handoff. `scope` must be the approved policy's original scope plus all
native/persisted exclusions, never a freshly widened environment/UI scope.
`ApprovedDiscoveryBase` is a Rust capability, not deserializable JSON or an
`approved: true` bit. Constructor/operations reject changed namespace edges.
The JSON `baseDirectories` proofs are transport evidence only: converting them
requires native retained roots and exact expected-ID comparisons.

The approved backend uses `SafeRoot::read_file` for every bounded metadata
content read, `SafeRoot::open_directory(&str) -> Result<File>` for nonempty
relative directories, and `SafeRoot::clone_root_directory_handle() -> Result<File>`
for a base itself. These owned handles support bounded immediate-entry listing
and no-follow node metadata from the **retained root**,
not a path reopen or recursive tree walk. Base and relative identities are
checked before/after operations; exclusions are checked before opening.
Unknown/new/missing bases add no authority. External Steam libraries require an
exact separate retained proof for the library or its `steamapps` directory,
even if another broader home/data proof exists. The Steam allow-list second
pass must reuse the same retained `proofs`; never fall back to ambient discovery.

Path-only macOS Security APIs cannot guarantee this held-handle confinement.
The approved backend therefore does not call them: signed-group confirmation
stays explicitly unavailable/unconfirmed rather than reading a raced replacement.
Fixture-injected signed evidence remains supported without live Security calls.
No Land (`com.noland.connect`), QuickSave, vault, credential, cache, log and
policy-protected paths are excluded before any metadata contents are read.

`discover_software_bundles`, `discover_software_bundles_in_scope`, and legacy
`discover_applications` remain explicit general read-only inventory APIs, **not
native tracking authorization**. They must not be called by service/UI polling
or substituted for the approved entry point. Status polling reuses the native
index/report rather than re-reading installation trees.

## Bundle-plan API contract (service integration)

The new API is a **local native inventory and root-planning layer**, not just a
title list, a grant, or a claim that a cloud backup exists. The legacy
`discover_applications` result remains compatible. New reports use camelCase:

- `bundlePlans`: only plans with **real verified installation/runtime/data root
  identities**. `unresolvedApplications` separately accounts for discovered apps
  lacking those identities; these are diagnostics, not counted/tracked bundles.
  No discovered app silently disappears. `appId` is based on an exact platform
  product identity and native installation identity, never the display title.
  Invalid metadata never turns into title/basename-based ownership.
- Each plan has `sourceRoots`, `unresolvedRoots`, `unresolvedReasons`,
  `profileMatchPolicy`, `identityEvidence`, and `sourceIdentity`.
  Each root has `rootId`, `path`, `classification`, `nativeIdentity` (or null),
  `status`, `confidence`, `evidence`, `exclusions`, and `requiresUserReview`.
  Classifications/roles distinguish installer/install/runtime/save/config/
  container/group-container/data/user-review. Unresolved roots remain diagnostics.
- `sourceIdentity` is null for unverified applications. Verified source plans
  carry the **snake_case No Land `AppIdentity` wire shape** inside that camelCase
  field: `app_id`, `display_name`, `canonical_executable`, `desktop_entry_id`,
  `steam_app_id`, `launcher`, `aliases`, `identity_confidence`, `icon_path`.
  The actual No Land field is `desktop_entry_id`, not `desktop_file_id`.
  This is a dependency-free typed wire contract, not an authorization object.
  Product IDs are `steam:<validated numeric app ID>`,
  `mac-bundle:<exact CFBundleIdentifier>`, `desktop:<exact XDG filename ID>`,
  or the exact Windows package/registry product ID. The enclosing plan's `appId`
  separately identifies a native installation. No title/alias normalization is
  used. `canonical_executable` is an actual verified no-follow executable path,
  not an installation directory; it is null for Steam manifests (which do not
  identify an executable) and unresolved/launcher-only runtimes. The exact macOS
  executable path also remains in `identityEvidence` with kind
  `cf_bundle_executable_native_handle`. `identity_confidence: 1.0` denotes this
  deterministic exact-platform-identity match, not statistical certainty,
  application completeness, process evidence, or a backup grant.
- Native identities come from no-follow OS handles (Unix device/inode, or a
  Windows identity supplied by an explicit native adapter), not `canonicalize`,
  string hashes, display names or a path existence check.
- `inventoryIncomplete` and bounded `diagnostics` disclose rejected metadata,
  unsafe paths, unsupported sources and enumeration limits. Per-app
  `rootsComplete` is false when any ownership/root question is unresolved.
  `omittedApplications` explicitly reports observed records that could not fit
  the total serialized-output budget; they are never counted as bundle plans.
  `protectedSourceRoots` appears once per report and applies to every root's
  exclusion policy. Both input expansion and plan-output bytes are bounded.
- `contentScanAuthorized`, `trackingAuthorized`, `uploadAuthorized` are always
  false. `backupAuthority` is `not_granted`. The service must obtain native
  inventory consent, show the plans, and seal **each selected root's identity**
  (a single native approval can approve the reviewed set; no per-app manual
  folder picker is required for verified mappings). It must deduplicate exact
  shared-root identities, normalize verified parent/child overlaps to one file
  index, reject incompatible overlapping selections, and revalidate identities.

There are no fabricated file counts or static/demo app datasets. The parent
engine must create the actual bounded file inventory/index after consent before
anything is called a tracked/local bundle. Plans are never "backed up."
macOS app roots require `safe_relative_link_metadata_without_traversal` from the
engine: discovery never walks framework links, nor grants permission to follow
them. Unsupported engine capabilities must block materialization explicitly.

`BundleInventoryScope` explicitly supplies installation directories, home/XDG
anchors, Steam launcher roots, optional inventory-approved Steam app IDs, and
protected QuickSave/repository paths. Steam userdata is considered only for an
exact approved numeric app ID, never a username or a title. Scope approval is
not content/backup permission. `SoftwareBundleBackend` allows isolated fixtures
and explicit Windows registry/package/Known Folder adapters. The fixture backend
requires an isolated child of the OS temporary directory, refuses source access
outside its pinned sandbox, and never calls
Security APIs, accounts, keychains or ambient discovery.

macOS planning uses bounded plist metadata, `CFBundleExecutable`'s real native
file identity, exact bundle-ID Application Support/preferences paths, container
metadata's `MCMMetadataIdentifier`, and validated signed application-group
entitlements via read-only Security APIs. Linux uses desktop IDs, literal
absolute executable metadata and exact XDG/Flatpak IDs; a launcher never grants
ownership of its executable's parent directory. Windows ambient discovery
remains explicitly unsupported unless an explicit adapter provides native
registry/package identities and Known Folder anchors. Portable Windows fixture
coverage is not Windows-native acceptance.

All candidates require review. Caches, logs, vault/keychain/credential stores,
QuickSave state and caller-protected roots are excluded. Unknown saves stay
unresolved; no entire home, Application Support, AppData or XDG directory becomes
an app's backup root. Container/group roots do not claim exclusive ownership or
application-atomic capture.

`discover_applications` reads bounded installation metadata, without processes,
network calls, credential stores or backup/restore actions. Its result contains
`applications`, `diagnostics`, `incomplete`, `limits` and `backup_authority`.
Unsafe/unreadable/oversized metadata is rejected and reported; absent optional
locations are skipped. A limit or rejected record makes the report incomplete.
Display text is untrusted UI data, never an ownership key.

## Legacy discovery (compatible `discover_applications`)

- **macOS:** top-level `/Applications` and `~/Applications` `.app` bundles.
  XML/binary `Contents/Info.plist` is parsed with Rust `plist`; bundle ID plus
  install path is the identity. No `plutil`, executable probe or recursive scan.
  The expanded event count, scalar bytes, nesting and capacity hints are checked
  before constructing a plist tree; duplicate top-level identity keys fail.
- **Linux:** top-level XDG `applications/*.desktop`, including precedence and
  `Hidden=true` masking. Desktop file IDs and metadata paths are identity evidence.
  `Exec` is never executed or treated as proof of an installation directory.
  Nested desktop entries are intentionally not scanned.
- **Steam on macOS/Linux:** known launcher roots and their bounded
  `steamapps/libraryfolders.vdf` / `appmanifest_<id>.acf`. Pure parsers also
  understand drive-absolute Windows library paths, without Windows native I/O.
  Product ID plus existing installation path is used, not the title.
  Manifests must match their filename ID and contain a safe explicit `installdir`.

Native directory handles open **every ancestor** without following symlinks.
Enumeration and regular-file reads are handle-relative, bounded, and reject
symlinks, invalid names and changing metadata. Linked Steam aliases are not
canonicalized; an independently present real known launcher root can be scanned.
Only `steamapps/common/<explicit installdir>` is an install candidate: no scanning
or ownership attribution of userdata, compatibility prefixes, saves or config.

Windows Desktop/Start Menu/uninstall-registry enumeration is **unsupported**.
The Windows public discovery function errors; it does not return an empty
successful scan. Capabilities include Microsoft implementation references.
Pure Windows-compatible parsing/types do not imply Windows native acceptance.
No platform packaging acceptance is asserted by this crate.

## Legacy templates and authority

Profiles contain typed product/install/platform/architecture identities, portable
relative root mappings (installation/save/config/optional cache), prerequisites,
truthful stable-file consistency requirements and explicit per-root approval.
Discovery leaves architecture unknown rather than inferring it from the host.
The Steam and universal-unknown templates do **not** implement app backup.
Unknown apps request explicit manual folder selection; save/config mappings are
not inferred by basename, title or a wide home-directory search.
These legacy templates are not used as the new bundle planner's sole policy:
its verified exact-ID/container/group/Steam/XDG/package root mappings are
automatic proposals and do not require manual selection of every app folder.

Portable saves require a data-specific compatibility declaration and review.
That declaration never permits cross-OS executable restoration; executables
require known matching OS/architecture. Config migration and cache restoration
are not generalized.

Discovery candidates are not grants. Nothing here verifies live application
quiescence or produces an application-atomic snapshot. Engine root approval,
native confinement and stable-file validation remain separate mandatory steps.

## Providers and native helpers

`TypedProviderConfig` describes `LocalFilesystem`, `S3Compatible`, `GoogleDrive`,
`OneDrive` and `OtherRclone`. Local filesystem is the only existing engine
transport. All cloud variants fail `validate_for_use` explicitly: their typed
settings are **planned contracts**, not working authentication or durability.
No config contains secret/key/token values, no Rclone process is run, and no
existing remote configuration is inspected. External recovery-key files remain
required; native vault references are future opaque references only.

Keychain/Credential Manager/Secret Service, native observers and APFS/VSS/Linux
snapshot helpers are explicitly planned. `require_helper` always errors until an
implementation exists. Observers must eventually be hints with reconciliation,
not a replacement for change validation. No cloud deletion/retirement is offered.

## Tests

`cargo test -p quicksave-integrations` covers synthetic plist (XML and binary),
ACF/VDF and desktop fixtures; parser limits and unsafe path rejection; profile
compatibility across all declared OS pairs; explicit unsupported providers and
native helpers; pinned-handle and symlink rejection; bounded discovery; and
identity/ownership/authority boundaries. Filesystem tests create only temporary
directories and do not call ambient application discovery.

`src/bundles/tests.rs` additionally exercises real temporary native installation/
executable identities, exact bundle-ID data roots, signed-entitlement injection,
container metadata, ambiguity refusal, all-app accounting without placeholder
bundles, safe-link metadata requirements, fixture sandbox replacement and
symlink refusal, exact inventory-approved Steam userdata IDs, XDG/Flatpak
mapping, Windows registry/package/Known Folder adapters, bounded output, changed
executables during signature inspection, and proof that preference/save/vault/
account contents are not read. It never calls ambient discovery or Security.
Runtime/process learned associations are not inferred or fabricated by this
metadata planner; they require separate native evidence within the approved
tracking policy. No engine index, cloud durability, or Windows/Linux packaging
acceptance is asserted by these fixture tests.

See `PROVENANCE.md` for the exact upstream Steam parser source and license caveat.
