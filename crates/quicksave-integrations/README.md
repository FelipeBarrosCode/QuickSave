# QuickSave integration boundary

Public entry points:

```rust
pub fn discover_applications() -> anyhow::Result<serde_json::Value>;
pub fn integration_capabilities() -> serde_json::Value;
```

`discover_applications` reads bounded installation metadata, without processes,
network calls, credential stores or backup/restore actions. Its result contains
`applications`, `diagnostics`, `incomplete`, `limits` and `backup_authority`.
Unsafe/unreadable/oversized metadata is rejected and reported; absent optional
locations are skipped. A limit or rejected record makes the report incomplete.
Display text is untrusted UI data, never an ownership key.

## Implemented discovery

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

## Profiles and authority

Profiles contain typed product/install/platform/architecture identities, portable
relative root mappings (installation/save/config/optional cache), prerequisites,
truthful stable-file consistency requirements and explicit per-root approval.
Discovery leaves architecture unknown rather than inferring it from the host.
The Steam and universal-unknown templates do **not** implement app backup.
Unknown apps request explicit manual folder selection; save/config mappings are
not inferred by basename, title or a wide home-directory search.

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

See `PROVENANCE.md` for the exact upstream Steam parser source and license caveat.
