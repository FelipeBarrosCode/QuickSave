<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Exact native dataset filename provenance

This is original GPL-3.0-only QuickSave integration in the audited active
No Land fork derived from commit
`e81238a7536aae201540956ce76981364fd36595`. Original notices and engine manifests
are preserved; this does not resolve their GPL/MIT license conflict or declare
the original snapshot MIT. `upstream/no-land/` is unchanged.

## Boundary and changed paths

All paths below are relative to `shared-storage/`.

- `crates/noland-state-core/src/logical_path.rs`: additive native component,
  Unix/Windows relative-path, exact constructor/join and confined-link checks.
  `LogicalPath::new`, legacy joins/normalization and logical-root IDs keep their
  original behavior.
- `crates/noland-state-core/src/native_layout.rs`: source-platform basename
  parsing is separate from target compatibility; the complete selected manifest
  is preflighted before target paths are built.
- `crates/noland-state-agent/src/native_host.rs`: only the native host uses the
  exact constructor; its existing relative-path entry point delegates to core.
- `crates/noland-state-agent/src/backup.rs`: native link capture uses native
  confinement instead of subsequently applying the legacy portable policy.
- `crates/noland-snapshot/src/source.rs`: held-handle enumeration/child leaf and
  native link checks share native filename rules; no-follow operations remain.
- `crates/noland-restore/src/native.rs`: exact native preview, frozen mapping,
  payload revalidation and execution joins; full-name preflight before writes.
- `crates/noland-restore/src/lib.rs`: only native-controlled reconstruction uses
  the exact resolver/join. The legacy restore branch is unchanged.
- `crates/noland-restore/src/native/windows_contract.rs` and
  `native/windows_contract/root_scope.rs`: Windows source hint/allowlist names
  remain strictly Windows-validated even when inspected on Unix.
- `crates/noland-restore/src/native/tests.rs`: exact preview/JSON/MAC-input
  binding and source-versus-target link-name regressions.
- `crates/noland-testkit/tests/native_optimized_pipeline.rs`: isolated actual
  source/LocalStorage roundtrip, reuse and additive-history regression.

Native UTF-8 dataset paths use `/` as their wire separator. Unix `:` and `\`
remain literal filename bytes, including in JSON/MAC input and metadata-only
directory/link nodes. Windows rejects separators, drives, UNC/device/ADS names,
reserved aliases and incompatible target basenames without renaming them.
Bounds, NUL/dot/traversal rejection, confinement, cryptography, identity/reuse
fences and the 512 MiB restore metadata ceiling remain enforced.

No manifest/pack/envelope schema or version changes, provider/remote-key changes,
scope-ID relaxations, extra content scan or sparse/hash/cache policy changes are
part of this adaptation. Public capture/restore metadata shapes are unchanged.

## Integration and validation

`native_layout::validate_native_restore_names(&BundleManifest)` and
`validate_windows_restore_names(&BundleManifest)` are read-only name gates.
`native_restore_layout` runs the current-target gate before creating mappings.
Native preview and execution payload validation also run it before destination
mutation. A caller that scaffolds earlier must invoke the same gate first.

The new source roundtrip test is
`native_unix_exact_names_roundtrip_files_directories_links_and_additive_history`.
It covers files, empty/nested directories, link names/text, real root basenames,
distinct `a\b`/`a/b`, unchanged zero-rehash/pack reuse, exact deletion and an
older additive revision. It uses only fresh temporary roots, generated data,
actual source storage/crypto and private synthetic recovery authority; it is not
Tracker/StoreAdapter interoperability or live-application acceptance.

Rust compilation and test/benchmark execution are reserved for the parent's
serialized bounded build lane. Formatting/static checks are not native runtime,
Windows/Linux, packaging, launch or application-atomicity acceptance.
