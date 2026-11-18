# Provenance and licensing

New code in this crate is GPL-3.0-only pending owner/license review.
The source-root GPLv3 and original No Land engine manifest MIT notices are
preserved; no claim is made that the whole upstream snapshot is MIT.

Read-only source references, inspected solely for the requested interoperable
storage-provider/credential formats and import policy:

- `no_land/src-tauri/src/models/application_bundle.rs`: 14 provider identifiers
  and tagged `StorageCredential` (`type`/`value`, snake_case payload fields).
- `no_land/src-tauri/src/models/app_state.rs`: camelCase storage profile reference
  and secret-profile projection.
- `no_land/src-tauri/src/services/shared_storage/provider_profiles.rs`: app-wide
  repository-key precedence and independent disconnect lifetime.
- `no_land/src-tauri/src/services/state_secrets.rs`: SHA-256 dynamic profile
  account names, desktop service namespace.
- `no_land/src-tauri/src/services/secure_store.rs`: v2 vault document key encoding
  as a JSON `(service,account)` tuple and explicit-null tombstone meaning.
- `no_land/src-tauri/tauri.conf.json`, `src/main.rs`, and
  `src/services/state_store.rs`: authoritative `com.noland.connect` identifier and
  Tauri native `app_data_dir()/state.json`. The atomic writer was inspected only
  to document that legacy owner-owned state files can be 0644; no source file is
  chmodded, migrated or written by import/discovery.
- `no_land/src-tauri/src/services/shared_storage/oauth_flow.rs` and the
  refresh section of `shared_storage_manager.rs`: concrete OneDrive fields,
  user-supplied registrations and refresh-token rotation semantics. New CAS,
  checked finalization and domain-separated native device MACs are original
  QuickSave code, not the source's stale-credential/error fallback.

Those original notices remain in their original files. No actual No Land state,
native-vault entries, provider account, bucket, credentials, remote machine,
provisioning, or lifecycle code is used by development/tests.

Production session creation calls the active audited
`shared-storage/crates/noland-rclone-adapter` path dependency, not the unmodified
`upstream/no-land` snapshot. This crate does not reimplement storage encryption
or bundle/pack formats.

The synchronous thread-local metadata frame, exact-Inner/RAII lifetime handling
and existing-key-only MAC entry points are original GPL-3.0-only additions.
They neither cache revocation results nor change grant/MAC domains or byte
canonicalization. `state_file.rs` and its owner's native stamp API were not
modified by this agent.
