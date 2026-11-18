# Windows native storage handoff

New code is GPL-3.0-only; original No Land notices and manifest licenses remain.
No source snapshot, provisioner, real provider account, credential vault entry
or No Land app state was modified/accessed. No Cargo build or tests were run.

## Implemented paths

- Guarded session creation, token checkpoints, private cached config replacement,
  checked finalization, retained-session inventory/recovery and known-leaf cleanup
  now select actual Windows implementations, not a Unix-only rejection.
- All security IDs are Snapshot `NativeIdentity` / `WindowsMetadata` from real
  handles (`FILE_ID_INFO`, full 128-bit file ID). No Rust std 64-bit file index is
  expanded into a fake Windows identity. Stable comparisons ignore access time,
  not change/write/creation time, size, attributes, reparse kind or link count.
- Directory opens and children use Snapshot no-follow handles. Only the owned
  execution directory is reopened with delete-sharing; every use revalidates its
  full named identity. Case aliases use the storage-parent's actual native ID
  plus a bounded case-folded internal leaf for live-directory registration.
- Cached config replacement uses handle-relative `NtSetInformationFile`
  `FileRenameInformation`, not path-based `std::fs::rename`, inode truncation, or
  ordinary restore's no-replace API. The ordinary temporary writer closes before
  the control handle seals/renames it. Vault CAS/read-back still precedes success.
- Owned empty directory removal uses checked POSIX namespace disposition.
  Immutable staging/retry cleanup can ignore a readonly *attribute* while
  unlinking the exact owned lease; it never clears the original pack's attribute,
  truncates its inode, sweeps unknown entries, or follows a reparse point.
- Original immutable batching, adaptive bounded concurrency, checksum handling,
  native progress, shared retries and provider tuning remain the transfer path.
  Windows local-provider file/metadata paths use no-follow native publication and
  real durability barriers, not a fabricated successful directory `fsync`.

## Exact private ACLs, including rclone's atomic rewrites

Snapshot's original strict current-user-owned, protected, one-ACE policy remains
the first accepted policy. A newly created QuickSave credential directory alone
can opt into this additional exact policy:

1. Protected current-user owner/DACL.
2. One normal full-control current-user ACE (flags zero).
3. One file-only/inherit-only full-control ACE for that same current user
   (`OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE`).

An ordinary rclone-created replacement file must have exactly one effective
inherited full-control ACE for the current user, current-user ownership, no
other principal or deny/object/unknown ACE, no reparse kind and one hard link.
The directory must still have its exact pinned user-only policy. This avoids
accepting the broader ambient default-token DACL after `CreateTemp` + rename.
Native cached files still use Snapshot's explicit protected file descriptor.
The source import/vault/restore ACL policy is unchanged. Existing foreign ACLs
are rejected, not repaired into success.

All variants require native NTFS/ReFS persistent ACL support. Snapshot's actual
volume/directory durability barriers remain mandatory. Missing rights, sharing
conflicts or unsupported OS/filesystem operations return errors. This is not a
claim that an unelevated packaged app already passes those permission gates.

## Trusted helper resource contract

Before preflight, the Windows engine must call:

```rust,ignore
noland_storage::pin_native_rclone_resource(&absolute_native_resource, trusted_blake3)?;
// Preflight THIS exact pinned executable's version and required flags.
noland_storage::install_native_rclone(&absolute_native_resource)?;
```

The pin is native-only: its digest comes from trusted build/package metadata or
an audited NativePaths resource, never JS, PATH, an environment override or an
adjacent writable checksum. Pins retain the actual source/file handles across
preflight/install (maximum eight resources). Windows additionally validates a
bounded PE header, executable-not-DLL type and native architecture. No installation,
download or bare `rclone` fallback occurs. Current Windows engine code can keep
its trusted compiled SHA-256 package proof and pass the verified bytes' BLAKE3.

Runtime pins validate the same full handle state before launch; they do not hash
the executable per chunk. The child environment is cleared; `SystemRoot`/`WINDIR`
come from `GetSystemWindowsDirectoryW`, not inherited environment, and the native
working directory is that OS-selected root. No console/shell/helper lookup occurs.

## Authored validation, not acceptance

Windows-gated synthetic cases cover actual handle IDs, exact inherited config
ACLs, checked rotation/finalization, retained failure/recovery, live case aliases,
external-hard-link safety, readonly immutable batch leases and rejected PE headers.
They launch no real helper/browser and access no account/native vault.

The macOS host has no Windows SDK/runtime acceptance. Parent owns serialized
compilation and Windows CI execution, native browser/helper packaging, actual
permission acceptance and performance measurements. No Windows/Linux/package or
real provider/client acceptance is claimed by these changes.

## API/ABI references

Windows SDK declarations and semantics were checked against Microsoft's
[NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile),
[FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information),
[FILE_DISPOSITION_INFORMATION_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex),
[ACE inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules),
and [GetSystemWindowsDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemwindowsdirectoryw).
The private ACL/identity/durability design reuses the active Snapshot Windows
adapter; the owned storage-specific rename/inheritance/disposition code is new.
