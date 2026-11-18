<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Native restore integration contract

The active fork's Unix legacy remote restore remains available. Native restore uses the
same authenticated manifest, pack reader, bounded reconstruction and verification
pipeline, with a separate authenticated mutation controller.

Implemented integration points:

- `noland_restore::NativeRestorePreview::prepare(job_id, manifest, roots,
  destination, destination_identity, conflict_mode)` produces an exact typed
  preview from an authenticated manifest. `NativeConflictMode::{CreateOnly,
  Merge, Overwrite}`; merge admits existing directories/identical files but never
  replaces different bytes. Overwrite still requires the exact preview approval.
- `NativeRestoreControl::approve(preview, authority, expected_gate)` freezes that
  preview. `authority: Arc<dyn NativeRecoveryAuthority>` authenticates **all**
  journal/intent bytes; `expected_gate: Arc<dyn Fn() -> Result<()> + Send + Sync>`
  must revalidate the native consent/state/provider/job before publication.
  `NativeRecoveryAuthority::mac(&self, bytes: &[u8]) -> Result<[u8; 32]>` is opaque;
  the caller retains its device-vault key. No journal checksum is authentication.
  `approve_shared` shares the immutable preview; it does not copy an entire
  manifest/inventory. Publication and recovery metadata are MAC-chained and
  flushed at publication barriers, never per plaintext chunk.
- `SharedRestorePlan::with_native_control(Arc<NativeRestoreControl>)` selects the
  controlled path. Native plans without this controller cannot mutate targets.
- `StateAgent::native_install_restore_control(job_id, control)` binds an approved
  controller before StartRestore/retry/reattachment. The controller is not accepted
  from RPC/JSON. Its exact manifest selection, destination, roots and expected
  payload must match the operation. Retry uses the original frozen approval;
  foreign replacements block replay and retain recovery data.
- `recover_native_restore(workspace, control)` verifies the authenticated scope
  and every chained intent before recovery. Ordinary `recover_interrupted_restores`
  must never replay native journals without this authority.
- `SharedRestorePlan::verify_native_completion()` independently MAC-replays the
  committed journal without repairing or deleting anything. Its
  `NativeRestoreCompletionReceipt::is_clean_committed()` gate proves that all
  authenticated partial, backup and capture slots are absent and only the two
  authenticated metadata files plus data-free, known scaffolding remain.
  `PipelineReport.io.commit.native_completion` carries the same gate from commit.
  Unknown files, links, foreign replacements or incomplete/tampered/uncommitted
  journals fail the gate; staging existence alone is not a completion test.
- `crates/quicksave-noland/src/restore_control.rs` supplies a device-key-backed
  authority adapter and the child `impl NativeEngine` bridge. The parent wires the
  **state secret**, never the repository master key or a persisted plaintext key.
  `EngineRestoreState::default`, `install_restore_authority`, `preview_restore`,
   `restore_preview_scope`, `download_guarded`, `recover_restore_local`,
   `restore_recovery_scope`, `restore_recovery_available`, `recover_restore`, and
   `retry_restore_guarded` are implemented there. The preview scope checks TTL and
  native identities without credentials or provider I/O. Durable private plans
   bind the provider/storage fingerprint and original source job ID.
   `restore_recovery_scope` reads only a bounded, private, stamp-checked plan.
   `restore_recovery_available(Uuid)` is a UI hint: small operation projection plus
   fixed private filename metadata, no inventory parse, vault/provider/tool call
   or destination walk. Spend authenticates the complete plan and binding.
   Local recovery accepts only the original ID/approved scope and fresh native
   consent; it is synchronous, revokes its temporary consent on return, reports
   actual retained results, and never reattaches cloud credentials or queues work.
   Credential reattachment/resume is a separate explicit API. The supplied device
   MAC must be read-only during recovery and fail if the original key is missing.

Recovery artifacts contain authenticated, destination-relative paths plus actual
native file IDs and observations. Originals have separate validated stable-file
rollback captures (including Linux independent-extent FICLONE where supported)
before being moved to create-new same-volume slots. An app retaining a writable
old fd cannot destroy the stable capture. Publication never clobbers a raced leaf.
Recovery only removes an observed owned file ID. A replaced/changed leaf or root
keeps original backups and recovery evidence. Native workspace/journal deletion
is not authorized by an unsigned path string.

Successful-data receipts permit exact finalization retry without redownloading
already committed files. A durable host completion hint can restrict recovery,
but never supplies deletion authority. Legacy unsigned native journals cannot be
promoted into authenticated cleanup grants.

The original pack scheduler, selective pack retrieval, streaming decoder,
bounded handles/hashers, checked unfinished-file counters, overlapped verification
and publication, and readback-avoidance remain in use. New diagnostics distinguish
original-copy vs CoW bytes and signed-record vs actual intent-file flush counts.
No real-world throughput benchmark is claimed.

## Authenticated native application layout

New QuickSave captures use `manifest.environment.quicksave_native_root_layouts`:

```text
{version:1, platform:"macos"|"windows"|"linux", app_id, software_instance_id,
 roots:[{logical_root, root_id,
         role:"installation"|"save"|"config"|"runtime"|"container"|
              "group_container"|"data"|"manual"|"installer",
         source_kind:"directory"|"file", leaf_name}]}
```

Only the native binding/capture owner may produce these AEAD-authenticated rows.
There is no absolute source path, relative-parent placement escape, UI mapping,
display-name fallback, or inferred installation bundle. Unknown fields/versions,
missing/duplicate root identities, incompatible single-file leaves, reserved
basenames and normalized/case-insensitive placement collisions fail validation.
Limits are 64 layout roots and 512 KiB for this metadata within the existing
512 MiB global native plan/authority budgets.

The new `noland_state_core::native_layout` module exports:

- `native_root_layouts(manifest)` validates the original, exact root set.
- `project_native_root_layouts(manifest)` narrows those validated rows after
  exact native selection. A reduced selection sets the native-only
  `quicksave_native_download.whole_bundle=false` marker before projection.
- `native_restore_layout(manifest, destination)` returns
  `NativeRestoreLayout { roots: BTreeMap<String, PathBuf>, metadata }`.
- `logical_root_map(&layout.roots)` converts this same frame to the engine API.

The parent declares the new core module and supplies its `blake3` and
`unicode-normalization` dependencies. `NativeRestorePreview` freezes the actual
map, layout metadata, root-directory conflict/metadata inventory and selection
extent. `NativeRestoreControl::logical_roots()` supplies execution/restart;
the mapping fingerprint is included in the authenticated journal header too.

Installation directories retain the actual captured basename directly beneath
the user-picked destination, e.g. `ActualApplication.app/Contents/...`. Other
roots use an explicit role directory and full root-ID hash guard, never host
HOME/config/runtime paths. Single-file entries already contain their leaf name.
Actual authenticated empty directory `rootCaptures` remain metadata roots, not
placeholder file entries or packs. Empty installation roots cannot become
placeholder apps. Native root-directory metadata uses the existing journaled
metadata/rollback mechanism and create-new also checks the package root itself.
Manifests without layouts keep the legacy confined hash-folder/files-only mode.

`RestoreCommitMetrics.native_reconstruction` reports the actual bounded plist,
executable-format and embedded signature-metadata checks; metadata-read bytes
are counted separately from assembly verification. Executable hashes reuse
authenticated stable pipeline receipts, with no extra whole-executable hashing.
The plist parser supports bounded XML/binary event streams (`plist` dependency).
All capture-relative content, resources and confined framework links still use
the original streaming/pack/reuse/publication pipeline.

**No runnable OS acceptance is fabricated.** Full scope and a `.app` basename
do not validate a native signature or dependency graph. This implementation
reports `files_only` or `reconstruction_unverified`; `runnable=false` until a
real compatible-platform signature/dependency acceptance path exists. In
particular the synthetic script fixture is reconstructed, never executed and
never advertised as a verified native executable. Native pipeline progress now
separates `critical_data_verified` from `ready_to_launch`.

Filesystem-agent coordination:

- The native mutation adapter uses `identity_from_file(&File)` and
  `SourceMetadata::from_file`; Windows observations use the complete
  `WindowsMetadata`/128-bit ID, never `fs::Metadata`'s truncated file index.
  Native file metadata uses
  `apply_file_metadata(&File, mode: Option<u32>, mtime_ns: Option<i64>,
  uid: Option<u32>, gid: Option<u32>) -> Result<()>`.
- All **new native** links use
  `validate_relative_symlink_target_within_root`, not the legacy Linux validator
  that permits absolute system links. Existing original link objects are moved
  back by authenticated identity during rollback, without following their target.
- The Windows adapter uses confined `create_new_relative_symlink`,
  `move_new_to_checked` (kernel no-replace), and the anchored SourcePath writer. Ancestors
  are no-follow. Unsupported root filesystems must return an exact error.
- Windows must retain the full native file ID and use its anchored writer and
  no-replace rename APIs; Unix chmod/chown must not pretend to implement Windows.
- The top-level native host/selection ABI and legacy restore modules still need
   their complete Windows integration/acceptance; a macOS check is not that proof.

## Windows portable filesystem boundary

Windows uses the same pack planning, selective streaming decoder, scheduler,
deduplication, bounded inline hashers/assembly handles, verification workers and
publication cohorts. It has no separate folder-copy restore. Every Windows
mutation requires a typed `NativeRestoreControl`; unsigned legacy preparation,
plaintext chunk-cache download/eviction, tombstones, path cleanup and automatic
startup replay return explicit errors instead of claiming unsupported success.
The UI must use its separately consented local-recovery adapter, not startup
recovery or credential reattachment.

`NativeEntryObservation.mode/uid/gid` are optional. Unix observations always
contain their actual values. Their JSON integer representation and omitted
Windows frame preserve the v1 Unix MAC bytes. Windows observations contain no
invented POSIX values: their native frame binds attributes, creation time, reparse
tag/data digest, actual volume/full 128-bit ID, full mtime/change time and hashed
current-user owner/DACL evidence. Journal replay also requires the observation's
principal to match the actual native destination user scope.

Windows previews and journal headers use **version 2**, with a Windows-v2 MAC
domain. Stable receipt filenames retain their existing names. Unix remains v1.
Old/unbound Windows or missing/foreign ownership frames are not promoted: MAC,
version or native-frame failures retain artifacts and return an error. No
checksum or repository master key can authorize recovery.

All namespace operations use held native parents. The Windows-only NT
create-new directory primitive returns its pinned created handle and uses a
protected current-user ACL, avoiding create-then-reopen ownership races. Guarded
source moves check complete `SourceMetadata`; file/directory deletion checks
actual native IDs. Files use real handle syncs; namespace durability uses the
source adapter's actual volume/directory flush, including honest privilege or
unsupported-filesystem failures. Metadata application requests real
`FILE_WRITE_ATTRIBUTES` access. Stable rollback captures remain independent,
bounded copies, never writable hardlinks or fabricated CoW.

New Windows links require the exact authenticated
`environment.windowsSymlinkMetadata` row
`{logicalRoot, relativePath, targetIsDirectory}`. Selected target entries,
extensions and headers are not substitutes. The source native symlink API
requires actual OS privilege and confined relative targets. Existing absolute
symlink objects can be observed opaquely and moved back by authenticated identity;
they are never followed or reconstructed through an absolute target.

The adapter rejects junctions/unknown reparse types, alternate data streams on
the actual opened object, stream/device/reserved names and normalized
case-insensitive entry/ancestor collisions. Windows partial basenames are bounded
hash-based names. No unknown partial, proposed create slot or rollback directory
is treated as a clean recovery merely because its create failed before an ID
could be logged. Unknown entries are retained, never swept by path.

No new Cargo dependency is needed for this adapter. Windows system imports are
`kernel32`, `advapi32`, `ntdll` and `normaliz`; the parent owns cross-compilation
and both lockfiles. The child does not claim a successful GNU cross-build,
Windows runtime tests, native packaging, power-loss acceptance or Runnable
status. Native signature/dependency acceptance remains separate.

### Windows manual leaves versus captured directory metadata

An authenticated manual-file root remains a **real directory identity** in
`quicksave_native_root_layouts`; it is not relabeled as a fabricated file-root.
Its `quicksave_native.full_scope.rootCaptures` row uses the producer contract:

```text
{id, logicalRoot, kind:"directory", stamp,
 metadata:null, allowedFiles:[...sorted exact relative file leaves...],
 metadataScope:{
   version:1, kind:"manual_leaves_only", sourceRootId,
   sourceRootIdentity:{device, fileId:[u64,u64]},
   allowedFilesDigest:<raw lowercase BLAKE3 of JSON sorted allowedFiles>
 }}
```

The native producer must add this discriminator to its already AEAD-sealed
source frame after checking it against the original tracker grants. The shared
consumer binds root ID/logical token, full native source ID, canonical allowlist
digest and both original/tracking root rows. Original evidence and tracker-scope
digests are checked once per preview, not once per leaf. Source absolute paths
and hints never supply placement or metadata authority.

This row permits only explicit regular-file leaves and authenticated prior
deleted IDs. It does **not** permit parent source timestamps, modes, UID/GID,
ACLs, foreign sibling capture, directory nodes, links or an empty-root claim.
Native preview retains a root entry with no requested metadata as a frozen
destination scaffold; the public preview schema and existing v1 MAC encoding
are unchanged. Existing scaffold directories can be reused in create-new mode,
but selected-file conflicts still apply. Only the minimum ancestors needed for
actual file publication are created. Parent time changes from foreign siblings
do not widen the file scope or become restored source metadata.

If the last allowed leaf is deleted, the authenticated source parent and
original deleted-node IDs must remain present. Missing destination parents stay
missing: deletion-only commits do not create empty source directories or
placeholder applications. Genuine empty-directory reconstruction instead needs
actual native directory metadata/stamps and original whole-root evidence with
`allowedFiles:null`; a manual grant cannot be promoted merely by adding a stat
frame. Unrecognized legacy metadata remains files-only for explicit nonempty
payloads, never guessed root permissions or empty-directory authority.

Validation is parent-serialized. The child ran `rustfmt`, not Cargo. Isolated
`native::tests` cover conflict approval, owned-ID rollback/recovery, foreign
replacements/root rename, MAC tampering, held-writer original capture protection,
strict relative links, actual LocalStorage subset and full pack pipelines, empty
file accounting, metadata/link restoration, deduplication, and no-download
committed retry, metadata-only completion receipts, readonly/torn-tail rejection,
foreign artifact retention and post-terminal journal rejection. Added pure
fixtures check v1 MAC-byte compatibility, missing/native ownership frames,
Windows root stamps/full IDs, exact link hints, opaque original reparse data and
bounded ADS parsing; isolated recovery fixtures retain unlogged create artifacts.
The parent must
run these and the existing accounting,
scheduling, publication and safety suites before claiming acceptance.

Source provenance: this GPL-3.0-only native control layer integrates with the
audited `shared-storage/` fork derived from No Land
`e81238a7536aae201540956ce76981364fd36595`. The upstream snapshot is untouched.
