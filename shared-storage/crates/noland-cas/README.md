# Native CAS / capture port

This active fork derives from No Land commit
`e81238a7536aae201540956ce76981364fd36595`. Original notices and the unresolved
GPL-root/MIT-manifest conflict are preserved. New native adapter code is
`GPL-3.0-only`; this is not a relicensing claim for the snapshot.

Owned paths for this revision: `noland-cas/**`, `noland-pack/**`; necessary native
source helpers remain in the assigned snapshot source/native files. Storage,
restore, and snapshot `lib.rs`/`metadata.rs` are not edited.

## Integration hooks (published before implementation)

- CAS adds `uuid.workspace = true`; pack adds `noland-snapshot.workspace = true`.
- Existing `ChunkFileReader`, `LocalCas`, `CasLease`, `ChunkSourceReader`, pack
  v1/v2 and capture v1/v2 public interfaces/formats remain compatible.
- Additive `capture_small_file_native` returns `SourceMetadata` obtained from
  the real handle. The legacy `fs::Metadata` result is not Windows ID authority.
- Native store helpers are exported through `noland_cas::native` for pack output:
  pinned private directory boundaries, exclusive staged files, identity-checked
  no-replace publication and operation-owned cleanup.
- Snapshot `native_metadata` gains bounded directory enumeration, actual native
  link counts, private-object (readonly / leased hard-link) verification, and
  `ScopedFileLock::lock_shared`. Recovery-key/private-state verification remains
  strict: these object policies do not relax the original APIs.
- Snapshot `SourcePath` gains native no-replace hard-link leasing and readonly
  immutable-object reads allowing delete-sharing but denying ordinary writers.
  All IDs come from `SourceMetadata::from_file` / native handles, never a truncated
  Windows `fs::Metadata` index.

**Parent-owned disk hook:** `noland-state-core::disk::available` initially had a
Unix-only rejection; the parent has now supplied its Windows implementation.
CAS/pack continue to use that shared global reservation/accounting registry, not
fake admission or an independent uncoordinated budget.

`verify_private_directory_live` is a directory **privacy/identity** check for
concurrent cache child creation, not a stable-content/snapshot proof. Immutable
file data still uses full native identity, mtime and ctime plus content digests.
Existing strict private-file/directory APIs keep their old policy.

CAS uses native hard links for independently owned operation leases and queries
actual link counts on Windows as well as Unix. Filesystems lacking the required
hard-link or disposition semantics return the actual OS error; no whole-chunk
copy fallback or fake pin is installed. Lease cleanup is bounded and scoped to
its verified private root and `.segments` directory, not a recursive path sweep.
Existing store/output roots must already be private (`0700` on Unix or the
protected user-only DACL on Windows). Missing roots are created privately.
Callers must not pre-create a public `0755` staging directory and expect silent
permission repair.

The FastCDC/BLAKE3 reuse paths, 32 MiB append-only capture containers, bounded
four-file read-ahead cache, streaming zstd level 1 pack construction, authenticated
selective streaming extraction and existing readback/global memory budgets are
retained. No serial whole-file copy fallback is introduced.

No Cargo builds/tests or live account/state/key probes are authorized for this
agent. Formatting/static review is not Windows/Linux/native acceptance. Windows
durability requires the actual NTFS/ReFS volume flush; OS/privilege failure is an
error, not success.

## Validation / handoff

No Cargo builds or tests were run by this agent. The parent owns serialized
validation; new Windows-gated fixtures distinguish ordinary native metadata
reads from elevated NTFS/ReFS durability acceptance. Ignored Windows acceptance
tests require real volume-flush permission. Native packaging and the full source
feature/UI remain separate, incomplete acceptance gates.

Owned implementation files: `src/{lib.rs,capture.rs,native.rs}`, CAS manifest and
tests, pack manifest/README/`src/lib.rs`/Windows tests; necessary source helpers
only in snapshot `source.rs`, `windows.rs`, and `native_metadata.rs`.
Neither storage, restore, snapshot `lib.rs`/`metadata.rs` nor the parent provenance
ledger is edited. The parent ledger should record the derived-code updates at the
commit above plus the original GPL-only native adapter/test additions.
