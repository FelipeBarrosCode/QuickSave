# Portable native pack I/O

The pack algorithms derive from No Land
`e81238a7536aae201540956ce76981364fd36595`; original notices/manifests are
preserved. New native adapter code is GPL-3.0-only pending the root/manifest
license review.

The v1/v2 record formats, zstd level 1 compression/context reuse, BLAKE3 checksum,
XChaCha authenticated records, bounded four-container input cache, selective
streaming decoder, one-record backpressure and existing global resource budgets
are not replaced. There is no extra whole-pack readback/hash or decrypted
temporary pack.

Output now uses `noland_cas::native::{PrivateRoot, StagedFile}`: a private pinned
directory, exclusive operation-owned temporary file, verified writer handle and
atomic no-replace native publication after flush/close. Failed publication never
deletes an unrelated final name. Directory durability uses the actual snapshot
native barrier, not `File::open(directory).sync_all()` on Windows.

File-backed extraction opens one no-follow native file and validates complete
native identity/length/write/change metadata before releasing plaintext. Windows
IDs come from real 128-bit handle queries, not legacy `fs::Metadata` indices.

Cargo adds the existing workspace `noland-snapshot` dependency. Admission uses
the parent-owned portable `noland-state-core::disk::available` and its existing
shared reservation registry.
OS/filesystem/flush privilege failures remain errors. No Windows/native acceptance
is claimed from formatting, Mac checks, or target compilation. The assigned agent
does not run Cargo, remote accounts, live app state, credentials, or vault probes.
