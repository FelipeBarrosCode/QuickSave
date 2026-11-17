# Content-layer provenance and security boundary

New QuickSave code is licensed **GPL-3.0-only**, pending owner/license review.
The immutable upstream snapshot is No Land commit
`e81238a7536aae201540956ce76981364fd36595`. Its source-root GPLv3 notice and
`state-agent/Cargo.toml` MIT package declaration conflict; neither this crate nor
its derived excerpts claim that the entire snapshot is MIT. Original upstream
files and notices remain unmodified.

## Derived algorithms

- `src/chunker.rs`: the gear table, `mask_for`, and streaming cut rule derive
  from `upstream/no-land/state-agent/crates/noland-cas/src/lib.rs`
  (`streaming_cut`, `fastcdc_offsets`, `GEAR`). Constants 1/4/8 MiB come from
  `noland-state-core/src/lib.rs`; the 256 KiB small-file rule comes from
  `noland-cas`. New code adds a native-independent `Read` interface, lazy
  small-file probing, interrupted-read handling, fallible bounded allocations,
  and a descriptor/input limit. This is the pinned upstream gear algorithm,
  not a promise of compatibility with every implementation named FastCDC.
- `tests/fixtures/upstream_fastcdc.rs`: read-only algorithm excerpts of
  `fastcdc_offsets`, `mask_for`, and `GEAR`, copied into a test-only reference.
  Equivalence tests compare ordered boundaries, every emitted byte, content
  hashes, and whole-file hashes, including short reads and boundary lengths.
- `src/envelope.rs`: the selection and use of RustCrypto
  `chacha20poly1305`, `hkdf`, `sha2`, and OS randomness are informed by
  `noland-crypto/src/lib.rs`. The key wrapper, explicit `zeroize` protection,
  domains, framing, record binding, and limits are new. No bespoke AEAD, hash,
  KDF, cipher, or MAC is implemented.

No dependency on upstream filesystem, snapshot, storage, CAS, pack, cloud, or
application-state crates is introduced. Compression was reviewed against
`noland-pack` but is intentionally not implemented: no zstd C dependency is
introduced. BLAKE3's `pure` feature disables its external C/assembly build path.
This content layer does not require a system C compiler/library.

## Key ownership

`RepositoryKey` has private bytes and no `Debug`, serde, `Clone`, or `Copy`
implementation. `zeroize` wipes the owned key on drop; derived-key bytes and
temporary plaintext buffers are also wiped. The cipher library wipes its
internal key. This is not a guarantee that CPU registers, allocator copies,
swap, crash dumps, caller-created recovery-key copies, or every internal
HKDF/SHA state can be erased. `generate()` uses `OsRng`; because the required
API returns `Self`, entropy failure panics rather than silently succeeding.
Envelope-identifier or nonce entropy failure returns an error.

## QuickSave envelope v2 (not a No Land format)

All integer fields are unsigned little-endian. Unknown flags and reserved bytes
are rejected, as are legacy `NLNE` / pack formats and prerelease QuickSave v1.
Version 2 fixes cross-generation record splicing: v1's common header/subkey for
the same context and plaintext length did not distinguish separate encryptions.

```
Envelope header (56 bytes):
  magic[8] = "QSAVAEAD", version:u8 = 2, flags:u8 = 0, reserved[2] = 0
  total_plaintext_len:u64, record_count:u32
  random_envelope_identifier[32]

For each record:
  compression:u8 = 0 (raw only), reserved[3] = 0
  plaintext_len:u32, stored_len:u32, random_nonce[24]
  ciphertext[stored_len], Poly1305_tag[16]
```

- Maximum total plaintext is **512 MiB**; maximum record plaintext is
  **16 MiB**, with at most 32 records. Records have exactly 16 MiB plaintext
  except the last. Empty plaintext has one authenticated zero-length record.
  Ciphertext is at most `MAX_CIPHERTEXT` (512 MiB + 1,720 bytes); no record
  exceeds 16 MiB + 52 framing/tag bytes.
- Context is at most **4,096 bytes**. HKDF-SHA256 uses the fixed salt
  `QuickSave/envelope/v2/HKDF-SHA256`, repository key as input key material,
  and info `QuickSave/envelope/v2/XChaCha20-Poly1305\0 || context_len:u64 ||
  context || random_envelope_identifier[32]`. The per-envelope 32-byte derived
  key is used with XChaCha20-Poly1305.
- Associated data is `QuickSave/envelope/v2/record\0 || context_digest[32] ||
  envelope_header[56] || record_index:u32 || record_header[36]`.
  `context_digest` is SHA256 of `QuickSave/envelope/v2/context\0 ||
  context_len:u64 || context`. The entire header, including the fresh
  OS-random 256-bit identifier, is authenticated by **every** record. This
  binds repository/object context, envelope generation, total length, record
  count, index/order, compression flag, lengths, and nonce. Records from
  different envelopes cannot be spliced even with identical key, context,
  lengths and indices. Replaying a complete authentic envelope is not
  prevented by this content layer; higher layers enforce their own history.
- Compression is **unsupported**. All nonzero compression flags fail
  explicitly, including correctly authenticated records. No decompressor is
  invoked, so compressed-input amplification is not possible. Stored length
  must equal plaintext length. A future compression implementation requires a
  separately documented and tested format decision.
- Structural checks precede plaintext allocation. Output grows fallibly within
  the global cap; encryption/decryption occurs in-place in that output, without
  another document-sized clone or compression workspace. AEAD calls never
  process the global document as one record. No partial plaintext escapes on error.
- Callers retain their smaller document/metadata guards. They must bound file
  reads **before** constructing the slices this API accepts; an already
  allocated input cannot be retroactively protected by this crate.

The deterministic splice regression uses seeded test-only CSPRNG instances to
encrypt two different plaintexts larger than 16 MiB under the same key/context
and total length, then combines record 0 from one with record 1 from the other
under either original header. Structural validation must pass and record
authentication must fail. Identifier bit flips, identifier truncations,
cross-context use, and v1 downgrade attempts are also covered. Production
`seal` always selects `OsRng`; caller-controlled randomness is not exposed.

`chunk_reader` retains one payload workspace of at most **8 MiB**, initially
probing small inputs without an 8 MiB allocation. Its descriptor vector is
bounded to **65,536 chunks**. Consequently input is also capped at **512 GiB**
and may reach the chunk-count ceiling sooner. A late read/callback/limit error
can leave operation-owned emitted objects, but must never publish a snapshot.
This crate makes no filesystem safety, durability, stable-capture, or
application-consistency claims.
