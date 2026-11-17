// SPDX-License-Identifier: GPL-3.0-only
// RustCrypto AEAD/HKDF usage informed by pinned noland-crypto/src/lib.rs;
// new, incompatible QuickSave framing/domain separation/bounds. See PROVENANCE.md.

use anyhow::{anyhow, ensure, Context, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::RepositoryKey;

const MAGIC: &[u8; 8] = b"QSAVAEAD";
const VERSION: u8 = 2;
const COMPRESSION_NONE: u8 = 0;
const HKDF_SALT: &[u8] = b"QuickSave/envelope/v2/HKDF-SHA256";
const HKDF_INFO: &[u8] = b"QuickSave/envelope/v2/XChaCha20-Poly1305\0";
const CONTEXT_DOMAIN: &[u8] = b"QuickSave/envelope/v2/context\0";
const AAD_DOMAIN: &[u8] = b"QuickSave/envelope/v2/record\0";

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const ENVELOPE_ID_LEN: usize = 32;
const ENVELOPE_ID_OFFSET: usize = 24;
pub const ENVELOPE_HEADER_LEN: usize = ENVELOPE_ID_OFFSET + ENVELOPE_ID_LEN;
pub const RECORD_HEADER_LEN: usize = 36;
/// Total plaintext bound, including metadata; this is not a single AEAD record.
pub const MAX_PLAINTEXT: usize = 512 * 1024 * 1024;
/// Each independently authenticated record contains at most 16 MiB plaintext.
pub const MAX_RECORD_PLAINTEXT: usize = 16 * 1024 * 1024;
pub const MAX_CONTEXT_LEN: usize = 4096;
const MAX_RECORDS: usize = MAX_PLAINTEXT / MAX_RECORD_PLAINTEXT;
/// Includes all framing and tags; v2 stores uncompressed records only.
pub const MAX_CIPHERTEXT: usize =
    MAX_PLAINTEXT + ENVELOPE_HEADER_LEN + MAX_RECORDS * (RECORD_HEADER_LEN + TAG_LEN);
const AAD_LEN: usize = AAD_DOMAIN.len() + 32 + ENVELOPE_HEADER_LEN + 4 + RECORD_HEADER_LEN;

/// Encrypt a QuickSave v2 envelope using HKDF-SHA256 and XChaCha20-Poly1305.
///
/// Both operations require a context of at most 4096 bytes, conventionally
/// including repository identity, object kind and content hash/manifest ID.
/// Plaintext is at most 512 MiB in total; it is split into canonical records of
/// at most 16 MiB, each with a fresh 24-byte OS-random nonce. Empty input still
/// has one authenticated record. A fresh 32-byte OS-random envelope identifier
/// binds every record to one generation, both in its HKDF subkey and its AAD.
/// Records from distinct generations cannot be mixed under the same context.
///
/// Compression is intentionally unsupported to avoid C/system dependencies.
/// Its reserved flag must be zero. Headers, record order and context are
/// authenticated. Callers must apply their smaller metadata limits before
/// serializing/reading documents; this global cap does not raise them.
pub fn seal(key: &RepositoryKey, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with_rng(key, context, plaintext, &mut rand::rngs::OsRng)
}

// Production always supplies OsRng. The private injection point also permits a
// deterministic regression test without exposing caller-controlled IDs/nonces.
fn seal_with_rng(
    key: &RepositoryKey,
    context: &[u8],
    plaintext: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    validate_plaintext_length(plaintext.len())?;
    validate_context(context)?;
    let record_count = record_count(plaintext.len());
    let mut id = [0; ENVELOPE_ID_LEN];
    rng.try_fill_bytes(&mut id)
        .map_err(|_| anyhow!("system entropy unavailable for envelope identifier"))?;
    let header = make_header(plaintext.len(), record_count, &id);
    let cipher = cipher(key, context, &id)?;
    let context_digest = context_digest(context);
    let mut output = Zeroizing::new(Vec::new());
    append(&mut output, &header, MAX_CIPHERTEXT)?;
    for index in 0..record_count {
        let start = index * MAX_RECORD_PLAINTEXT;
        let end = (start + MAX_RECORD_PLAINTEXT).min(plaintext.len());
        let plain = &plaintext[start..end];
        let mut record_header = [0; RECORD_HEADER_LEN];
        record_header[0] = COMPRESSION_NONE;
        record_header[4..8].copy_from_slice(&(plain.len() as u32).to_le_bytes());
        record_header[8..12].copy_from_slice(&(plain.len() as u32).to_le_bytes());
        rng.try_fill_bytes(&mut record_header[12..])
            .map_err(|_| anyhow!("system entropy unavailable for envelope nonce"))?;
        let aad = record_aad(&context_digest, &header, index, &record_header);
        append(&mut output, &record_header, MAX_CIPHERTEXT)?;
        let body_start = output.len();
        append(&mut output, plain, MAX_CIPHERTEXT)?;
        // Reserve the tag before in-place encryption, so no allocation can fail
        // while extending a partially produced record.
        reserve_additional(&mut output, TAG_LEN, MAX_CIPHERTEXT)?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&record_header[12..]),
                &aad,
                &mut output[body_start..],
            )
            .map_err(|_| anyhow!("QuickSave record encryption failed"))?;
        output.extend_from_slice(&tag);
    }
    Ok(std::mem::take(&mut *output))
}

/// Authenticate and decrypt an entire QuickSave envelope before returning bytes.
///
/// Rejects legacy formats, unknown versions/flags, noncanonical lengths,
/// truncation, trailing bytes, oversized records and total plaintext above
/// 512 MiB before allocating from untrusted header lengths. Nonzero compression
/// flags fail explicitly; no decoder or external C library is invoked.
/// No partial plaintext is returned. Failed output is wiped; the caller owns
/// and must protect the successful returned `Vec`.
pub fn open(key: &RepositoryKey, context: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    validate_context(context)?;
    validate_ciphertext_length(ciphertext.len())?;
    let header: &[u8; ENVELOPE_HEADER_LEN] = ciphertext[..ENVELOPE_HEADER_LEN]
        .try_into()
        .expect("validated envelope header size");
    let (total, count) = parse_header(header)?;

    // Validate every record and the exact final offset before output allocation
    // or invoking AEAD. No allocation follows an
    // attacker-controlled declared size until it has passed these fixed caps.
    let mut offset = ENVELOPE_HEADER_LEN;
    for index in 0..count {
        let _ = parse_record(ciphertext, &mut offset, total, index)?;
    }
    ensure!(
        offset == ciphertext.len(),
        "trailing QuickSave envelope bytes"
    );

    let cipher = cipher(key, context, envelope_id(header))?;
    let context_digest = context_digest(context);
    let mut output = Zeroizing::new(Vec::new());
    offset = ENVELOPE_HEADER_LEN;
    for index in 0..count {
        let record = parse_record(ciphertext, &mut offset, total, index)?;
        let aad = record_aad(&context_digest, header, index, record.header);
        let start = output.len();
        let end = start
            .checked_add(record.plaintext_len)
            .context("decrypted output length overflow")?;

        append(&mut output, record.message, MAX_PLAINTEXT)?;
        authenticate(&cipher, &aad, &record, &mut output[start..end])?;
    }
    ensure!(output.len() == total, "QuickSave plaintext length mismatch");
    Ok(std::mem::take(&mut *output))
}

fn validate_context(context: &[u8]) -> Result<()> {
    ensure!(
        context.len() <= MAX_CONTEXT_LEN,
        "envelope context exceeds bound"
    );
    Ok(())
}

fn validate_plaintext_length(length: usize) -> Result<()> {
    ensure!(
        length <= MAX_PLAINTEXT,
        "plaintext exceeds 512 MiB envelope bound"
    );
    Ok(())
}

fn validate_ciphertext_length(length: usize) -> Result<()> {
    ensure!(
        (ENVELOPE_HEADER_LEN + RECORD_HEADER_LEN + TAG_LEN..=MAX_CIPHERTEXT).contains(&length),
        "invalid or oversized QuickSave envelope length"
    );
    Ok(())
}

fn record_count(total: usize) -> usize {
    total.div_ceil(MAX_RECORD_PLAINTEXT).max(1)
}

fn make_header(
    total: usize,
    count: usize,
    id: &[u8; ENVELOPE_ID_LEN],
) -> [u8; ENVELOPE_HEADER_LEN] {
    let mut header = [0; ENVELOPE_HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[12..20].copy_from_slice(&(total as u64).to_le_bytes());
    header[20..24].copy_from_slice(&(count as u32).to_le_bytes());
    header[ENVELOPE_ID_OFFSET..].copy_from_slice(id);
    header
}

fn envelope_id(header: &[u8; ENVELOPE_HEADER_LEN]) -> &[u8; ENVELOPE_ID_LEN] {
    header[ENVELOPE_ID_OFFSET..]
        .try_into()
        .expect("fixed envelope identifier size")
}

fn parse_header(header: &[u8; ENVELOPE_HEADER_LEN]) -> Result<(usize, usize)> {
    ensure!(&header[..8] == MAGIC, "not a QuickSave envelope");
    ensure!(
        header[8] == VERSION,
        "unsupported QuickSave envelope version"
    );
    ensure!(
        header[9..12] == [0; 3],
        "unsupported QuickSave envelope flags"
    );
    let total = u64::from_le_bytes(header[12..20].try_into().expect("eight length bytes"));
    ensure!(
        total <= MAX_PLAINTEXT as u64,
        "plaintext exceeds envelope bound"
    );
    let count = u32::from_le_bytes(header[20..24].try_into().expect("four count bytes")) as usize;
    ensure!(
        count == record_count(total as usize),
        "invalid envelope record count"
    );
    Ok((total as usize, count))
}

struct Record<'a> {
    header: &'a [u8; RECORD_HEADER_LEN],
    message: &'a [u8],
    tag: &'a [u8],
    plaintext_len: usize,
}

fn parse_record<'a>(
    input: &'a [u8],
    offset: &mut usize,
    total: usize,
    index: usize,
) -> Result<Record<'a>> {
    let header: &[u8; RECORD_HEADER_LEN] = take(input, offset, RECORD_HEADER_LEN)?
        .try_into()
        .expect("fixed record header");
    ensure!(
        header[0] == COMPRESSION_NONE && header[1..4] == [0; 3],
        "unsupported QuickSave record flags"
    );
    let plaintext_len =
        u32::from_le_bytes(header[4..8].try_into().expect("four length bytes")) as usize;
    let stored_len =
        u32::from_le_bytes(header[8..12].try_into().expect("four stored length bytes")) as usize;
    let expected = total
        .checked_sub(index * MAX_RECORD_PLAINTEXT)
        .context("record outside envelope plaintext")?
        .min(MAX_RECORD_PLAINTEXT);
    ensure!(
        plaintext_len == expected,
        "invalid bounded record plaintext length"
    );
    ensure!(stored_len == plaintext_len, "invalid raw record length");
    Ok(Record {
        header,
        message: take(input, offset, stored_len)?,
        tag: take(input, offset, TAG_LEN)?,
        plaintext_len,
    })
}

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .context("record offset overflow")?;
    let bytes = input
        .get(*offset..end)
        .context("truncated QuickSave record")?;
    *offset = end;
    Ok(bytes)
}

fn cipher(
    key: &RepositoryKey,
    context: &[u8],
    id: &[u8; ENVELOPE_ID_LEN],
) -> Result<XChaCha20Poly1305> {
    let mut derived = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), key.as_bytes())
        .expand_multi_info(
            &[
                HKDF_INFO,
                &(context.len() as u64).to_le_bytes(),
                context,
                id,
            ],
            &mut *derived,
        )
        .map_err(|_| anyhow!("QuickSave HKDF derivation failed"))?;
    // The library's cipher also zeroizes its internal key on drop.
    Ok(XChaCha20Poly1305::new((&*derived).into()))
}

fn context_digest(context: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CONTEXT_DOMAIN);
    digest.update((context.len() as u64).to_le_bytes());
    digest.update(context);
    digest.finalize().into()
}

fn record_aad(
    context_digest: &[u8; 32],
    header: &[u8; ENVELOPE_HEADER_LEN],
    index: usize,
    record_header: &[u8; RECORD_HEADER_LEN],
) -> [u8; AAD_LEN] {
    let mut aad = [0; AAD_LEN];
    let mut offset = 0;
    for part in [
        AAD_DOMAIN,
        context_digest,
        header,
        &(index as u32).to_le_bytes(),
        record_header,
    ] {
        aad[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    aad
}

fn authenticate(
    cipher: &XChaCha20Poly1305,
    aad: &[u8],
    record: &Record<'_>,
    message: &mut [u8],
) -> Result<()> {
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&record.header[12..]),
            aad,
            message,
            Tag::from_slice(record.tag),
        )
        .map_err(|_| anyhow!("QuickSave record authentication failed"))
}

fn reserve_additional(output: &mut Vec<u8>, additional: usize, limit: usize) -> Result<()> {
    let length = output
        .len()
        .checked_add(additional)
        .context("bounded content buffer length overflow")?;
    ensure!(length <= limit, "content buffer exceeds bound");
    output
        .try_reserve_exact(additional)
        .context("allocate bounded content buffer")?;
    Ok(())
}

fn append(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<()> {
    reserve_additional(output, bytes.len(), limit)?;
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn roundtrip_empty_small_and_larger_uncompressed_records() {
        let key = RepositoryKey::from_bytes([7; 32]);
        for plain in [
            Vec::new(),
            b"private saved state".to_vec(),
            vec![b'a'; 131_072],
        ] {
            let sealed = seal(&key, b"repository/object-kind/id", &plain).unwrap();
            assert_eq!(&sealed[..8], MAGIC);
            assert_eq!(sealed[8], VERSION);
            assert_eq!(
                open(&key, b"repository/object-kind/id", &sealed).unwrap(),
                plain
            );
            assert_eq!(sealed[ENVELOPE_HEADER_LEN], COMPRESSION_NONE);
            assert_eq!(
                sealed.len(),
                ENVELOPE_HEADER_LEN + RECORD_HEADER_LEN + plain.len() + TAG_LEN
            );
        }
    }

    #[test]
    fn wrong_key_wrong_context_and_every_single_byte_flip_fail_closed() {
        let key = RepositoryKey::from_bytes([9; 32]);
        let wrong_key = RepositoryKey::from_bytes([8; 32]);
        let sealed = seal(
            &key,
            b"repo/chunk/id",
            b"do not release unauthenticated plaintext",
        )
        .unwrap();
        assert!(open(&wrong_key, b"repo/chunk/id", &sealed).is_err());
        for context in [
            b"repo/chunk/id\0".as_slice(),
            b"repo/manifest/id",
            b"other/chunk/id",
        ] {
            assert!(open(&key, context, &sealed).is_err());
        }
        for index in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert!(
                open(&key, b"repo/chunk/id", &changed).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn truncation_trailing_data_and_legacy_envelopes_are_rejected() {
        let key = RepositoryKey::from_bytes([4; 32]);
        let sealed = seal(&key, b"right", b"secret").unwrap();
        for length in 0..sealed.len() {
            assert!(
                open(&key, b"right", &sealed[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = sealed.clone();
        trailing.push(0);
        assert!(open(&key, b"right", &trailing).is_err());
        let mut old_version = sealed.clone();
        old_version[8] = 1;
        assert!(open(&key, b"right", &old_version).is_err());
        let mut legacy = sealed;
        legacy[..4].copy_from_slice(b"NLNE");
        assert!(open(&key, b"right", &legacy).is_err());
    }

    #[test]
    fn oversized_headers_and_contexts_fail_without_large_allocations() {
        let key = RepositoryKey::from_bytes([1; 32]);
        let original = seal(&key, b"context", b"data").unwrap();
        for (range, value) in [
            (12..20, u64::MAX.to_le_bytes().to_vec()),
            (12..20, (MAX_PLAINTEXT as u64 + 1).to_le_bytes().to_vec()),
            (20..24, u32::MAX.to_le_bytes().to_vec()),
            (
                ENVELOPE_HEADER_LEN + 4..ENVELOPE_HEADER_LEN + 8,
                u32::MAX.to_le_bytes().to_vec(),
            ),
            (
                ENVELOPE_HEADER_LEN + 8..ENVELOPE_HEADER_LEN + 12,
                u32::MAX.to_le_bytes().to_vec(),
            ),
        ] {
            let mut changed = original.clone();
            changed[range].copy_from_slice(&value);
            assert!(open(&key, b"context", &changed).is_err());
        }
        let oversized_context = vec![0; MAX_CONTEXT_LEN + 1];
        assert!(seal(&key, &oversized_context, b"").is_err());
        assert!(open(&key, &oversized_context, &original).is_err());
        assert!(validate_plaintext_length(MAX_PLAINTEXT).is_ok());
        assert!(validate_plaintext_length(MAX_PLAINTEXT + 1).is_err());
        assert!(validate_ciphertext_length(MAX_CIPHERTEXT).is_ok());
        assert!(validate_ciphertext_length(MAX_CIPHERTEXT + 1).is_err());
        assert_eq!(record_count(MAX_PLAINTEXT), MAX_RECORDS);
    }

    #[test]
    fn nonces_are_random_and_not_derived_from_content_hash() {
        let key = RepositoryKey::from_bytes([5; 32]);
        let first = seal(&key, b"same", b"identical plaintext").unwrap();
        let second = seal(&key, b"same", b"identical plaintext").unwrap();
        let nonce = ENVELOPE_HEADER_LEN + 12..ENVELOPE_HEADER_LEN + RECORD_HEADER_LEN;
        assert_ne!(first[nonce.clone()], second[nonce]);
        assert_ne!(
            first[ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN],
            second[ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN]
        );
        assert_ne!(first, second);
        assert_eq!(
            open(&key, b"same", &first).unwrap(),
            open(&key, b"same", &second).unwrap()
        );
    }

    #[test]
    fn deterministic_cross_generation_record_splices_fail_authentication() {
        let key = RepositoryKey::from_bytes([0x44; 32]);
        let context = b"same repository/manifest context";
        let mut plain_a = vec![0x11; MAX_RECORD_PLAINTEXT + 257];
        plain_a[MAX_RECORD_PLAINTEXT..].fill(0xa1);
        let mut plain_b = vec![0x22; plain_a.len()];
        plain_b[MAX_RECORD_PLAINTEXT..].fill(0xb2);
        let sealed_a =
            seal_with_rng(&key, context, &plain_a, &mut StdRng::from_seed([0xa1; 32])).unwrap();
        let sealed_b =
            seal_with_rng(&key, context, &plain_b, &mut StdRng::from_seed([0xb2; 32])).unwrap();
        assert!(open(&key, context, &sealed_a).unwrap() == plain_a);
        assert!(open(&key, context, &sealed_b).unwrap() == plain_b);
        drop(plain_a);
        drop(plain_b);
        assert_eq!(sealed_a.len(), sealed_b.len());
        assert_eq!(
            sealed_a[..ENVELOPE_ID_OFFSET],
            sealed_b[..ENVELOPE_ID_OFFSET]
        );
        assert_ne!(
            sealed_a[ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN],
            sealed_b[ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN]
        );

        let first_end = ENVELOPE_HEADER_LEN + RECORD_HEADER_LEN + MAX_RECORD_PLAINTEXT + TAG_LEN;
        for header_source in [&sealed_a, &sealed_b] {
            let mut hybrid = Vec::with_capacity(sealed_a.len());
            hybrid.extend_from_slice(&header_source[..ENVELOPE_HEADER_LEN]);
            hybrid.extend_from_slice(&sealed_a[ENVELOPE_HEADER_LEN..first_end]);
            hybrid.extend_from_slice(&sealed_b[first_end..]);
            let header: &[u8; ENVELOPE_HEADER_LEN] =
                hybrid[..ENVELOPE_HEADER_LEN].try_into().unwrap();
            let (total, count) = parse_header(header).unwrap();
            assert_eq!(count, 2);
            let mut offset = ENVELOPE_HEADER_LEN;
            for index in 0..count {
                // Same length, record count, indices and canonical framing:
                // rejection must be cryptographic, not a structural shortcut.
                assert!(parse_record(&hybrid, &mut offset, total, index).is_ok());
            }
            assert_eq!(offset, hybrid.len());
            let Err(error) = open(&key, context, &hybrid) else {
                panic!("cross-generation record splice must never release hybrid plaintext");
            };
            assert!(error.to_string().contains("record authentication failed"));
        }
    }

    #[test]
    fn envelope_identifier_bits_are_authenticated_and_truncations_rejected() {
        let key = RepositoryKey::from_bytes([0x55; 32]);
        let sealed = seal_with_rng(
            &key,
            b"identifier context",
            b"secret",
            &mut StdRng::from_seed([0xc3; 32]),
        )
        .unwrap();
        for byte in ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN {
            for bit in 0..8 {
                let mut changed = sealed.clone();
                changed[byte] ^= 1 << bit;
                let Err(error) = open(&key, b"identifier context", &changed) else {
                    panic!("identifier bit change must fail authentication");
                };
                assert!(error.to_string().contains("record authentication failed"));
            }
        }
        for length in ENVELOPE_ID_OFFSET..ENVELOPE_HEADER_LEN {
            assert!(open(&key, b"identifier context", &sealed[..length]).is_err());
        }
        assert!(open(&key, b"different context", &sealed).is_err());
    }

    #[test]
    fn multi_record_envelopes_bind_order_count_and_total_length() {
        let key = RepositoryKey::from_bytes([6; 32]);
        let mut plaintext = vec![b'a'; 2 * MAX_RECORD_PLAINTEXT + 137];
        plaintext[MAX_RECORD_PLAINTEXT..2 * MAX_RECORD_PLAINTEXT].fill(b'b');
        plaintext[2 * MAX_RECORD_PLAINTEXT..].fill(b'c');
        let sealed = seal(&key, b"large manifest", &plaintext).unwrap();
        assert_eq!(open(&key, b"large manifest", &sealed).unwrap(), plaintext);
        let header: &[u8; ENVELOPE_HEADER_LEN] = sealed[..ENVELOPE_HEADER_LEN].try_into().unwrap();
        assert_eq!(parse_header(header).unwrap(), (plaintext.len(), 3));
        let mut offset = ENVELOPE_HEADER_LEN;
        let first_start = offset;
        let _ = parse_record(&sealed, &mut offset, plaintext.len(), 0).unwrap();
        let second_start = offset;
        let _ = parse_record(&sealed, &mut offset, plaintext.len(), 1).unwrap();
        let third_start = offset;
        let _ = parse_record(&sealed, &mut offset, plaintext.len(), 2).unwrap();
        let mut reordered = header.to_vec();
        reordered.extend_from_slice(&sealed[second_start..third_start]);
        reordered.extend_from_slice(&sealed[first_start..second_start]);
        reordered.extend_from_slice(&sealed[third_start..]);
        // Both swapped records are full-sized: framing still validates, so the
        // failure proves that the AEAD binds the implicit record index.
        let mut reordered_offset = ENVELOPE_HEADER_LEN;
        for index in 0..3 {
            assert!(
                parse_record(&reordered, &mut reordered_offset, plaintext.len(), index).is_ok()
            );
        }
        assert!(open(&key, b"large manifest", &reordered).is_err());
        let mut reduced = sealed.clone();
        reduced[12..20].copy_from_slice(&(MAX_RECORD_PLAINTEXT as u64).to_le_bytes());
        reduced[20..24].copy_from_slice(&1u32.to_le_bytes());
        reduced.truncate(second_start);
        assert!(open(&key, b"large manifest", &reduced).is_err());
    }

    // Even correctly authenticated compressed payloads must fail explicitly,
    // rather than claiming to support a decoder that is not implemented.
    fn authenticated_flagged_record(
        key: &RepositoryKey,
        flag: u8,
        declared_length: usize,
        stored: &[u8],
    ) -> Vec<u8> {
        let id = [0x33; ENVELOPE_ID_LEN];
        let header = make_header(declared_length, 1, &id);
        let mut record_header = [0u8; RECORD_HEADER_LEN];
        record_header[0] = flag;
        record_header[4..8].copy_from_slice(&(declared_length as u32).to_le_bytes());
        record_header[8..12].copy_from_slice(&(stored.len() as u32).to_le_bytes());
        record_header[12..].fill(0x55);
        let aad = record_aad(&context_digest(b"test"), &header, 0, &record_header);
        let mut message = stored.to_vec();
        let tag = cipher(key, b"test", &id)
            .unwrap()
            .encrypt_in_place_detached(XNonce::from_slice(&record_header[12..]), &aad, &mut message)
            .unwrap();
        [header.as_slice(), &record_header, &message, &tag].concat()
    }

    #[test]
    fn compression_and_other_nonzero_flags_are_explicitly_unsupported() {
        let key = RepositoryKey::from_bytes([11; 32]);
        for flag in [1, 2, 255] {
            let flagged = authenticated_flagged_record(
                &key,
                flag,
                4096,
                b"authenticated but unsupported compressed content",
            );
            let error = open(&key, b"test", &flagged).unwrap_err();
            assert!(error
                .to_string()
                .contains("unsupported QuickSave record flags"));
        }
    }
}
