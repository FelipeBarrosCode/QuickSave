// SPDX-License-Identifier: GPL-3.0-only
// Upstream algorithm fixture provenance: fixtures/upstream_fastcdc.rs and
// ../PROVENANCE.md. Tests use in-memory readers only, never live app state.

use std::io::{ErrorKind, Read};

use anyhow::{bail, Result};
use quicksave_content::{
    chunk_reader, hash, open, seal, Chunk, RepositoryKey, FASTCDC_AVG, FASTCDC_MAX, FASTCDC_MIN,
    SMALL_FILE_THRESHOLD,
};

#[path = "fixtures/upstream_fastcdc.rs"]
mod upstream_fastcdc;

fn deterministic_bytes(length: usize) -> Vec<u8> {
    // A fixed xorshift64* fixture, not cryptographic randomness.
    let mut state = 0xD1B5_4A32_D192_ED03u64;
    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

struct ShortReads<'a> {
    bytes: &'a [u8],
    maximum: usize,
}

impl Read for ShortReads<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let length = self.bytes.len().min(output.len()).min(self.maximum);
        output[..length].copy_from_slice(&self.bytes[..length]);
        self.bytes = &self.bytes[length..];
        Ok(length)
    }
}

fn assert_upstream_equivalent(data: &[u8], reader: impl Read) {
    let offsets = upstream_fastcdc::fastcdc_offsets(data, FASTCDC_MIN, FASTCDC_AVG, FASTCDC_MAX);
    let mut expected_chunks = Vec::new();
    let mut start = 0usize;
    for &end in &offsets {
        expected_chunks.push(Chunk {
            hash: hash(&data[start..end]),
            size: (end - start) as u64,
        });
        start = end;
    }
    let mut count = 0;
    let mut consumed = 0;
    let actual = chunk_reader(reader, |chunk, payload| {
        let end = offsets[count];
        assert_eq!(payload, &data[consumed..end], "chunk {count}");
        assert_eq!(chunk, &expected_chunks[count], "chunk {count}");
        assert!(payload.len() <= FASTCDC_MAX);
        consumed = end;
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, offsets.len());
    assert_eq!(consumed, data.len());
    assert_eq!(actual, (hash(data), data.len() as u64, expected_chunks));
}

#[test]
fn streaming_bytes_boundaries_and_hashes_match_pinned_upstream_slice_algorithm() {
    let fixture = deterministic_bytes(19 * 1024 * 1024 + 137);
    for length in [
        0,
        1,
        4096,
        65_536,
        SMALL_FILE_THRESHOLD - 1,
        SMALL_FILE_THRESHOLD,
        SMALL_FILE_THRESHOLD + 1,
        FASTCDC_MIN,
        FASTCDC_MIN + 1,
        FASTCDC_MAX - 1,
        FASTCDC_MAX,
        FASTCDC_MAX + 1,
        10 * 1024 * 1024 + 17,
        fixture.len(),
    ] {
        let data = &fixture[..length];
        assert_upstream_equivalent(data, data);
    }
}

#[test]
fn short_read_boundaries_do_not_change_content_or_small_file_representation() {
    let fixture = deterministic_bytes(19 * 1024 * 1024 + 137);
    for (length, maximum) in [
        (0, 1),
        (1, 1),
        (4097, 1),
        (65_536, 17),
        (SMALL_FILE_THRESHOLD, 997),
        (SMALL_FILE_THRESHOLD + 1, 997),
        (FASTCDC_MIN + 1, 997),
        (FASTCDC_MAX + 17, 65_537),
        (fixture.len(), 997),
    ] {
        let data = &fixture[..length];
        assert_upstream_equivalent(
            data,
            ShortReads {
                bytes: data,
                maximum,
            },
        );
    }
}

#[test]
fn dedup_addresses_plaintext_not_random_envelopes() {
    let key = RepositoryKey::from_bytes([3; 32]);
    let input = vec![3; 2 * FASTCDC_MAX];
    let mut unique = std::collections::HashMap::new();
    let (file_hash, size, chunks) = chunk_reader(&input[..], |chunk, payload| {
        assert_eq!(chunk.hash, hash(payload));
        if !unique.contains_key(&chunk.hash) {
            let encrypted = seal(&key, chunk.hash.as_bytes(), payload)?;
            assert!(encrypted.len() > payload.len());
            assert_ne!(hash(&encrypted), chunk.hash);
            assert_eq!(open(&key, chunk.hash.as_bytes(), &encrypted)?, payload);
            unique.insert(chunk.hash.clone(), encrypted);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(size, input.len() as u64);
    assert_eq!(file_hash, hash(&input));
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0], chunks[1]);
    assert_eq!(unique.len(), 1);
}

#[test]
fn late_reader_and_callback_failures_do_not_return_successful_partial_manifests() {
    struct FailsAfter {
        remaining: usize,
    }
    impl Read for FailsAfter {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "fixture late reader failure",
                ));
            }
            let length = self.remaining.min(output.len());
            output[..length].fill(7);
            self.remaining -= length;
            Ok(length)
        }
    }
    let mut emitted = 0;
    let result = chunk_reader(
        FailsAfter {
            remaining: 2 * FASTCDC_MAX,
        },
        |_, _| {
            emitted += 1;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(
        emitted > 0,
        "fixture must exercise a failure after publication"
    );

    let input = vec![7; 2 * FASTCDC_MAX];
    let mut called = 0;
    let result = chunk_reader(&input[..], |_, _| -> Result<()> {
        called += 1;
        bail!("fixture callback failure");
    });
    assert!(result.is_err());
    assert_eq!(called, 1);
}
