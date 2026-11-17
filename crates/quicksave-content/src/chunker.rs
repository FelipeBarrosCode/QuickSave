// SPDX-License-Identifier: GPL-3.0-only
// Gear/cut algorithm derived from upstream/no-land/state-agent/crates/noland-cas/
// src/lib.rs at e81238a7536aae201540956ce76981364fd36595.
// Original snapshot has root GPLv3 / engine-manifest MIT ambiguity; see PROVENANCE.md.

use std::io::{ErrorKind, Read};

use anyhow::{bail, ensure, Context, Result};

use crate::{hash, Chunk};

pub const FASTCDC_MIN: usize = 1024 * 1024;
pub const FASTCDC_AVG: usize = 4 * 1024 * 1024;
pub const FASTCDC_MAX: usize = 8 * 1024 * 1024;
pub const SMALL_FILE_THRESHOLD: usize = 256 * 1024;

/// Bounds the returned descriptor vector, not just the streaming payload buffer.
pub const MAX_CHUNKS_PER_FILE: usize = 65_536;
/// Absolute input ceiling; the descriptor ceiling can be reached before this.
pub const MAX_FILE_BYTES: u64 = MAX_CHUNKS_PER_FILE as u64 * FASTCDC_MAX as u64;

/// Stream upstream-compatible 1/4/8 MiB gear-hash chunks.
///
/// Returns `(whole_file_hash, whole_file_size, ordered_chunk_descriptors)`.
/// Empty input emits no chunks; nonempty input up to 256 KiB emits one chunk
/// whose hash is also the file hash. The chunker owns at most an 8 MiB payload
/// workspace and 65,536 descriptors. Oversized inputs fail explicitly.
///
/// The callback borrows the current payload only. It may already have accepted
/// chunks when a later read, callback or limit fails; callers must publish a
/// snapshot only after this function and their own source validation succeed.
/// No filesystem identity or application-atomic consistency is implied.
pub fn chunk_reader(
    reader: impl Read,
    emit: impl FnMut(&Chunk, &[u8]) -> Result<()>,
) -> Result<(String, u64, Vec<Chunk>)> {
    chunk_reader_buffered(
        reader,
        FASTCDC_MIN,
        FASTCDC_AVG,
        FASTCDC_MAX,
        MAX_CHUNKS_PER_FILE,
        &mut Vec::new(),
        emit,
    )
}

fn chunk_reader_buffered(
    mut reader: impl Read,
    min: usize,
    avg: usize,
    max: usize,
    max_chunks: usize,
    buffer: &mut Vec<u8>,
    mut emit: impl FnMut(&Chunk, &[u8]) -> Result<()>,
) -> Result<(String, u64, Vec<Chunk>)> {
    ensure!(
        min != 0 && min <= avg && avg <= max && max <= FASTCDC_MAX && max_chunks != 0,
        "invalid bounded FastCDC parameters"
    );
    let input_limit = (max_chunks as u64)
        .checked_mul(max as u64)
        .context("FastCDC input bound overflow")?;
    let mut file_hasher = blake3::Hasher::new();
    let mut read_size = 0u64;
    let mut buffered = 0usize;
    let mut eof = false;
    let mut chunks = Vec::new();
    let mut emitted_size = 0u64;

    // Read progressively to prove the small-file fast path without metadata or
    // reopening a file. One lookahead byte distinguishes exactly 256 KiB from a
    // growing stream. The FastCDC-sized allocation is lazy.
    let small_probe_limit = (SMALL_FILE_THRESHOLD + 1).min(max);
    resize_workspace(buffer, small_probe_limit.min(4096))?;
    loop {
        fill(
            &mut reader,
            buffer,
            &mut buffered,
            &mut eof,
            &mut file_hasher,
            &mut read_size,
            input_limit,
        )?;
        if eof || buffer.len() == small_probe_limit {
            break;
        }
        resize_workspace(buffer, (buffer.len() * 2).min(small_probe_limit))?;
    }

    if eof && buffered <= SMALL_FILE_THRESHOLD.min(min) {
        let file_hash = digest(&file_hasher);
        if buffered != 0 {
            let chunk = Chunk {
                hash: file_hash.clone(),
                size: buffered as u64,
            };
            reserve_descriptor(&mut chunks, max_chunks)?;
            emit(&chunk, &buffer[..buffered])?;
            chunks.push(chunk);
        }
        return Ok((file_hash, buffered as u64, chunks));
    }

    resize_workspace(buffer, max)?;
    let mask = mask_for(avg);
    loop {
        fill(
            &mut reader,
            buffer,
            &mut buffered,
            &mut eof,
            &mut file_hasher,
            &mut read_size,
            input_limit,
        )?;
        if buffered == 0 {
            break;
        }
        reserve_descriptor(&mut chunks, max_chunks)?;

        let cut = streaming_cut(&buffer[..buffered], min, max, mask, eof);
        let payload = &buffer[..cut];
        let chunk = Chunk {
            hash: if eof && chunks.is_empty() && cut == buffered {
                digest(&file_hasher)
            } else {
                hash(payload)
            },
            size: cut as u64,
        };
        emit(&chunk, payload)?;
        emitted_size = emitted_size
            .checked_add(cut as u64)
            .context("chunked file size overflow")?;
        chunks.push(chunk);
        buffer.copy_within(cut..buffered, 0);
        buffered -= cut;
    }
    ensure!(read_size == emitted_size, "chunked file length mismatch");
    Ok((digest(&file_hasher), emitted_size, chunks))
}

fn resize_workspace(buffer: &mut Vec<u8>, length: usize) -> Result<()> {
    ensure!(length <= FASTCDC_MAX, "chunk workspace exceeds bound");
    if length > buffer.len() {
        buffer
            .try_reserve_exact(length - buffer.len())
            .context("allocate bounded chunk workspace")?;
    }
    buffer.resize(length, 0);
    Ok(())
}

fn reserve_descriptor(chunks: &mut Vec<Chunk>, limit: usize) -> Result<()> {
    ensure!(chunks.len() < limit, "file exceeds chunk descriptor limit");
    if chunks.len() == chunks.capacity() {
        let capacity = chunks.capacity().saturating_mul(2).max(16).min(limit);
        chunks
            .try_reserve_exact(capacity - chunks.len())
            .context("allocate bounded chunk descriptors")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fill(
    reader: &mut impl Read,
    buffer: &mut [u8],
    buffered: &mut usize,
    eof: &mut bool,
    hasher: &mut blake3::Hasher,
    size: &mut u64,
    input_limit: u64,
) -> Result<()> {
    while *buffered < buffer.len() && !*eof {
        let available = buffer.len() - *buffered;
        let count = match reader.read(&mut buffer[*buffered..]) {
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("read chunk input"),
        };
        ensure!(count <= available, "reader returned an invalid byte count");
        if count == 0 {
            *eof = true;
        } else {
            let new_size = size
                .checked_add(count as u64)
                .context("chunk input length overflow")?;
            if new_size > input_limit {
                bail!("file exceeds bounded chunk input limit");
            }
            hasher.update(&buffer[*buffered..*buffered + count]);
            *buffered += count;
            *size = new_size;
        }
    }
    Ok(())
}

fn digest(hasher: &blake3::Hasher) -> String {
    format!("blake3:{}", hasher.finalize().to_hex())
}

// Keep this deliberately equivalent to the pinned upstream streaming_cut.
fn streaming_cut(data: &[u8], min: usize, max: usize, mask: u64, eof: bool) -> usize {
    if eof && data.len() <= min {
        return data.len();
    }
    let window_end = data.len().min(max);
    let mut gear_hash = 0u64;
    let mut index = min.min(window_end);
    while index < window_end {
        gear_hash = (gear_hash << 1).wrapping_add(GEAR[data[index] as usize]);
        if (gear_hash & mask) == 0 {
            return index + 1;
        }
        index += 1;
    }
    window_end
}

fn mask_for(avg: usize) -> u64 {
    let bits = (avg.max(2) as f64).log2().floor() as u32;
    (1u64 << bits.min(31)) - 1
}

const GEAR: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        // Deterministic splitmix-style constants; not a secret.
        let mut z = (i as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct GeneratedReader {
        remaining: usize,
        offset: usize,
        requested: Rc<Cell<usize>>,
    }

    impl Read for GeneratedReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.requested.set(self.requested.get().max(output.len()));
            let length = self.remaining.min(output.len()).min(997);
            for (index, byte) in output[..length].iter_mut().enumerate() {
                *byte = ((self.offset + index) % 251) as u8;
            }
            self.offset += length;
            self.remaining -= length;
            Ok(length)
        }
    }

    #[test]
    fn generated_stream_bounds_payload_workspace_and_descriptor_vector() {
        const TOTAL: usize = 32 * 1024 * 1024 + 17;
        let requested = Rc::new(Cell::new(0));
        let mut workspace = Vec::new();
        let mut emitted = 0usize;
        let result = chunk_reader_buffered(
            GeneratedReader {
                remaining: TOTAL,
                offset: 0,
                requested: requested.clone(),
            },
            FASTCDC_MIN,
            FASTCDC_AVG,
            FASTCDC_MAX,
            MAX_CHUNKS_PER_FILE,
            &mut workspace,
            |chunk, bytes| {
                assert!(bytes.len() <= FASTCDC_MAX);
                assert_eq!(chunk.size, bytes.len() as u64);
                emitted += bytes.len();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.1, TOTAL as u64);
        assert_eq!(emitted, TOTAL);
        assert!(requested.get() <= FASTCDC_MAX);
        assert!(workspace.capacity() <= FASTCDC_MAX);
        assert!(result.2.capacity() <= MAX_CHUNKS_PER_FILE);
    }

    #[test]
    fn descriptor_and_input_limits_are_errors_not_successful_truncation() {
        let mut emitted = 0;
        let result = chunk_reader_buffered(
            std::io::repeat(7).take(4096),
            64,
            256,
            512,
            3,
            &mut Vec::new(),
            |_, _| {
                emitted += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(emitted <= 3);
        let mut descriptors = Vec::new();
        reserve_descriptor(&mut descriptors, 1).unwrap();
        descriptors.push(Chunk {
            hash: hash(b"x"),
            size: 1,
        });
        assert!(reserve_descriptor(&mut descriptors, 1).is_err());
        assert!(descriptors.capacity() <= 1);
    }

    #[test]
    fn small_reader_does_not_allocate_large_workspace() {
        for length in [0, 1, 4096, 65_536, SMALL_FILE_THRESHOLD] {
            let mut workspace = Vec::new();
            let result = chunk_reader_buffered(
                std::io::repeat(3).take(length as u64),
                FASTCDC_MIN,
                FASTCDC_AVG,
                FASTCDC_MAX,
                MAX_CHUNKS_PER_FILE,
                &mut workspace,
                |_, _| Ok(()),
            )
            .unwrap();
            assert_eq!(result.1, length as u64);
            assert_eq!(result.2.len(), usize::from(length != 0));
            assert!(workspace.capacity() <= SMALL_FILE_THRESHOLD + 1);
        }
    }

    #[test]
    fn interrupted_reads_retry_and_other_errors_propagate() {
        struct InterruptedOnce {
            interrupted: bool,
            bytes: &'static [u8],
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(ErrorKind::Interrupted.into());
                }
                self.bytes.read(output)
            }
        }
        let result = chunk_reader(
            InterruptedOnce {
                interrupted: false,
                bytes: b"short reads",
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(result.0, hash(b"short reads"));

        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture read failure"))
            }
        }
        assert!(chunk_reader(FailedReader, |_, _| panic!("failed read emitted")).is_err());
        assert!(chunk_reader(&b"x"[..], |_, _| bail!("fixture sink failure")).is_err());
    }
}
