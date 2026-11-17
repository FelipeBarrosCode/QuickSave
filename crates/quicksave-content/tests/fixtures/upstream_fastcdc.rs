// SPDX-License-Identifier: GPL-3.0-only
// Test-only extracted algorithm from the unmodified No Land snapshot at commit
// e81238a7536aae201540956ce76981364fd36595:
// upstream/no-land/state-agent/crates/noland-cas/src/lib.rs, lines 501-539,
// 1042-1054. Root GPLv3 / engine-manifest MIT ambiguity: see ../../PROVENANCE.md.
// The following functions/table are unchanged, including the original comments.

/// FastCDC using a gear hash. Parameters are stored in the bundle manifest.
pub fn fastcdc_offsets(data: &[u8], min: usize, avg: usize, max: usize) -> Vec<usize> {
    let mut offsets = Vec::new();
    if data.is_empty() {
        return offsets;
    }
    let mask = mask_for(avg);
    let mut pos = 0usize;
    while pos < data.len() {
        let remaining = data.len() - pos;
        if remaining <= min {
            offsets.push(data.len());
            break;
        }
        let window_end = remaining.min(max);
        let mut hash: u64 = 0;
        let mut i = min.min(window_end);
        let mut cut = window_end;
        while i < window_end {
            hash = (hash << 1).wrapping_add(GEAR[data[pos + i] as usize]);
            if i >= min && (hash & mask) == 0 {
                cut = i + 1;
                break;
            }
            i += 1;
        }
        pos += cut;
        offsets.push(pos);
    }
    if *offsets.last().unwrap_or(&0) != data.len() {
        offsets.push(data.len());
    }
    offsets
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
