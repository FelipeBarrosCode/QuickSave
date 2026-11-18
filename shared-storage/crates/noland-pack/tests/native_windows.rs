// SPDX-License-Identifier: GPL-3.0-only
// Native adaptations of No Land e81238a7536aae201540956ce76981364fd36595.
#![cfg(windows)]

use noland_cas::{blake3_hex, LocalCas};
use noland_crypto::MasterKey;
use noland_pack::{pack_chunk_files, PackStreamDecoder};
use std::fs;

#[test]
#[ignore = "native NTFS/ReFS acceptance: actual volume flush permission required"]
fn native_capture_containers_feed_original_zstd_pack_and_selective_stream_decoder() {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let preferred = base.join("opencode");
    let base = if preferred.is_dir() { preferred } else { base };
    let root = base.join(format!("noland-pack-native-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let cas = LocalCas::new(root.join("cas")).unwrap();
    let lease = cas.lease().unwrap();
    let payload = b"native optimized capture".repeat(2048);
    let hash = blake3_hex(&payload);
    let captured = lease.capture_streaming_prehashed(&hash, &payload).unwrap();
    lease.sync_all().unwrap();
    let key = MasterKey::generate(); // Synthetic in-memory fixture, never a vault.
    let pack = pack_chunk_files(&root.join("packs"), &key, [(hash, captured.source)], |_| {
        false
    })
    .unwrap()
    .remove(0);
    let mut decoder = PackStreamDecoder::new(&pack.pack_id, pack.entries.clone()).unwrap();
    let mut decoded = Vec::new();
    for part in fs::read(&pack.path).unwrap().chunks(97) {
        decoder
            .push(part, &key, |_, plain| {
                decoded.extend_from_slice(plain);
                Ok(())
            })
            .unwrap();
    }
    decoder.finish().unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(pack.checksum, noland_cas::blake3_file(&pack.path).unwrap());
    drop(lease);
    drop(cas);
    fs::remove_dir_all(root).unwrap();
}
