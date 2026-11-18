// SPDX-License-Identifier: GPL-3.0-only
// Native adaptations of No Land e81238a7536aae201540956ce76981364fd36595.
#![cfg(windows)]

use noland_cas::{blake3_hex, native, ChunkFileReader, LocalCas};
use noland_snapshot::{SourceMetadata, SourcePath};
use std::{fs, path::PathBuf};

fn isolated(label: &str) -> PathBuf {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let preferred = base.join("opencode");
    let base = if preferred.is_dir() { preferred } else { base };
    let root = base.join(format!("noland-cas-{label}-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    root
}

#[test]
fn real_handle_metadata_not_legacy_windows_file_index_drives_chunking() {
    let root = isolated("native-identity");
    let path = root.join("file");
    fs::write(&path, b"real native capture").unwrap();
    let mut file = SourcePath::new(&path).unwrap().open_regular().unwrap();
    let before = native::observe_file(&file).unwrap();
    assert!(before.native_identity().is_some());
    assert!(SourceMetadata::from(&file.metadata().unwrap())
        .native_identity()
        .is_none());
    let summary = ChunkFileReader::default()
        .chunk_open_file(&mut file, |_, _| Ok(()))
        .unwrap();
    assert_eq!(summary.file_hash, blake3_hex(b"real native capture"));
    native::verify_file(&file, &before).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    drop(file);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "native NTFS/ReFS acceptance: actual volume flush permission required"]
fn actual_hard_link_leases_keep_objects_pinned_until_the_last_owner_releases() {
    let root = isolated("lease-gc");
    let cas = LocalCas::new(root.join("cas")).unwrap();
    let first = cas.lease().unwrap();
    let second = cas.lease().unwrap();
    let hash = blake3_hex(b"shared immutable object");
    let a = first
        .put_prehashed(&hash, b"shared immutable object")
        .unwrap();
    let b = second
        .put_prehashed(&hash, b"shared immutable object")
        .unwrap();
    assert_eq!(
        SourcePath::new(&a.path).unwrap().native_identity().unwrap(),
        SourcePath::new(&b.path).unwrap().native_identity().unwrap()
    );
    first.sync_all().unwrap();
    second.sync_all().unwrap();
    assert!(!cas.evict_to(0).unwrap().target_met);
    drop(first);
    assert!(!cas.evict_to(0).unwrap().target_met);
    assert_eq!(cas.read(&hash).unwrap(), b"shared immutable object");
    drop(second);
    assert!(cas.evict_to(0).unwrap().target_met);
    drop(cas);
    fs::remove_dir_all(root).unwrap();
}
