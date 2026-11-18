// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::tests::{test_file, test_manifest, test_plan};
use noland_state_core::{ChunkRef, ManifestFile, PersistenceClass, SemanticRole};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

struct FixtureDeviceMac;

impl crate::NativeRecoveryAuthority for FixtureDeviceMac {
    fn mac(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        Ok(*blake3::keyed_hash(&[0x56; 32], bytes).as_bytes())
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let approved =
            Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
        let base = if approved.is_dir() {
            approved.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let root = base.join(format!("qs-restore-accounting-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        // Only this test-owned synthetic directory, after its workers/tx drop.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn file(name: &str, chunks: &[&[u8]]) -> ManifestFile {
    let mut file = test_file(
        name,
        PersistenceClass::PersistentState,
        SemanticRole::UserState,
        &chunks.concat(),
    );
    file.chunks = chunks
        .iter()
        .map(|bytes| ChunkRef {
            hash: noland_cas::blake3_hex(bytes),
            size: bytes.len() as u64,
        })
        .collect();
    file
}

fn assert_unfinished_accounting<F: FnMut(PipelineProgress) -> Result<()> + Send>(
    pipeline: &Pipeline<'_, '_, F>,
) {
    assert_eq!(
        pipeline.progress.io.unfinished_files,
        pipeline
            .pending
            .values()
            .filter(|file| file.assembly_started)
            .count() as u64
    );
    assert_eq!(
        pipeline.progress.io.unfinished_bytes,
        pipeline
            .pending
            .values()
            .map(|file| file.received)
            .sum::<u64>()
    );
    assert!(pipeline.pending.values().all(|file| file.remaining != 0));
    assert!(pipeline.handles.files.len() <= MAX_ASSEMBLY_HANDLES);
    assert!(pipeline.active_hashers.len() <= MAX_ACTIVE_HASHERS);
    assert!(pipeline.unpublished_files <= MAX_UNPUBLISHED_FILES);
    assert!(pipeline.unpublished_bytes <= MAX_UNPUBLISHED_BYTES);
}

#[test]
fn precreated_native_partials_enter_unfinished_accounting_only_on_first_placement() {
    for native in [false, true] {
        for count in [1, MAX_ACTIVE_HASHERS + 1] {
            let root = TestRoot::new();
            let home = root.0.join("home");
            fs::create_dir(&home).unwrap();
            let mut files = vec![file("game/empty", &[]), file("game/single", &[b"solo"])];
            files.extend(
                (0..count).map(|index| file(&format!("game/{index:04}"), &[b"aa", b"bbb"])),
            );
            let mut manifest = test_manifest(files);
            if native {
                let identity = fs::metadata(&home).unwrap();
                manifest.environment["quicksave_native_download"] = serde_json::json!({
                    "no_overwrite": true, "files_only": true, "destination": home,
                    "identity": [identity.dev(), identity.ino()]
                });
            }
            let mut plan = test_plan(&root.0, manifest);
            if native {
                // Authenticated native journals require the actual attempt ID
                // in this test-owned workspace name, not a legacy marker flag.
                let staging = root.0.join(plan.restore_id.to_string());
                fs::rename(&plan.staging, &staging).unwrap();
                plan.staging = staging;
            }
            let roots = LogicalRootMap::from_home(&home);
            let mut transaction = if native {
                let identity = fs::metadata(&home).unwrap();
                let preview = crate::NativeRestorePreview::prepare(
                    uuid::Uuid::new_v4(),
                    &plan.manifest,
                    &roots,
                    &home,
                    (identity.dev(), identity.ino()),
                    crate::NativeConflictMode::CreateOnly,
                )
                .unwrap();
                let control = crate::NativeRestoreControl::approve(
                    preview,
                    Arc::new(FixtureDeviceMac),
                    Arc::new(|| Ok(())),
                )
                .unwrap();
                RestoreTransaction::new_native(&plan, &roots, Arc::new(control)).unwrap()
            } else {
                RestoreTransaction::new(&plan, &roots, None)
            };
            let mut pipeline = Pipeline::new(&mut transaction, 2, |_| Ok(())).unwrap();
            assert_eq!(pipeline.pending.len(), count + 1);
            assert!(pipeline.pending.values().all(|file| {
                file.opened == native && !file.assembly_started && file.received == 0
            }));
            assert_eq!(pipeline.progress.io.peak_unfinished_files, 0);
            assert_unfinished_accounting(&pipeline);

            // Completing a one-chunk precreated file previously subtracted zero.
            pipeline
                .consume(&noland_cas::blake3_hex(b"solo"), b"solo")
                .unwrap();
            assert_eq!(pipeline.progress.io.unfinished_files, 0);
            assert_eq!(pipeline.progress.io.peak_unfinished_files, 1);
            assert_unfinished_accounting(&pipeline);

            pipeline
                .consume(&noland_cas::blake3_hex(b"aa"), b"aa")
                .unwrap();
            assert_eq!(pipeline.progress.io.unfinished_files, count as u64);
            assert_eq!(pipeline.progress.io.unfinished_bytes, count as u64 * 2);
            assert_unfinished_accounting(&pipeline);
            // Retry of the same authenticated hash must not admit it twice.
            pipeline
                .consume(&noland_cas::blake3_hex(b"aa"), b"aa")
                .unwrap();
            assert_eq!(pipeline.progress.io.unfinished_files, count as u64);
            assert_eq!(pipeline.progress.io.unfinished_bytes, count as u64 * 2);
            assert_unfinished_accounting(&pipeline);

            pipeline
                .consume(&noland_cas::blake3_hex(b"bbb"), b"bbb")
                .unwrap();
            assert_unfinished_accounting(&pipeline);
            let report = pipeline.finish().unwrap();
            assert_eq!(report.io.unfinished_files, 0);
            assert_eq!(report.io.unfinished_bytes, 0);
            assert_eq!(report.io.peak_unfinished_files, count as u64);
            assert_eq!(report.io.peak_unfinished_bytes, count as u64 * 2 + 3);
            assert_eq!(
                report.io.hash_state_evictions,
                u64::from(count > MAX_ACTIVE_HASHERS)
            );
            assert!(report.io.peak_assembly_handles <= MAX_ASSEMBLY_HANDLES as u64);
            assert!(report.io.peak_active_hashers <= MAX_ACTIVE_HASHERS as u64);
            transaction.commit().unwrap();
            assert_eq!(fs::read(home.join(".local/share/game/empty")).unwrap(), b"");
            assert_eq!(
                fs::read(home.join(".local/share/game/single")).unwrap(),
                b"solo"
            );
            for index in 0..count {
                assert_eq!(
                    fs::read(home.join(format!(".local/share/game/{index:04}"))).unwrap(),
                    b"aabbb"
                );
            }
        }
    }
}

// Pure counter fixtures: these placeholder paths are never opened.
fn pending(remaining: usize, opened: bool) -> PendingFile {
    PendingFile {
        planned: PlannedDestination {
            manifest_index: 0,
            root: PathBuf::new(),
            destination: PathBuf::new(),
            identical: false,
            verified: None,
            existed: false,
            prior_identity: None,
        },
        partial: PathBuf::new(),
        remaining,
        cursor: 0,
        received: 0,
        hasher: None,
        out_of_order: false,
        readback: false,
        readback_cause: None,
        opened,
        assembly_started: false,
        identity: None,
        last_write: None,
        native_boundary: None,
        native_filesystem: None,
    }
}

#[test]
fn zero_byte_placements_count_once_independently_of_partial_open_state() {
    for opened in [false, true] {
        let mut pending = pending(3, opened);
        let mut io = PipelineIoMetrics::default();
        for _ in 0..2 {
            assert!(!pending.record_placement(0, &mut io).unwrap());
            assert_eq!(io.unfinished_files, 1);
            assert_eq!(io.unfinished_bytes, 0);
            assert_eq!(io.peak_unfinished_files, 1);
        }
        assert!(pending.record_placement(7, &mut io).unwrap());
        assert_eq!(io.unfinished_files, 0);
        assert_eq!(io.unfinished_bytes, 0);
        assert_eq!(io.peak_unfinished_files, 1);
        assert_eq!(io.peak_unfinished_bytes, 7);
        assert_eq!(pending.received, 7);
        assert!(pending.record_placement(0, &mut io).is_err());
        assert_eq!(pending.remaining, 0);
        assert_eq!(pending.received, 7);
        assert_eq!(io.unfinished_files, 0);
        assert_eq!(io.unfinished_bytes, 0);
    }
}

#[test]
fn invalid_unfinished_counter_transitions_fail_without_wrapping_or_partial_updates() {
    for case in 0..6 {
        let mut pending = pending(2, true);
        let mut io = PipelineIoMetrics::default();
        match case {
            0 => io.unfinished_files = u64::MAX,
            1 => io.unfinished_bytes = u64::MAX,
            2 | 3 => {
                pending.record_placement(4, &mut io).unwrap();
                if case == 2 {
                    io.unfinished_files = 0;
                } else {
                    io.unfinished_bytes = 3;
                }
            }
            4 => {
                pending.record_placement(u64::MAX, &mut io).unwrap();
            }
            5 => pending.remaining = 0,
            _ => unreachable!(),
        }
        let before = (
            pending.remaining,
            pending.received,
            pending.assembly_started,
            io.unfinished_files,
            io.unfinished_bytes,
            io.peak_unfinished_files,
            io.peak_unfinished_bytes,
        );
        assert!(matches!(
            pending.record_placement(1, &mut io),
            Err(StateError::Integrity(_))
        ));
        assert_eq!(
            before,
            (
                pending.remaining,
                pending.received,
                pending.assembly_started,
                io.unfinished_files,
                io.unfinished_bytes,
                io.peak_unfinished_files,
                io.peak_unfinished_bytes,
            ),
            "case {case} changed accounting on failure"
        );
    }
}
