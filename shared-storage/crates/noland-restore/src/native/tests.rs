// SPDX-License-Identifier: GPL-3.0-only
//! Isolated provider/vault fixtures only. No installed apps or provider accounts.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use noland_crypto::MasterKey;
use noland_state_core::*;
use noland_storage::{commit_bundle_with_index, LocalStorage};

use super::*;
use crate::{restore_pipelined, PipelineOptions, RestorePlan, RestoreTarget, RestoreTransaction};

#[path = "manual_scope_tests.rs"]
mod manual_scope_tests;

struct TestAuthority([u8; 32]);
impl NativeRecoveryAuthority for TestAuthority {
    fn mac(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        Ok(*blake3::keyed_hash(&self.0, bytes).as_bytes())
    }
}

struct Fixture {
    root: PathBuf,
    paths: AgentPaths,
    destination: PathBuf,
    roots: LogicalRootMap,
}

impl Fixture {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = base.join(format!("quicksave-native-restore-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let paths = AgentPaths::from_roots(root.join("state"), root.join("run"));
        paths.ensure_dirs().unwrap();
        let destination = root.join("destination");
        fs::create_dir(&destination).unwrap();
        let mut roots = LogicalRootMap::default();
        roots.xdg_data_home = Some(destination.join("application-data"));
        Self {
            root,
            paths,
            destination,
            roots,
        }
    }

    fn plan(&self, files: Vec<ManifestFile>) -> RestorePlan {
        crate::tests::crash_test_plan(&self.paths, crate::tests::test_manifest(files))
    }

    fn control(&self, plan: &RestorePlan, mode: NativeConflictMode) -> Arc<NativeRestoreControl> {
        let metadata = fs::metadata(&self.destination).unwrap();
        let preview = NativeRestorePreview::prepare(
            Uuid::new_v4(),
            &plan.manifest,
            &self.roots,
            &self.destination,
            filesystem::file_id(&metadata),
            mode,
        )
        .unwrap();
        Arc::new(
            NativeRestoreControl::approve(
                preview,
                Arc::new(TestAuthority([73; 32])),
                Arc::new(|| Ok(())),
            )
            .unwrap(),
        )
    }

    fn seed(&self, plan: &RestorePlan, files: &[(&ManifestFile, &[u8])]) {
        for (file, bytes) in files {
            for chunk in &file.chunks {
                fs::write(crate::restore_chunk_path(plan, &chunk.hash).unwrap(), bytes).unwrap();
            }
        }
    }

    fn target(&self, relative: &str) -> PathBuf {
        self.destination.join("application-data").join(relative)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This fixture alone owns the fresh UUID temporary root.
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn file(relative: &str, bytes: &[u8]) -> ManifestFile {
    crate::tests::test_file(
        relative,
        PersistenceClass::PersistentState,
        SemanticRole::UserState,
        bytes,
    )
}

fn committed_empty_file(
    fixture: &Fixture,
) -> (
    RestorePlan,
    Arc<NativeRestoreControl>,
    NativeRestoreCompletionReceipt,
) {
    let mut empty = file("game/empty", b"");
    empty.chunks.clear();
    let plan = fixture.plan(vec![empty]);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let mut transaction =
        RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    let metrics = transaction.commit_with_metrics().unwrap();
    (plan, control, metrics.native_completion.unwrap())
}

#[test]
fn committed_receipt_requires_authenticated_metadata_only_workspace_without_repair() {
    use std::io::Write;
    let fixture = Fixture::new();
    let (plan, control, receipt) = committed_empty_file(&fixture);
    assert!(receipt.is_clean_committed());
    assert_eq!(receipt.retained_metadata_files, 2);
    assert_eq!(receipt.scaffold_directories, 4);
    let log = plan.staging.join("restore-native.v1.log");
    let header = plan.staging.join("restore-native.v1.json");
    let before = fs::read(&log).unwrap();
    let header_before = fs::read(&header).unwrap();
    let shared = plan.clone().into_shared().with_native_control(control);
    assert!(shared
        .verify_native_completion()
        .unwrap()
        .is_clean_committed());
    assert_eq!(fs::read(&log).unwrap(), before);
    assert_eq!(fs::read(&header).unwrap(), header_before);

    let mut file = fs::OpenOptions::new().append(true).open(&log).unwrap();
    file.write_all(&[8, 0]).unwrap();
    file.sync_all().unwrap();
    let torn = fs::read(&log).unwrap();
    assert!(shared.verify_native_completion().is_err());
    assert_eq!(
        fs::read(&log).unwrap(),
        torn,
        "inspection never repairs a tail"
    );
    assert!(fixture.target("game/empty").is_file());
}

#[test]
fn completion_inspection_rejects_uncommitted_and_authenticated_post_terminal_records() {
    let fixture = Fixture::new();
    let active_plan = fixture.plan(vec![file("uncommitted", b"")]);
    let active_control = fixture.control(&active_plan, NativeConflictMode::CreateOnly);
    let active = NativeTransaction::begin(
        &active_plan.staging,
        active_plan.restore_id,
        Arc::clone(&active_control),
        &active_plan.manifest,
        active_plan.mode,
        &fixture.roots,
    )
    .unwrap();
    assert!(verify_native_restore_completion(&active_plan.staging, active_control).is_err());
    assert!(!active.committed);
    drop(active);

    let (plan, control, _) = committed_empty_file(&fixture);
    let mut journal =
        NativeJournal::replay(&plan.staging, Arc::clone(&control), |_| Ok(())).unwrap();
    journal.append(&Event::Committed).unwrap();
    journal.flush().unwrap();
    assert!(verify_native_restore_completion(&plan.staging, control).is_err());
    assert!(fixture.target("game/empty").is_file());
}

#[test]
fn authenticated_missing_owner_frame_fails_closed_without_recovery_mutation() {
    let fixture = Fixture::new();
    let mut empty = file("game/empty", b"");
    empty.chunks.clear();
    let plan = fixture.plan(vec![empty]);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let mut transaction =
        RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    std::mem::forget(transaction);

    // Synthetic device MAC authority is deliberately able to sign a malformed
    // historical/foreign ownership record. Authentication never substitutes for
    // the platform frame, and replay must validate every record before undo.
    let root =
        NativeRoot::open(&fixture.destination, control.preview.destination_identity).unwrap();
    let mut observation = root.observe("application-data/game/empty").unwrap();
    observation.uid = None;
    let mut journal =
        NativeJournal::replay(&plan.staging, Arc::clone(&control), |_| Ok(())).unwrap();
    journal
        .append(&Event::Owned {
            path: "application-data/unknown.partial".into(),
            observation,
            role: OwnershipRole::Partial,
        })
        .unwrap();
    journal.flush().unwrap();
    drop(journal);
    let log_path = plan.staging.join("restore-native.v1.log");
    let header_path = plan.staging.join("restore-native.v1.json");
    let log = fs::read(&log_path).unwrap();
    let header = fs::read(&header_path).unwrap();
    assert!(recover_native_restore(&plan.staging, control).is_err());
    assert_eq!(fs::read(&log_path).unwrap(), log);
    assert_eq!(fs::read(&header_path).unwrap(), header);
    assert!(fixture.target("game/empty").is_file());
    assert_eq!(fs::read(fixture.target("game/empty")).unwrap(), b"");
}

#[test]
fn unlogged_create_slots_and_ancestors_remain_explicitly_retained_not_clean() {
    for kind in ["ancestor", "partial", "rollback"] {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.target("game")).unwrap();
        let mut empty = file("game/empty", b"");
        empty.chunks.clear();
        let plan = fixture.plan(vec![empty]);
        let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
        let transaction =
            RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
        std::mem::forget(transaction);
        let unlogged = match kind {
            "ancestor" => {
                let path = fixture.target("game/empty");
                fs::create_dir(&path).unwrap();
                path
            }
            "partial" => {
                let path =
                    crate::destination_partial_path(&fixture.target("game/empty"), plan.restore_id)
                        .unwrap();
                fs::write(&path, b"foreign bytes never covered by an owned-ID record").unwrap();
                path
            }
            _ => {
                let path = fixture
                    .destination
                    .join(format!(".quicksave-restore-{}", plan.restore_id));
                fs::create_dir(&path).unwrap();
                path
            }
        };
        let report = recover_native_restore(&plan.staging, control).unwrap();
        assert!(!report.retained_artifacts.is_empty(), "{kind}");
        assert!(!report.rolled_back, "{kind}");
        assert!(!report.owned_artifacts_clean, "{kind}");
        assert!(!report.metadata_only_workspace, "{kind}");
        assert!(fs::symlink_metadata(&unlogged).is_ok(), "{kind}");
    }
}

#[test]
fn completion_inspection_retains_plaintext_links_foreign_slots_and_tampered_journals() {
    let fixture = Fixture::new();
    let (plan, control, _) = committed_empty_file(&fixture);
    let unknown = plan.staging.join("materialized/.chunks/unapproved");
    fs::write(&unknown, b"retained plaintext").unwrap();
    assert!(verify_native_restore_completion(&plan.staging, Arc::clone(&control)).is_err());
    assert_eq!(fs::read(&unknown).unwrap(), b"retained plaintext");
    fs::remove_file(&unknown).unwrap();

    fs::create_dir(plan.staging.join("logs")).unwrap();
    let link = plan.staging.join("logs/link");
    std::os::unix::fs::symlink(&fixture.destination, &link).unwrap();
    assert!(verify_native_restore_completion(&plan.staging, Arc::clone(&control)).is_err());
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(&link).unwrap();

    let transaction =
        NativeTransaction::load_readonly(&plan.staging, Arc::clone(&control)).unwrap();
    let partial = transaction
        .owned
        .iter()
        .find(|(_, (_, role))| *role == OwnershipRole::Partial)
        .unwrap()
        .0;
    let foreign_slot = fixture.destination.join(partial);
    fs::write(&foreign_slot, b"foreign replacement").unwrap();
    assert!(verify_native_restore_completion(&plan.staging, Arc::clone(&control)).is_err());
    assert_eq!(fs::read(&foreign_slot).unwrap(), b"foreign replacement");
    fs::remove_file(&foreign_slot).unwrap();
    drop(transaction);

    let log = plan.staging.join("restore-native.v1.log");
    let mut bytes = fs::read(&log).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&log, &bytes).unwrap();
    assert!(verify_native_restore_completion(&plan.staging, control).is_err());
    assert_eq!(fs::read(&log).unwrap(), bytes);
    assert!(fixture.target("game/empty").is_file());
}

#[test]
fn native_preview_rejects_absolute_linux_links_and_escaping_relative_targets() {
    let fixture = Fixture::new();
    for target in ["/usr/lib/libc.so", "../outside", "child/../outside"] {
        let mut link = file("link", b"");
        link.file_type = "symlink".into();
        link.chunks.clear();
        link.symlink_target = Some(target.into());
        let plan = fixture.plan(vec![link]);
        assert!(
            NativeRestorePreview::prepare(
                Uuid::new_v4(),
                &plan.manifest,
                &fixture.roots,
                &fixture.destination,
                filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
                NativeConflictMode::CreateOnly,
            )
            .is_err(),
            "{target}"
        );
    }
}

#[test]
fn native_preview_preserves_unix_filename_and_link_bytes_in_json_and_mac_input() {
    let fixture = Fixture::new();
    let mut literal = file(r"a\b", b"literal");
    let nested = file("a/b", b"nested");
    let mut directory = file("a", b"");
    directory.file_type = "directory".into();
    directory.file_hash.clear();
    directory.chunks.clear();
    let mut link = file(r"link:one\literal", b"");
    link.file_type = "symlink".into();
    link.chunks.clear();
    link.symlink_target = Some(r"a\b".into());
    let plan = fixture.plan(vec![literal.clone(), directory, nested, link]);
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &plan.manifest,
        &fixture.roots,
        &fixture.destination,
        filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
        NativeConflictMode::CreateOnly,
    )
    .unwrap();
    let exact = preview
        .entries
        .iter()
        .find(|entry| entry.relative_path == r"a\b")
        .unwrap();
    assert_eq!(exact.destination_relative, r"application-data/a\b");
    assert!(preview
        .entries
        .iter()
        .any(|entry| entry.destination_relative == "application-data/a/b"));
    let bytes = serde_json::to_vec(&preview).unwrap();
    let decoded: NativeRestorePreview = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, preview);
    decoded.validate_shape().unwrap();
    let authority = TestAuthority([73; 32]);
    let mac = authority.mac(&bytes).unwrap();
    assert_eq!(
        authority
            .mac(&serde_json::to_vec(&decoded).unwrap())
            .unwrap(),
        mac
    );
    let mut rewritten = decoded;
    rewritten
        .entries
        .iter_mut()
        .find(|entry| entry.relative_path == r"a\b")
        .unwrap()
        .relative_path = "a/b".into();
    assert_ne!(
        authority
            .mac(&serde_json::to_vec(&rewritten).unwrap())
            .unwrap(),
        mac
    );
    assert!(
        rewritten.validate_shape().is_err(),
        "normalizing would alias a distinct selected entry"
    );
    let digest = payload_digest(&plan.manifest, plan.mode).unwrap();
    let mut rewritten_manifest = plan.manifest.clone();
    literal.relative_path = "a/b".into();
    rewritten_manifest.files[0] = literal;
    assert_ne!(
        payload_digest(&rewritten_manifest, plan.mode).unwrap(),
        digest
    );
    assert!(native_layout::validate_windows_restore_names(&plan.manifest).is_err());
    assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none());
}

#[test]
fn native_preview_target_rules_do_not_treat_unix_drive_looking_names_as_windows_paths() {
    let fixture = Fixture::new();
    for target in ["C:/relative-directory", r"..\one-literal-leaf"] {
        let mut link = file("link", b"");
        link.file_type = "symlink".into();
        link.chunks.clear();
        link.symlink_target = Some(target.into());
        let plan = fixture.plan(vec![link]);
        native_layout::validate_native_restore_names(&plan.manifest).unwrap();
        assert!(native_layout::validate_windows_restore_names(&plan.manifest).is_err());
        fixture.control(&plan, NativeConflictMode::CreateOnly);
    }
    // A bad final entry cannot start publication/scaffolding for earlier names.
    let plan = fixture.plan(vec![file("first-safe-entry", b""), file("../outside", b"")]);
    assert!(NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &plan.manifest,
        &fixture.roots,
        &fixture.destination,
        filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
        NativeConflictMode::CreateOnly,
    )
    .is_err());
    assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none());
}

#[test]
fn conflict_preview_requires_exact_overwrite_approval_and_preserves_foreign_siblings() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.target("game")).unwrap();
    fs::write(fixture.target("game/save"), b"original").unwrap();
    fs::write(fixture.target("game/foreign"), b"never selected").unwrap();
    let restored = file("game/save", b"restored");
    let plan = fixture.plan(vec![restored.clone()]);
    let identity = filesystem::file_id(&fs::metadata(&fixture.destination).unwrap());
    let merge = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &plan.manifest,
        &fixture.roots,
        &fixture.destination,
        identity,
        NativeConflictMode::Merge,
    )
    .unwrap();
    assert!(merge.has_conflicts());
    assert!(NativeRestoreControl::approve(
        merge,
        Arc::new(TestAuthority([73; 32])),
        Arc::new(|| Ok(())),
    )
    .is_err());
    fixture.seed(&plan, &[(&restored, b"restored")]);
    let control = fixture.control(&plan, NativeConflictMode::Overwrite);
    let mut transaction = RestoreTransaction::new_native(&plan, &fixture.roots, control).unwrap();
    transaction.enable_chunk_eviction().unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"restored");
    transaction.abort().unwrap();
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"original");
    assert_eq!(
        fs::read(fixture.target("game/foreign")).unwrap(),
        b"never selected"
    );
    assert!(plan.staging.join("restore-native.v1.json").exists());
    assert!(!plan.staging.join(crate::TRANSACTION_JOURNAL_FILE).exists());
}

#[test]
fn crash_recovery_authenticates_actual_ids_and_restores_original_inode_then_retries() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.target("game")).unwrap();
    fs::write(fixture.target("game/save"), b"original").unwrap();
    let original_id = filesystem::file_id(&fs::metadata(fixture.target("game/save")).unwrap());
    let replaced = file("game/save", b"restored");
    let created = file("new/save", b"new");
    let plan = fixture.plan(vec![replaced.clone(), created.clone()]);
    fixture.seed(&plan, &[(&replaced, b"restored"), (&created, b"new")]);
    let control = fixture.control(&plan, NativeConflictMode::Overwrite);
    let mut transaction =
        RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
    transaction.enable_chunk_eviction().unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    std::mem::forget(transaction);
    let recovered = recover_native_restore(&plan.staging, Arc::clone(&control)).unwrap();
    assert!(recovered.rolled_back);
    assert_eq!(
        filesystem::file_id(&fs::metadata(fixture.target("game/save")).unwrap()),
        original_id
    );
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"original");
    assert!(!fixture.target("new/save").exists());
    control
        .validate_fresh(&plan.manifest, plan.mode, &fixture.roots)
        .unwrap();

    // Reattach from a new controller and the same device-key-authenticated plan.
    let reattached = Arc::new(
        NativeRestoreControl::approve(
            control.preview().clone(),
            Arc::new(TestAuthority([73; 32])),
            Arc::new(|| Ok(())),
        )
        .unwrap(),
    );
    recover_native_restore(&plan.staging, Arc::clone(&reattached)).unwrap();
    reattached
        .validate_fresh(&plan.manifest, plan.mode, &fixture.roots)
        .unwrap();
}

#[test]
fn foreign_replacement_and_renamed_root_are_retained_not_path_deleted() {
    let fixture = Fixture::new();
    let restored = file("game/save", b"restored");
    let plan = fixture.plan(vec![restored.clone()]);
    fixture.seed(&plan, &[(&restored, b"restored")]);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let mut transaction =
        RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    fs::rename(
        fixture.target("game/save"),
        fixture.target("game/detached-owned"),
    )
    .unwrap();
    fs::write(fixture.target("game/save"), b"foreign").unwrap();
    assert!(transaction.abort().is_err());
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"foreign");
    assert_eq!(
        fs::read(fixture.target("game/detached-owned")).unwrap(),
        b"restored"
    );
    assert!(plan.staging.join("restore-native.v1.log").exists());

    let renamed = fixture.root.join("renamed-destination");
    fs::rename(&fixture.destination, &renamed).unwrap();
    fs::create_dir(&fixture.destination).unwrap();
    fs::write(fixture.destination.join("unapproved"), b"keep").unwrap();
    assert!(recover_native_restore(&plan.staging, control).is_err());
    assert_eq!(
        fs::read(fixture.destination.join("unapproved")).unwrap(),
        b"keep"
    );
    assert_eq!(
        fs::read(renamed.join("application-data/game/save")).unwrap(),
        b"foreign"
    );
}

#[test]
fn journal_checksum_cannot_replace_device_authentication_or_widen_scope() {
    let fixture = Fixture::new();
    let restored = file("game/save", b"restored");
    let plan = fixture.plan(vec![restored.clone()]);
    fixture.seed(&plan, &[(&restored, b"restored")]);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let mut transaction =
        RestoreTransaction::new_native(&plan, &fixture.roots, Arc::clone(&control)).unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    std::mem::forget(transaction);
    let wrong_device = Arc::new(
        NativeRestoreControl::approve(
            control.preview().clone(),
            Arc::new(TestAuthority([19; 32])),
            Arc::new(|| Ok(())),
        )
        .unwrap(),
    );
    assert!(recover_native_restore(&plan.staging, wrong_device).is_err());
    let log = plan.staging.join("restore-native.v1.log");
    let mut bytes = fs::read(&log).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&log, bytes).unwrap();
    assert!(recover_native_restore(&plan.staging, control).is_err());
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"restored");
}

#[test]
fn app_writing_a_held_original_fd_cannot_destroy_the_stable_rollback_capture() {
    use std::io::Write;
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.target("game")).unwrap();
    fs::write(fixture.target("game/save"), b"original").unwrap();
    let mut app_fd = fs::OpenOptions::new()
        .write(true)
        .open(fixture.target("game/save"))
        .unwrap();
    let restored = file("game/save", b"restored");
    let plan = fixture.plan(vec![restored.clone()]);
    fixture.seed(&plan, &[(&restored, b"restored")]);
    let control = fixture.control(&plan, NativeConflictMode::Overwrite);
    let mut transaction = RestoreTransaction::new_native(&plan, &fixture.roots, control).unwrap();
    transaction.publish_to(RestoreTarget::Complete).unwrap();
    app_fd.write_all(b"new-user").unwrap();
    app_fd.sync_all().unwrap();
    assert!(transaction.abort().is_err());
    // Both the new restored output and the actual pre-restore bytes survive.
    assert_eq!(fs::read(fixture.target("game/save")).unwrap(), b"restored");
    let capture = fs::read_dir(&plan.staging)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("native-original-")
        })
        .unwrap();
    assert_eq!(fs::read(capture).unwrap(), b"original");
}

#[tokio::test]
async fn real_local_storage_pipeline_preserves_selective_packs_metadata_links_and_no_readback() {
    let fixture = Fixture::new();
    let master = MasterKey::generate();
    let storage = LocalStorage::new(fixture.root.join("provider"));
    let mut restored = file(
        "Test.app/Contents/MacOS/program",
        b"native executable fixture",
    );
    restored.mode = Some(0o755);
    restored.mtime_ns = Some(1_600_000_000_123_456_789);
    let unselected = file("not-selected", b"not downloaded");
    let mut link = file("Test.app/Contents/current", b"");
    link.file_type = "symlink".into();
    link.chunks.clear();
    link.symlink_target = Some("MacOS/program".into());
    let mut manifest =
        crate::tests::test_manifest(vec![restored.clone(), unselected.clone(), link.clone()]);
    let mut packs = Vec::new();
    // Separate real packs prove a subset does not fetch unselected packs.
    for (name, bytes) in [
        ("selected", b"native executable fixture".as_slice()),
        ("unselected", b"not downloaded".as_slice()),
    ] {
        packs.extend(
            noland_pack::pack_chunks(
                &fixture.root.join(name),
                &master,
                [(noland_cas::blake3_hex(bytes), bytes.to_vec())],
                |_| false,
            )
            .unwrap(),
        );
    }
    let index = packs
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let pack_files = packs
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    commit_bundle_with_index(
        &storage,
        &master,
        &manifest,
        &pack_files,
        Some(&serde_json::to_vec(&index).unwrap()),
        None,
    )
    .await
    .unwrap();
    manifest
        .files
        .retain(|file| file.relative_path != "not-selected");
    let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let report = restore_pipelined(
        &storage,
        &master,
        plan.clone().into_shared().with_native_control(control),
        &index,
        &fixture.roots,
        None,
        None,
        PipelineOptions::default(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(report.packs_downloaded, 1);
    assert_eq!(report.restore.published_entries, 2);
    assert_eq!(report.io.readback_bytes, 0);
    assert!(report
        .io
        .commit
        .native_completion
        .as_ref()
        .is_some_and(|receipt| receipt.is_clean_committed()));
    assert_eq!(report.io.native_original_capture_bytes, 0);
    assert!(report.io.native_intent_flushes <= report.io.publication_batches * 2 + 6);
    assert_eq!(
        fs::read(fixture.target(&restored.relative_path)).unwrap(),
        b"native executable fixture"
    );
    assert!(!fixture.target("not-selected").exists());
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(fixture.target(&restored.relative_path)).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o755);
    assert_eq!(
        metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
        restored.mtime_ns.unwrap()
    );
    assert_eq!(
        fs::read_link(fixture.target(&link.relative_path)).unwrap(),
        Path::new("MacOS/program")
    );
}

#[tokio::test]
async fn revoked_gate_cancels_streaming_without_deleting_unapproved_data() {
    let fixture = Fixture::new();
    let restored = file("game/save", b"save");
    let plan = fixture.plan(vec![restored.clone()]);
    fixture.seed(&plan, &[(&restored, b"save")]);
    let preview = fixture
        .control(&plan, NativeConflictMode::CreateOnly)
        .preview()
        .clone();
    let allowed = Arc::new(AtomicBool::new(true));
    let gate_allowed = Arc::clone(&allowed);
    let control = Arc::new(
        NativeRestoreControl::approve(
            preview,
            Arc::new(TestAuthority([73; 32])),
            Arc::new(move || {
                if gate_allowed.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(StateError::Conflict("fixture revoked".into()))
                }
            }),
        )
        .unwrap(),
    );
    let mut transaction = RestoreTransaction::new_native(&plan, &fixture.roots, control).unwrap();
    allowed.store(false, Ordering::Release);
    assert!(transaction.publish_to(RestoreTarget::Complete).is_err());
    assert!(
        transaction.abort().is_err(),
        "unconsumed fixture plaintext is retained, not waived"
    );
    assert!(!fixture.target("game/save").exists());
}

#[tokio::test]
async fn full_local_storage_stream_reuses_one_chunk_for_two_files_and_keeps_empty_accounting_exact()
{
    let fixture = Fixture::new();
    let master = MasterKey::generate();
    let storage = LocalStorage::new(fixture.root.join("provider"));
    let first = file("one/save", b"shared");
    let second = file("two/save", b"shared");
    let mut empty = file("three/empty", b"");
    empty.chunks.clear();
    let manifest = crate::tests::test_manifest(vec![first.clone(), second.clone(), empty.clone()]);
    let packs = noland_pack::pack_chunks(
        &fixture.root.join("packs"),
        &master,
        [(noland_cas::blake3_hex(b"shared"), b"shared".to_vec())],
        |_| false,
    )
    .unwrap();
    let index = packs
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let objects = packs
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    commit_bundle_with_index(
        &storage,
        &master,
        &manifest,
        &objects,
        Some(&serde_json::to_vec(&index).unwrap()),
        None,
    )
    .await
    .unwrap();
    let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let report = restore_pipelined(
        &storage,
        &master,
        plan.clone()
            .into_shared()
            .with_native_control(Arc::clone(&control)),
        &index,
        &fixture.roots,
        None,
        None,
        PipelineOptions::default(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(report.packs_downloaded, 1);
    assert_eq!(report.restore.published_entries, 3);
    assert_eq!(report.io.readback_bytes, 0);
    let receipt =
        crate::verify_native_restore_completion(&plan.staging, Arc::clone(&control)).unwrap();
    assert!(receipt.is_clean_committed());
    assert_eq!(receipt.retained_metadata_files, 2);
    assert_eq!(report.io.unfinished_files, 0);
    assert_eq!(report.io.unfinished_bytes, 0);
    assert!(report.io.peak_active_hashers <= 2);
    assert!(report.io.peak_assembly_handles <= 2);
    assert_eq!(fs::read(fixture.target("one/save")).unwrap(), b"shared");
    assert_eq!(fs::read(fixture.target("two/save")).unwrap(), b"shared");
    assert_eq!(
        fs::metadata(fixture.target("three/empty")).unwrap().len(),
        0
    );

    // Simulate repository/credential finalization retry after data committed.
    // MAC-authenticated output/parent receipts avoid duplicate reconstruction.
    recover_native_restore(&plan.staging, Arc::clone(&control)).unwrap();
    control
        .validate_fresh(&plan.manifest, plan.mode, &fixture.roots)
        .unwrap();
    let next = crate::tests::crash_test_plan(&fixture.paths, plan.manifest.clone());
    let retry = restore_pipelined(
        &storage,
        &master,
        next.into_shared().with_native_control(control),
        &index,
        &fixture.roots,
        None,
        None,
        PipelineOptions::default(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(retry.packs_downloaded, 0);
    assert_eq!(retry.restore.reused_entries, 3);
    assert_eq!(retry.restore.published_entries, 0);
    assert_eq!(retry.io.readback_bytes, 0);
}

#[tokio::test]
async fn unknown_workspace_data_is_retained_and_cannot_receive_a_clean_completion_receipt() {
    let fixture = Fixture::new();
    let master = MasterKey::generate();
    let storage = LocalStorage::new(fixture.root.join("provider"));
    let manifest = crate::tests::test_manifest(vec![file("save", b"verified")]);
    let packs = noland_pack::pack_chunks(
        &fixture.root.join("packs"),
        &master,
        [(noland_cas::blake3_hex(b"verified"), b"verified".to_vec())],
        |_| false,
    )
    .unwrap();
    let index = packs
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let objects = packs
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    commit_bundle_with_index(
        &storage,
        &master,
        &manifest,
        &objects,
        Some(&serde_json::to_vec(&index).unwrap()),
        None,
    )
    .await
    .unwrap();
    let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
    fs::write(plan.staging.join("unapproved-data"), b"must stay").unwrap();
    let control = fixture.control(&plan, NativeConflictMode::CreateOnly);
    let shared = plan
        .clone()
        .into_shared()
        .with_native_control(Arc::clone(&control));
    let result = restore_pipelined(
        &storage,
        &master,
        &shared,
        &index,
        &fixture.roots,
        None,
        None,
        PipelineOptions::default(),
        |_| Ok(()),
    )
    .await;
    assert!(
        result.is_err(),
        "unproven working data cannot be labelled completed/clean"
    );
    assert_eq!(
        fs::read(fixture.target("save")).unwrap(),
        b"verified",
        "the committed output must not be rolled back after cleanup failure"
    );
    assert_eq!(
        fs::read(plan.staging.join("unapproved-data")).unwrap(),
        b"must stay"
    );
    assert!(shared.verify_native_completion().is_err());
}

fn app_layout_manifest(
    fixture: &Fixture,
) -> (BundleManifest, Vec<(String, Vec<u8>)>, LogicalRootMap) {
    use noland_state_core::native_layout::{
        logical_root_map, native_restore_layout, NATIVE_ROOT_LAYOUTS_KEY,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let app_id = "quicksave:synthetic-native-package";
    let root_id = "installation-fixture";
    let token = format!(
        "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
        app_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        root_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let payloads = vec![
        ("Contents/Info.plist".to_owned(),br#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.quicksave.synthetic</string><key>CFBundleExecutable</key><string>fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#.to_vec()),
        ("Contents/MacOS/fixture".into(),b"#!/bin/sh\n# synthetic fixture; never executed\nexit 0\n".to_vec()),
        ("Contents/Resources/state.bin".into(),b"actual captured application resource".to_vec()),
        ("Contents/Frameworks/Demo.framework/Versions/A/Demo".into(),b"synthetic framework resource, not native code".to_vec()),
    ];
    let source = fixture.root.join("Actual Synthetic.app");
    fs::create_dir(&source).unwrap();
    for (path, bytes) in &payloads {
        fs::create_dir_all(source.join(path).parent().unwrap()).unwrap();
        fs::write(source.join(path), bytes).unwrap();
    }
    fs::set_permissions(
        source.join("Contents/MacOS/fixture"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let root_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::File::open(&source)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(root_time))
        .unwrap();
    let source_metadata = fs::metadata(&source).unwrap();
    let mut entries = payloads
        .iter()
        .map(|(path, bytes)| {
            let mut entry = file(path, bytes);
            entry.logical_root = token.clone();
            entry.source_path_hint = Some(format!("/untrusted-original-source/{path}"));
            entry.mode = Some(if path == "Contents/MacOS/fixture" {
                0o755
            } else {
                0o644
            });
            entry
        })
        .collect::<Vec<_>>();
    let mut directory = file("Contents/Resources", b"");
    directory.logical_root = token.clone();
    directory.file_type = "directory".into();
    directory.file_hash.clear();
    directory.chunks.clear();
    directory.mode = Some(0o755);
    directory.mtime_ns = Some(1_500_000_000_000_000_000);
    entries.push(directory);
    for (path, target) in [
        ("Contents/Frameworks/Demo.framework/Versions/Current", "A"),
        (
            "Contents/Frameworks/Demo.framework/Demo",
            "Versions/Current/Demo",
        ),
    ] {
        std::os::unix::fs::symlink(target, source.join(path)).unwrap();
        let mut link = file(path, b"");
        link.logical_root = token.clone();
        link.file_type = "symlink".into();
        link.file_hash.clear();
        link.chunks.clear();
        link.symlink_target = Some(target.into());
        entries.push(link);
    }
    let mut manifest = crate::tests::test_manifest(entries);
    manifest.app.app_id = AppId(app_id.into());
    manifest.app.display_name = "Not the original package basename".into();
    manifest.app.canonical_executable = Some(PathBuf::from("/untrusted-absolute-launch-hint"));
    manifest.environment["quicksave_native"] = serde_json::json!({
        "version":1,"platform":"macos","software_instance_id":"synthetic-instance",
        "coverage":"full_approved_scope","full_scope":{"version":1,"rootCaptures":[{
            "id":root_id,"logicalRoot":token,"mode":source_metadata.mode(),
            "owner":source_metadata.uid(),"group":source_metadata.gid(),
            "stamp":{"modified_seconds":source_metadata.mtime(),"modified_nanoseconds":source_metadata.mtime_nsec()},
        }]},
    });
    manifest.environment[NATIVE_ROOT_LAYOUTS_KEY] = serde_json::json!({
        "version":1,"platform":"macos","app_id":app_id,"software_instance_id":"synthetic-instance",
        "roots":[{"logical_root":token,"root_id":root_id,"role":"installation",
            "source_kind":"directory","leaf_name":"Actual Synthetic.app"}],
    });
    let save_id = "empty-save-fixture";
    let save_token = format!(
        "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
        app_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        save_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let empty_source = fixture.root.join("Actual Empty Saves");
    fs::create_dir(&empty_source).unwrap();
    let empty_metadata = fs::metadata(&empty_source).unwrap();
    manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"]
        .as_array_mut().unwrap().push(serde_json::json!({
            "id":save_id,"logicalRoot":save_token,"mode":empty_metadata.mode(),
            "owner":empty_metadata.uid(),"group":empty_metadata.gid(),
            "stamp":{"modified_seconds":empty_metadata.mtime(),"modified_nanoseconds":empty_metadata.mtime_nsec()},
        }));
    manifest.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "logical_root":save_token,"root_id":save_id,"role":"save","source_kind":"directory",
            "leaf_name":"Actual Empty Saves",
        }));
    let mapping = native_restore_layout(&manifest, &fixture.destination).unwrap();
    let roots = logical_root_map(&mapping.roots).unwrap();
    (manifest, payloads, roots)
}

#[tokio::test]
async fn authenticated_native_app_layout_restores_real_package_resources_and_framework_links_without_runnable_claim(
) {
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::new();
    let (manifest, payloads, roots) = app_layout_manifest(&fixture);
    let master = MasterKey::generate();
    let storage = LocalStorage::new(fixture.root.join("provider"));
    let packs = noland_pack::pack_chunks(
        &fixture.root.join("packs"),
        &master,
        payloads
            .iter()
            .map(|(_, bytes)| (noland_cas::blake3_hex(bytes), bytes.clone())),
        |_| false,
    )
    .unwrap();
    let index = packs
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let objects = packs
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    commit_bundle_with_index(
        &storage,
        &master,
        &manifest,
        &objects,
        Some(&serde_json::to_vec(&index).unwrap()),
        None,
    )
    .await
    .unwrap();
    let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &plan.manifest,
        &roots,
        &fixture.destination,
        filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
        NativeConflictMode::CreateOnly,
    )
    .unwrap();
    assert_eq!(preview.root_entries.len(), 2);
    assert!(preview
        .root_mappings
        .values()
        .any(|path| path == &fixture.destination.join("Actual Synthetic.app")));
    let control = Arc::new(
        NativeRestoreControl::approve(
            preview,
            Arc::new(TestAuthority([73; 32])),
            Arc::new(|| Ok(())),
        )
        .unwrap(),
    );
    let shared = plan.into_shared().with_native_control(Arc::clone(&control));
    let mut last_ready = false;
    let report = restore_pipelined(
        &storage,
        &master,
        &shared,
        &index,
        &roots,
        None,
        None,
        PipelineOptions::default(),
        |sample| {
            last_ready |= sample.ready_to_launch;
            Ok(())
        },
    )
    .await
    .unwrap();
    let package = fixture.destination.join("Actual Synthetic.app");
    assert!(package.is_dir());
    for (path, bytes) in &payloads {
        assert_eq!(fs::read(package.join(path)).unwrap(), *bytes);
    }
    assert_eq!(
        fs::read_link(package.join("Contents/Frameworks/Demo.framework/Versions/Current")).unwrap(),
        Path::new("A")
    );
    assert_eq!(
        fs::read_link(package.join("Contents/Frameworks/Demo.framework/Demo")).unwrap(),
        Path::new("Versions/Current/Demo")
    );
    assert_eq!(fs::metadata(&package).unwrap().mode() & 0o7777, 0o755);
    assert_eq!(fs::metadata(&package).unwrap().mtime(), 1_600_000_000);
    assert_eq!(
        fs::metadata(package.join("Contents/Resources"))
            .unwrap()
            .mtime(),
        1_500_000_000
    );
    let save_layout = control
        .preview()
        .root_layout
        .as_ref()
        .unwrap()
        .roots
        .iter()
        .find(|root| root.role == noland_state_core::native_layout::NativeLayoutRole::Save)
        .unwrap();
    let saves = &control.preview().root_mappings[&save_layout.logical_root];
    assert!(saves.starts_with(fixture.destination.join("save")));
    assert!(saves.is_dir() && fs::read_dir(saves).unwrap().next().is_none());
    assert_eq!(
        report.restore.published_entries, 7,
        "root metadata is not a placeholder file inventory"
    );
    assert_eq!(report.io.readback_bytes, 0);
    assert!(!last_ready);
    assert!(shared
        .verify_native_completion()
        .unwrap()
        .is_clean_committed());
    let assessment = report.io.commit.native_reconstruction.unwrap();
    assert!(
        assessment.layout_reconstructed
            && assessment.entire_manifest
            && assessment.source_full_scope
    );
    assert!(!assessment.runnable);
    assert!(assessment.metadata_read_bytes > 0 && assessment.metadata_read_bytes < 2 * 1024 * 1024);
    assert!(assessment.applications[0].bundle_metadata_validated);
    assert!(assessment.applications[0].executable_capture_hash_verified);
    assert_eq!(
        assessment.applications[0].executable_format,
        "script_not_native_launch_verified"
    );
    assert!(!assessment.applications[0].native_signature_verified);
    assert!(!fixture
        .destination
        .join("Not the original package basename.app")
        .exists());
}

#[test]
fn native_package_root_is_in_create_new_conflicts_and_remapping_breaks_frozen_authority() {
    let fixture = Fixture::new();
    let (manifest, _, roots) = app_layout_manifest(&fixture);
    fs::create_dir(fixture.destination.join("Actual Synthetic.app")).unwrap();
    let identity = filesystem::file_id(&fs::metadata(&fixture.destination).unwrap());
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &manifest,
        &roots,
        &fixture.destination,
        identity,
        NativeConflictMode::CreateOnly,
    )
    .unwrap();
    assert!(
        preview.has_conflicts(),
        "an empty existing .app is not create-new authority"
    );
    assert!(preview
        .root_entries
        .iter()
        .any(|root| root.destination_relative == "Actual Synthetic.app"
            && root.action == NativeRestoreAction::Conflict));
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &manifest,
        &roots,
        &fixture.destination,
        identity,
        NativeConflictMode::Merge,
    )
    .unwrap();
    let control = NativeRestoreControl::approve(
        preview,
        Arc::new(TestAuthority([73; 32])),
        Arc::new(|| Ok(())),
    )
    .unwrap();
    let mut changed = roots;
    for path in changed.custom_roots.values_mut() {
        *path = fixture.root.join("unapproved");
    }
    assert!(control
        .validate_fresh(&manifest, RestoreMode::CompleteApplication, &changed)
        .is_err());
}

#[test]
fn reduced_native_package_selection_drops_unselected_roots_and_cannot_become_a_complete_app() {
    use noland_state_core::native_layout::{
        logical_root_map, native_restore_layout, native_root_layouts, project_native_root_layouts,
    };
    let fixture = Fixture::new();
    let (mut manifest, _, _) = app_layout_manifest(&fixture);
    native_root_layouts(&manifest).unwrap();
    manifest
        .files
        .retain(|entry| entry.relative_path == "Contents/Resources/state.bin");
    manifest.environment["quicksave_native_download"] = serde_json::json!({"whole_bundle":false});
    project_native_root_layouts(&mut manifest).unwrap();
    let layout = native_restore_layout(&manifest, &fixture.destination).unwrap();
    assert_eq!(
        layout.roots.len(),
        1,
        "empty source save roots are not individual-file consent"
    );
    let roots = logical_root_map(&layout.roots).unwrap();
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &manifest,
        &roots,
        &fixture.destination,
        filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
        NativeConflictMode::CreateOnly,
    )
    .unwrap();
    assert!(!preview.entire_manifest && !preview.reconstruction_eligible());
    assert_eq!(preview.entries.len(), 1);
    let control = NativeRestoreControl::approve(
        preview,
        Arc::new(TestAuthority([73; 32])),
        Arc::new(|| Ok(())),
    )
    .unwrap();
    manifest.environment["quicksave_native_download"]["whole_bundle"] = true.into();
    assert!(control
        .validate_payload(&manifest, RestoreMode::CompleteApplication)
        .is_err());
}
