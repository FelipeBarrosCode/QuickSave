// SPDX-License-Identifier: GPL-3.0-only
//! Portable reproductions of Windows full_scope.rs root captures. Source paths,
//! source IDs and tracker grants are synthetic data; no Windows OS probe, native
//! account, installed app, provider account or actual vault is used.
use super::*;
use noland_state_core::native_layout::{
    logical_root_map, native_restore_layout, native_root_layouts,
};
use serde::Serialize;
use serde_json::{json, Value};

const ROOT_ID: &str = "manual-save";
const LEAF: &str = "nested/leaf.dat";
const OLD: &[u8] = b"original exact selected leaf";
const NEW: &[u8] = b"restored exact selected leaf";
const CANONICAL_APP: &str = "steam:480";
const SOFTWARE_INSTANCE: &str = "steam:480@fixture";
const WORKSPACE_SOFTWARE: &str = "fixture-software";

fn digest(value: &impl Serialize) -> String {
    bounded_digest(value).unwrap()
}

fn leaf_id() -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave logical file v1\0");
    hash.update(&(ROOT_ID.len() as u64).to_le_bytes());
    hash.update(ROOT_ID.as_bytes());
    hash.update(LEAF.as_bytes());
    format!("file-{}", hash.finalize().to_hex())
}

fn stamp(file: bool) -> Value {
    json!({"device":9,"file_id":[if file {91} else {7},1u64<<63],
        "size":if file {OLD.len()} else {0},
        "modified_seconds":1,"modified_nanoseconds":200,
        "changed_seconds":2,"changed_nanoseconds":300})
}

fn native_metadata(file: bool) -> Value {
    json!({"platform":"windows","identity":{"device":9,"fileId":[if file {91} else {7},1u64<<63]},
        "kind":if file {"file"} else {"directory"},"size":if file {OLD.len()} else {0},
        "creationTime":116_444_736_000_000_001i64,"lastAccessTime":116_444_736_000_000_001i64,
        "lastWriteTime":116_444_736_010_000_002i64,"changeTime":116_444_736_020_000_003i64,
        "attributes":if file {32} else {16},"linkCount":1,"reparseTag":0})
}

fn manifest(deletion_only: bool) -> BundleManifest {
    let app = CANONICAL_APP;
    let hex = |value: &str| {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let token = format!(
        "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
        hex(app),
        hex(ROOT_ID)
    );
    let mut selected = file(LEAF, NEW);
    selected.logical_root = token.clone();
    selected.source_path_hint = Some(r"C:\never-open-this-source-hint\foreign-parent".into());
    selected.mode = None;
    selected.uid = None;
    selected.gid = None;
    selected.mtime_ns = Some(1_000_000_200);
    let mut manifest = crate::tests::test_manifest(if deletion_only {
        vec![]
    } else {
        vec![selected]
    });
    manifest.app.app_id = AppId(app.into());
    manifest.mode = BackupMode::CompleteApplication;
    let identity = json!({"device":9,"fileId":[7,1u64<<63]});
    let source_root = json!({"id":ROOT_ID,"path":r"C:\never-open-this-original-parent",
        "identity":identity,"role":"save","allowedFiles":[LEAF]});
    let tracking = json!({"softwareId":WORKSPACE_SOFTWARE,"appId":SOFTWARE_INSTANCE,
        "roots":[source_root]});
    let deleted = if deletion_only {
        json!([{"id":leaf_id(),"logicalRoot":token,"path":LEAF,"kind":"file",
            "size":OLD.len(),"stamp":stamp(true),"metadata":native_metadata(true),
            "fileHash":blake3::hash(OLD).to_hex().to_string(),"linkTargetHash":null}])
    } else {
        json!([])
    };
    let original_deleted = if deletion_only {
        let mut row = deleted[0].clone();
        row.as_object_mut().unwrap().remove("logicalRoot");
        row["rootId"] = json!(ROOT_ID);
        json!([row])
    } else {
        json!([])
    };
    let deleted_ids = if deletion_only {
        vec![leaf_id()]
    } else {
        vec![]
    };
    let baseline = if deletion_only {
        json!({"kind":"partial","snapshotIdentity":"c".repeat(64),
            "reference":{"name":"original-baseline","hash":"d".repeat(64)},
            "scope":{"name":"original-baseline","hash":"d".repeat(64)}})
    } else {
        json!({"kind":"none","snapshotIdentity":null,"reference":null,"scope":null})
    };
    let evidence = json!({
        "version":1,"workId":"manual-fixture-work","softwareId":WORKSPACE_SOFTWARE,
        "sourceIdentity":{"app_id":app},"providerId":"fixture","generation":1,
        "metadataIdentity":"a".repeat(64),"fullScope":true,"completeFileList":true,
        "keepsVersionHistory":true,"coverageScope":"approved_evidenced_roots_only",
        "expectedFullScope":{"grant":{"syntheticNativeOwnerOnly":true},"scope":{
            "version":1,"workId":"manual-fixture-work","softwareId":WORKSPACE_SOFTWARE,
            "providerId":"fixture","generation":1,"metadataIdentity":"a".repeat(64),
            "trackingScopeHash":digest(&tracking),"rootIds":[ROOT_ID],
            "expectedNodeIdsHash":digest(&if deletion_only {vec![]} else {vec![leaf_id()]}),
            "deletedNodeIdsHash":digest(&deleted_ids),"baselineKind":baseline["kind"],
            "baselineIdentity":baseline["snapshotIdentity"],"snapshotMode":"additive_full_scope",
            "keepsHistory":true}},
        "authorization":{"trackingScope":tracking,"trackingGrant":{"syntheticNativeOwnerOnly":true}},
        "roots":[source_root],"rootMetadata":{},"rootStamps":{},
        "deletedFileIds":deleted_ids,"deletedNodes":original_deleted,"baseline":baseline,
    });
    let parent = deletion_only.then(Uuid::new_v4);
    manifest.parent_bundle_id = parent;
    if deletion_only {
        manifest.tombstones.push(ManifestTombstone {
            logical_root: token.clone(),
            relative_path: LEAF.into(),
            reason: "authenticated manual leaf omission; prior version retained".into(),
        });
    }
    manifest.environment = json!({
        "quicksave_native":{"platform":"windows","coverage":"full_approved_scope",
            "software_instance_id":SOFTWARE_INSTANCE,"full_scope":{
                "version":1,"evidenceHash":digest(&evidence),"originalTrackerEvidence":evidence,
                "rootCaptures":[{"id":ROOT_ID,"logicalRoot":token,"kind":"directory",
                    "stamp":stamp(false),"metadata":null,"allowedFiles":[LEAF],
                    "metadataScope":{"version":1,"kind":"manual_leaves_only",
                        "sourceRootId":ROOT_ID,"sourceRootIdentity":identity,
                        "allowedFilesDigest":digest(&vec![LEAF])}}],
                "deletedNodes":deleted,"operationId":"manual-fixture-work",
                "sourceParent":parent,"sourceParentManifestHash":parent.map(|_|format!("blake3:{}","b".repeat(64))),
                "keepsVersionHistory":true}},
        "quicksave_native_root_layouts":{"version":1,"platform":"windows","app_id":app,
            "software_instance_id":SOFTWARE_INSTANCE,"roots":[{
                "logical_root":token,"root_id":ROOT_ID,"role":"save",
                "source_kind":"directory","leaf_name":"Original Parent"}]},
    });
    manifest
}

fn policy(manifest: &BundleManifest) -> Result<windows_contract::RootMetadata> {
    let layout = native_root_layouts(manifest)?.unwrap();
    windows_contract::WindowsRootMetadata::new(manifest, &layout)?.root(&layout.roots[0])
}

fn whole_directory_proof(manifest: &mut BundleManifest) {
    let ids = if manifest.files.is_empty() {
        vec![]
    } else {
        vec![leaf_id()]
    };
    let full = &mut manifest.environment["quicksave_native"]["full_scope"];
    let capture = &mut full["rootCaptures"][0];
    capture.as_object_mut().unwrap().remove("metadataScope");
    capture["allowedFiles"] = Value::Null;
    capture["metadata"] = native_metadata(false);
    let stamp = capture["stamp"].clone();
    let metadata = capture["metadata"].clone();
    let evidence = &mut full["originalTrackerEvidence"];
    evidence["roots"][0]["allowedFiles"] = Value::Null;
    evidence["authorization"]["trackingScope"]["roots"][0]["allowedFiles"] = Value::Null;
    evidence["rootMetadata"][ROOT_ID] = metadata;
    evidence["rootStamps"][ROOT_ID] = stamp;
    let tracking_digest = digest(&evidence["authorization"]["trackingScope"]);
    evidence["expectedFullScope"]["scope"]["trackingScopeHash"] = json!(tracking_digest);
    evidence["expectedFullScope"]["scope"]["expectedNodeIdsHash"] = json!(digest(&ids));
    let evidence_digest = digest(evidence);
    full["evidenceHash"] = json!(evidence_digest);
}

// Only unsigned synthetic fixture variants are rehashed. The production parser
// verifies original evidence read-only; it never adds fields or repairs a MAC.
fn refresh_fixture_proof_hashes(manifest: &mut BundleManifest) {
    let full = &mut manifest.environment["quicksave_native"]["full_scope"];
    let evidence = &mut full["originalTrackerEvidence"];
    let tracking_digest = digest(&evidence["authorization"]["trackingScope"]);
    evidence["expectedFullScope"]["scope"]["trackingScopeHash"] = json!(tracking_digest);
    let evidence_digest = digest(evidence);
    full["evidenceHash"] = json!(evidence_digest);
}

#[test]
fn windows_source_proof_distinguishes_three_ids_and_needs_no_tracking_provider() {
    let valid = manifest(false);
    let original = &valid.environment["quicksave_native"]["full_scope"]["originalTrackerEvidence"];
    let tracking = &original["authorization"]["trackingScope"];
    assert_eq!(valid.app.app_id.as_str(), CANONICAL_APP);
    assert_eq!(original["sourceIdentity"]["app_id"], CANONICAL_APP);
    assert_eq!(tracking["appId"], SOFTWARE_INSTANCE);
    assert_eq!(tracking["softwareId"], WORKSPACE_SOFTWARE);
    assert_eq!(original["softwareId"], WORKSPACE_SOFTWARE);
    assert!(tracking.get("providerId").is_none());
    let original_bytes = serde_json::to_vec(original).unwrap();
    assert_eq!(
        policy(&valid).unwrap(),
        windows_contract::RootMetadata::ManualLeavesOnly
    );
    assert_eq!(
        serde_json::to_vec(original).unwrap(),
        original_bytes,
        "validation cannot rewrite existing authenticated source evidence"
    );

    for (pointer, value) in [
        (
            "/authorization/trackingScope/appId",
            json!("steam:480@another-instance"),
        ),
        ("/authorization/trackingScope/appId", Value::Null),
        (
            "/authorization/trackingScope/softwareId",
            json!("another-workspace-software"),
        ),
        ("/softwareId", json!(SOFTWARE_INSTANCE)),
        (
            "/expectedFullScope/scope/softwareId",
            json!(SOFTWARE_INSTANCE),
        ),
        (
            "/expectedFullScope/scope/providerId",
            json!("another-provider"),
        ),
        ("/providerId", json!("another-provider")),
        ("/providerId", Value::Null),
        ("/sourceIdentity/app_id", json!(SOFTWARE_INSTANCE)),
    ] {
        let mut changed = valid.clone();
        *changed.environment["quicksave_native"]["full_scope"]["originalTrackerEvidence"]
            .pointer_mut(pointer)
            .unwrap() = value;
        refresh_fixture_proof_hashes(&mut changed);
        assert!(policy(&changed).is_err(), "{pointer}");
    }
    let mut wrong_layout = valid.clone();
    wrong_layout.environment["quicksave_native"]["software_instance_id"] =
        json!("steam:480@another-instance");
    wrong_layout.environment["quicksave_native_root_layouts"]["software_instance_id"] =
        json!("steam:480@another-instance");
    assert!(policy(&wrong_layout).is_err());
    let mut missing_provider = valid.clone();
    let evidence = &mut missing_provider.environment["quicksave_native"]["full_scope"]
        ["originalTrackerEvidence"];
    evidence.as_object_mut().unwrap().remove("providerId");
    evidence["expectedFullScope"]["scope"]
        .as_object_mut()
        .unwrap()
        .remove("providerId");
    refresh_fixture_proof_hashes(&mut missing_provider);
    assert!(policy(&missing_provider).is_err());
    let mut wrong_work = valid;
    wrong_work.environment["quicksave_native"]["full_scope"]["operationId"] = json!("another-work");
    assert!(policy(&wrong_work).is_err());
}

#[test]
fn windows_null_parent_metadata_needs_exact_versioned_manual_leaf_proof_without_os_probe() {
    let valid = manifest(false);
    assert_eq!(
        policy(&valid).unwrap(),
        windows_contract::RootMetadata::ManualLeavesOnly
    );
    for (pointer, value) in [
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope",
            Value::Null,
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope/version",
            json!(2),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope/kind",
            json!("whole_root"),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope/sourceRootId",
            json!("another"),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope/sourceRootIdentity/fileId/1",
            json!(0),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadataScope/allowedFilesDigest",
            json!("0".repeat(64)),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/metadata",
            native_metadata(false),
        ),
        (
            "/quicksave_native/full_scope/rootCaptures/0/allowedFiles",
            json!([]),
        ),
    ] {
        let mut changed = valid.clone();
        *changed.environment.pointer_mut(pointer).unwrap() = value;
        assert!(policy(&changed).is_err(), "{pointer}");
    }
    let mut sibling = valid.clone();
    sibling.files[0].relative_path = "unselected-sibling.dat".into();
    assert!(policy(&sibling).is_err());
    let mut directory = valid.clone();
    directory.files[0].file_type = "directory".into();
    assert!(policy(&directory).is_err());
    let mut unix_permissions = valid.clone();
    unix_permissions.files[0].uid = Some(0);
    assert!(policy(&unix_permissions).is_err());
    let mut promoted = valid;
    let capture = &mut promoted.environment["quicksave_native"]["full_scope"]["rootCaptures"][0];
    capture.as_object_mut().unwrap().remove("metadataScope");
    capture["allowedFiles"] = Value::Null;
    capture["metadata"] = native_metadata(false);
    assert!(
        policy(&promoted).is_err(),
        "a native metadata stat cannot promote original manual-leaf grants to whole-root authority"
    );
}

#[test]
fn unknown_windows_root_metadata_is_files_only_and_empty_root_needs_actual_native_metadata() {
    let mut unknown = manifest(false);
    let capture = &mut unknown.environment["quicksave_native"]["full_scope"]["rootCaptures"][0];
    capture.as_object_mut().unwrap().remove("metadataScope");
    capture["allowedFiles"] = Value::Null;
    unknown.environment["quicksave_native"]["full_scope"]
        .as_object_mut()
        .unwrap()
        .remove("originalTrackerEvidence");
    assert_eq!(
        policy(&unknown).unwrap(),
        windows_contract::RootMetadata::UnknownFilesOnly
    );
    unknown.files.clear();
    assert!(
        policy(&unknown).is_err(),
        "null is not whole/empty root authority"
    );
    let mut genuine = manifest(false);
    genuine.files.clear();
    whole_directory_proof(&mut genuine);
    assert_eq!(
        policy(&genuine).unwrap(),
        windows_contract::RootMetadata::Captured(1_000_000_200)
    );
    genuine.environment["quicksave_native"]["full_scope"]["rootCaptures"][0]["owner"] = json!(0);
    assert!(
        policy(&genuine).is_err(),
        "unsupported legacy Unix ownership is explicit"
    );
}

#[tokio::test]
async fn windows_manual_leaf_frame_uses_shared_pipeline_without_parent_metadata_or_foreign_sibling_capture(
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let fixture = Fixture::new();
    let manifest = manifest(false);
    let mapping = native_restore_layout(&manifest, &fixture.destination).unwrap();
    let mapped = mapping.roots.values().next().unwrap().clone();
    let roots = logical_root_map(&mapping.roots).unwrap();
    fs::create_dir_all(mapped.join("nested")).unwrap();
    fs::write(mapped.join(LEAF), OLD).unwrap();
    let sibling = mapped.join("unselected-sibling.dat");
    fs::write(&sibling, b"foreign data must never be copied or deleted").unwrap();
    fs::set_permissions(&mapped, fs::Permissions::from_mode(0o750)).unwrap();
    let sibling_before = fs::metadata(&sibling).unwrap();
    let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
    let preview = NativeRestorePreview::prepare(
        Uuid::new_v4(),
        &plan.manifest,
        &roots,
        &fixture.destination,
        filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
        NativeConflictMode::Overwrite,
    )
    .unwrap();
    assert!(preview.root_entries[0].is_scaffold_root());
    assert_eq!(preview.root_entries[0].action, NativeRestoreAction::Reuse);
    assert!(!preview.reconstruction_eligible());
    // A foreign sibling update changes parent times, not the selected-file or
    // native ancestor identity approval. It must not become captured metadata.
    fs::write(
        mapped.join("another-foreign-sibling"),
        b"also outside the exact leaf",
    )
    .unwrap();
    let parent_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_500_000_000);
    fs::File::open(&mapped)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(parent_time))
        .unwrap();
    preview.validate_native_destination().unwrap();
    let control = Arc::new(
        NativeRestoreControl::approve(
            preview,
            Arc::new(TestAuthority([73; 32])),
            Arc::new(|| Ok(())),
        )
        .unwrap(),
    );
    let master = MasterKey::generate();
    let storage = LocalStorage::new(fixture.root.join("provider"));
    let packs = noland_pack::pack_chunks(
        &fixture.root.join("packs"),
        &master,
        [(noland_cas::blake3_hex(NEW), NEW.to_vec())],
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
        &plan.manifest,
        &objects,
        Some(&serde_json::to_vec(&index).unwrap()),
        None,
    )
    .await
    .unwrap();
    let shared = plan.into_shared().with_native_control(Arc::clone(&control));
    let report = restore_pipelined(
        &storage,
        &master,
        &shared,
        &index,
        &roots,
        None,
        None,
        PipelineOptions::default(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(fs::read(mapped.join(LEAF)).unwrap(), NEW);
    assert_eq!(
        fs::read(&sibling).unwrap(),
        b"foreign data must never be copied or deleted"
    );
    assert_eq!(
        filesystem::file_id(&fs::metadata(&sibling).unwrap()),
        filesystem::file_id(&sibling_before)
    );
    let parent = fs::metadata(&mapped).unwrap();
    assert_eq!(parent.mode() & 0o7777, 0o750);
    assert_eq!(
        parent.mtime(),
        1_500_000_000,
        "source parent metadata was never applied"
    );
    assert_eq!(report.io.native_original_capture_bytes, OLD.len() as u64);
    assert_eq!(
        report.io.native_original_copy_bytes + report.io.native_original_cow_bytes,
        OLD.len() as u64
    );
    assert_eq!(report.io.readback_bytes, 0);
    assert!(shared
        .verify_native_completion()
        .unwrap()
        .is_clean_committed());
    let reconstruction = report.io.commit.native_reconstruction.unwrap();
    assert_eq!(reconstruction.readiness.as_str(), "files_only");
    assert!(!reconstruction.runnable);
    assert!(reconstruction
        .diagnostics
        .iter()
        .any(|value| value == "source_parent_metadata_not_captured_destination_scaffold_only"));
}

#[test]
fn manual_last_leaf_deletion_preserves_prior_ids_without_creating_an_empty_parent_application() {
    for existing in [false, true] {
        let fixture = Fixture::new();
        let manifest = manifest(true);
        assert_eq!(
            policy(&manifest).unwrap(),
            windows_contract::RootMetadata::ManualLeavesOnly
        );
        let mapping = native_restore_layout(&manifest, &fixture.destination).unwrap();
        let mapped = mapping.roots.values().next().unwrap().clone();
        let roots = logical_root_map(&mapping.roots).unwrap();
        if existing {
            fs::create_dir_all(mapped.join("nested")).unwrap();
            fs::write(mapped.join(LEAF), OLD).unwrap();
            fs::write(
                mapped.join("foreign-sibling"),
                b"foreign survives deletion-only scope",
            )
            .unwrap();
        }
        let plan = crate::tests::crash_test_plan(&fixture.paths, manifest);
        let preview = NativeRestorePreview::prepare(
            Uuid::new_v4(),
            &plan.manifest,
            &roots,
            &fixture.destination,
            filesystem::file_id(&fs::metadata(&fixture.destination).unwrap()),
            NativeConflictMode::Overwrite,
        )
        .unwrap();
        let control = Arc::new(
            NativeRestoreControl::approve(
                preview,
                Arc::new(TestAuthority([73; 32])),
                Arc::new(|| Ok(())),
            )
            .unwrap(),
        );
        let mut transaction =
            RestoreTransaction::new_native(&plan, &roots, Arc::clone(&control)).unwrap();
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        let metrics = transaction.commit_with_metrics().unwrap();
        assert!(metrics.native_completion.unwrap().is_clean_committed());
        let reconstruction = metrics.native_reconstruction.unwrap();
        assert!(!reconstruction.layout_reconstructed);
        assert!(!reconstruction.runnable);
        assert_eq!(
            plan.manifest.environment["quicksave_native"]["full_scope"]["deletedNodes"][0]["id"],
            leaf_id()
        );
        assert!(plan.manifest.parent_bundle_id.is_some());
        assert!(!mapped.join(LEAF).exists());
        if existing {
            assert_eq!(
                fs::read(mapped.join("foreign-sibling")).unwrap(),
                b"foreign survives deletion-only scope"
            );
        } else {
            assert!(
                !mapped.exists(),
                "manual metadata:null never creates an empty source parent"
            );
        }
    }
    let mut lost_history = manifest(true);
    lost_history.environment["quicksave_native"]["full_scope"]["deletedNodes"] = json!([]);
    assert!(policy(&lost_history).is_err());
}
