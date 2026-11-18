// SPDX-License-Identifier: GPL-3.0-only
//! Isolated controller fixtures, not Windows runtime/packaging acceptance.
use super::*;
use noland_state_core::{ManifestApp, ManifestSource};

fn preview() -> NativeRestorePreview {
    NativeRestorePreview {
        version: 1,
        job_id: Uuid::new_v4(),
        bundle_id: Uuid::new_v4(),
        app_id: AppId("steam:480".into()),
        destination: PathBuf::from(r"C:\isolated-fixture\destination"),
        destination_identity: NativeObjectId {
            device: 17,
            file_id: [23, 1 << 63],
        },
        conflict_mode: NativeConflictMode::Overwrite,
        mode: RestoreMode::CompleteApplication,
        expected_payload: format!("blake3:{}", "a".repeat(64)),
        parents: BTreeMap::new(),
        entries: Vec::new(),
        tombstones: Vec::new(),
        root_mappings: BTreeMap::new(),
        root_layout: None,
        entire_manifest: true,
        source_full_scope: false,
        source_app_name: "Fixture".into(),
        root_entries: Vec::new(),
    }
}

fn document() -> RestoreDocument {
    let preview = preview();
    let id = Uuid::new_v4();
    RestoreDocument {
        version: 1,
        instance: Uuid::new_v4(),
        provider: "fixture".into(),
        storage: "1".repeat(64),
        preview_id: id,
        fingerprint: fingerprint("fixture", id, &preview).unwrap(),
        commit: Uuid::new_v4(),
        manifest_hash: format!("blake3:{}", "2".repeat(64)),
        preview,
        device_mac: [7; 32],
    }
}

#[test]
fn download_requires_original_ticket_and_rejects_editable_legacy_arguments() {
    let id = Uuid::new_v4();
    assert!(
        validate_download_request(&json!({"restorePreviewId":id,"operationId":Uuid::new_v4(),
        "overwriteAcknowledgement":false,"_approvedPaths":[]}))
        .is_ok()
    );
    for addition in [
        "destination",
        "fileIds",
        "mappings",
        "appId",
        "bundleId",
        "mode",
    ] {
        let mut value = json!({"restorePreviewId":id});
        value[addition] = json!("not authority");
        assert!(validate_download_request(&value).is_err(), "{addition}");
    }
    assert!(validate_download_request(&json!({"destination":r"C:\new"})).is_err());
    assert!(validate_download_request(
        &json!({"restorePreviewId":id,"overwriteAcknowledgement":"true"})
    )
    .is_err());
}

#[test]
fn root_scope_and_approval_keep_every_native_id_bit() {
    let preview = preview();
    let proof = root_scope(&preview);
    assert_eq!(proof[0]["identity"]["fileId"][1], 1u64 << 63);
    let mut request = json!({"_approvedPaths":proof});
    check_approved_root(&request, &preview).unwrap();
    request["_approvedPaths"][0]["identity"]["fileId"][1] = json!(0);
    assert!(check_approved_root(&request, &preview).is_err());
    assert!(check_approved_root(&json!({}), &preview).is_err());
}

#[test]
fn local_document_and_scope_digest_bind_exact_job_provider_preview_and_full_ids() {
    let mut document = document();
    validate_description(&document, document.preview.job_id, document.instance).unwrap();
    let digest = document_digest(&document).unwrap();
    let message = document_message(&document).unwrap();
    let mac = *blake3::keyed_hash(&[9; 32], &message).as_bytes();
    document.preview.destination_identity.file_id[1] ^= 1;
    assert_ne!(document_digest(&document).unwrap(), digest);
    assert!(!constant_equal(
        &mac,
        blake3::keyed_hash(&[9; 32], &document_message(&document).unwrap()).as_bytes()
    ));
    assert!(validate_description(&document, document.preview.job_id, document.instance).is_err());
}

#[test]
fn provider_binding_preserves_read_only_and_refresh_does_not_change_preview_authority() {
    let mut private = PrivateAccess {
        provider: "fixture".into(),
        session: EphemeralRcloneSession {
            operation_id: Uuid::new_v4().to_string(),
            provider: "onedrive".into(),
            backend_type: "onedrive".into(),
            remote_name: "native-fixture".into(),
            root: "approved-root".into(),
            config_ini: "synthetic config; never executed".into(),
            expires_at_unix: 1,
            upload_concurrency: None,
        },
        master: MasterKey::from_bytes([17; 32]),
        read_only: true,
        authority_revision: Some(7),
        _sink: None,
        lifecycle: None,
    };
    let original = storage_fingerprint(&private).unwrap();
    private.session.config_ini = "synthetic refreshed config; never executed".into();
    private.session.operation_id = Uuid::new_v4().to_string();
    private.session.expires_at_unix = 2;
    assert_eq!(
        storage_fingerprint(&private).unwrap(),
        original,
        "ordinary refresh is neither a namespace change nor new consent"
    );
    assert!(
        private.read_only,
        "imported read-only policy must not be upgraded for reader-claim writes"
    );
    private.authority_revision = Some(8);
    assert_ne!(storage_fingerprint(&private).unwrap(), original);
    private.authority_revision = Some(7);
    private.read_only = false;
    assert_ne!(storage_fingerprint(&private).unwrap(), original);
    private.read_only = true;
    private.session.root = "other-root".into();
    assert_ne!(storage_fingerprint(&private).unwrap(), original);
    private.authority_revision = None;
    assert!(
        storage_fingerprint(&private).is_err(),
        "missing native authority is unsupported, not guessed"
    );
}

#[test]
fn metadata_replacements_need_separate_acknowledgement_too() {
    let mut preview = preview();
    preview
        .root_entries
        .push(noland_restore::NativeRestoreEntry {
            logical_root: "$DOCUMENTS".into(),
            relative_path: String::new(),
            destination_relative: "Root".into(),
            kind: noland_restore::NativeEntryKind::Directory,
            size: 0,
            file_hash: String::new(),
            symlink_target: None,
            target_is_directory: None,
            mode: None,
            mtime_ns: Some(17),
            uid: None,
            gid: None,
            expected: None,
            action: NativeRestoreAction::Metadata,
        });
    assert!(check_ack(&preview, false).is_err());
    check_ack(&preview, true).unwrap();
}

#[test]
fn local_recovery_ids_and_hints_cannot_redirect_or_expand_the_job() {
    let id = Uuid::new_v4();
    assert_eq!(
        recovery_id(&json!({"operationId":id,"jobId":id})).unwrap(),
        id
    );
    assert!(recovery_id(&json!({"operationId":id,"jobId":Uuid::new_v4()})).is_err());
    assert!(recovery_id(&json!({"operationId":Uuid::nil()})).is_err());
    assert!(validate_recovery_request(&json!({"operationId":id,
        "filePlanDigest":"1".repeat(64),"frozenPlanFingerprint":"2".repeat(64),
        "destination":r"C:\elsewhere"}))
    .is_err());
    assert!(!public_recovery(id, &[])["recovered"].as_bool().unwrap());
}

#[test]
fn selected_empty_inventory_requires_real_authenticated_root_layout() {
    let app = AppId("steam:480".into());
    let mut manifest = BundleManifest::new(
        ManifestApp::from(&AppIdentity::new(app.clone(), "Fixture")),
        ManifestSource {
            instance_id: Uuid::new_v4(),
            image_id: "fixture".into(),
            captured_at: chrono::Utc::now(),
        },
        noland_state_core::BackupMode::CompleteApplication,
    );
    assert!(select_payload(&mut manifest, None).is_err());
    let token = logical_token(app.as_str(), "empty-save");
    manifest.environment = json!({
        "quicksave_native":{"platform":"windows","software_instance_id":"steam:480@fixture",
            "full_scope":{"version":1,"rootCaptures":[{"id":"empty-save","logicalRoot":token}]}},
        "quicksave_native_root_layouts":{"version":1,"platform":"windows","app_id":app.as_str(),
            "software_instance_id":"steam:480@fixture","roots":[{
                "logical_root":token,"root_id":"empty-save","role":"save",
                "source_kind":"directory","leaf_name":"Save",
            }]},
    });
    select_payload(&mut manifest, None).unwrap();
    assert!(manifest.files.is_empty());
    assert!(
        select_payload(&mut manifest, Some(&BTreeSet::new())).is_err(),
        "Some([]) must never become wildcard/empty-root authority"
    );
}

#[test]
fn local_scope_and_recovery_need_no_helper_provider_repository_key_or_new_device_key() {
    use crate::windows::tests::Fixture;
    use std::sync::atomic::AtomicUsize;
    struct ExistingDevice {
        calls: Arc<AtomicUsize>,
    }
    impl NativeRecoveryAuthority for ExistingDevice {
        fn mac(&self, bytes: &[u8]) -> noland_state_core::Result<[u8; 32]> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(*blake3::keyed_hash(&[41; 32], bytes).as_bytes())
        }
    }
    let fixture = Fixture::new();
    let data = fixture.root.join("data");
    let home = fixture.root.join("home");
    let home_root = SafeRoot::open(&home).unwrap();
    home_root.create_dir("offline-restore").unwrap();
    let destination = home.join("offline-restore");
    let identity = SafeRoot::open(&destination).unwrap().identity().unwrap();
    let engine = NativeEngine::open(&data, &home).unwrap();
    engine
        .install_authority_guard(Arc::new(|_, _| {
            bail!("provider access must not occur in local recovery")
        }))
        .unwrap();
    engine
        .install_operation_authority(Arc::new(|_| {
            bail!("repository operation keys are not local recovery authority")
        }))
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    engine
        .install_recovery_authority(Arc::new(ExistingDevice {
            calls: Arc::clone(&calls),
        }))
        .unwrap();
    let mut manifest = BundleManifest::new(
        ManifestApp::from(&AppIdentity::new(AppId::steam(480), "Fixture")),
        ManifestSource {
            instance_id: Uuid::new_v4(),
            image_id: "fixture".into(),
            captured_at: chrono::Utc::now(),
        },
        noland_state_core::BackupMode::Custom,
    );
    let logical = noland_state_core::LogicalRoot::Documents.as_token();
    manifest.files.push(noland_state_core::ManifestFile {
        logical_root: logical,
        relative_path: "data.dat".into(),
        source_path_hint: None,
        file_type: "file".into(),
        size: 0,
        file_hash: noland_cas::blake3_hex(b""),
        chunks: Vec::new(),
        mode: None,
        mtime_ns: None,
        uid: None,
        gid: None,
        symlink_target: None,
        persistence_class: noland_state_core::PersistenceClass::PersistentState,
        semantic_role: noland_state_core::SemanticRole::UserState,
        association_confidence: 1.0,
        shared_app_ids: Vec::new(),
    });
    let mappings = noland_state_core::LogicalRootMap {
        documents: Some(destination.join("payload")),
        ..Default::default()
    };
    // Metadata-only stopped job, with no recorded mutation/journal. Recovery
    // must report no workspaces, NOT fabricate clean completion.
    let id = Uuid::new_v4();
    let preview = NativeRestorePreview::prepare(
        id,
        &manifest,
        &mappings,
        &destination,
        NativeObjectId {
            device: identity.device,
            file_id: identity.file_id,
        },
        NativeConflictMode::CreateOnly,
    )
    .unwrap();
    let preview_id = Uuid::new_v4();
    let fingerprint = fingerprint("fixture", preview_id, &preview).unwrap();
    engine
        .persist_restore_document(RestoreDocumentRef {
            version: 1,
            instance: engine.inner.instance,
            provider: "fixture",
            storage: &"a".repeat(64),
            preview_id,
            fingerprint: &fingerprint,
            commit: Uuid::new_v4(),
            manifest_hash: &format!("blake3:{}", "b".repeat(64)),
            preview: &preview,
            device_mac: [0; 32],
        })
        .unwrap();
    let now = chrono::Utc::now();
    engine
        .inner
        .db
        .upsert_operation(&OperationRecord {
            operation_id: id,
            kind: "restore".into(),
            app_id: Some(AppId::steam(480)),
            state: "FAILED".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: json!({}),
        })
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(engine.restore_recovery_available(id).unwrap());
    let destination_root = SafeRoot::open(&destination).unwrap();
    destination_root.create_dir("payload").unwrap();
    destination_root
        .write_new("payload/data.dat", |_| Ok(()))
        .unwrap();
    assert!(
        preview.validate_native_destination().is_err(),
        "an interrupted/local output can legitimately differ from pre-write observations"
    );
    let scope = engine.restore_recovery_scope(&id.to_string()).unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "UI metadata queries cannot access a device key"
    );
    let selection = json!({"operationId":id,"filePlanDigest":scope["filePlanDigest"],
        "frozenPlanFingerprint":scope["frozenPlanFingerprint"],"_approvedPaths":scope["roots"]});
    let result = engine
        .recover_restore_local(selection.clone(), Arc::new(|| Ok(())))
        .unwrap();
    assert_eq!(result["operationId"], id.to_string());
    assert_eq!(result["localOnly"], true);
    assert_eq!(result["newTransferStarted"], false);
    assert_eq!(result["noRecordedWorkspaces"], true);
    assert_eq!(result["recovered"], false);
    assert_eq!(
        destination_root
            .read_file("payload/data.dat")
            .unwrap()
            .1
            .size,
        0,
        "without a recorded authenticated journal, an entry is never cleanup authority"
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "only actual local spend authenticates the existing device key"
    );
    assert!(engine.inner.active.lock().unwrap().is_empty());
    drop(engine);
    let restarted = NativeEngine::open(&data, &home).unwrap();
    assert!(restarted.restore_recovery_available(id).unwrap());
    restarted.restore_recovery_scope(&id.to_string()).unwrap();
    assert!(
        restarted
            .recover_restore_local(selection, Arc::new(|| Ok(())))
            .is_err(),
        "a missing installed/existing device key must fail, never create a replacement"
    );
}
