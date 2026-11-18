// SPDX-License-Identifier: GPL-3.0-only
//! Real Source dependency planning over isolated NLPK/LocalStorage fixtures.
//! Tests do not execute deletion, discover helpers, contact providers or use a vault.
use super::*;
use crate::windows::tests::Fixture;
use noland_state_core::{
    BackupMode, ChunkRef, ManifestApp, ManifestFile, ManifestSource, PersistenceClass, SemanticRole,
};

fn access() -> PrivateAccess {
    PrivateAccess {
        provider: "fixture".into(),
        session: EphemeralRcloneSession {
            operation_id: Uuid::new_v4().to_string(),
            provider: "local".into(),
            backend_type: "local".into(),
            remote_name: "isolated_deletion".into(),
            root: "isolated_deletion:fixture".into(),
            config_ini: "[isolated_deletion]\ntype = local\n".into(),
            expires_at_unix: i64::MAX,
            upload_concurrency: None,
        },
        master: MasterKey::from_bytes([43; 32]),
        read_only: false,
        authority_revision: Some(7),
        _sink: None,
        lifecycle: None,
    }
}

async fn actual_preview(fixture: &Fixture, native: &PrivateAccess) -> Preview {
    SafeRoot::open(&fixture.root)
        .unwrap()
        .create_dir("packs")
        .unwrap();
    let bytes = b"shared exact deletion fixture chunk";
    let hash = noland_cas::blake3_hex(bytes);
    let packs = noland_pack::pack_chunks(
        &fixture.root.join("packs"),
        &native.master,
        [(hash.clone(), bytes.to_vec())],
        |_| false,
    )
    .unwrap();
    let paths = packs
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    let index = packs
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let storage = noland_storage::LocalStorage::new(fixture.root.join("remote"));
    let instance = Uuid::new_v4();
    let mut requested = None;
    for app in [AppId::steam(480), AppId::steam(481)] {
        let mut manifest = BundleManifest::new(
            ManifestApp::from(&AppIdentity::new(app.clone(), "Isolated deletion fixture")),
            ManifestSource {
                instance_id: instance,
                image_id: "isolated-fixture".into(),
                captured_at: chrono::Utc::now(),
            },
            BackupMode::Custom,
        );
        manifest.files.push(ManifestFile {
            logical_root: logical_token(app.as_str(), "save"),
            relative_path: "save.dat".into(),
            source_path_hint: None,
            file_type: "file".into(),
            size: bytes.len() as u64,
            file_hash: hash.clone(),
            chunks: vec![ChunkRef {
                hash: hash.clone(),
                size: bytes.len() as u64,
            }],
            mode: None,
            mtime_ns: None,
            uid: None,
            gid: None,
            symlink_target: None,
            persistence_class: PersistenceClass::PersistentState,
            semantic_role: SemanticRole::UserState,
            association_confidence: 1.0,
            shared_app_ids: Vec::new(),
        });
        noland_storage::commit_bundle_with_pack_index_for_operation(
            &storage,
            &native.master,
            &manifest,
            &paths,
            Some(&index),
            None,
            None,
        )
        .await
        .unwrap();
        noland_storage::update_catalog_with_bundle(&storage, &native.master, &manifest, 0)
            .await
            .unwrap();
        if requested.is_none() {
            requested = Some((app, manifest.bundle_id));
        }
    }
    let (app, bundle) = requested.unwrap();
    let plan = prepare_full_deletion_selected(
        &storage,
        &native.master,
        &[(app.clone(), bundle)],
        Uuid::new_v4(),
        "isolated-owner",
    )
    .await
    .unwrap();
    assert_eq!(plan.requested_count, 1);
    assert_eq!(
        plan.targets.len(),
        2,
        "actual Source shared-pack closure must supply the dependency"
    );
    let frozen = projection(
        &plan,
        &[DeletionSelection {
            app_id: app.to_string(),
            bundle_id: bundle.to_string(),
        }],
    )
    .unwrap();
    Preview {
        provider: native.provider.clone(),
        storage: storage_binding(native).unwrap(),
        plan,
        frozen,
        created: Instant::now(),
    }
}

#[tokio::test]
async fn exact_source_deletion_projection_requires_separate_original_dependency_ack() {
    let fixture = Fixture::new();
    let native = access();
    let mut preview = actual_preview(&fixture, &native).await;
    let summary = summary(&native.provider, &preview.plan, &preview.frozen).unwrap();
    let dependency = &preview.frozen.dependencies.as_ref().unwrap()[0];
    assert_eq!(summary["dependentBundleCount"], 1);
    assert_eq!(
        summary["dependentBundles"],
        json!([{
            "id":dependency.bundle_id,"appId":dependency.app_id,"commitId":dependency.commit_id,
        }])
    );
    assert_eq!(summary["affectedBundles"], json!(preview.frozen.targets));
    assert_eq!(summary["planDigest"], preview.frozen.digest);
    let mut selection = json!({"previewId":preview.plan.plan_id,"providerId":native.provider,
        "acknowledgeDependencies":false});
    assert!(check_preview(&preview, &native, &selection).is_err());
    selection["acknowledgeDependencies"] = json!(true);
    assert!(check_preview(&preview, &native, &selection).unwrap());
    for (field, value) in [
        ("previewId", json!(Uuid::new_v4())),
        ("providerId", json!("different-provider")),
        ("planDigest", json!("f".repeat(64))),
        ("dependentBundles", json!([])),
        ("affectedBundles", json!([])),
        ("acknowledgeDependencies", json!("true")),
    ] {
        let mut changed = selection.clone();
        changed[field] = value;
        assert!(
            check_preview(&preview, &native, &changed).is_err(),
            "{field}"
        );
    }
    let original = preview.plan.targets[0].deletion.commit_id;
    preview.plan.targets[0].deletion.commit_id = Uuid::new_v4();
    assert!(
        check_preview(&preview, &native, &selection).is_err(),
        "same count/IDs cannot acknowledge a changed original commit/digest"
    );
    preview.plan.targets[0].deletion.commit_id = original;
    preview.created = Instant::now() - Duration::from_secs(601);
    assert!(check_preview(&preview, &native, &selection).is_err());
}

#[tokio::test]
async fn frozen_deletion_rejects_changed_repository_scope_without_new_inventory() {
    let fixture = Fixture::new();
    let native = access();
    let preview = actual_preview(&fixture, &native).await;
    let selection = json!({"previewId":preview.plan.plan_id,"acknowledgeDependencies":true});
    let changes: [fn(&mut PrivateAccess); 7] = [
        |value| value.provider = "another-provider".into(),
        |value| value.session.root.push_str("/another-root"),
        |value| value.session.remote_name = "another-account".into(),
        |value| value.session.backend_type = "another-backend".into(),
        |value| value.master = MasterKey::from_bytes([44; 32]),
        |value| value.authority_revision = Some(8),
        |value| value.read_only = true,
    ];
    for change in changes {
        let mut changed = access();
        change(&mut changed);
        assert!(check_preview(&preview, &changed, &selection).is_err());
    }
    let mut rotated = access();
    rotated
        .session
        .config_ini
        .push_str("# synthetic token rotation, no scope change\n");
    assert!(check_preview(&preview, &rotated, &selection).is_ok());
    // Validation is a pure projection of the held plan: no remote objects are
    // needed, and no new dependency closure can be silently authorized.
    std::fs::rename(
        fixture.root.join("remote"),
        fixture.root.join("remote-retained"),
    )
    .unwrap();
    assert!(check_preview(&preview, &native, &selection).is_ok());
}

#[tokio::test]
async fn unguarded_or_revoked_deletion_cannot_consume_preview_discover_helper_or_admit_retry() {
    let fixture = Fixture::new();
    let native = access();
    let preview = actual_preview(&fixture, &native).await;
    let id = preview.plan.plan_id;
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    engine
        .install_authority_guard(Arc::new(|_, _| Ok(())))
        .unwrap();
    let plan = Arc::new(FrozenPlan {
        version: 1,
        api: 22,
        operation: id,
        instance: engine.inner.instance,
        provider: native.provider.clone(),
        storage: native.session.root_cache_key(),
        created_at: chrono::Utc::now(),
        work: Work::Delete {
            plan: preview.plan.clone(),
            dependency_ack: true,
        },
    });
    let selection = json!({"previewId":id,"acknowledgeDependencies":true});
    let public_access = || ProviderAccess {
        provider_id: native.provider.clone(),
        read_only: false,
        repository_key: native.master.0,
        session: serde_json::to_value(&native.session).unwrap(),
    };
    engine.inner.previews.lock().unwrap().insert(id, preview);
    assert!(engine
        .delete(public_access(), selection.clone())
        .await
        .is_err());
    let revoked: PublishGuard = Arc::new(|| bail!("synthetic native ticket revoked"));
    assert!(engine
        .delete_guarded(public_access(), selection, revoked.clone())
        .await
        .is_err());
    assert!(engine.inner.previews.lock().unwrap().contains_key(&id));
    assert!(engine.inner.db.get_operation(id).unwrap().is_none());
    assert!(engine.inner.active.lock().unwrap().is_empty());
    assert!(engine.inner.runtime.get().is_none());
    assert!(check_guard(&plan, None).is_err());
    assert!(check_guard(&plan, Some(&revoked)).is_err());
    assert!(engine.inner.session(&native,Some(revoked.clone()),
        Arc::new(AtomicBool::new(false)),true).is_err(),
        "the existing checked session must reject a revoked operation guard despite global provider permission");
    assert!(
        engine
            .enqueue(plan, access(), None, true, None, None)
            .is_err(),
        "unguarded retry must not fall back to global provider write authority"
    );
    assert!(engine.inner.db.get_operation(id).unwrap().is_none());
    assert!(engine.inner.active.lock().unwrap().is_empty());
}

#[tokio::test]
async fn larger_source_plan_fails_exact_review_bound_instead_of_truncating_dependency_ids() {
    let fixture = Fixture::new();
    let native = access();
    let preview = actual_preview(&fixture, &native).await;
    let mut large = preview.plan.clone();
    let mut requested = Vec::new();
    large.targets.clear();
    for _ in 0..257 {
        let mut target = preview.plan.targets[0].clone();
        target.deletion.bundle_id = Uuid::new_v4();
        target.deletion.commit_id = Uuid::new_v4();
        large.targets.push(target);
    }
    // Synthetic oversized DTO solely tests the wrapper cap. It is never
    // executed/persisted and is not accepted as a Source execution plan.
    requested.push(DeletionSelection {
        app_id: large.targets[0].deletion.app_id.to_string(),
        bundle_id: large.targets[0].deletion.bundle_id.to_string(),
    });
    assert!(projection(&large, &requested).is_err());
}
