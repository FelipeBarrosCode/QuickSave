// SPDX-License-Identifier: GPL-3.0-only
//! Actual shared catalog/deletion formats in isolated LocalStorage. No helper,
//! OS vault, installed application or provider account is accessed.
use super::*;
use crate::windows::tests::Fixture;
use noland_state_core::{
    BackupMode, CatalogDocument, CatalogInstance, ManifestApp, ManifestSource,
};
use noland_storage::{LocalStorage, MetadataBatch, MetadataWrite, RemoteKey};

#[tokio::test]
async fn typed_current_catalog_keeps_heads_instances_lineage_pending_and_unknown_requested_scope() {
    let fixture = Fixture::new();
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    engine
        .install_operation_authority(Arc::new(|bytes| {
            Ok(*blake3::keyed_hash(&[37; 32], bytes).as_bytes())
        }))
        .unwrap();
    let access = PrivateAccess {
        provider: "fixture".into(),
        session: EphemeralRcloneSession {
            operation_id: Uuid::new_v4().to_string(),
            provider: "local".into(),
            backend_type: "local".into(),
            remote_name: "isolated_catalog".into(),
            root: "isolated_catalog:fixture".into(),
            config_ini: "[isolated_catalog]\ntype = local\n".into(),
            expires_at_unix: i64::MAX,
            upload_concurrency: None,
        },
        master: MasterKey::from_bytes([17; 32]),
        read_only: false,
        authority_revision: Some(4),
        _sink: None,
        lifecycle: None,
    };
    let storage = LocalStorage::new(fixture.root.join("remote"));
    let app = AppId::steam(480);
    let mut document = CatalogDocument::empty();
    let mut parent = None;
    let mut latest = None;
    // These are synthetic catalog records, not a claim of app-wide consistency
    // or reconstruction. Both modes and the source-instance history stay intact.
    for mode in [BackupMode::Custom, BackupMode::PersonalState] {
        let mut manifest = BundleManifest::new(
            ManifestApp::from(&AppIdentity::new(app.clone(), "Catalog fixture")),
            ManifestSource {
                instance_id: engine.inner.instance,
                image_id: "isolated-fixture".into(),
                captured_at: chrono::Utc::now(),
            },
            mode,
        );
        manifest.parent_bundle_id = parent;
        manifest.environment = json!({"platform":"windows","quicksave_native":{
            "coverage":if mode == BackupMode::Custom {"selected_nodes"} else {"personal_state"},
        }});
        noland_storage::commit_bundle_with_index(
            &storage,
            &access.master,
            &manifest,
            &[],
            None,
            None,
        )
        .await
        .unwrap();
        document =
            noland_storage::update_catalog_with_bundle(&storage, &access.master, &manifest, 0)
                .await
                .unwrap();
        parent = Some(manifest.bundle_id);
        latest = Some(manifest);
    }
    let latest = latest.unwrap();
    document.instances.push(CatalogInstance {
        instance_id: engine.inner.instance,
        image_id: "isolated-fixture".into(),
        last_seal: None,
    });
    document.catalog_commit_id = Uuid::new_v4();
    // Seed the typed document with the source's actual catalog/COMMITTED/LATEST
    // format; write_catalog is deliberately not exported by the library.
    let catalog_key = noland_crypto::derive_keys(&access.master).catalog;
    let sealed = noland_storage::seal_metadata(&catalog_key, b"catalog", &document).unwrap();
    storage
        .put_metadata_batch(&MetadataBatch::with_committed(
            vec![MetadataWrite::new(
                RemoteKey::new(noland_state_core::catalog_commit_key(
                    document.catalog_commit_id,
                )),
                bytes::Bytes::from(sealed.envelope),
            )],
            MetadataWrite::new(
                RemoteKey::new(format!(
                    "catalog/commits/{}.COMMITTED",
                    document.catalog_commit_id
                )),
                bytes::Bytes::from_static(b"COMMITTED"),
            ),
        ))
        .await
        .unwrap();
    storage
        .put_small_versioned(
            bytes::Bytes::from(document.catalog_commit_id.to_string()),
            &RemoteKey::new("catalog/LATEST"),
        )
        .await
        .unwrap();
    let scope = private_key(&engine.inner, &access).unwrap();
    let before = read_catalog_current(&engine.inner, &access, &storage, &scope)
        .await
        .unwrap()
        .projection;
    assert_pure_projection(&before);
    assert_eq!(before["heads"], json!([app]));
    assert_eq!(
        before["instances"][0]["instanceId"],
        engine.inner.instance.to_string()
    );
    assert_eq!(
        before["apps"][0]["headsByMode"]["personalState"],
        latest.bundle_id.to_string()
    );
    assert!(before["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["completeness"] == "unknown"));
    let authenticated = read_committed_manifest(&storage, &access.master, &app, latest.bundle_id)
        .await
        .unwrap();
    remember_manifest(&engine.inner, &access, &authenticated).unwrap();
    let current = read_catalog_current(&engine.inner, &access, &storage, &scope)
        .await
        .unwrap();
    assert!(current.metrics["metadataProviderIo"].is_object());
    let detailed = current.projection;
    assert_pure_projection(&detailed);
    assert_ne!(detailed["revision"], before["revision"]);
    let row = detailed["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == latest.bundle_id.to_string())
        .unwrap();
    assert_eq!(row["completeness"], "personal_state");
    assert_eq!(row["commitId"], latest.commit_id.to_string());
    assert_eq!(row["sourceInstanceId"], engine.inner.instance.to_string());
    assert_eq!(row["parentBundleId"], json!(latest.parent_bundle_id));
    assert_eq!(detailed["authoritativeForExecution"], false);
    assert_eq!(detailed["freshness"]["source"], "live_remote_validation");
    assert!(detailed.get("catalogMetrics").is_none());
    let mut coalesced = detailed.clone();
    coalesced["freshness"]["coalesced"] = json!(true);
    assert_pure_projection(&coalesced);

    let plan = prepare_full_deletion_selected(
        &storage,
        &access.master,
        &[(app.clone(), latest.bundle_id)],
        Uuid::new_v4(),
        "isolated-owner",
    )
    .await
    .unwrap();
    // Seed a pending intent using the actual source framing, without executing
    // deletion or manufacturing the typed plan from incoming UI JSON.
    let key = noland_crypto::derive_keys(&access.master).catalog;
    for (name, aad, bytes) in [
        (
            format!("deletions/plans/{}.enc", plan.plan_id),
            b"full-deletion-plan-v1".as_slice(),
            serde_json::to_vec(&plan).unwrap(),
        ),
        (
            format!("maintenance/pending/{}.enc", plan.plan_id),
            b"pending-deletion-v1".as_slice(),
            serde_json::to_vec(&plan.plan_id).unwrap(),
        ),
    ] {
        let sealed = noland_storage::seal_metadata_json(&key, aad, &bytes).unwrap();
        storage
            .put_small_versioned(bytes::Bytes::from(sealed.envelope), &RemoteKey::new(name))
            .await
            .unwrap();
    }
    let pending = read_catalog_current(&engine.inner, &access, &storage, &scope)
        .await
        .unwrap()
        .projection;
    assert_pure_projection(&pending);
    assert_ne!(pending["revision"], detailed["revision"]);
    assert_eq!(
        pending["pendingDeletions"][0]["planId"],
        plan.plan_id.to_string()
    );
    assert_eq!(
        pending["pendingDeletions"][0]["targets"][0]["commitId"],
        latest.commit_id.to_string()
    );
    assert!(pending["pendingDeletions"][0]["requested"].is_null());
    assert!(pending["pendingDeletions"][0]["dependencies"].is_null());
    let selected = vec![DeletionSelection {
        app_id: app.to_string(),
        bundle_id: latest.bundle_id.to_string(),
    }];
    remember_requested(&engine.inner, &access, &plan, selected).unwrap();
    let bound = read_catalog_current(&engine.inner, &access, &storage, &scope)
        .await
        .unwrap()
        .projection;
    assert_pure_projection(&bound);
    assert_ne!(bound["revision"], pending["revision"]);
    assert_eq!(
        bound["pendingDeletions"][0]["requested"][0]["bundleId"],
        latest.bundle_id.to_string()
    );
    assert_eq!(bound["pendingDeletions"][0]["dependencies"], json!([]));
    engine
        .inner
        .catalog
        .lock()
        .unwrap()
        .requested
        .get_mut(&(scope.clone(), plan.plan_id))
        .unwrap()
        .device_mac[31] ^= 1;
    assert!(
        read_catalog_current(&engine.inner, &access, &storage, &scope)
            .await
            .is_err()
    );
    assert!(engine.inner.runtime.get().is_none());
}

#[test]
fn paging_clones_only_requested_rows_and_binds_revision_without_repeating_full_metadata() {
    let snapshot = json!({
        "projectionVersion":1,"providerId":"fixture","revision":"a".repeat(64),
        "bundles":[{"id":"one"},{"id":"two"},{"id":"three"}],"apps":[{"bundleIds":["one","two","three"]}],
        "heads":["steam:480"],"instances":[{"instanceId":Uuid::new_v4()}],"pendingDeletions":[{}],
        "freshness":{"source":"live_remote_validation","observedAt":"2026-11-17T00:00:00Z"},
        "authoritativeForExecution":false,
    });
    let first = catalog_page(&snapshot, &json!({"limit":1}), true).unwrap();
    assert_eq!(first["bundles"], json!([{"id":"one"}]));
    let second = catalog_page(
        &snapshot,
        &json!({"limit":1,"cursor":first["nextCursor"]}),
        false,
    )
    .unwrap();
    assert_eq!(second["bundles"], json!([{"id":"two"}]));
    for field in [
        "apps",
        "heads",
        "instances",
        "pendingDeletions",
        "catalogMetrics",
    ] {
        assert!(second.get(field).is_none(), "{field}");
    }
    assert_eq!(second["freshness"]["source"], "immutable_revision_page");
    assert_eq!(second["catalogRevision"], snapshot["revision"]);
    let mut changed = snapshot.clone();
    changed["revision"] = json!("b".repeat(64));
    assert!(catalog_page(
        &changed,
        &json!({"limit":1,"cursor":first["nextCursor"]}),
        false
    )
    .is_err());
    let mut state = CatalogState::default();
    state.snapshots.insert(
        "old".into(),
        Snapshot {
            value: Arc::new(snapshot),
            _metrics: json!({}),
            bytes: MAX_CATALOG_BYTES,
            completed: Instant::now(),
        },
    );
    state.reserve(1024).unwrap();
    assert!(state.snapshots.is_empty());
    assert!(state.used() + 1024 <= MAX_CATALOG_BYTES);
    assert!(state.reserve(MAX_CATALOG_BYTES + 1).is_err());
}

fn assert_pure_projection(value: &Value) {
    let expected = [
        "projectionVersion",
        "providerId",
        "schemaVersion",
        "catalogCommitId",
        "createdAt",
        "heads",
        "apps",
        "bundles",
        "instances",
        "pendingDeletions",
        "revision",
        "freshness",
        "authoritativeForExecution",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected,
        "Service must receive only the exact shared catalog projection fields"
    );
    let mut hashed = value.clone();
    for field in ["revision", "freshness", "authoritativeForExecution"] {
        hashed.as_object_mut().unwrap().remove(field);
    }
    assert_eq!(
        value["revision"],
        blake3::hash(&serde_json::to_vec(&hashed).unwrap())
            .to_hex()
            .to_string(),
        "per-request freshness and private I/O metrics never enter revision hashing"
    );
}
