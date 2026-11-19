// SPDX-License-Identifier: GPL-3.0-only
//! Real Tracker/WorkspaceStore/MemoryVault -> Windows receipt -> CAS/NLPK ->
//! LocalStorage COMMITTED/AEAD -> native completion. All paths/accounts/keys are
//! isolated fixtures. No rclone, OS vault, provider account or collector is run.
use super::*;
use crate::windows::tests::Fixture;
use quicksave_state::{CredentialVault, MemoryVault, QUICKSAVE_VAULT_SERVICE};
use quicksave_tracking::{NativeCaptureReceipt, Tracker, TrackingPolicy, TrackingStore};

const SOFTWARE: &str = "fixture-software";
const INSTANCE: &str = "steam:480@fixture-installation";
const CANONICAL: &str = "steam:480";

struct Store(WorkspaceStore);
impl TrackingStore for Store {
    fn load_records(&self) -> Result<Vec<Value>> {
        self.0
            .document()?
            .software
            .iter()
            .map(|record| Ok(serde_json::to_value(record)?))
            .collect()
    }
    fn save_record(&self, record: &Value) -> Result<()> {
        self.0.update_software(record)?;
        Ok(())
    }
    fn read_record(&self, id: &str) -> Result<Option<Value>> {
        Ok(Some(self.0.software_record(id)?))
    }
    fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
        self.0.issue_grant(kind, scope)
    }
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
        self.0.verify_grant(kind, scope, grant)
    }
    fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
        self.0.revoke_grant(kind, scope)
    }
    fn provider_writable(&self, id: &str) -> Result<bool> {
        self.0.provider_writable(id)
    }
    fn provider_known(&self, id: &str) -> Result<bool> {
        Ok(self
            .0
            .document()?
            .providers
            .iter()
            .any(|provider| provider.id == id))
    }
}

struct Receipt(Arc<capture::PreparedCaptureReceipt>);
impl NativeCaptureReceipt for Receipt {
    fn evidence(&self) -> Result<Value> {
        self.0.evidence()
    }
    fn revalidate(&self) -> Result<()> {
        self.0.revalidate()
    }
    fn immutable_prepared_capture(&self) -> bool {
        true
    }
}

struct FullOwner {
    tracker: Arc<Tracker>,
    work: String,
    evidence: Value,
}
impl capture::NativeFullScopeAuthority for FullOwner {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        ensure!(
            self.tracker.full_scope_evidence(&self.work)? == self.evidence,
            "original actual Tracker full-scope proof changed"
        );
        Ok(())
    }
}

struct Controller {
    tracker: Arc<Tracker>,
    work: String,
    full: Option<Arc<FullOwner>>,
}
impl capture::NativeCaptureController for Controller {
    fn node_page(
        &self,
        scope: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<capture::FrozenCaptureNode>> {
        let cursor = format!("{}:{}:{offset}", scope.work_id, scope.metadata_identity);
        let page = self
            .tracker
            .prepared_node_listing(&self.work, Some(&cursor), limit)?;
        page["nodes"]
            .as_array()
            .context("actual Tracker node page is missing")?
            .iter()
            .map(|node| {
                let root = node["rootId"]
                    .as_str()
                    .context("actual root ID is missing")?;
                Ok(capture::FrozenCaptureNode {
                    id: node["id"].as_str().unwrap().into(),
                    root_id: root.into(),
                    logical_root: logical_token(CANONICAL, root),
                    path: node["path"].as_str().unwrap().into(),
                    kind: node["kind"].as_str().unwrap().into(),
                    size: node["size"].as_u64().unwrap(),
                    stamp: serde_json::from_value(node["stamp"].clone())?,
                    link_target_hash: node["linkTargetHash"].as_str().map(str::to_owned),
                })
            })
            .collect()
    }
    fn full_scope_authority(
        &self,
        _: &CaptureScope,
    ) -> Result<Option<Arc<dyn capture::NativeFullScopeAuthority>>> {
        Ok(self
            .full
            .as_ref()
            .map(|owner| Arc::clone(owner) as Arc<dyn capture::NativeFullScopeAuthority>))
    }
    fn accept(&self, receipt: Arc<capture::PreparedCaptureReceipt>) -> Result<()> {
        self.tracker
            .accept_capture_receipt(&self.work, Arc::new(Receipt(receipt)))?;
        Ok(())
    }
    fn verify_publication(&self) -> Result<()> {
        self.tracker.verify_capture_receipt(&self.work)?;
        Ok(())
    }
}

struct ActualCapture {
    engine: NativeEngine,
    tracker: Arc<Tracker>,
    store: WorkspaceStore,
    vault: Arc<MemoryVault>,
    job: Job,
    manifest: BundleManifest,
    index: Vec<noland_pack::PackIndexEntry>,
    packs: Vec<(String, PathBuf)>,
    storage: noland_storage::LocalStorage,
    binding: Value,
    _fixture: Fixture,
}

impl Drop for ActualCapture {
    fn drop(&mut self) {
        self.tracker.shutdown().unwrap();
    }
}

async fn actual_capture(empty_full: bool) -> ActualCapture {
    let fixture = Fixture::new();
    let source_path = fixture.root.join("software");
    let source = SafeRoot::open(&source_path).unwrap();
    if !empty_full {
        source
            .write_new("save.dat", |file| {
                file.write_all(b"actual native capture fixture bytes")?;
                Ok(())
            })
            .unwrap();
    }
    let vault = Arc::new(MemoryVault::default());
    let store = WorkspaceStore::open_with_vault(&fixture.root.join("data"), vault.clone()).unwrap();
    let configured = store
        .connect_provider(&json!({
            "kind":"backblaze_b2","name":"Isolated completion metadata",
            "bucket":"synthetic-bucket","prefix":"synthetic-prefix",
            "credentials":{"type":"backblaze_b2","value":{
                "key_id":"synthetic-key","application_key":"synthetic-injected-secret",
            }},
        }))
        .unwrap();
    let provider = configured["providers"].as_array().unwrap().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    store
        .record_provider_health(
            &provider,
            &json!({
                "canList":true,"canRead":true,"repositoryAccessible":true,
                "repositoryEmpty":false,"keyVerified":true,
            }),
        )
        .unwrap(); // Fixture observation, never production permission/durability.
    let mut policy = TrackingPolicy::new(fixture.root.join("data"));
    policy.supports_metadata_snapshots = true;
    policy.supports_deletion_snapshots = true;
    policy.audit_interval = Duration::from_secs(3600);
    policy.max_file_bytes = 1024 * 1024;
    let tracker = Arc::new(
        Tracker::open(
            Arc::new(Store(store.clone())),
            Arc::new(|_| bail!("no automatic enqueue consent in this fixture")),
            policy,
        )
        .unwrap(),
    );
    let mut identity = AppIdentity::new(AppId::steam(480), "Native completion fixture");
    identity.steam_app_id = Some(480);
    tracker.approve_software(&json!({
        "softwareId":SOFTWARE,"appId":INSTANCE,"name":identity.display_name,
        "sourceIdentity":identity,"providerId":provider,
        "roots":[{"path":source_path,"role":"save"}],
        "_approvedPaths":[{"path":source_path,"kind":"directory","identity":source.identity().unwrap()}],
    })).unwrap();
    let engine = NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home"))
        .unwrap()
        .with_workspace(store.clone())
        .unwrap();
    let record = store.software_record(SOFTWARE).unwrap();
    assert_eq!(record["id"], SOFTWARE);
    assert_eq!(record["appId"], INSTANCE);
    assert_eq!(record["sourceIdentity"]["app_id"], CANONICAL);
    engine.register(&record).await.unwrap();
    let ids = tracker.file_listing(SOFTWARE, None, 500).unwrap()["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|file| file["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let work = tracker
        .prepare_upload_scope(
            SOFTWARE,
            &provider,
            if empty_full { None } else { Some(&ids) },
        )
        .unwrap();
    let work_id = work["workId"].as_str().unwrap().to_owned();
    let full = if empty_full {
        Some(Arc::new(FullOwner {
            tracker: Arc::clone(&tracker),
            work: work_id.clone(),
            evidence: tracker.full_scope_evidence(&work_id).unwrap(),
        }))
    } else {
        None
    };
    let controller = Arc::new(Controller {
        tracker: Arc::clone(&tracker),
        work: work_id,
        full,
    });
    let metadata = &work["captureSource"]["metadataSelection"];
    let scope = CaptureScope {
        version: 1,
        work_id: work["workId"].as_str().unwrap().into(),
        metadata_identity: metadata["metadataIdentity"].as_str().unwrap().into(),
        node_count: metadata["nodeCount"].as_u64().unwrap() as usize,
        full_scope: controller
            .full
            .as_ref()
            .map(|owner| capture::full_scope_from_evidence(&owner.evidence).unwrap()),
    };
    let binding = engine.binding(&json!({"softwareId":SOFTWARE})).unwrap();
    let (files, metadata, full) =
        capture::freeze(&binding, &scope, controller.as_ref(), &provider).unwrap();
    let id = Uuid::new_v4();
    let access = store.provider_access(&provider, &id.to_string()).unwrap();
    let access = Arc::new(engine.private_access(&access, Some(id)).unwrap());
    let roots = binding
        .roots
        .iter()
        .map(|root| root.spec.clone())
        .collect::<Vec<_>>();
    let origin = CaptureOrigin {
        generation: work["generation"].as_u64().unwrap(),
        automatic: work["automatic"].as_bool().unwrap(),
        authorization: work["authorization"].clone(),
    };
    let plan = Arc::new(FrozenPlan {
        version: 1,
        api: 22,
        operation: id,
        instance: engine.inner.instance,
        provider,
        storage: access.session.root_cache_key(),
        created_at: chrono::Utc::now(),
        work: Work::Upload {
            software: SOFTWARE.into(),
            software_instance_id: INSTANCE.into(),
            app: binding.app.clone(),
            name: binding.name.clone(),
            source_identity: binding.identity.clone(),
            roots: roots.clone(),
            snapshot: scope.metadata_identity.clone(),
            files: files.clone(),
            metadata,
            complete_approved_scope: empty_full,
            coverage: if empty_full {
                NativeCoverage::FullApprovedScope
            } else {
                NativeCoverage::SelectedNodes
            },
            capture_scope: Some(scope.clone()),
            capture_origin: Some(origin),
            full_snapshot: full,
            reuse_epoch: None,
            bundle: Uuid::new_v4(),
            commit: Uuid::new_v4(),
        },
    });
    plan.validate().unwrap();
    let sealed = plan.seal(&access.master).unwrap();
    let mac = store.operation_mac_existing(&sealed).unwrap();
    engine
        .inner
        .plans
        .write_new(&format!("{id}.plan"), |file| {
            file.write_all(&sealed)?;
            Ok(())
        })
        .unwrap();
    engine
        .inner
        .plans
        .write_new(&format!("{id}.device"), |file| {
            file.write_all(&mac)?;
            Ok(())
        })
        .unwrap();
    pipeline::operation_directory(&engine.inner, id, "upload").unwrap();
    let root = SafeRoot::open(&fixture.root).unwrap();
    for name in ["cas", "packs", "remote"] {
        root.create_dir(name).unwrap();
    }
    let cas = noland_cas::LocalCas::new(fixture.root.join("cas")).unwrap();
    let lease = cas.lease().unwrap();
    let mut reader = noland_cas::ChunkFileReader::default();
    let mut chunks = BTreeMap::new();
    let mut captured = Vec::new();
    for expected in &files {
        let (mut file, stamp) = source.read_file(&expected.relative).unwrap();
        assert_eq!(stamp, expected.stamp);
        let result = reader
            .chunk_open_file(&mut file, |chunk, bytes| {
                let stored = lease.capture_streaming_prehashed(&chunk.hash, bytes)?;
                chunks.entry(chunk.hash.clone()).or_insert(stored.source);
                Ok(())
            })
            .unwrap();
        source.verify_file(&expected.relative, &stamp).unwrap();
        captured.push(noland_state_core::ManifestFile {
            logical_root: expected.root.clone(),
            relative_path: expected.relative.clone(),
            source_path_hint: None,
            file_type: "file".into(),
            size: result.size,
            file_hash: result.file_hash,
            chunks: result.chunks,
            mode: None,
            mtime_ns: Some(mtime_ns_from_stamp(&stamp).unwrap()),
            uid: None,
            gid: None,
            symlink_target: None,
            persistence_class: noland_state_core::PersistenceClass::PersistentState,
            semantic_role: noland_state_core::SemanticRole::UserState,
            association_confidence: 1.0,
            shared_app_ids: Vec::new(),
        });
    }
    lease.sync_all().unwrap();
    let built =
        noland_pack::pack_chunk_files(&fixture.root.join("packs"), &access.master, chunks, |_| {
            false
        })
        .unwrap();
    let index = built
        .iter()
        .flat_map(|pack| pack.entries.clone())
        .collect::<Vec<_>>();
    let packs = built
        .iter()
        .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
        .collect::<Vec<_>>();
    let Work::Upload {
        bundle,
        commit,
        coverage,
        full_snapshot,
        ..
    } = &plan.work
    else {
        unreachable!()
    };
    let mut manifest = BundleManifest::new(
        noland_state_core::ManifestApp::from(&binding.identity),
        noland_state_core::ManifestSource {
            instance_id: plan.instance,
            image_id: "quicksave-native-windows".into(),
            captured_at: plan.created_at,
        },
        if empty_full {
            noland_state_core::BackupMode::CompleteApplication
        } else {
            noland_state_core::BackupMode::Custom
        },
    );
    manifest.bundle_id = *bundle;
    manifest.commit_id = *commit;
    manifest.consistency = noland_state_core::ConsistencyKind::BestEffort;
    manifest.files = captured;
    let selected = manifest
        .files
        .iter()
        .map(|file| file.logical_root.as_str())
        .collect::<BTreeSet<_>>();
    let roots_hash = native_roots_fingerprint(&binding.app, &roots).unwrap();
    manifest.environment = json!({
        "platform":"windows","capture_consistency":"validated_stable_files_not_application_atomic",
        "software_instance_id":INSTANCE,"quicksave_native_root_layouts":
            frozen_root_layouts_value(&binding.app,INSTANCE,&roots,if empty_full {None}else{Some(&selected)}).unwrap(),
        "quicksave_native":{"platform":"windows","coverage":coverage,"software_instance_id":INSTANCE,
            "operation_id":id,"rootsFingerprint":roots_hash,
            "selection":{"coverage":coverage,"capture_scope":scope,
                "software_instance_id":INSTANCE,"roots_fingerprint":roots_hash}},
        "windowsSymlinkMetadata":[],
    });
    if let Some(full) = full_snapshot {
        full.apply_manifest(&mut manifest, None, &roots).unwrap();
    }
    pipeline::validate_captured_manifest(&manifest, &plan).unwrap();
    let now = chrono::Utc::now();
    engine
        .inner
        .db
        .upsert_operation(&OperationRecord {
            operation_id: id,
            kind: "backup".into(),
            app_id: Some(binding.app.clone()),
            state: "RUNNING".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: json!({}),
        })
        .unwrap();
    let job = Job {
        plan,
        access,
        guard: None,
        stop: Arc::new(AtomicBool::new(false)),
        controller: Some(controller),
        restore: None,
    };
    capture::accept(&engine.inner, &job, &manifest).unwrap();
    let binding = tracker
        .capture_completion_binding(job.plan.work_capture_id_for_test())
        .unwrap();
    let storage = noland_storage::LocalStorage::new(fixture.root.join("remote"));
    ActualCapture {
        engine,
        tracker,
        store,
        vault,
        job,
        manifest,
        index,
        packs,
        storage,
        binding,
        _fixture: fixture,
    }
}

impl FrozenPlan {
    fn work_capture_id_for_test(&self) -> &str {
        let Work::Upload {
            capture_scope: Some(scope),
            ..
        } = &self.work
        else {
            unreachable!()
        };
        &scope.work_id
    }
}

async fn publish(fixture: &ActualCapture) {
    noland_storage::commit_bundle_with_pack_index_for_operation(
        &fixture.storage,
        &fixture.job.access.master,
        &fixture.manifest,
        &fixture.packs,
        Some(&fixture.index),
        Some(&fixture.engine.inner.db),
        Some(fixture.job.plan.operation),
    )
    .await
    .unwrap();
    record_committed(
        &fixture.engine.inner,
        &fixture.job,
        &fixture.storage,
        &fixture.manifest,
    )
    .await
    .unwrap();
    if let Some(lifecycle) = &fixture.job.access.lifecycle {
        lifecycle.invalidate().unwrap();
    }
    finalize(&fixture.engine.inner, &fixture.job).unwrap();
    fixture
        .engine
        .inner
        .state(fixture.job.plan.operation, "COMPLETED", None)
        .unwrap();
    retain(&fixture.engine.inner, &fixture.job).unwrap();
}

#[tokio::test]
async fn forged_completed_row_and_real_preparation_without_committed_marker_never_verify() {
    let fixture = actual_capture(false).await;
    fixture
        .engine
        .inner
        .state(fixture.job.plan.operation, "COMPLETED", None)
        .unwrap();
    assert!(fixture
        .engine
        .inner
        .completion
        .lock()
        .unwrap()
        .accepted
        .contains_key(&fixture.job.plan.operation));
    let error = record_committed(
        &fixture.engine.inner,
        &fixture.job,
        &fixture.storage,
        &fixture.manifest,
    )
    .await
    .unwrap_err();
    assert!(
        !error
            .to_string()
            .contains("accepted native capture proof is missing"),
        "the negative test must reach the actual missing COMMITTED marker"
    );
    assert!(finalize(&fixture.engine.inner, &fixture.job).is_err());
    retain(&fixture.engine.inner, &fixture.job).unwrap(); // Deliberately adversarial DB/cache setup.
    assert!(fixture
        .engine
        .verify_capture_completion(
            &fixture.job.plan.operation.to_string(),
            fixture.binding.clone()
        )
        .await
        .is_err());
    assert!(fixture.engine.inner.runtime.get().is_none());
}

#[tokio::test]
async fn completion_only_reads_fresh_grant_nonces_not_credentials_keys_or_current_files() {
    let fixture = actual_capture(false).await;
    publish(&fixture).await;
    let source = SafeRoot::open(&fixture._fixture.root.join("software")).unwrap();
    // Same native file is changed after immutable captured bytes were published.
    // Explicit Tracker reconciliation records the newer dirty generation.
    let path = fixture._fixture.root.join("software/save.dat");
    std::fs::write(
        &path,
        b"newer local mutation is not the published generation",
    )
    .unwrap();
    fixture.tracker.scan_metadata(SOFTWARE).unwrap();
    let older = fixture.binding["generation"].as_u64().unwrap();
    assert!(
        fixture.store.software_record(SOFTWARE).unwrap()["dirtyGeneration"]
            .as_u64()
            .unwrap()
            > older
    );
    drop(source);
    fixture.tracker.shutdown().unwrap(); // Freeze unrelated background I/O counters.
    let io = fixture.tracker.performance_counters();
    // Migration protection must freshly prove the aggregate key item is absent
    // before using a retained legacy device key. This is an absence probe, not
    // permission to fetch any credential or encrypted-state key.
    const MISSING_MIGRATION_ANCHOR: &str = "QuickSaveEncryptedStateVault.v1";
    assert!(fixture
        .vault
        .read(QUICKSAVE_VAULT_SERVICE, MISSING_MIGRATION_ANCHOR)
        .unwrap()
        .is_none());
    let vault = fixture.vault.access_log().unwrap();
    fixture.engine.inner.proofs.lock().unwrap().insert(
        fixture.job.plan.operation,
        PublicationProof {
            guard: Arc::new(|| panic!("status must not call a publication/vault callback")),
            roots: Vec::new(),
            capture: None,
        },
    );
    fixture
        .engine
        .status(&fixture.job.plan.operation.to_string())
        .await
        .unwrap();
    assert_eq!(
        fixture.vault.access_log().unwrap(),
        vault,
        "status cannot read any vault entry"
    );
    let record = fixture.store.software_record(SOFTWARE).unwrap();
    let nonce_accounts = [
        record["trackingGrant"]["authorityRef"].as_str().unwrap(),
        record["captureReceipt"]["grant"]["authorityRef"]
            .as_str()
            .unwrap(),
        record["captureReceipt"]["reference"]["grant"]["authorityRef"]
            .as_str()
            .unwrap(),
    ];
    let before = vault["reads"].as_array().unwrap().len();
    let result = fixture
        .engine
        .verify_capture_completion(
            &fixture.job.plan.operation.to_string(),
            fixture.binding.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result["generation"], older);
    assert_eq!(result["verified"], true);
    assert!(result["committedManifestAuth"]
        .as_str()
        .is_some_and(full_scope::raw_hash));
    let after = fixture.vault.access_log().unwrap();
    assert_eq!(after["writes"], vault["writes"]);
    assert!(after["reads"].as_array().unwrap()[before..].iter().all(|read|
        read[0] == QUICKSAVE_VAULT_SERVICE
            && (nonce_accounts.contains(&read[1].as_str().unwrap())
                || read[1] == MISSING_MIGRATION_ANCHOR)),
        "completion may read only original grant nonces and probe an absent migration anchor; never fetch credentials/keys");
    // With no intervening writes and absence verified on both sides, the added
    // account cannot conceal an encryption-key read or a secret/key creation.
    assert!(fixture
        .vault
        .read(QUICKSAVE_VAULT_SERVICE, MISSING_MIGRATION_ANCHOR)
        .unwrap()
        .is_none());
    assert_eq!(fixture.tracker.performance_counters(), io);
    assert_eq!(
        std::fs::read(path).unwrap(),
        b"newer local mutation is not the published generation"
    );
    assert_eq!(
        fixture.store.software_record(SOFTWARE).unwrap()["dirty"],
        true
    );
    assert!(fixture.engine.inner.runtime.get().is_none());
    fixture.vault.deny_access(true).unwrap();
    assert!(
        fixture
            .engine
            .verify_capture_completion(
                &fixture.job.plan.operation.to_string(),
                fixture.binding.clone()
            )
            .await
            .is_err(),
        "even a cached historical proof cannot bypass a fresh nonce check"
    );
    fixture
        .engine
        .status(&fixture.job.plan.operation.to_string())
        .await
        .unwrap();
    fixture.vault.deny_access(false).unwrap();
}

#[tokio::test]
async fn genuine_empty_full_scope_has_distinct_workspace_installation_and_canonical_ids() {
    let fixture = actual_capture(true).await;
    assert!(fixture.manifest.files.is_empty());
    assert_eq!(
        fixture.manifest.mode,
        noland_state_core::BackupMode::CompleteApplication
    );
    assert_eq!(
        fixture.manifest.environment["quicksave_native"]["software_instance_id"],
        INSTANCE
    );
    assert_eq!(fixture.binding["softwareId"], SOFTWARE);
    assert_eq!(fixture.binding["appId"], CANONICAL);
    assert_eq!(fixture.binding["softwareInstanceId"], INSTANCE);
    publish(&fixture).await;
    let result = fixture
        .engine
        .verify_capture_completion(
            &fixture.job.plan.operation.to_string(),
            fixture.binding.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result["verified"], true);
    for field in [
        "softwareId",
        "softwareInstanceId",
        "appId",
        "providerId",
        "workId",
        "metadataIdentity",
    ] {
        let mut forged = fixture.binding.clone();
        forged[field] = json!("other-scope");
        assert!(
            fixture
                .engine
                .verify_capture_completion(&fixture.job.plan.operation.to_string(), forged)
                .await
                .is_err(),
            "{field}"
        );
    }
    let mut forged = fixture.binding.clone();
    forged["sourceExpectedManifestAuth"]["manifestHash"] = json!("f".repeat(64));
    assert!(fixture
        .engine
        .verify_capture_completion(&fixture.job.plan.operation.to_string(), forged)
        .await
        .is_err());
}

#[tokio::test]
async fn actual_committed_envelopes_reject_forged_mode_role_selection_and_repository_scope() {
    let fixture = actual_capture(false).await;
    publish(&fixture).await;
    let directory = directory(&fixture.engine.inner, fixture.job.plan.operation).unwrap();
    let committed = pipeline::read_document::<CommitReceipt>(
        &directory,
        POST_COMMIT,
        &fixture.job.access.master,
        fixture.job.plan.operation,
    )
    .unwrap()
    .unwrap();
    let drained = pipeline::read_document::<DrainReceipt>(
        &directory,
        DRAINED,
        &fixture.job.access.master,
        fixture.job.plan.operation,
    )
    .unwrap()
    .unwrap();
    for field in ["mode", "role", "selection", "repository"] {
        let mut forged: CommitReceipt =
            serde_json::from_value(serde_json::to_value(&committed).unwrap()).unwrap();
        match field {
            "mode" => forged.manifest.mode = noland_state_core::BackupMode::CompleteApplication,
            "role" => {
                forged.manifest.files[0].semantic_role = noland_state_core::SemanticRole::AppContent
            }
            "selection" => {
                forged.manifest.environment["quicksave_native"]["selection"]["coverage"] =
                    json!("full_approved_scope")
            }
            "repository" => forged.repository_binding = "f".repeat(64),
            _ => unreachable!(),
        }
        // Even a locally re-signed outer receipt cannot widen the source's
        // original AEAD expected-manifest body and frozen operation.
        let mut matching = drained.clone();
        matching.committed_receipt_hash = full_scope::metadata_digest(&forged).unwrap();
        assert!(
            validate_receipts(
                &fixture.job.plan,
                &fixture.job.access,
                &fixture.binding["sourceExpectedManifestAuth"],
                &fixture.binding["captureReceipt"],
                &forged,
                &matching
            )
            .is_err(),
            "{field}"
        );
    }
    fixture.tracker.shutdown().unwrap();
    fixture
        .engine
        .verify_capture_completion(
            &fixture.job.plan.operation.to_string(),
            fixture.binding.clone(),
        )
        .await
        .unwrap(); // Populate the engine's historical-proof cache first.
    let other_store =
        WorkspaceStore::open_with_vault(&fixture._fixture.root.join("data"), fixture.vault.clone())
            .unwrap();
    other_store
        .revoke_grant(
            "tracking_capture_receipt",
            &fixture.binding["captureReceipt"]["scope"],
        )
        .unwrap();
    assert!(fixture
        .engine
        .verify_capture_completion(
            &fixture.job.plan.operation.to_string(),
            fixture.binding.clone()
        )
        .await
        .is_err());
}
