// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic-only orchestration tests. No native account, OS vault, rclone,
//! public application discovery, real No Land state, or live provider is used.

use super::*;
use crate::interfaces::{NativeFuture, SourceGuard};
use quicksave_state::ProviderAccess;
use std::sync::atomic::{AtomicU64, Ordering};

const SECRET: &str = "DO_NOT_EXPOSE_ACCESS_TOKEN_OR_MASTER_KEY";

// Parser/orchestration fixtures only; these paths are never opened.
fn synthetic_path(path: &str) -> String {
    if cfg!(windows) {
        format!("C:{}", path.replace('/', "\\"))
    } else {
        path.to_owned()
    }
}

struct FakeStore {
    document: Mutex<Value>,
    access_reads: AtomicUsize,
    connected: AtomicUsize,
    writable: AtomicBool,
    received_credentials: Mutex<Option<Value>>,
    discovery_reads: AtomicUsize,
    import_reads: AtomicUsize,
}
impl FakeStore {
    fn new(read_only: bool) -> Arc<Self> {
        Arc::new(Self {
            document: Mutex::new(json!({
                "generation":1,
                "providers":[{"id":"provider-1","name":"Synthetic provider","kind":"s3","status":"connected","origin":"noland","readOnly":read_only,"credentialRef":"provider.provider-1","repositoryKeyRef":"repository.import.provider-1","bucket":"synthetic","prefix":"approved"}],
                "software":[{
                    "id":"software-1","appId":"stable.app.identity","name":"Synthetic application",
                    "tracked":true,"providerId":"provider-1","status":"needs_backup","autosave":false,
                    "dirty":true,"dirtyGeneration":1,"trackingGrant":{"opaque":"native signature"},
                    "roots":[{"id":"root-1","path":synthetic_path("/synthetic/approved"),"role":"manual","identity":{"device":7,"fileId":[11,0]},"allowedFiles":null}],
                }],
            })),
            access_reads: AtomicUsize::new(0),
            connected: AtomicUsize::new(0),
            writable: AtomicBool::new(!read_only),
            received_credentials: Mutex::new(None),
            discovery_reads: AtomicUsize::new(0),
            import_reads: AtomicUsize::new(0),
        })
    }
}
impl ServiceStore for FakeStore {
    fn provider_credential_generation(&self, id: &str) -> Result<u64> {
        ensure!(id == "provider-1", "Synthetic provider mismatch");
        Ok(17)
    }
    fn complete_provider_reauthorization(
        &self,
        id: &str,
        expected: u64,
        credentials: &Value,
    ) -> Result<()> {
        ensure!(
            id == "provider-1" && expected == 17,
            "Synthetic native CAS mismatch"
        );
        *self.received_credentials.lock().unwrap() = Some(credentials.clone());
        let mut document = self.document.lock().unwrap();
        document["providers"][0]["status"] = json!("connecting");
        document["software"][0]["autosave"] = json!(false);
        document["software"][0]["autosaveGrant"] = Value::Null;
        Ok(())
    }
    fn snapshot(&self) -> Result<Value> {
        Ok(self.document.lock().unwrap().clone())
    }
    fn provider_types(&self) -> Value {
        json!({"providers":[{"kind":"s3","fields":[{"name":"bucket","required":true}]}]})
    }
    fn connect_provider(&self, input: &Value) -> Result<Value> {
        self.connected.fetch_add(1, Ordering::SeqCst);
        *self.received_credentials.lock().unwrap() = input.get("credentials").cloned();
        self.document.lock().unwrap()["providers"][0]["status"] = json!("connecting");
        Ok(json!({"id":"provider-1"}))
    }
    fn disconnect_provider(&self, _id: &str) -> Result<()> {
        self.document.lock().unwrap()["providers"][0]["status"] = json!("disconnected");
        self.writable.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn import_noland(&self, _input: &Value) -> Result<Value> {
        self.import_reads.fetch_add(1, Ordering::SeqCst);
        self.document.lock().unwrap()["providers"][0]["readOnly"] = json!(true);
        self.document.lock().unwrap()["providers"][0]["status"] = json!("connecting");
        self.writable.store(false, Ordering::SeqCst);
        Ok(json!({}))
    }
    fn discover_noland_sources(&self) -> Result<Value> {
        self.discovery_reads.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"candidates":[{"sourceId":"native-source-1","name":"No Land","pathSafeSummary":"…/com.noland.connect/state.json"}],
            "selectedSourceId":"native-source-1","requiresChoice":false,"hasData":true,
            "credentialReads":false,"manualFallback":"advanced_only"}),
        )
    }
    fn noland_source_scope(&self, source: &str) -> Result<Value> {
        ensure!(source == "native-source-1", "unregistered native source");
        Ok(
            json!({"sourceId":source,"path":"/synthetic/com.noland.connect/state.json",
            "file":{"kind":"file","identity":{"device":7,"fileId":[43,0]}}}),
        )
    }
    fn provider_access(&self, id: &str, _operation: &str) -> Result<ProviderAccess> {
        self.access_reads.fetch_add(1, Ordering::SeqCst);
        ensure!(id == "provider-1", "wrong native provider");
        ensure!(
            self.document.lock().unwrap()["providers"][0]["status"] != "disconnected",
            "disconnected"
        );
        Ok(ProviderAccess {
            provider_id: id.into(),
            session: json!({"private":SECRET}),
            repository_key: [0x5a; 32],
            read_only: !self.writable.load(Ordering::SeqCst),
        })
    }
    fn record_provider_health(&self, _id: &str, report: &Value) -> Result<()> {
        let healthy = report["canList"] == true
            && report["repositoryAccessible"] == true
            && (report["repositoryEmpty"] == true
                || (report["canRead"] == true && report["keyVerified"] == true));
        self.document.lock().unwrap()["providers"][0]["status"] =
            json!(if healthy { "connected" } else { "error" });
        Ok(())
    }
    fn grant_provider_write(&self, _id: &str) -> Result<()> {
        self.writable.store(true, Ordering::SeqCst);
        self.document.lock().unwrap()["providers"][0]["readOnly"] = json!(false);
        Ok(())
    }
    fn provider_writable(&self, _id: &str) -> Result<bool> {
        Ok(self.writable.load(Ordering::SeqCst)
            && self.document.lock().unwrap()["providers"][0]["status"] == "connected")
    }
}

#[derive(Clone)]
struct Pending {
    generation: u64,
    selected: BTreeSet<String>,
    snapshot: u64,
}
struct FakeTracking {
    store: Arc<FakeStore>,
    signed: AtomicBool,
    autosave_signed: AtomicBool,
    identity_valid: Arc<AtomicBool>,
    snapshot: AtomicU64,
    pending: Mutex<BTreeMap<String, Pending>>,
    dirty: Mutex<BTreeSet<String>>,
    completed: Mutex<Vec<(String, u64, bool)>>,
    fail_finalize: AtomicBool,
    source_reads: AtomicUsize,
    finalized: tokio::sync::Notify,
}
impl FakeTracking {
    fn new(store: Arc<FakeStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            signed: AtomicBool::new(true),
            autosave_signed: AtomicBool::new(false),
            identity_valid: Arc::new(AtomicBool::new(true)),
            snapshot: AtomicU64::new(1),
            pending: Mutex::new(BTreeMap::new()),
            dirty: Mutex::new(BTreeSet::from(["file-a".into(), "file-b".into()])),
            completed: Mutex::new(Vec::new()),
            fail_finalize: AtomicBool::new(false),
            source_reads: AtomicUsize::new(0),
            finalized: tokio::sync::Notify::new(),
        })
    }
    fn begin(&self, input: &Value) -> Result<Value> {
        ensure!(self.signed.load(Ordering::SeqCst), "unsigned scope");
        ensure!(self.identity_valid.load(Ordering::SeqCst), "root replaced");
        ensure!(self.pending.lock().unwrap().is_empty(), "already in flight");
        let document = self.store.document.lock().unwrap();
        let record = &document["software"][0];
        ensure!(
            input["softwareId"] == record["id"] && input["providerId"] == record["providerId"],
            "scope changed"
        );
        self.source_reads.fetch_add(1, Ordering::SeqCst);
        let file_ids = input
            .get("fileIds")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!(["file-a", "file-b"]));
        let selected = file_ids
            .as_array()
            .map(|ids| {
                ids.iter()
                    .map(|id| id.as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_else(|| BTreeSet::from(["file-a".into(), "file-b".into()]));
        ensure!(
            selected
                .iter()
                .all(|id| ["file-a", "file-b"].contains(&id.as_str())),
            "selection outside signed root"
        );
        let work_id = Uuid::new_v4().to_string();
        let generation = record["dirtyGeneration"].as_u64().unwrap();
        let snapshot = self.snapshot.load(Ordering::SeqCst);
        self.pending.lock().unwrap().insert(
            work_id.clone(),
            Pending {
                generation,
                selected,
                snapshot,
            },
        );
        Ok(json!({
            "workId":work_id,"softwareId":"software-1","providerId":"provider-1",
            "generation":generation,"fileIds":file_ids,"roots":native::authority_roots(record)?,
            "captureSource":{"snapshotIdentity":snapshot.to_string(),"changedDirty":true},
        }))
    }
    fn changed(&self) {
        self.snapshot.fetch_add(1, Ordering::SeqCst);
        let mut document = self.store.document.lock().unwrap();
        let generation = document["software"][0]["dirtyGeneration"].as_u64().unwrap() + 1;
        document["software"][0]["dirtyGeneration"] = json!(generation);
        document["software"][0]["dirty"] = json!(true);
    }
}
struct FakePin(Arc<AtomicBool>);
impl SourceGuard for FakePin {
    fn verify(&self) -> Result<()> {
        ensure!(self.0.load(Ordering::SeqCst), "native root replaced");
        Ok(())
    }
}
impl ServiceTracking for FakeTracking {
    fn call(&self, method: &str, input: &Value) -> Result<Value> {
        match method {
            "software" => {
                let mut record = self.store.document.lock().unwrap()["software"][0].clone();
                if !self.signed.load(Ordering::SeqCst) {
                    record["tracked"] = json!(false);
                    record["autosave"] = json!(false);
                }
                Ok(json!([record]))
            }
            "file_listing" => {
                ensure!(
                    self.signed.load(Ordering::SeqCst),
                    "unsigned persisted roots"
                );
                self.source_reads.fetch_add(1, Ordering::SeqCst);
                Ok(
                    json!({"files":[{"id":"file-a","name":"a.txt","path":"a.txt","directory":false,"size":7,"rootId":"root-1","credentials":SECRET}],"nextCursor":"next-native-page"}),
                )
            }
            "begin_upload" => self.begin(input),
            "complete_upload" => {
                ensure!(
                    !self.fail_finalize.load(Ordering::SeqCst),
                    "durability failure"
                );
                let id = dto::id(input, "workId")?.to_owned();
                let generation = input["generation"].as_u64().unwrap();
                let success = input["success"].as_bool().unwrap();
                let pending = self
                    .pending
                    .lock()
                    .unwrap()
                    .remove(&id)
                    .ok_or_else(|| anyhow!("unknown work"))?;
                ensure!(generation == pending.generation, "wrong generation");
                if success && self.snapshot.load(Ordering::SeqCst) == pending.snapshot {
                    let mut dirty = self.dirty.lock().unwrap();
                    for selected in pending.selected {
                        dirty.remove(&selected);
                    }
                    self.store.document.lock().unwrap()["software"][0]["dirty"] =
                        json!(!dirty.is_empty());
                }
                self.completed
                    .lock()
                    .unwrap()
                    .push((id, generation, success));
                self.finalized.notify_one();
                Ok(json!({}))
            }
            "set_provider" => {
                let mut document = self.store.document.lock().unwrap();
                document["software"][0]["providerId"] = input["providerId"].clone();
                document["software"][0]["autosave"] = json!(false);
                self.autosave_signed.store(false, Ordering::SeqCst);
                Ok(json!({}))
            }
            "configure_autosave" => {
                ensure!(self.signed.load(Ordering::SeqCst), "tracking unsigned");
                ensure!(self.store.writable.load(Ordering::SeqCst), "read only");
                let enabled = input["enabled"].as_bool().unwrap();
                self.autosave_signed.store(enabled, Ordering::SeqCst);
                self.store.document.lock().unwrap()["software"][0]["autosave"] = json!(enabled);
                Ok(json!({}))
            }
            "verify_autosave_work" => {
                ensure!(
                    self.signed.load(Ordering::SeqCst)
                        && self.autosave_signed.load(Ordering::SeqCst),
                    "no native autosave authority"
                );
                ensure!(
                    self.store.document.lock().unwrap()["software"][0]["providerId"]
                        == input["providerId"],
                    "changed provider"
                );
                Ok(json!({}))
            }
            "verify_upload_authority" => {
                ensure!(
                    self.signed.load(Ordering::SeqCst)
                        && self.identity_valid.load(Ordering::SeqCst),
                    "tracking grant revoked"
                );
                ensure!(
                    self.store.document.lock().unwrap()["software"][0]["providerId"]
                        == input["providerId"],
                    "provider scope changed"
                );
                if input["automatic"] == true {
                    ensure!(
                        self.autosave_signed.load(Ordering::SeqCst)
                            && self.store.document.lock().unwrap()["software"][0]["autosave"]
                                == true,
                        "autosave disabled"
                    );
                }
                Ok(json!({}))
            }
            "disconnect_provider" => {
                self.autosave_signed.store(false, Ordering::SeqCst);
                Ok(json!({}))
            }
            _ => bail!("unsupported synthetic tracker method"),
        }
    }
    fn pin_scope(&self, _record: &Value) -> Result<Arc<dyn SourceGuard>> {
        ensure!(self.signed.load(Ordering::SeqCst), "no tracking grant");
        Ok(Arc::new(FakePin(self.identity_valid.clone())))
    }
    fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

struct FakeEngine {
    calls: Mutex<Vec<(String, Value)>>,
    statuses: Mutex<BTreeMap<String, Value>>,
    fail_submit: AtomicBool,
    hold: AtomicBool,
    healthy: AtomicBool,
    unavailable_status: AtomicBool,
    missing_rclone: AtomicBool,
    oauth_ready: AtomicBool,
    started: tokio::sync::Notify,
    status_seen: tokio::sync::Notify,
    guards: Mutex<BTreeMap<String, PublishGuard>>,
    published: AtomicUsize,
}
impl FakeEngine {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            statuses: Mutex::new(BTreeMap::new()),
            fail_submit: AtomicBool::new(false),
            hold: AtomicBool::new(false),
            healthy: AtomicBool::new(true),
            unavailable_status: AtomicBool::new(false),
            missing_rclone: AtomicBool::new(false),
            oauth_ready: AtomicBool::new(true),
            started: tokio::sync::Notify::new(),
            status_seen: tokio::sync::Notify::new(),
            guards: Mutex::new(BTreeMap::new()),
            published: AtomicUsize::new(0),
        })
    }
    fn count(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == method)
            .count()
    }
    fn complete(&self) {
        let guards = self.guards.lock().unwrap().clone();
        for (id, status) in self.statuses.lock().unwrap().iter_mut() {
            if dto::terminal(status) {
                continue;
            }
            let allowed = guards.get(id).is_none_or(|guard| guard().is_ok());
            status["state"] = json!(if allowed { "completed" } else { "failed" });
            if allowed {
                self.published.fetch_add(1, Ordering::SeqCst);
            }
            status["canCancel"] = json!(false);
        }
    }
}
impl ServiceEngine for FakeEngine {
    fn shutdown<'a>(&'a self) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            ensure!(
                self.statuses.lock().unwrap().values().all(dto::terminal),
                "Synthetic native work is still active"
            );
            Ok(())
        })
    }
    fn delete_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            guard()?;
            self.guards
                .lock()
                .unwrap()
                .insert(dto::id(&selection, "operationId")?.to_owned(), guard);
            self.call("delete", Some(access), selection).await
        })
    }
    fn recover_restore_local<'a>(
        &'a self,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            guard()?;
            self.guards
                .lock()
                .unwrap()
                .insert(dto::id(&selection, "operationId")?.to_owned(), guard);
            self.call("recover_restore_local", None, selection).await
        })
    }
    fn download_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            guard()?;
            self.guards
                .lock()
                .unwrap()
                .insert(dto::id(&selection, "operationId")?.to_owned(), guard);
            self.call("download", Some(access), selection).await
        })
    }
    fn upload_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.guards
                .lock()
                .unwrap()
                .insert(dto::id(&selection, "operationId")?.to_owned(), guard);
            self.call("upload", Some(access), selection).await
        })
    }
    fn retry_guarded<'a>(&'a self, id: &'a str, guard: PublishGuard) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.guards.lock().unwrap().insert(id.to_owned(), guard);
            self.call("retry", None, json!({"operationId":id})).await
        })
    }
    fn call<'a>(
        &'a self,
        method: &'a str,
        _access: Option<ProviderAccess>,
        input: Value,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_owned(), input.clone()));
            match method {
                "preflight" => {
                    ensure!(!self.missing_rclone.load(Ordering::SeqCst),"rclone is not installed in a supported native tool location; install rclone >=1.76 separately");
                    Ok(
                        json!({"available":true,"oauthRefreshPersistence":self.oauth_ready.load(Ordering::SeqCst)}),
                    )
                }
                "register" | "reattach" => Ok(json!({})),
                "upload" | "download" | "delete" => {
                    if self.fail_submit.load(Ordering::SeqCst) {
                        bail!(SECRET);
                    }
                    let id = input["operationId"].as_str().unwrap().to_owned();
                    let held = self.hold.load(Ordering::SeqCst);
                    let allowed = self
                        .guards
                        .lock()
                        .unwrap()
                        .get(&id)
                        .is_none_or(|guard| guard().is_ok());
                    if !held && allowed {
                        self.published.fetch_add(1, Ordering::SeqCst);
                    }
                    self.statuses.lock().unwrap().insert(id.clone(),json!({
                        "id":id,"kind":if method == "delete" {"delete"} else {method},
                        "state":if held {"running"} else if allowed {"completed"} else {"failed"},
                        "name":"Synthetic storage operation","canCancel":true,
                        "completedBytes":3,"totalBytes":7,"detail":{"private":SECRET},
                    }));
                    self.started.notify_one();
                    Ok(json!({"operationId":id}))
                }
                "status" => {
                    self.status_seen.notify_one();
                    ensure!(!self.unavailable_status.load(Ordering::SeqCst), SECRET);
                    self.statuses
                        .lock()
                        .unwrap()
                        .get(dto::id(&input, "operationId")?)
                        .cloned()
                        .ok_or_else(|| anyhow!(SECRET))
                }
                "recent" => Ok(json!([])),
                "cancel" => {
                    let id = dto::id(&input, "operationId")?.to_owned();
                    let mut statuses = self.statuses.lock().unwrap();
                    let status = statuses
                        .get_mut(&id)
                        .ok_or_else(|| anyhow!("unknown synthetic op"))?;
                    if !dto::terminal(status) {
                        status["state"] = json!("cancelled");
                    }
                    Ok(status.clone())
                }
                "retry" => {
                    let id = dto::id(&input, "operationId")?.to_owned();
                    let allowed = self
                        .guards
                        .lock()
                        .unwrap()
                        .get(&id)
                        .is_none_or(|guard| guard().is_ok());
                    let mut statuses = self.statuses.lock().unwrap();
                    let status = statuses
                        .get_mut(&id)
                        .ok_or_else(|| anyhow!("unknown synthetic op"))?;
                    status["state"] = json!(if allowed { "completed" } else { "failed" });
                    if allowed {
                        self.published.fetch_add(1, Ordering::SeqCst);
                    }
                    self.started.notify_one();
                    Ok(json!({"operationId":id}))
                }
                "health_check" => {
                    ensure!(!self.missing_rclone.load(Ordering::SeqCst),"rclone is not installed in a supported native tool location; install rclone >=1.76 separately");
                    let good = self.healthy.load(Ordering::SeqCst);
                    Ok(
                        json!({"canList":good,"canRead":good,"repositoryAccessible":good,"repositoryEmpty":false,"keyVerified":good,"credentials":SECRET}),
                    )
                }
                "preview_delete" => Ok(json!({"previewId":"preview-1","dependentBundles":[
                        {"id":"dependent-1","appId":"app-1","commitId":"commit-1"},
                        {"id":"dependent-2","appId":"app-1","commitId":"commit-2"}],
                        "dependentBundleCount":2,"items":3,"logicalBytes":7,"physicalBytes":11,"names":["synthetic"]})),
                "preview_restore" => Ok(
                    json!({"previewId":"restore-preview-1","requiresOverwriteAcknowledgement":false,"frozenPlanFingerprint":"b".repeat(64),
                    "fileCount":1,"logicalBytes":7,"conflictCount":0,
                    "roots":[{"id":"root-1","path":input["destination"]}]}),
                ),
                "restore_preview_scope" => Ok(
                    json!({"previewId":"restore-preview-1","frozenPlanFingerprint":"b".repeat(64)}),
                ),
                "restore_recovery_scope" => Ok(json!({
                    "operationId":input["operationId"],"providerId":"provider-1",
                    "frozenPlanFingerprint":"c".repeat(64),"roots":[{"path":synthetic_path("/synthetic/original-restore-target")}],
                    "summary":"Recover only original owned local restore outputs. No cloud connection or download is authorized.",
                })),
                "recover_restore_local" => {
                    Ok(json!({"operationId":input["operationId"],"retained":0,"recovered":true}))
                }
                "catalog" => Ok(
                    json!({"bundles":[{"id":"bundle-1","appId":"stable.app.identity","name":"Synthetic backup","providerId":"provider-1","credentials":SECRET}]}),
                ),
                "files" => Ok(json!({"files":[],"nextCursor":"2"})),
                _ => bail!("unsupported synthetic engine method"),
            }
        })
    }
}
struct FakeDiscovery;
impl ServiceDiscovery for FakeDiscovery {
    fn applications(&self) -> Result<Value> {
        Ok(json!({"applications":[{
            "identity":{"product":{"kind":"mac_bundle_identifier","id":"discovered.app"},"install":{"location":"/synthetic/not-approved"}},
            "display_name":"Discovered only","root_candidates":[{"path":"/synthetic/not-approved"}],
        }]}))
    }
}
struct Fixture {
    service: Arc<WorkspaceService>,
    store: Arc<FakeStore>,
    tracker: Arc<FakeTracking>,
    engine: Arc<FakeEngine>,
}
impl Fixture {
    fn new(read_only: bool) -> Self {
        let store = FakeStore::new(read_only);
        let tracker = FakeTracking::new(store.clone());
        let engine = FakeEngine::new();
        let service = WorkspaceService::with_components(
            store.clone(),
            engine.clone(),
            tracker.clone(),
            Arc::new(FakeDiscovery),
        )
        .unwrap();
        Self {
            service,
            store,
            tracker,
            engine,
        }
    }
    async fn join(&self) {
        let tasks = std::mem::take(&mut *self.service.tasks.lock().unwrap());
        for task in tasks {
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("bounded synthetic operation")
                .unwrap();
        }
    }
    async fn idle(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.service.lifetime.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !self.service.shutdown_blocked() {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap();
    }
}
fn upload() -> Value {
    json!({"softwareId":"software-1","providerId":"provider-1"})
}

#[tokio::test]
async fn unavailable_history_does_not_hide_local_tracking_or_admit_new_data_operations() {
    let fixture = Fixture::new(false);
    fixture
        .service
        .history_initialization_failed
        .store(true, Ordering::Release);
    let dashboard = fixture.service.dashboard().await.unwrap();
    assert_eq!(dashboard["activityUnavailable"], true);
    assert!(dashboard["activityIssue"]
        .as_str()
        .unwrap()
        .contains("retained"));
    assert!(!dashboard["software"].as_array().unwrap().is_empty());
    assert!(fixture.service.activities().await.is_err());
    assert!(fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .is_err());
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configuration_is_not_connection_and_discovery_is_not_tracking() {
    let fixture = Fixture::new(false);
    let dashboard = fixture.service.query("dashboard", json!({})).await.unwrap();
    assert_eq!(dashboard["providers"][0]["status"], "connecting");
    assert_eq!(dashboard["summary"]["connectedProviders"], 0);
    assert!(!dashboard["software"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "Discovered only"));
    assert_eq!(dashboard["software"].as_array().unwrap().len(), 1);
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    assert!(!dashboard.to_string().contains(SECRET));
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_noland_finder_is_consent_only_and_import_uses_opaque_source() {
    let fixture = Fixture::new(false);
    fixture.service.query("dashboard", json!({})).await.unwrap();
    let scope = fixture
        .service
        .approval_scope("discover_noland_import", &json!({}))
        .await
        .unwrap();
    assert!(scope["discovery"]["summary"]
        .as_str()
        .unwrap()
        .contains("com.noland.connect"));
    assert_eq!(fixture.store.discovery_reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.import_reads.load(Ordering::SeqCst), 0);
    let result = fixture
        .service
        .execute_authorized("discover_noland_import", json!({}))
        .await
        .unwrap();
    assert_eq!(result["selectedId"], "native-source-1");
    assert_eq!(
        result["candidates"][0],
        json!({
            "id":"native-source-1","label":"No Land","path":"…/com.noland.connect/state.json",
        })
    );
    assert_eq!(result["manualFallback"], "advanced_only");
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    let params = json!({"sourceId":result["selectedId"]});
    let scope = fixture
        .service
        .approval_scope("import_noland", &params)
        .await
        .unwrap();
    assert_eq!(
        scope["source"]["path"],
        "/synthetic/com.noland.connect/state.json"
    );
    assert!(!scope.to_string().contains(SECRET));
    assert!(fixture
        .service
        .approval_scope("import_noland", &json!({"sourceId":"unregistered"}))
        .await
        .is_err());
    fixture
        .service
        .execute_authorized("import_noland", params)
        .await
        .unwrap();
    assert_eq!(fixture.store.import_reads.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn local_restore_recovery_never_connects_or_retries_a_disconnected_provider() {
    let fixture = Fixture::new(true);
    fixture.engine.missing_rclone.store(true, Ordering::SeqCst);
    fixture.store.document.lock().unwrap()["providers"][0]["status"] = json!("disconnected");
    let original = uuid::Uuid::new_v4().to_string();
    let params = json!({"operationId":original});
    let scope = fixture
        .service
        .approval_scope("recover_restore", &params)
        .await
        .unwrap();
    assert_eq!(scope["restore"]["operationId"], original);
    assert_eq!(scope["restore"]["requestedOperationId"], original);
    assert!(scope.get("provider").is_none());
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    let result = fixture
        .service
        .execute_authorized("recover_restore", params)
        .await
        .unwrap();
    assert_eq!(result["recovery"]["operationId"], original);
    assert_eq!(result["recovery"]["recovered"], true);
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.published.load(Ordering::SeqCst), 0);
    {
        let calls = fixture.engine.calls.lock().unwrap();
        assert!(calls.iter().all(|(method, _)| matches!(
            method.as_str(),
            "restore_recovery_scope" | "recover_restore_local"
        )));
    }
    assert!(
        fixture.engine.guards.lock().unwrap()[&original]().is_err(),
        "Recovery authority must expire when the owned local recovery returns"
    );
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn native_previews_match_renderer_contract_without_exposing_engine_authority() {
    let fixture = Fixture::new(true);
    let disabled = fixture
        .service
        .query("app_tracking", json!({}))
        .await
        .unwrap();
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["scanning"], false);
    assert_eq!(disabled["completedApps"], 0);
    assert_eq!(disabled["totalApps"], 0);
    let preview = fixture
        .service
        .execute_authorized(
            "preview_restore",
            json!({
                "providerId":"provider-1","bundleId":"b","appId":"a",
                "destination":synthetic_path("/synthetic/native-target"),"mode":"create_new",
            }),
        )
        .await
        .unwrap();
    assert_eq!(preview["files"], 1);
    assert_eq!(preview["bytes"], 7);
    assert_eq!(preview["conflicts"], json!([]));
    assert_eq!(preview["requiresOverwriteAcknowledgement"], false);
    assert!(preview.get("device_mac").is_none());
    assert!(preview.get("manifest").is_none());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn reauthorization_keeps_provider_scope_private_and_requires_fresh_health() {
    let fixture = Fixture::new(true);
    let request = json!({"providerId":"provider-1","credentials":{"type":"access_key",
        "value":{"access_key_id":"synthetic","secret_access_key":SECRET}}});
    let approved = fixture
        .service
        .approval_scope("reauthorize_provider", &request)
        .await
        .unwrap();
    assert_eq!(approved["provider"]["id"], "provider-1");
    assert!(!approved.to_string().contains(SECRET));
    let result = fixture
        .service
        .execute_authorized("reauthorize_provider", request)
        .await
        .unwrap();
    fixture.join().await;
    let activity = fixture
        .service
        .operation(result["operationId"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(activity["state"], "completed", "{activity}");
    assert!(!activity.to_string().contains(SECRET));
    assert_eq!(
        fixture.store.document.lock().unwrap()["software"][0]["autosave"],
        false
    );
    assert_eq!(
        fixture.store.document.lock().unwrap()["providers"][0]["readOnly"],
        true
    );
    assert!(fixture
        .engine
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|(method, _)| method == "health_check"));
    assert!(!fixture
        .engine
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|(_, input)| input.to_string().contains(SECRET)));
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn approved_boolean_is_not_authority_and_oauth_never_fakes_success() {
    let fixture = Fixture::new(false);
    let mut params = upload();
    params["approved"] = json!(true);
    assert!(fixture
        .service
        .execute_authorized("upload", params)
        .await
        .is_err());
    let error = fixture
        .service
        .execute_authorized(
            "connect_oauth",
            json!({"kind":"drive","name":"Synthetic OAuth"}),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("PKCE"));
    assert_eq!(fixture.store.connected.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.count("upload"), 0);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_scope_is_deterministic_vault_free_and_binds_scope() {
    let fixture = Fixture::new(false);
    let before = fixture
        .service
        .approval_scope("upload", &upload())
        .await
        .unwrap();
    let again = fixture
        .service
        .approval_scope("upload", &upload())
        .await
        .unwrap();
    assert_eq!(before, again);
    assert_eq!(
        before["software"]["roots"][0]["path"],
        synthetic_path("/synthetic/approved")
    );
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    fixture.store.document.lock().unwrap()["software"][0]["roots"][0]["allowedFiles"] =
        json!(["one.txt"]);
    let after = fixture
        .service
        .approval_scope("upload", &upload())
        .await
        .unwrap();
    assert_ne!(before["scopeFingerprint"], after["scopeFingerprint"]);
    let mut stale = upload();
    stale["_scopeFingerprint"] = before["scopeFingerprint"].clone();
    assert!(fixture
        .service
        .execute_authorized("upload", stale)
        .await
        .is_err());
    assert_eq!(fixture.engine.count("upload"), 0);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn connect_requires_actual_native_health_evidence() {
    let fixture = Fixture::new(false);
    fixture.engine.healthy.store(false, Ordering::SeqCst);
    let result = fixture
        .service
        .execute_authorized(
            "connect_provider",
            json!({"kind":"s3","name":"Synthetic","credentials":{"secret":SECRET}}),
        )
        .await
        .unwrap();
    fixture.join().await;
    let activity = fixture.service.query("operation", result).await.unwrap();
    assert_eq!(activity["state"], "failed");
    let dashboard = fixture.service.query("dashboard", json!({})).await.unwrap();
    assert_ne!(dashboard["providers"][0]["status"], "connected");
    assert_eq!(fixture.engine.count("health_check"), 1);
    assert!(!activity.to_string().contains(SECRET));
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn real_health_completion_can_report_connected() {
    let fixture = Fixture::new(false);
    fixture
        .service
        .execute_authorized(
            "connect_provider",
            json!({"kind":"s3","name":"Synthetic","credentials":{"secret":SECRET}}),
        )
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(
        fixture.service.query("dashboard", json!({})).await.unwrap()["providers"][0]["status"],
        "connected"
    );
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_provider_recovers_retained_credentials_only_after_real_read_only_health() {
    let fixture = Fixture::new(false);
    let original_key =
        fixture.store.document.lock().unwrap()["providers"][0]["repositoryKeyRef"].clone();
    fixture.store.document.lock().unwrap()["providers"][0]["status"] = json!("error");
    fixture.engine.healthy.store(false, Ordering::SeqCst);
    assert!(fixture
        .service
        .execute_authorized("verify_provider", json!({"providerId":"provider-1"}))
        .await
        .is_err());
    assert_eq!(
        fixture.store.document.lock().unwrap()["providers"][0]["status"],
        "error"
    );
    assert_eq!(fixture.engine.count("health_check"), 1);
    fixture.engine.healthy.store(true, Ordering::SeqCst);
    let dashboard = fixture
        .service
        .execute_authorized("verify_provider", json!({"providerId":"provider-1"}))
        .await
        .unwrap();
    assert_eq!(dashboard["providers"][0]["status"], "connected");
    assert_eq!(fixture.engine.count("health_check"), 2);
    assert_eq!(fixture.engine.count("upload"), 0);
    assert_eq!(fixture.engine.count("delete"), 0);
    assert_eq!(fixture.store.connected.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.document.lock().unwrap()["providers"][0]["repositoryKeyRef"],
        original_key
    );
    assert!(!dashboard.to_string().contains(SECRET));
    // Explicit verification must not pass solely from the successful cache.
    fixture.engine.healthy.store(false, Ordering::SeqCst);
    assert!(fixture
        .service
        .execute_authorized("verify_provider", json!({"providerId":"provider-1"}))
        .await
        .is_err());
    assert_eq!(fixture.engine.count("health_check"), 3);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn disconnected_provider_requires_fresh_connection_without_attempting_vault_access() {
    let fixture = Fixture::new(false);
    fixture.store.document.lock().unwrap()["providers"][0]["status"] = json!("disconnected");
    let error = fixture
        .service
        .execute_authorized("verify_provider", json!({"providerId":"provider-1"}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("connect it again or reimport"));
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.count("health_check"), 0);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn read_only_json_edit_does_not_grant_upload_authority() {
    let fixture = Fixture::new(true);
    fixture.store.document.lock().unwrap()["providers"][0]["readOnly"] = json!(false);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert!(matches!(
        fixture.service.query("operation", operation).await.unwrap()["state"].as_str(),
        Some("failed" | "cancelled")
    ));
    assert_eq!(fixture.engine.count("upload"), 0);
    assert!(fixture.tracker.pending.lock().unwrap().is_empty());
    assert!(fixture
        .tracker
        .completed
        .lock()
        .unwrap()
        .iter()
        .all(|(_, _, success)| !*success));
    assert!(!fixture.service.shutdown_blocked());
    fixture
        .service
        .execute_authorized(
            "authorize_provider_writes",
            json!({"providerId":"provider-1"}),
        )
        .await
        .unwrap();
    fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.engine.count("upload"), 1);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsigned_manual_tracking_cannot_browse_or_capture() {
    let fixture = Fixture::new(false);
    fixture.tracker.signed.store(false, Ordering::SeqCst);
    assert!(fixture
        .service
        .query("software_files", json!({"softwareId":"software-1"}))
        .await
        .is_err());
    fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.tracker.source_reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.count("upload"), 0);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn partial_success_does_not_clear_other_dirty_files() {
    let fixture = Fixture::new(false);
    let mut params = upload();
    params["fileIds"] = json!(["file-a"]);
    fixture
        .service
        .execute_authorized("upload", params)
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(
        *fixture.tracker.dirty.lock().unwrap(),
        BTreeSet::from(["file-b".to_owned()])
    );
    assert_eq!(
        fixture.store.document.lock().unwrap()["software"][0]["dirty"],
        true
    );
    {
        let calls = fixture.engine.calls.lock().unwrap();
        let (_, input) = calls.iter().find(|(method, _)| method == "upload").unwrap();
        assert_eq!(input["fileIds"], json!(["file-a"]));
    }
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn changes_during_upload_remain_pending_and_shutdown_guard_is_nonblocking() {
    let fixture = Fixture::new(false);
    fixture.engine.hold.store(true, Ordering::SeqCst);
    fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
        .await
        .unwrap();
    {
        let _held = fixture.service.operations.lock().unwrap();
        assert!(fixture.service.shutdown_blocked()); // Must not lock or perform I/O.
    }
    assert!(fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .is_err());
    assert!(fixture.service.shutdown().await.is_err());
    fixture.tracker.changed();
    fixture.engine.complete();
    fixture.join().await;
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    assert!(!fixture.service.shutdown_blocked());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_submission_releases_flight_retains_dirty_and_redacts_errors() {
    let fixture = Fixture::new(false);
    fixture.engine.fail_submit.store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert!(fixture.tracker.pending.lock().unwrap().is_empty());
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    assert!(!fixture.service.shutdown_blocked());
    let activity = fixture
        .service
        .query("operation", operation.clone())
        .await
        .unwrap();
    assert_eq!(activity["state"], "failed");
    assert!(!activity.to_string().contains(SECRET));
    fixture.engine.fail_submit.store(false, Ordering::SeqCst);
    fixture
        .service
        .execute_authorized("retry", operation)
        .await
        .unwrap();
    fixture.join().await;
    assert!(!fixture.service.shutdown_blocked());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn changed_full_scope_retry_does_not_capture_new_files() {
    let fixture = Fixture::new(false);
    fixture.engine.fail_submit.store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    let before = fixture.engine.count("upload");
    fixture.engine.fail_submit.store(false, Ordering::SeqCst);
    fixture.tracker.changed();
    fixture
        .service
        .execute_authorized("retry", operation)
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.engine.count("upload"), before);
    assert!(fixture.tracker.pending.lock().unwrap().is_empty());
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    fixture.idle().await;
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_waits_for_real_native_terminal_state() {
    let fixture = Fixture::new(false);
    fixture.engine.hold.store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
        .await
        .unwrap();
    fixture
        .service
        .execute_authorized("cancel", operation.clone())
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(
        fixture.service.query("operation", operation).await.unwrap()["state"],
        "cancelled"
    );
    assert!(!fixture.tracker.completed.lock().unwrap()[0].2);
    assert!(!fixture.service.shutdown_blocked());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn provider_or_root_scope_change_cannot_confirm_saved_generation() {
    let fixture = Fixture::new(false);
    fixture.engine.hold.store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
        .await
        .unwrap();
    fixture.store.document.lock().unwrap()["software"][0]["roots"][0]["allowedFiles"] =
        json!(["new-unapproved.txt"]);
    fixture.engine.complete();
    fixture.join().await;
    assert!(matches!(
        fixture.service.query("operation", operation).await.unwrap()["state"].as_str(),
        Some("failed" | "cancelled")
    ));
    assert!(!fixture.tracker.completed.lock().unwrap()[0].2);
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_durable_finalization_keeps_close_blocked() {
    let fixture = Fixture::new(false);
    fixture.tracker.fail_finalize.store(true, Ordering::SeqCst);
    fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert!(fixture.service.shutdown_blocked());
    assert!(fixture.service.shutdown().await.is_err());
    assert!(fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .is_err());
    // Explicit test cleanup only; production has no forged-success escape.
    fixture
        .service
        .lifetime
        .finalization_blocked
        .store(false, Ordering::SeqCst);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn autosave_callback_enqueues_bounded_work_and_unsigned_grant_is_denied() {
    let fixture = Fixture::new(false);
    let request = fixture.tracker.begin(&upload()).unwrap();
    fixture.service.autosave_enqueue()(request).unwrap();
    // The watcher callback itself performs no access/cloud writes.
    assert_eq!(fixture.engine.count("upload"), 0);
    tokio::time::timeout(Duration::from_secs(5), fixture.tracker.finalized.notified())
        .await
        .unwrap();
    assert_eq!(fixture.engine.count("upload"), 0);
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    assert!(fixture.tracker.pending.lock().unwrap().is_empty());
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    fixture.idle().await;
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn autosave_work_is_verified_off_callback_before_cloud_access() {
    let fixture = Fixture::new(false);
    fixture
        .tracker
        .autosave_signed
        .store(true, Ordering::SeqCst);
    fixture.store.document.lock().unwrap()["software"][0]["autosave"] = json!(true);
    let mut request = fixture.tracker.begin(&upload()).unwrap();
    request["automatic"] = json!(true);
    fixture.service.autosave_enqueue()(request).unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.engine.count("upload"), 1);
    assert!(fixture.tracker.completed.lock().unwrap()[0].2);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn file_pagination_is_bounded_and_cursor_scope_cannot_be_reused() {
    let fixture = Fixture::new(false);
    let first = fixture
        .service
        .query(
            "software_files",
            json!({"softwareId":"software-1","limit":1}),
        )
        .await
        .unwrap();
    assert!(!first.to_string().contains(SECRET));
    let cursor = first["nextCursor"].clone();
    fixture.store.document.lock().unwrap()["software"][0]["roots"][0]["identity"]["fileId"] =
        json!([22, 0]);
    assert!(fixture
        .service
        .query(
            "software_files",
            json!({"softwareId":"software-1","cursor":cursor,"limit":1})
        )
        .await
        .is_err());
    assert!(fixture
        .service
        .query(
            "software_files",
            json!({"softwareId":"software-1","limit":501})
        )
        .await
        .is_err());
    let cursor = fixture
        .service
        .query(
            "bundle_files",
            json!({"providerId":"provider-1","bundleId":"bundle-1","appId":"app-1","limit":1}),
        )
        .await
        .unwrap()["nextCursor"]
        .clone();
    assert!(fixture.service.query("bundle_files",json!({"providerId":"provider-1","bundleId":"bundle-2","appId":"app-1","cursor":cursor,"limit":1})).await.is_err());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn imported_profiles_stay_read_only_without_a_separate_native_write_action() {
    let fixture = Fixture::new(false);
    let result = fixture
        .service
        .execute_authorized(
            "import_noland",
            json!({"stateFile":synthetic_path("/synthetic/read-only-source/state.json")}),
        )
        .await
        .unwrap();
    assert_eq!(result["providers"][0]["readOnly"], true);
    assert_ne!(result["providers"][0]["status"], "connected");
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.engine.count("upload"), 0);
    assert!(fixture
        .service
        .execute_authorized(
            "set_autosave",
            json!({"softwareId":"software-1","providerId":"provider-1","enabled":true})
        )
        .await
        .is_err());
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn editing_a_verified_provider_profile_invalidates_connected_projection() {
    let fixture = Fixture::new(false);
    fixture
        .service
        .execute_authorized(
            "connect_provider",
            json!({"kind":"s3","name":"Synthetic","credentials":{"secret":SECRET}}),
        )
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(
        fixture.service.query("dashboard", json!({})).await.unwrap()["providers"][0]["status"],
        "connected"
    );
    fixture.store.document.lock().unwrap()["providers"][0]["prefix"] =
        json!("unapproved-new-prefix");
    assert_ne!(
        fixture.service.query("dashboard", json!({})).await.unwrap()["providers"][0]["status"],
        "connected"
    );
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn revoked_autosave_provider_scope_releases_work_without_cloud_access() {
    let fixture = Fixture::new(false);
    fixture
        .tracker
        .autosave_signed
        .store(true, Ordering::SeqCst);
    let request = fixture.tracker.begin(&upload()).unwrap();
    fixture
        .tracker
        .call(
            "set_provider",
            &json!({"softwareId":"software-1","providerId":"provider-2"}),
        )
        .unwrap();
    fixture.service.autosave_enqueue()(request).unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.tracker.finalized.notified())
        .await
        .unwrap();
    fixture.idle().await;
    assert_eq!(fixture.engine.count("upload"), 0);
    assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
    assert!(fixture.tracker.pending.lock().unwrap().is_empty());
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn unavailable_native_status_never_fakes_terminal_failure_or_releases_admission() {
    let fixture = Fixture::new(false);
    fixture.engine.hold.store(true, Ordering::SeqCst);
    fixture
        .engine
        .unavailable_status
        .store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized("upload", upload())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        fixture.engine.status_seen.notified(),
    )
    .await
    .unwrap();
    assert!(fixture.service.shutdown_blocked());
    assert!(fixture.tracker.completed.lock().unwrap().is_empty());
    let status = fixture
        .service
        .query("operation", operation.clone())
        .await
        .unwrap();
    assert_ne!(status["state"], "completed");
    assert_ne!(status["state"], "failed");
    fixture
        .engine
        .unavailable_status
        .store(false, Ordering::SeqCst);
    fixture.engine.complete();
    fixture.join().await;
    assert_eq!(
        fixture.service.query("operation", operation).await.unwrap()["state"],
        "completed"
    );
    fixture.service.shutdown().await.unwrap();
}

struct FakeOAuth(Arc<AtomicUsize>);
impl ServiceOAuth for FakeOAuth {
    fn supports(&self, kind: &str) -> bool {
        kind == "google_drive"
    }
    fn authorize<'a>(&'a self, mut input: Value) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            input.as_object_mut().unwrap().remove("clientId");
            input["fields"] = json!({"client_id":"synthetic-client"});
            input["credentials"] = json!({"type":"o_auth2","value":{"access_token":SECRET,"refresh_token":SECRET,"expires_at":4_000_000_000_i64}});
            Ok(input)
        })
    }
}

#[tokio::test]
async fn oauth_tokens_go_only_into_private_store_then_actual_health_not_ipc_or_history() {
    let store = FakeStore::new(false);
    let tracker = FakeTracking::new(store.clone());
    let engine = FakeEngine::new();
    let service = WorkspaceService::with_oauth_components(
        store.clone(),
        engine.clone(),
        tracker.clone(),
        Arc::new(FakeDiscovery),
        Arc::new(FakeOAuth(Arc::new(AtomicUsize::new(0)))),
    )
    .unwrap();
    let fixture = Fixture {
        service,
        store,
        tracker,
        engine,
    };
    let result = fixture
        .service
        .execute_authorized(
            "connect_oauth",
            json!({"kind":"google_drive","name":"Synthetic OAuth","clientId":"synthetic-client"}),
        )
        .await
        .unwrap();
    fixture.join().await;
    let private = fixture
        .store
        .received_credentials
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(private["type"], "o_auth2");
    assert_eq!(private["value"]["access_token"], SECRET);
    assert_eq!(fixture.engine.count("health_check"), 1);
    let dashboard = fixture.service.query("dashboard", json!({})).await.unwrap();
    let operation = fixture
        .service
        .query("operation", result.clone())
        .await
        .unwrap();
    assert_eq!(dashboard["providers"][0]["status"], "connected");
    assert_eq!(operation["state"], "completed");
    assert!(!dashboard.to_string().contains(SECRET));
    assert!(!operation.to_string().contains(SECRET));
    assert!(!result.to_string().contains(SECRET));
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn oauth_storage_preflight_blocks_before_authorization_vault_or_master_key_creation() {
    for missing_tool in [false, true] {
        let store = FakeStore::new(false);
        let tracker = FakeTracking::new(store.clone());
        let engine = FakeEngine::new();
        engine.oauth_ready.store(false, Ordering::SeqCst);
        engine.missing_rclone.store(missing_tool, Ordering::SeqCst);
        let called = Arc::new(AtomicUsize::new(0));
        let service = WorkspaceService::with_oauth_components(
            store.clone(),
            engine.clone(),
            tracker.clone(),
            Arc::new(FakeDiscovery),
            Arc::new(FakeOAuth(called.clone())),
        )
        .unwrap();
        let fixture = Fixture {
            service,
            store,
            tracker,
            engine,
        };
        let operation=fixture.service.execute_authorized("connect_oauth",json!({"kind":"google_drive","name":"Synthetic OAuth","clientId":"synthetic-client"})).await.unwrap();
        fixture.join().await;
        let activity = fixture.service.query("operation", operation).await.unwrap();
        assert_eq!(activity["state"], "failed");
        assert_eq!(
            activity["error"],
            if missing_tool {
                dto::MISSING_RCLONE
            } else {
                dto::OAUTH_STORAGE_UNAVAILABLE
            }
        );
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.connected.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.access_reads.load(Ordering::SeqCst), 0);
        assert!(fixture.store.received_credentials.lock().unwrap().is_none());
        assert_eq!(fixture.engine.count("health_check"), 0);
        fixture.service.shutdown().await.unwrap();
    }
}

#[test]
fn watcher_enqueue_is_nonblocking_bounded_and_stopping_safe() {
    let queue = Queue::new();
    let enqueue = queue.enqueue();
    for index in 0..AUTOSAVE_QUEUE {
        enqueue(json!({"workId":format!("work-{index}")})).unwrap();
    }
    assert!(enqueue(json!({"workId":"overflow"})).is_err());
    assert_eq!(queue.lifetime.queued.load(Ordering::SeqCst), AUTOSAVE_QUEUE);
    queue.lifetime.stopping.store(true, Ordering::SeqCst);
    assert!(enqueue(json!({"workId":"after-stop"})).is_err());
    assert_eq!(queue.lifetime.queued.load(Ordering::SeqCst), AUTOSAVE_QUEUE);
}

#[tokio::test]
async fn deletion_confirmation_uses_frozen_counts_and_never_invokes_delete() {
    let fixture = Fixture::new(false);
    let preview = fixture
        .service
        .execute_authorized(
            "preview_delete",
            json!({"providerId":"provider-1","bundleId":"bundle-1","appId":"app-1"}),
        )
        .await
        .unwrap();
    let mut input = json!({"providerId":"provider-1","previewId":preview["previewId"],"acknowledgeDependencies":false});
    let context = fixture
        .service
        .approval_scope("delete_cloud", &input)
        .await
        .unwrap();
    assert_eq!(context["deletion"]["previewId"], "preview-1");
    assert_eq!(context["deletion"]["dependentBundleCount"], 2);
    let summary = context["deletion"]["summary"].as_str().unwrap();
    assert!(
        summary.contains("3 item(s)")
            && summary.contains("7 logical bytes")
            && summary.contains("2 dependent backup(s)")
    );
    assert!(!summary.chars().any(char::is_control));
    assert_eq!(fixture.engine.count("delete"), 0);
    assert!(fixture
        .service
        .execute_authorized("delete_cloud", input.clone())
        .await
        .is_err());
    input["acknowledgeDependencies"] = json!(true);
    fixture
        .service
        .execute_authorized("delete_cloud", input)
        .await
        .unwrap();
    fixture.join().await;
    assert_eq!(fixture.engine.count("delete"), 1);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_autosave_is_rejected_at_actual_publication_barrier() {
    let fixture = Fixture::new(false);
    fixture.engine.hold.store(true, Ordering::SeqCst);
    fixture
        .tracker
        .autosave_signed
        .store(true, Ordering::SeqCst);
    fixture.store.document.lock().unwrap()["software"][0]["autosave"] = json!(true);
    let mut request = fixture.tracker.begin(&upload()).unwrap();
    request["automatic"] = json!(true);
    fixture.service.autosave_enqueue()(request).unwrap();
    tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
        .await
        .unwrap();
    // Revoke immediately before the fake engine's publication, without relying
    // on any monitor tick/cancellation to win the race.
    fixture
        .tracker
        .autosave_signed
        .store(false, Ordering::SeqCst);
    fixture.store.document.lock().unwrap()["software"][0]["autosave"] = json!(false);
    fixture.engine.complete();
    fixture.join().await;
    fixture.idle().await;
    assert_eq!(fixture.engine.published.load(Ordering::SeqCst), 0);
    assert!(fixture
        .tracker
        .completed
        .lock()
        .unwrap()
        .iter()
        .all(|(_, _, success)| !*success));
    assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn disconnected_provider_or_revoked_manual_roots_cannot_publish_cached_credentials() {
    for revoke_roots in [false, true] {
        let fixture = Fixture::new(false);
        fixture.engine.hold.store(true, Ordering::SeqCst);
        fixture
            .service
            .execute_authorized("upload", upload())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), fixture.engine.started.notified())
            .await
            .unwrap();
        if revoke_roots {
            fixture.tracker.signed.store(false, Ordering::SeqCst);
        } else {
            fixture.store.document.lock().unwrap()["providers"][0]["status"] =
                json!("disconnected");
        }
        fixture.engine.complete();
        fixture.join().await;
        assert_eq!(fixture.engine.published.load(Ordering::SeqCst), 0);
        assert!(fixture
            .tracker
            .completed
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, success)| !*success));
        assert_eq!(fixture.tracker.dirty.lock().unwrap().len(), 2);
        fixture.service.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn missing_rclone_is_actionable_fixed_failure_not_fake_connection_or_raw_output() {
    let fixture = Fixture::new(false);
    fixture.engine.missing_rclone.store(true, Ordering::SeqCst);
    let operation = fixture
        .service
        .execute_authorized(
            "connect_provider",
            json!({"kind":"s3","name":"Synthetic","credentials":{"secret":SECRET}}),
        )
        .await
        .unwrap();
    fixture.join().await;
    let activity = fixture.service.query("operation", operation).await.unwrap();
    assert_eq!(activity["state"], "failed");
    assert_eq!(activity["error"], dto::MISSING_RCLONE);
    assert!(!activity.to_string().contains(SECRET));
    assert_eq!(
        fixture.service.query("dashboard", json!({})).await.unwrap()["providers"][0]["status"],
        "error"
    );
    fixture.service.shutdown().await.unwrap();
}

#[test]
fn source_native_listing_preserves_literal_backslashes_without_turning_them_into_paths() {
    let raw = json!({"files":[
        {"id":"literal","name":"a\\b","path":"a\\b","directory":false,"size":1},
        {"id":"nested","name":"b","path":"a/b","directory":false,"size":2},
        {"id":"colon","name":"a:b","path":"a:b","directory":false,"size":3},
    ],"nextCursor":null});
    let page = dto::files(&raw, 3).unwrap();
    assert_eq!(page["files"][0]["path"], "a\\b");
    assert_eq!(page["files"][1]["path"], "a/b");
    for path in ["../escape", "a/../escape", "/absolute", "bad\0name"] {
        let mut invalid = raw.clone();
        invalid["files"][0]["path"] = json!(path);
        assert!(dto::files(&invalid, 3).is_err());
    }
}

#[test]
fn error_categories_never_echo_private_bodies() {
    assert_eq!(
        dto::engine_error(&anyhow!("rclone is not installed: {SECRET}")),
        dto::MISSING_RCLONE
    );
    assert_eq!(
        dto::engine_error(&anyhow!(
            "native bridge unsupported on this platform: {SECRET}"
        )),
        dto::UNSUPPORTED_PLATFORM
    );
    assert_eq!(
        dto::engine_error(&anyhow!("provider is read-only: {SECRET}")),
        dto::READ_ONLY_PROVIDER
    );
    assert_eq!(dto::engine_error(&anyhow!("{SECRET}")), dto::NATIVE_FAILURE);
}

#[tokio::test]
async fn native_pins_are_excluded_from_scope_digest_and_preserved_for_owned_download() {
    let fixture = Fixture::new(false);
    let preview = fixture.service.execute_authorized("preview_restore",
        json!({"providerId":"provider-1","bundleId":"bundle-1","appId":"app-1","destination":synthetic_path("/synthetic/approved-destination"),"mode":"create_new"}))
        .await.unwrap();
    let mut params =
        json!({"restorePreviewId":preview["previewId"],"overwriteAcknowledgement":false});
    let before = fixture
        .service
        .approval_scope("download", &params)
        .await
        .unwrap();
    let proofs = json!([{"path":synthetic_path("/synthetic/approved-destination"),"kind":"directory","identity":{"device":7,"fileId":[42,0]}}]);
    params["_approvedPaths"] = proofs.clone();
    let after = fixture
        .service
        .approval_scope("download", &params)
        .await
        .unwrap();
    assert_eq!(before, after);
    params["_scopeFingerprint"] = before["scopeFingerprint"].clone();
    fixture
        .service
        .execute_authorized("download", params)
        .await
        .unwrap();
    fixture.join().await;
    {
        let calls = fixture.engine.calls.lock().unwrap();
        let selection = &calls
            .iter()
            .find(|(method, _)| method == "download")
            .unwrap()
            .1;
        assert_eq!(selection["_approvedPaths"], proofs);
    }
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn one_atomic_outstanding_counter_covers_queue_handoff_and_shutdown_barrier() {
    let fixture = Fixture::new(false);
    fixture
        .service
        .lifetime
        .outstanding
        .store(1, Ordering::SeqCst);
    fixture.service.lifetime.queued.store(1, Ordering::SeqCst);
    assert!(fixture.service.shutdown_blocked());
    fixture.service.lifetime.active.store(1, Ordering::SeqCst);
    fixture.service.lifetime.queued.store(0, Ordering::SeqCst);
    assert!(fixture.service.shutdown_blocked());
    assert!(fixture.service.shutdown().await.is_err());
    fixture.service.lifetime.active.store(0, Ordering::SeqCst);
    fixture
        .service
        .lifetime
        .outstanding
        .store(0, Ordering::SeqCst);
    fixture.service.shutdown().await.unwrap();
    assert!(fixture
        .service
        .lifetime
        .shutdown_complete
        .load(Ordering::Acquire));
}

#[test]
fn bounded_parameters_reject_deep_large_and_ambiguous_inputs() {
    let mut deep = json!(null);
    for _ in 0..30 {
        deep = json!({"nested":deep});
    }
    assert!(dto::bounded(&deep, dto::MAX_INPUT_BYTES).is_err());
    assert!(dto::bounded(
        &json!({"credentials":"x".repeat(dto::MAX_INPUT_BYTES)}),
        dto::MAX_INPUT_BYTES
    )
    .is_err());
    assert!(dto::validate_action(
        "download",
        &json!({"providerId":"p","bundleId":"b","appId":"a","destination":"/synthetic/../escape"})
    )
    .is_err());
    assert!(dto::validate_action(
        "upload",
        &json!({"softwareId":"s","providerId":"p","fileIds":[]})
    )
    .is_err());
    assert!(dto::validate_action(
        "upload",
        &json!({"softwareId":"s","providerId":"p","fileIds":["same","same"]})
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn owned_native_root_guard_rejects_replacement_and_symlinks() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();
    let metadata = std::fs::metadata(&root).unwrap();
    let record = json!({"roots":[{"path":root,"identity":{"device":metadata.dev(),"fileId":[metadata.ino(),0]}}]});
    let guard = root_guard::pin(&record).unwrap();
    guard.verify().unwrap();
    let moved = base.join("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(guard.verify().is_err());
    assert!(root_guard::pin(&record).is_err());
    let link = base.join("link");
    symlink(&moved, &link).unwrap();
    let mut symlink_record = record;
    symlink_record["roots"][0]["path"] = json!(link);
    assert!(root_guard::pin(&symlink_record).is_err());
}
