// SPDX-License-Identifier: GPL-3.0-only
//! Isolated batch fixtures. Loaded from batch.rs, never a production backend.

use super::*;
use crate::{
    interfaces::{ServiceDiscovery, ServiceEngine, ServiceStore, ServiceTracking},
    native_plans::{WorkspaceOperationSigner, MAX_NATIVE_PLAN_BYTES},
};
use quicksave_platform::{ensure_private_directory, SafeRoot};
use quicksave_state::{MemoryVault, ProviderAccess, WorkspaceStore};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
};

struct FixtureStore {
    state: Mutex<Value>,
    provider_accesses: AtomicUsize,
}
impl ServiceStore for FixtureStore {
    fn snapshot(&self) -> Result<Value> {
        Ok(self.state.lock().unwrap().clone())
    }
    fn provider_types(&self) -> Value {
        json!([])
    }
    fn connect_provider(&self, _: &Value) -> Result<Value> {
        bail!("No live accounts in batch fixtures")
    }
    fn disconnect_provider(&self, _: &str) -> Result<()> {
        bail!("Not a fixture action")
    }
    fn import_noland(&self, _: &Value) -> Result<Value> {
        bail!("No live No Land state in fixtures")
    }
    fn provider_access(&self, id: &str, operation: &str) -> Result<ProviderAccess> {
        ensure!(
            id == "fixture-provider" && Uuid::parse_str(operation).is_ok(),
            "Fixture provider/operation scope changed"
        );
        self.provider_accesses.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderAccess {
            provider_id: id.into(),
            session: json!({"fixture":true}),
            repository_key: [19; 32],
            read_only: false,
        })
    }
    fn record_provider_health(&self, _: &str, _: &Value) -> Result<()> {
        Ok(())
    }
    fn grant_provider_write(&self, _: &str) -> Result<()> {
        bail!("Not a fixture action")
    }
    fn provider_writable(&self, id: &str) -> Result<bool> {
        Ok(id == "fixture-provider")
    }
}
struct NoDiscovery;
impl ServiceDiscovery for NoDiscovery {
    fn applications(&self) -> Result<Value> {
        bail!("Batch execution must not run discovery")
    }
}
struct RealRootPin(Vec<(SafeRoot, quicksave_platform::RootIdentity)>);
impl SourceGuard for RealRootPin {
    fn verify(&self) -> Result<()> {
        for (root, expected) in &self.0 {
            ensure!(&root.identity()? == expected, "Fixture native root changed");
        }
        Ok(())
    }
}
struct PendingFixture {
    work: Value,
    nodes: Vec<Value>,
    full_scope: Value,
    receipt: Option<Arc<dyn quicksave_tracking::NativeCaptureReceipt>>,
}
struct FixtureTracking {
    store: Arc<FixtureStore>,
    signer: Arc<WorkspaceOperationSigner>,
    pending: Mutex<BTreeMap<String, PendingFixture>>,
    source_by_work: Mutex<BTreeMap<String, Uuid>>,
    prepared: AtomicUsize,
    successful_finalizations: AtomicUsize,
    dirty_reconciliations: AtomicUsize,
    metadata_checks: AtomicUsize,
    source_key: [u8; 32],
}
fn tracking_scope(record: &Value) -> Value {
    json!({"domain":"fixture-native-tracking","id":record["id"],"appId":record["appId"],
        "sourceIdentity":record["sourceIdentity"],"providerId":record["providerId"],"roots":record["roots"]})
}
fn fixture_hash(value: &Value) -> Result<String> {
    // Tracker's signed scope uses raw hexadecimal JSON digests, not the
    // source's separately namespaced `blake3:` manifest/content hash syntax.
    native_plans::fingerprint(value)
}
fn fixture_source_mac(key: &[u8; 32], value: &Value) -> Result<String> {
    Ok(
        blake3::keyed_hash(key, native_plans::fingerprint(value)?.as_bytes())
            .to_hex()
            .to_string(),
    )
}
fn fixture_root_metadata(root: &SafeRoot) -> Result<Value> {
    #[cfg(not(windows))]
    let metadata = root.clone_root_directory_handle()?.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.is_dir(),
            "Fixture full-scope root is not a native directory"
        );
        Ok(json!({
            "stamp":{
                "device":metadata.dev(),"file_id":[metadata.ino(),0],"size":metadata.len(),
                "modified_seconds":metadata.mtime(),"modified_nanoseconds":metadata.mtime_nsec(),
                "changed_seconds":metadata.ctime(),"changed_nanoseconds":metadata.ctime_nsec(),
            },
            "metadata":{
                "mode":metadata.mode(),"owner":metadata.uid(),"group":metadata.gid(),
                "linkCount":metadata.nlink(),
            },
        }))
    }
    #[cfg(windows)]
    {
        let native =
            noland_snapshot::WindowsMetadata::from_file(&root.clone_root_directory_handle()?)?;
        ensure!(
            native.kind == noland_snapshot::NativeEntryKind::Directory,
            "Fixture full-scope root is not a native directory"
        );
        let time = |ticks: i64| -> Result<(i64, u32)> {
            Ok((
                ticks
                    .div_euclid(10_000_000)
                    .checked_sub(11_644_473_600)
                    .context("Fixture native timestamp exceeds representable range")?,
                ticks.rem_euclid(10_000_000) as u32 * 100,
            ))
        };
        let modified = time(native.last_write_time)?;
        let changed = time(native.change_time)?;
        Ok(json!({
            "stamp":{
                "device":native.identity.volume,"file_id":native.identity.file_id,
                "size":native.size,
                "modified_seconds":modified.0,"modified_nanoseconds":modified.1,
                "changed_seconds":changed.0,"changed_nanoseconds":changed.1,
            },
            "metadata":{
                "platform":"windows",
                "identity":{"device":native.identity.volume,"fileId":native.identity.file_id},
                "kind":"directory","size":native.size,
                "creationTime":native.creation_time,"lastAccessTime":native.last_access_time,
                "lastWriteTime":native.last_write_time,"changeTime":native.change_time,
                "attributes":native.attributes,"linkCount":native.number_of_links,
                "reparseTag":native.reparse_tag,
            },
        }))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        bail!("This isolated full-scope fixture requires Unix native metadata")
    }
}
impl FixtureTracking {
    fn record(&self, id: &str) -> Result<Value> {
        let state = self.store.state.lock().unwrap();
        state["software"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["id"] == id)
            .cloned()
            .context("Fixture software missing")
    }
    fn prepare(&self, input: &Value) -> Result<Value> {
        let record = self.record(dto::id(input, "softwareId")?)?;
        ensure!(
            record.get("pendingWork").is_none_or(Value::is_null),
            "original durable native work requires recovery before creating new work"
        );
        let mut pending = self.pending.lock().unwrap();
        ensure!(
            pending
                .values()
                .all(|pending| pending.work["softwareId"] != record["id"]),
            "Original fixture work is already in flight for this software"
        );
        self.metadata_checks.fetch_add(1, Ordering::SeqCst);
        self.pin_scope(&record)?.verify()?;
        ensure!(
            input.get("fileIds").is_none(),
            "Whole-app batch cannot silently become selected-file work"
        );
        let work_id = Uuid::new_v4().to_string();
        let mut nodes = Vec::new();
        for root in record["roots"].as_array().unwrap() {
            let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
            for entry in native.entries()? {
                ensure!(!entry.is_directory, "Fixture expects one real regular leaf");
                let (_, stamp) = native.read_file(&entry.relative_path)?;
                let id = format!(
                    "file-{}",
                    blake3::hash(format!("{}:{}", root["id"], entry.relative_path).as_bytes())
                        .to_hex()
                );
                nodes.push(json!({
                    "id":id,"rootId":root["id"],"path":entry.relative_path,"kind":"file",
                    "size":stamp.size,"stamp":stamp,
                }));
            }
        }
        nodes.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        let ids = nodes
            .iter()
            .map(|node| node["id"].clone())
            .collect::<Vec<_>>();
        let metadata = native_plans::fingerprint(&json!(nodes))?;
        let mut root_stamps = serde_json::Map::new();
        let mut root_metadata = serde_json::Map::new();
        for root in record["roots"].as_array().unwrap() {
            let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
            let actual = fixture_root_metadata(&native)?;
            let id = dto::id(root, "id")?.to_owned();
            root_stamps.insert(id.clone(), actual["stamp"].clone());
            root_metadata.insert(id, actual["metadata"].clone());
        }
        let proof_scope = json!({
            "domain":"fixture-native-full-capture","version":1,
            "workId":work_id,"softwareId":record["id"],"providerId":input["providerId"],
            "generation":1,"metadataIdentity":metadata,
            "trackingScopeHash":fixture_hash(&tracking_scope(&record))?,
            "rootIds":record["roots"].as_array().unwrap().iter().map(|root|&root["id"]).collect::<Vec<_>>(),
            "expectedNodeIdsHash":fixture_hash(&json!(ids))?,
            "deletedNodeIdsHash":fixture_hash(&json!([]))?,
            "baselineKind":"none","baselineIdentity":Value::Null,
            "snapshotMode":"additive_full_scope","keepsHistory":true,
        });
        let full_proof = json!({
            "scope":proof_scope,"grant":self.signer.seal(&proof_scope)?,
        });
        let work = json!({
            "workId":work_id,"generation":1,"softwareId":record["id"],"appId":record["appId"],
            "sourceIdentity":record["sourceIdentity"],"providerId":input["providerId"],
            "roots":record["roots"],"fileIds":ids,"deletedFileIds":[],"automatic":false,
            "captureSource":{"stage":"awaiting_native_capture_receipt","selectionKind":"full_scope","snapshotIdentity":metadata,
                "metadataSelection":{"workId":work_id,"metadataIdentity":metadata,
                    "nodeCount":nodes.len(),"source":"tracker_native_index"},
                "expectedFullScope":full_proof},
        });
        let full_scope = json!({
            "version":1,"workId":work_id,"softwareId":record["id"],"sourceIdentity":record["sourceIdentity"],
            "providerId":input["providerId"],"generation":1,"metadataIdentity":metadata,
            "fullScope":true,"completeFileList":true,"keepsVersionHistory":true,
            "coverageScope":"approved_evidenced_roots_only","expectedFullScope":full_proof,
            "authorization":{"trackingScope":tracking_scope(&record),"trackingGrant":record["trackingGrant"]},
            "roots":record["roots"],"rootMetadata":root_metadata,"rootStamps":root_stamps,
            "deletedFileIds":[],"deletedNodes":[],
            "baseline":{"kind":"none","snapshotIdentity":Value::Null,"reference":Value::Null,"scope":Value::Null},
            "autoEnrollment":Value::Null,
        });
        pending.insert(
            work_id,
            PendingFixture {
                work: work.clone(),
                nodes,
                full_scope,
                receipt: None,
            },
        );
        self.prepared.fetch_add(1, Ordering::SeqCst);
        Ok(work)
    }
    fn full_scope_evidence(&self, id: &str) -> Result<Value> {
        self.metadata_checks.fetch_add(1, Ordering::SeqCst);
        let (work, nodes, evidence) = {
            let pending = self.pending.lock().unwrap();
            let pending = pending
                .get(id)
                .context("Unknown original full-scope fixture work")?;
            (
                pending.work.clone(),
                pending.nodes.clone(),
                pending.full_scope.clone(),
            )
        };
        let record = self.record(dto::id(&work, "softwareId")?)?;
        self.pin_scope(&record)?.verify()?;
        let proof = &evidence["expectedFullScope"];
        ensure!(
            self.signer.verify(&proof["scope"], &proof["grant"])?
                && proof == &work["captureSource"]["expectedFullScope"]
                && evidence["roots"] == record["roots"]
                && proof["scope"]["workId"] == id
                && proof["scope"]["metadataIdentity"] == work["captureSource"]["snapshotIdentity"]
                && proof["scope"]["generation"] == work["generation"]
                && proof["scope"]["trackingScopeHash"] == fixture_hash(&tracking_scope(&record))?
                && proof["scope"]["expectedNodeIdsHash"] == fixture_hash(&work["fileIds"])?,
            "Original fixture full-scope grant/root/selection binding failed"
        );
        let mut actual_nodes = Vec::new();
        for root in record["roots"].as_array().unwrap() {
            let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
            let actual = fixture_root_metadata(&native)?;
            let root_id = dto::id(root, "id")?;
            ensure!(
                evidence["rootStamps"][root_id] == actual["stamp"]
                    && evidence["rootMetadata"][root_id] == actual["metadata"],
                "Frozen native full-scope root metadata changed"
            );
            for entry in native.entries()? {
                let node = nodes
                    .iter()
                    .find(|node| node["rootId"] == root_id && node["path"] == entry.relative_path)
                    .context("Native full-scope fixture contains a late/unapproved node")?;
                ensure!(
                    !entry.is_directory,
                    "Fixture does not support directory payload nodes"
                );
                let (_, stamp) = native.read_file(&entry.relative_path)?;
                ensure!(
                    serde_json::to_value(&stamp)? == node["stamp"],
                    "Original native node metadata changed"
                );
                actual_nodes.push(node["id"].clone());
            }
        }
        actual_nodes.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        ensure!(
            json!(actual_nodes) == work["fileIds"],
            "Native full-scope inventory omitted a frozen node"
        );
        Ok(evidence)
    }
    fn verify_source_receipt(
        &self,
        work: &Value,
        nodes: &[Value],
        receipt: &Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<()> {
        receipt.revalidate()?;
        let evidence = receipt.evidence()?;
        let scope = &evidence["scope"];
        ensure!(
            evidence["mac"] == fixture_source_mac(&self.source_key, scope)?
                && scope["domain"] == "fixture-source-capture-receipt"
                && scope["workId"] == work["workId"]
                && scope["generation"] == work["generation"]
                && scope["metadataIdentity"] == work["captureSource"]["snapshotIdentity"]
                && scope["roots"] == work["roots"]
                && scope["selectionDigest"] == native_plans::fingerprint(&work["fileIds"])?,
            "Synthetic source MAC did not authenticate this original native capture"
        );
        let actual = scope["nodes"]
            .as_array()
            .context("Source native receipt omitted its exact nodes")?;
        ensure!(
            actual.len() == nodes.len(),
            "Source receipt changed the frozen node count"
        );
        for (actual, expected) in actual.iter().zip(nodes) {
            for key in ["id", "rootId", "path", "kind", "size", "stamp"] {
                ensure!(
                    actual[key] == expected[key],
                    "Source native receipt changed frozen node metadata"
                );
            }
            native_plans::checked_digest(dto::text(actual, "fileHash", 64)?)?;
        }
        self.full_scope_evidence(dto::id(work, "workId")?)?;
        Ok(())
    }
    fn finish(&self, input: &Value) -> Result<Value> {
        let id = dto::id(input, "workId")?;
        let (work, nodes, receipt) = {
            let pending = self.pending.lock().unwrap();
            let pending = pending.get(id).context("Unknown original fixture work")?;
            (
                pending.work.clone(),
                pending.nodes.clone(),
                pending.receipt.clone(),
            )
        };
        let success = dto::boolean(input, "success")?;
        ensure!(
            input["generation"] == work["generation"],
            "Fixture generation changed"
        );
        if success {
            self.verify_source_receipt(
                &work,
                &nodes,
                receipt
                    .as_ref()
                    .context("No original native fixture capture receipt")?,
            )?;
        }
        let mut state = self.store.state.lock().unwrap();
        let record = state["software"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["id"] == work["softwareId"])
            .unwrap();
        ensure!(
            record.get("pendingWork").is_none_or(Value::is_null),
            "This fresh fixture work cannot retire an unrelated original native frame"
        );
        record["dirty"] = json!(!success);
        record["status"] = json!(if success { "saved" } else { "needs_backup" });
        // Match the complete-record retirement contract, rather than relying
        // on a patch store to infer removal from an omitted pointer.
        record["pendingWork"] = Value::Null;
        if success {
            let source = *self
                .source_by_work
                .lock()
                .unwrap()
                .get(id)
                .context("Fixture source ID missing")?;
            record["baseline"] = json!({
                "generation":work["generation"],"sourceId":source,
                "snapshotIdentity":work["captureSource"]["snapshotIdentity"],
            });
            record["lastConfirmedUploadedGeneration"] = work["generation"].clone();
            if !record["versionHistory"].is_array() {
                record["versionHistory"] = json!([]);
            }
            let baseline = record["baseline"].clone();
            record["versionHistory"]
                .as_array_mut()
                .unwrap()
                .push(baseline);
            self.successful_finalizations.fetch_add(1, Ordering::SeqCst);
        }
        self.pending.lock().unwrap().remove(id);
        Ok(record.clone())
    }
}
impl ServiceTracking for FixtureTracking {
    fn call(&self, method: &str, input: &Value) -> Result<Value> {
        match method {
            "software" => Ok(self.store.snapshot()?["software"].clone()),
            "prepare_upload_scope" => self.prepare(input),
            "full_scope_evidence" => self.full_scope_evidence(dto::id(input, "workId")?),
            "begin_upload" => bail!("A batch must not use the prehash/folder-copy path"),
            "verify_upload_authority" => {
                self.pin_scope(&self.record(dto::id(input, "softwareId")?)?)?
                    .verify()?;
                Ok(json!({}))
            }
            "prepared_node_listing" => {
                let pending = self.pending.lock().unwrap();
                let work = pending
                    .get(dto::id(input, "workId")?)
                    .context("Original node page missing")?;
                let cursor = dto::text(input, "cursor", 1024)?;
                let (prefix, offset) = cursor
                    .rsplit_once(':')
                    .context("Invalid fixture native cursor")?;
                ensure!(
                    prefix
                        == format!(
                            "{}:{}",
                            work.work["workId"].as_str().unwrap(),
                            work.work["captureSource"]["metadataSelection"]["metadataIdentity"]
                                .as_str()
                                .unwrap()
                        ),
                    "Native fixture cursor changed scope"
                );
                let offset = offset.parse::<usize>()?;
                let limit = dto::limit(input)?;
                Ok(
                    json!({"nodes":work.nodes.iter().skip(offset).take(limit).collect::<Vec<_>>(),
                    "metadataIdentity":work.work["captureSource"]["metadataSelection"]["metadataIdentity"]}),
                )
            }
            "verify_capture_receipt" => {
                let (work, nodes, receipt) = {
                    let pending = self.pending.lock().unwrap();
                    let pending = pending
                        .get(dto::id(input, "workId")?)
                        .context("Fixture source receipt missing")?;
                    (
                        pending.work.clone(),
                        pending.nodes.clone(),
                        pending.receipt.clone(),
                    )
                };
                self.verify_source_receipt(
                    &work,
                    &nodes,
                    receipt
                        .as_ref()
                        .context("Fixture source has not accepted a native receipt")?,
                )?;
                Ok(
                    json!({"verified":true,"workId":work["workId"],"generation":work["generation"],
                    "sourceExpectedManifestAuthPreserved":true}),
                )
            }
            "capture_reuse_epoch" => Ok(json!({"epoch":Value::Null})),
            "complete_upload" => self.finish(input),
            _ => bail!("Unsupported fixture tracking operation: {method}"),
        }
    }
    fn pin_scope(&self, record: &Value) -> Result<Arc<dyn SourceGuard>> {
        ensure!(
            self.signer
                .verify(&tracking_scope(record), &record["trackingGrant"])?,
            "Fixture native tracking grant failed"
        );
        let mut pins = Vec::new();
        for root in record["roots"]
            .as_array()
            .context("Fixture roots missing")?
        {
            let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
            let expected: quicksave_platform::RootIdentity =
                serde_json::from_value(root["identity"].clone())?;
            ensure!(
                native.identity()? == expected,
                "Fixture approved root identity changed"
            );
            pins.push((native, expected));
        }
        Ok(Arc::new(RealRootPin(pins)))
    }
    fn shutdown(&self) -> Result<()> {
        ensure!(
            self.pending.lock().unwrap().is_empty(),
            "Original fixture tracking work has not been released"
        );
        Ok(())
    }
    fn accept_capture_receipt(
        &self,
        work_id: &str,
        receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<Value> {
        let (work, nodes) = {
            let pending = self.pending.lock().unwrap();
            let pending = pending
                .get(work_id)
                .context("No original fixture capture owner")?;
            ensure!(
                pending.receipt.is_none(),
                "Fixture native receipt was already accepted"
            );
            (pending.work.clone(), pending.nodes.clone())
        };
        self.verify_source_receipt(&work, &nodes, &receipt)?;
        self.pending
            .lock()
            .unwrap()
            .get_mut(work_id)
            .context("Original fixture work ended during source acceptance")?
            .receipt = Some(receipt);
        Ok(json!({"workId":work_id,"generation":work["generation"]}))
    }
}

struct FixtureSourceRow {
    body: Value,
    mac: String,
    guard: PublishGuard,
}
/// Isolated source-produced Rust receipt. It is not an incoming JSON
/// authentication flag and is never installed as a production implementation.
/// Unlike an immutable source checkpoint, this fixture requires live stamp
/// revalidation and therefore deliberately does not claim immutable capture.
struct FixtureCaptureReceipt {
    scope: Value,
    mac: String,
    key: [u8; 32],
    roots: Vec<(SafeRoot, Value)>,
    files: Vec<(SafeRoot, String, quicksave_platform::FileStamp)>,
}
impl quicksave_tracking::NativeCaptureReceipt for FixtureCaptureReceipt {
    fn evidence(&self) -> Result<Value> {
        Ok(json!({"scope":self.scope,"mac":self.mac}))
    }
    fn revalidate(&self) -> Result<()> {
        ensure!(
            fixture_source_mac(&self.key, &self.scope)? == self.mac,
            "Synthetic native source capture MAC changed"
        );
        for (root, metadata) in &self.roots {
            ensure!(
                fixture_root_metadata(root)? == *metadata,
                "Native source root changed after fixture capture"
            );
        }
        for (root, path, stamp) in &self.files {
            root.verify_file(path, stamp)?;
        }
        Ok(())
    }
    fn immutable_prepared_capture(&self) -> bool {
        false
    }
}
struct FixtureEngine {
    tracking: Arc<FixtureTracking>,
    rows: Mutex<BTreeMap<Uuid, FixtureSourceRow>>,
    owners: Mutex<BTreeSet<Uuid>>,
    submissions: Mutex<Vec<(Uuid, Value)>>,
    reads: AtomicUsize,
    hold: AtomicBool,
    corrupt: AtomicBool,
    signing_key: [u8; 32],
    reauthentications: Mutex<Vec<Uuid>>,
    history_owner_unknown: AtomicBool,
    history_owner_pages: Mutex<Vec<usize>>,
}
impl FixtureEngine {
    fn mac(&self, body: &Value) -> Result<String> {
        fixture_source_mac(&self.signing_key, body)
    }
    fn set_terminal(&self, id: Uuid, state: &str) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .get_mut(&id)
            .context("Fixture actual source row missing")?;
        if state == "completed" {
            (row.guard)()?;
        }
        row.body["state"] = json!(state);
        row.body["workerRunning"] = json!(false);
        row.mac = self.mac(&row.body)?;
        self.owners.lock().unwrap().remove(&id);
        Ok(())
    }
    fn activity(&self, id: Uuid) -> Result<Value> {
        let rows = self.rows.lock().unwrap();
        let row = rows
            .get(&id)
            .context("Unknown actual fixture source operation")?;
        Ok(json!({
            "id":id,"kind":"upload","name":"Actual injected source job",
            "state":row.body["state"],"phase":if row.body["state"]=="completed" {"completed"} else {"uploading"},
            "canCancel":self.owners.lock().unwrap().contains(&id),"canRetry":false,
            "completedBytes":row.body["bytes"],"totalBytes":row.body["bytes"],
        }))
    }
}
impl ServiceEngine for FixtureEngine {
    fn shutdown<'a>(&'a self) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let rows = self
                .rows
                .lock()
                .map_err(|_| anyhow::anyhow!("Fixture source owner lock failed"))?;
            ensure!(
                self.owners.lock().unwrap().is_empty(),
                "An actual fixture source worker has not drained"
            );
            for row in rows.values() {
                ensure!(
                    matches!(
                        row.body["state"].as_str(),
                        Some("completed" | "failed" | "cancelled" | "interrupted")
                    ),
                    "An actual fixture source owner is still running or unknown"
                );
            }
            Ok(())
        })
    }
    fn native_capture_supported(&self) -> bool {
        true
    }
    fn call<'a>(
        &'a self,
        method: &'a str,
        _: Option<ProviderAccess>,
        input: Value,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            match method {
                "preflight" => Ok(json!({"available":true})),
                "health_check" => Ok(
                    json!({"canList":true,"canRead":true,"repositoryAccessible":true,
                    "repositoryEmpty":false,"keyVerified":true}),
                ),
                "register" => {
                    ensure!(
                        input["sourceIdentity"]["app_id"].is_string(),
                        "Original canonical identity was not preserved"
                    );
                    self.tracking.pin_scope(&input)?.verify()?;
                    Ok(json!({}))
                }
                "status" => self.activity(parse_id(dto::id(&input, "operationId")?)?),
                "cancel" => {
                    let id = parse_id(dto::id(&input, "operationId")?)?;
                    if self.rows.lock().unwrap().contains_key(&id) {
                        self.set_terminal(id, "cancelled")?;
                    }
                    Ok(json!({"operationId":id}))
                }
                "recent" => Ok(json!([])),
                _ => bail!("No unguarded source RPC path in this fixture"),
            }
        })
    }
    fn upload_guarded<'a>(
        &'a self,
        _: ProviderAccess,
        _: Value,
        _: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async { bail!("A batch must delegate to actual captured native upload") })
    }
    fn retry_guarded<'a>(&'a self, _: &'a str, _: PublishGuard) -> NativeFuture<'a, Value> {
        Box::pin(async { bail!("Fixture cannot recover original source prepared work") })
    }
    #[cfg(unix)]
    fn upload_captured_guarded<'a>(
        &'a self,
        _: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
        controller: Arc<dyn quicksave_noland::capture_control::NativeCaptureController>,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            guard()?;
            let id = parse_id(dto::id(&selection, "operationId")?)?;
            ensure!(
                !self.rows.lock().unwrap().contains_key(&id),
                "Completed source child must not be resubmitted"
            );
            let work_id = dto::id(&selection, "workId")?;
            let record = self.tracking.record(dto::id(&selection, "softwareId")?)?;
            let mut scope: quicksave_noland::capture_control::CaptureScope =
                serde_json::from_value(json!({
                    "version":1,"workId":work_id,
                    "metadataIdentity":selection["captureSource"]["metadataSelection"]["metadataIdentity"],
                    "nodeCount":selection["fileIds"].as_array().unwrap().len(),
                }))?;
            let full = controller
                .full_scope_authority(&scope)?
                .context("Whole-app fixture source has no native full-scope owner")?;
            full.revalidate()?;
            let evidence = full.evidence()?;
            ensure!(
                evidence["expectedFullScope"] == selection["captureSource"]["expectedFullScope"]
                    && evidence["roots"] == selection["roots"]
                    && evidence["workId"] == selection["workId"]
                    && evidence["generation"] == selection["generation"],
                "Native source full-scope authority changed original work/root scope"
            );
            scope.full_scope = Some(quicksave_noland::capture_control::full_scope_from_evidence(
                &evidence,
            )?);
            scope.validate()?;
            let mut nodes = Vec::new();
            while nodes.len() < scope.node_count {
                let page = controller.node_page(
                    &scope,
                    nodes.len(),
                    500.min(scope.node_count - nodes.len()),
                )?;
                ensure!(
                    !page.is_empty(),
                    "Native fixture source lost original metadata nodes"
                );
                nodes.extend(page);
            }
            ensure!(
                nodes.len() == selection["fileIds"].as_array().unwrap().len(),
                "Actual fixture source omitted native nodes"
            );
            let mut bytes = 0u64;
            let mut hashes = Vec::new();
            let mut root_pins = Vec::new();
            for root in record["roots"].as_array().unwrap() {
                let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
                let metadata = fixture_root_metadata(&native)?;
                root_pins.push((native, metadata));
            }
            let mut files = Vec::new();
            for node in &nodes {
                let root = record["roots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|root| root["id"] == node.root_id)
                    .context("Native source root widened")?;
                let native = SafeRoot::open(Path::new(root["path"].as_str().unwrap()))?;
                let (file, before) = native.read_file(&node.path)?;
                ensure!(
                    serde_json::to_value(&before)? == serde_json::to_value(&node.stamp)?,
                    "Native source opened a file outside its frozen metadata stamp"
                );
                let mut content = Vec::new();
                file.take(1024 * 1024).read_to_end(&mut content)?;
                ensure!(
                    content.len() as u64 == before.size,
                    "Fixture bounded source capture changed size"
                );
                native.verify_file(&node.path, &before)?;
                bytes += content.len() as u64;
                hashes.push(json!({
                    "id":node.id,"logicalRoot":node.logical_root,"rootId":node.root_id,
                    "path":node.path,"kind":node.kind,"size":content.len(),"stamp":before,
                    "fileHash":blake3::hash(&content).to_hex().to_string(),
                }));
                files.push((native, node.path.clone(), before));
                self.reads.fetch_add(1, Ordering::SeqCst);
            }
            let receipt_scope = json!({
                "domain":"fixture-source-capture-receipt",
                "workId":selection["workId"],"generation":selection["generation"],
                "metadataIdentity":selection["captureSource"]["snapshotIdentity"],
                "roots":selection["roots"],"nodes":hashes,
                "selectionDigest":native_plans::fingerprint(&selection["fileIds"])?,
                "fullScope":scope.full_scope,
            });
            let receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt> =
                Arc::new(FixtureCaptureReceipt {
                    mac: self.mac(&receipt_scope)?,
                    scope: receipt_scope,
                    key: self.signing_key,
                    roots: root_pins,
                    files,
                });
            self.tracking.accept_capture_receipt(work_id, receipt)?;
            self.tracking
                .source_by_work
                .lock()
                .unwrap()
                .insert(work_id.into(), id);
            controller.verify_publication()?;
            full.revalidate()?;
            guard()?;
            let held = self.hold.load(Ordering::Acquire);
            let manifest = json!({
                "app":selection["sourceIdentity"],"mode":"complete_application",
                "coverage":"full_approved_scope","roots":record["roots"],"files":hashes,
                "fullScope":scope.full_scope,
            });
            let body = json!({
                "sourceId":id,"softwareId":selection["softwareId"],
                "trackerAppId":selection["appId"],"canonicalAppId":selection["sourceIdentity"]["app_id"],
                "providerId":selection["providerId"],"mode":"complete_application",
                "rootAuthorityRevision":native_plans::root_authority_revision(&record)?,
                "metadataIdentity":selection["captureSource"]["metadataSelection"]["metadataIdentity"],
                "selectionDigest":native_plans::fingerprint(&selection["fileIds"])?,
                "workId":selection["workId"],"generation":selection["generation"],
                "state":if held {"running"} else {"completed"},"workerRunning":held,
                "bytes":bytes,"manifest":manifest,"committedResult":native_plans::fingerprint(&manifest)?,
            });
            let mut mac = self.mac(&body)?;
            if self.corrupt.load(Ordering::Acquire) {
                mac = "0".repeat(64);
            }
            self.rows
                .lock()
                .unwrap()
                .insert(id, FixtureSourceRow { body, mac, guard });
            if held {
                self.owners.lock().unwrap().insert(id);
            }
            self.submissions.lock().unwrap().push((id, selection));
            Ok(json!({"operationId":id}))
        })
    }
}

struct FixtureVerifier {
    engine: Arc<FixtureEngine>,
    retained_sources: BTreeSet<Uuid>,
    authenticated: Mutex<BTreeSet<Uuid>>,
}
impl FixtureVerifier {
    fn new(engine: Arc<FixtureEngine>, requires_explicit: bool) -> Self {
        // Model restart permission only for sources that already existed.
        // Fresh admissions keep their actual in-process source authority; they
        // still pass the synthetic source MAC and exact capture checks below.
        let retained_sources = if requires_explicit {
            let mut retained = engine
                .rows
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            retained.extend(engine.owners.lock().unwrap().iter().copied());
            retained
        } else {
            BTreeSet::new()
        };
        Self {
            engine,
            retained_sources,
            authenticated: Mutex::new(BTreeSet::new()),
        }
    }
    fn read_source(
        &self,
        plan: &FrozenNativePlan,
        capture: Option<&FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> Result<VerifiedSourceOperation> {
        let rows = self.engine.rows.lock().unwrap();
        let Some(row) = rows.get(&plan.source_id) else {
            return Ok(VerifiedSourceOperation {
                purpose,
                observation: NativeObservation::Absent {
                    source_id: plan.source_id,
                },
                root_authority_revision: plan.root_authority_revision.clone(),
                capture_digest: capture.map(FrozenCaptureBinding::digest).transpose()?,
                binding_digest: None,
                completion_digest: None,
            });
        };
        if purpose == SourceProofPurpose::Observation {
            ensure!(
                self.engine.mac(&row.body)? == row.mac,
                "Actual fixture source HMAC failed"
            );
            let capture = capture.context("Original capture binding absent")?;
            ensure!(
                row.body["canonicalAppId"] == plan.canonical_app_id
                    && row.body["mode"] == "complete_application"
                    && row.body["trackerAppId"] == plan.tracker_app_id
                    && row.body["softwareId"] == plan.software_id
                    && row.body["providerId"] == plan.provider_id
                    && row.body["rootAuthorityRevision"] == plan.root_authority_revision
                    && row.body["metadataIdentity"] == capture.metadata_identity
                    && row.body["selectionDigest"] == capture.selection_digest
                    && row.body["workId"] == capture.work_id
                    && row.body["generation"].as_u64() == Some(capture.generation)
                    && row.body["manifest"]["coverage"] == "full_approved_scope"
                    && native_plans::authority_roots(&row.body["manifest"])? == plan.roots
                    && native_plans::fingerprint(&row.body["manifest"])?
                        == row.body["committedResult"],
                "Actual source selection/instance differs from frozen approval"
            );
        }
        let state = match row.body["state"].as_str() {
            Some("completed") => ChildState::Completed,
            Some("cancelled") => ChildState::Cancelled,
            Some("failed") => ChildState::Failed,
            Some("interrupted") => ChildState::Interrupted,
            Some("running") => ChildState::Running,
            _ => ChildState::Unknown,
        };
        Ok(VerifiedSourceOperation {
            purpose,
            observation: NativeObservation::Present {
                status: NativeChildStatus {
                    source_id: plan.source_id,
                    state,
                    worker_running: self.engine.owners.lock().unwrap().contains(&plan.source_id),
                    progress: Some(crate::operations::NativeProgress {
                        phase: "uploading".into(),
                        unit: "bytes".into(),
                        completed: row.body["bytes"].as_u64().unwrap(),
                        total: row.body["bytes"].as_u64(),
                    }),
                },
            },
            root_authority_revision: plan.root_authority_revision.clone(),
            capture_digest: capture.map(FrozenCaptureBinding::digest).transpose()?,
            binding_digest: Some(row.mac.clone()),
            completion_digest: (state == ChildState::Completed)
                .then(|| row.body["committedResult"].as_str().unwrap().to_owned()),
        })
    }
}
impl BatchSourceVerifier for FixtureVerifier {
    fn require_supported(&self) -> Result<()> {
        Ok(())
    }
    fn history_owners<'a>(
        &'a self,
        _: Uuid,
        root_digest: &'a str,
        children: &'a [NativeHistoryChild],
    ) -> NativeFuture<'a, Vec<NativeObservation>> {
        Box::pin(async move {
            native_plans::checked_digest(root_digest)?;
            ensure!(
                !children.is_empty() && children.len() <= MAX_CHILDREN_PER_JOB,
                "Fixture ownership lookup exceeded the exact-ID page bound"
            );
            self.engine
                .history_owner_pages
                .lock()
                .unwrap()
                .push(children.len());
            let rows = self.engine.rows.lock().unwrap();
            let owners = self.engine.owners.lock().unwrap();
            Ok(children
                .iter()
                .map(|child| {
                    if self.engine.history_owner_unknown.load(Ordering::Acquire) {
                        return NativeObservation::Unknown {
                            source_id: child.source_id,
                        };
                    }
                    let Some(row) = rows.get(&child.source_id) else {
                        return if owners.contains(&child.source_id) {
                            NativeObservation::Unknown {
                                source_id: child.source_id,
                            }
                        } else {
                            NativeObservation::Absent {
                                source_id: child.source_id,
                            }
                        };
                    };
                    if row.body["sourceId"] != child.source_id.to_string()
                        || row.body["canonicalAppId"] != child.app_id
                    {
                        return NativeObservation::Unknown {
                            source_id: child.source_id,
                        };
                    }
                    let state = match row.body["state"].as_str() {
                        Some("completed") => ChildState::Completed,
                        Some("failed") => ChildState::Failed,
                        Some("cancelled") => ChildState::Cancelled,
                        Some("interrupted") => ChildState::Interrupted,
                        Some("running") => ChildState::Running,
                        _ => ChildState::Unknown,
                    };
                    NativeObservation::Present {
                        status: NativeChildStatus {
                            source_id: child.source_id,
                            state,
                            worker_running: owners.contains(&child.source_id),
                            progress: None,
                        },
                    }
                })
                .collect())
        })
    }
    fn authenticate<'a>(
        &'a self,
        _: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        Box::pin(async move {
            if purpose == SourceProofPurpose::Observation
                && self.retained_sources.contains(&plan.source_id)
            {
                let present = self
                    .engine
                    .rows
                    .lock()
                    .unwrap()
                    .contains_key(&plan.source_id);
                ensure!(
                    !present || self.authenticated.lock().unwrap().contains(&plan.source_id),
                    "Explicit fixture source reauthentication is required after restart"
                );
            }
            self.read_source(plan, capture, purpose)
        })
    }
    fn reauthenticate_existing<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: &'a FrozenCaptureBinding,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        Box::pin(async move {
            let expected_child = plan.child()?;
            ensure!(
                parent.operation_id == plan.plan_set_id
                    && parent
                        .children()
                        .any(|child| child.source_id == plan.source_id && child == &expected_child),
                "Fixture reauthentication changed the signed parent or source ID"
            );
            let verified =
                self.read_source(plan, Some(capture), SourceProofPurpose::Observation)?;
            verified.validate(plan, Some(capture), SourceProofPurpose::Observation)?;
            // The cache is populated only after the actual synthetic source MAC
            // and its exact original native selection have verified.
            self.authenticated.lock().unwrap().insert(plan.source_id);
            self.engine
                .reauthentications
                .lock()
                .unwrap()
                .push(plan.source_id);
            Ok(verified)
        })
    }
}
struct FixtureRecovery {
    tracking: Arc<FixtureTracking>,
}
impl BatchRecovery for FixtureRecovery {
    fn recover_original_work<'a>(
        &'a self,
        _: &'a FrozenPlanSet,
        _: &'a FrozenNativePlan,
        _: &'a FrozenCaptureBinding,
        _: &'a VerifiedSourceOperation,
        _: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async {
            bail!("Original source receipt reattachment deliberately unavailable in this fixture")
        })
    }
    fn mark_unknown_dirty<'a>(
        &'a self,
        plan: &'a FrozenNativePlan,
        _: Option<&'a FrozenCaptureBinding>,
        _: ReconciliationGapKind,
    ) -> NativeFuture<'a, DirtyBaselineReceipt> {
        Box::pin(async move {
            let mut state = self.tracking.store.state.lock().unwrap();
            let record = state["software"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|record| record["id"] == plan.software_id)
                .context("Original software missing")?;
            ensure!(
                native_plans::root_authority_revision(record)? == plan.root_authority_revision,
                "Do not overwrite a differently authorized software scope"
            );
            record["dirty"] = json!(true);
            record["status"] = json!("needs_backup");
            record["lastConfirmedUploadedGeneration"] = Value::Null;
            record["reconciliationRequired"] = json!(true);
            self.tracking
                .dirty_reconciliations
                .fetch_add(1, Ordering::SeqCst);
            Ok(DirtyBaselineReceipt {
                software_id: plan.software_id.clone(),
                root_authority_revision: plan.root_authority_revision.clone(),
                proof_digest: native_plans::fingerprint(&json!({
                    "softwareId":plan.software_id,"dirty":true,"authority":plan.root_authority_revision,
                }))?,
            })
        })
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    _native_store: WorkspaceStore,
    vault: Arc<MemoryVault>,
    signer: Arc<WorkspaceOperationSigner>,
    state: Arc<FixtureStore>,
    tracking: Arc<FixtureTracking>,
    engine: Arc<FixtureEngine>,
    service: Arc<WorkspaceService>,
    batch: Arc<NativeBatchRuntime>,
}
struct ReopenedFixture {
    service: Arc<WorkspaceService>,
    runtime: Arc<NativeBatchRuntime>,
}
impl std::ops::Deref for ReopenedFixture {
    type Target = Arc<NativeBatchRuntime>;
    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}
impl Fixture {
    fn new(count: usize) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let native_store =
            WorkspaceStore::open_with_vault(&base.join("device-state"), vault.clone()).unwrap();
        let signer = Arc::new(WorkspaceOperationSigner::new(native_store.clone()));
        let state = Arc::new(FixtureStore {
            provider_accesses: AtomicUsize::new(0),
            state: Mutex::new(json!({
                "providers":[{"id":"fixture-provider","name":"Fixture provider","kind":"fixture",
                    "status":"connected","readOnly":false,"authorityGeneration":1}],
                "software":[],
            })),
        });
        let tracking = Arc::new(FixtureTracking {
            store: state.clone(),
            signer: signer.clone(),
            pending: Mutex::new(BTreeMap::new()),
            source_by_work: Mutex::new(BTreeMap::new()),
            prepared: AtomicUsize::new(0),
            successful_finalizations: AtomicUsize::new(0),
            dirty_reconciliations: AtomicUsize::new(0),
            metadata_checks: AtomicUsize::new(0),
            source_key: [23; 32],
        });
        let engine = Arc::new(FixtureEngine {
            tracking: tracking.clone(),
            rows: Mutex::new(BTreeMap::new()),
            owners: Mutex::new(BTreeSet::new()),
            submissions: Mutex::new(Vec::new()),
            reads: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            signing_key: [23; 32],
            reauthentications: Mutex::new(Vec::new()),
            history_owner_unknown: AtomicBool::new(false),
            history_owner_pages: Mutex::new(Vec::new()),
        });
        let service = WorkspaceService::with_components(
            state.clone(),
            engine.clone(),
            tracking.clone(),
            Arc::new(NoDiscovery),
        )
        .unwrap();
        let batch = NativeBatchRuntime::open(
            &service,
            &base.join("batch"),
            signer.clone(),
            Arc::new(FixtureVerifier::new(engine.clone(), false)),
            Arc::new(FixtureRecovery {
                tracking: tracking.clone(),
            }),
        )
        .unwrap();
        assert!(
            service.batch.set(batch.clone()).is_ok(),
            "Fixture must exercise the actual publication and pre-finalization hooks"
        );
        assert!(Arc::ptr_eq(&service.batch_runtime().unwrap(), &batch));
        batch.confirm_core_hooks_installed();
        let fixture = Self {
            _temp: temp,
            base,
            _native_store: native_store,
            vault,
            signer,
            state,
            tracking,
            engine,
            service,
            batch,
        };
        for index in 0..count {
            fixture.add_software(index, "desktop:original.fixture");
        }
        fixture
    }
    fn add_software(&self, index: usize, canonical: &str) {
        let path = self.base.join(format!("software-{index}"));
        ensure_private_directory(&path).unwrap();
        std::fs::write(
            path.join("state.dat"),
            format!("real isolated fixture bytes {index}"),
        )
        .unwrap();
        let identity = SafeRoot::open(&path).unwrap().identity().unwrap();
        let mut record = json!({
            "id":format!("software-{index}"),"appId":format!("installation:{index}"),
            "sourceIdentity":{"app_id":canonical,"display_name":"Original application","aliases":[]},
            "name":format!("Fixture installation {index}"),"providerId":"fixture-provider","tracked":true,
            "dirty":true,"status":"needs_backup",
            "roots":[{"id":format!("root-{index}"),"path":path,"role":"installation","identity":identity,
                "allowedFiles":Value::Null}],
        });
        record["trackingGrant"] = self.signer.seal(&tracking_scope(&record)).unwrap();
        self.state.state.lock().unwrap()["software"]
            .as_array_mut()
            .unwrap()
            .push(record);
    }
    async fn preview(&self, ids: Option<Vec<&str>>) -> Value {
        let mut params = json!({"providerId":"fixture-provider"});
        if let Some(ids) = ids {
            params["softwareIds"] = json!(ids);
        }
        self.batch.preview_upload_all(params).await.unwrap()
    }
    async fn wait_finished(&self, id: Uuid) -> Value {
        self.wait_finished_on(&self.batch, id).await
    }
    async fn wait_finished_on(&self, runtime: &Arc<NativeBatchRuntime>, id: Uuid) -> Value {
        let owner = runtime.service().unwrap();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(value) = runtime
                    .groups
                    .lock()
                    .unwrap()
                    .get(&id)
                    .filter(|group| {
                        !group.running && owner.lifetime.outstanding.load(Ordering::SeqCst) == 0
                    })
                    .map(|group| group.activity.clone())
                {
                    return value;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("Actual batch fixture worker did not finish")
    }
    fn reopen(&self, requires_explicit: bool) -> ReopenedFixture {
        self.reopen_with_source(Arc::new(FixtureVerifier::new(
            self.engine.clone(),
            requires_explicit,
        )))
    }
    fn reopen_with_source(&self, source: Arc<dyn BatchSourceVerifier>) -> ReopenedFixture {
        let service = WorkspaceService::with_components(
            self.state.clone(),
            self.engine.clone(),
            self.tracking.clone(),
            Arc::new(NoDiscovery),
        )
        .unwrap();
        let runtime = NativeBatchRuntime::with_stores(
            &service,
            self.batch.plans.clone(),
            self.batch.ledger.clone(),
            source,
            Arc::new(FixtureRecovery {
                tracking: self.tracking.clone(),
            }),
        )
        .unwrap();
        assert!(
            service.batch.set(runtime.clone()).is_ok(),
            "A restarted service must install its own native batch runtime exactly once"
        );
        assert!(Arc::ptr_eq(&service.batch_runtime().unwrap(), &runtime));
        runtime.confirm_core_hooks_installed();
        ReopenedFixture { service, runtime }
    }
    #[cfg(unix)]
    async fn commit_without_tracker_finalization(
        &self,
        id: Uuid,
    ) -> (
        FrozenPlanSet,
        FrozenChildPlan,
        FrozenNativePlan,
        FrozenCaptureBinding,
    ) {
        let parent = self.batch.ledger.load(id).unwrap();
        let child = parent.jobs[0].children[0].clone();
        let plan = self.batch.plans.plan(id, &child).unwrap();
        self.batch.plans.admit(&parent).unwrap();
        let work = self
            .tracking
            .call(
                "prepare_upload_scope",
                &json!({
                    "softwareId":plan.software_id,"providerId":plan.provider_id,
                }),
            )
            .unwrap();
        let capture = FrozenCaptureBinding::from_work(&plan, &work).unwrap();
        self.batch.plans.bind_capture(&plan, &capture).unwrap();
        let pin = self
            .tracking
            .pin_scope(&plan.registration_record())
            .unwrap();
        let guard: PublishGuard = Arc::new(move || pin.verify());
        let controller =
            Arc::new(crate::capture::CaptureController::new(self.tracking.clone(), &work).unwrap());
        let mut selection = work;
        selection["operationId"] = json!(child.source_id);
        self.engine
            .upload_captured_guarded(
                self.state
                    .provider_access("fixture-provider", &child.source_id.to_string())
                    .unwrap(),
                selection,
                guard,
                controller,
            )
            .await
            .unwrap();
        (parent, child, plan, capture)
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_app_batch_runs_actual_service_capture_and_finalization_with_fixed_ids() {
    let fixture = Fixture::new(3);
    let preview = fixture.preview(None).await;
    assert_eq!(preview["softwareCount"], 3);
    assert_eq!(preview["appCount"], 3);
    assert_eq!(preview["canonicalAppCount"], 1);
    assert_eq!(preview["rootCount"], 3);
    assert_eq!(preview["rootRoles"]["installation"], 3);
    assert!(preview["summary"].as_str().unwrap().contains("Local data"));
    assert_eq!(
        fixture.engine.reads.load(Ordering::SeqCst),
        0,
        "Preview must not hash/read payloads"
    );
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    assert!(preview.get("roots").is_none());
    assert!(preview.get("plans").is_none());
    assert!(!preview.to_string().contains("trackingGrant"));
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let frozen = fixture.batch.ledger.load(id).unwrap();
    let expected = frozen
        .children()
        .map(|child| child.source_id)
        .collect::<Vec<_>>();
    assert_eq!(
        frozen
            .children()
            .map(|child| &child.app_id)
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "Two installation IDs must not invent separate canonical No Land identities"
    );
    fixture.batch.execute(&id.to_string()).unwrap();
    let completed = fixture.wait_finished(id).await;
    assert_eq!(completed["state"], "completed", "{completed}");
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        3
    );
    assert!(
        fixture.engine.reauthentications.lock().unwrap().is_empty(),
        "Fresh children must not acquire provider access through retained-source reauthentication"
    );
    assert_eq!(fixture.engine.reads.load(Ordering::SeqCst), 3);
    {
        let submissions = fixture.engine.submissions.lock().unwrap();
        assert_eq!(
            submissions.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            expected
        );
        for (_, selection) in submissions.iter() {
            assert_eq!(
                selection["sourceIdentity"]["app_id"],
                "desktop:original.fixture"
            );
            assert_ne!(selection["appId"], selection["sourceIdentity"]["app_id"]);
        }
    }
    assert!(!fixture.service.shutdown_blocked());
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_batch_does_not_add_a_later_native_enrollment_or_other_instances() {
    let fixture = Fixture::new(3);
    let preview = fixture.preview(Some(vec!["software-1"])).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.add_software(9, "desktop:late.enrollment");
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    {
        let submissions = fixture.engine.submissions.lock().unwrap();
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0].1["softwareId"], "software-1");
    }
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 1);
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frozen_root_replacement_is_rejected_before_native_capture_or_source_admission() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = preview["planSetId"].as_str().unwrap();
    let current = fixture.base.join("software-0");
    std::fs::rename(&current, fixture.base.join("old-software-0")).unwrap();
    ensure_private_directory(&current).unwrap();
    std::fs::write(current.join("state.dat"), b"not the approved native root").unwrap();
    // The file-backed plan still has the old device/file identity.
    fixture.batch.execute(id).unwrap();
    let activity = fixture.wait_finished(parse_id(id).unwrap()).await;
    assert_ne!(activity["state"], "completed");
    assert_eq!(fixture.engine.reads.load(Ordering::SeqCst), 0);
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_uses_real_child_ids_and_does_not_start_the_rest_of_the_group() {
    let fixture = Fixture::new(3);
    fixture.engine.hold.store(true, Ordering::Release);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.engine.submissions.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        fixture.service.shutdown_blocked(),
        "One group and its actual child must own close protection"
    );
    assert!(
        fixture.engine.shutdown().await.is_err(),
        "A fixture may not acknowledge shutdown while its real source owner is running"
    );
    let current = fixture.engine.submissions.lock().unwrap()[0].0;
    fixture.batch.cancel(&id.to_string()).await.unwrap();
    let result = fixture.wait_finished(id).await;
    assert_eq!(result["state"], "cancelled", "{result}");
    assert_eq!(fixture.engine.submissions.lock().unwrap().len(), 1);
    assert!(
        fixture.engine.reauthentications.lock().unwrap().is_empty(),
        "Cancellation may use retained exact-ID authority but cannot reauthenticate a provider"
    );
    assert_eq!(
        fixture.engine.activity(current).unwrap()["state"],
        "cancelled"
    );
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_source_json_is_not_authenticated_completion_or_a_saved_tracker_baseline() {
    let fixture = Fixture::new(1);
    fixture.engine.corrupt.store(true, Ordering::Release);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !fixture.engine.rows.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let child = fixture.batch.ledger.load(id).unwrap().jobs[0].children[0].clone();
    let native = fixture.batch.plans.plan(id, &child).unwrap();
    let capture = fixture.batch.plans.capture(&native).unwrap().unwrap();
    assert!(fixture
        .batch
        .backend
        .authenticated(
            &fixture.batch.ledger.load(id).unwrap(),
            &native,
            Some(&capture),
            SourceProofPurpose::Observation,
        )
        .await
        .is_err());
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
    assert_ne!(
        fixture.state.snapshot().unwrap()["software"][0]["status"],
        "saved"
    );
    let _ = fixture.batch.cancel(&id.to_string()).await;
    let result = fixture.wait_finished(id).await;
    assert_ne!(result["state"], "completed");
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn native_plan_sidecars_use_real_workspace_mac_and_reject_unsigned_scope_changes() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let child = fixture.batch.ledger.load(id).unwrap().jobs[0].children[0].clone();
    let plan = fixture.batch.plans.plan(id, &child).unwrap();
    assert_eq!(plan.software_id, "software-0");
    assert_ne!(plan.tracker_app_id, plan.canonical_app_id);
    assert!(
        fixture.batch.plans.admission(id).unwrap().is_none(),
        "Preview is not cloud write admission"
    );
    let path = fixture.base.join(format!(
        "batch/native-plans/set-{id}/plan-{}.json",
        plan.native_plan_id
    ));
    let mut envelope: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["scope"]["payload"]["providerId"] = json!("different-provider");
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(fixture.batch.plans.plan(id, &child).is_err());
    assert!(fixture.batch.execute(&id.to_string()).is_err());
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
    assert!(std::fs::metadata(path).unwrap().len() < (MAX_NATIVE_PLAN_BYTES as u64));
}

#[tokio::test]
async fn exact_batch_limits_reject_duplicates_unknown_instances_and_uninstalled_hooks() {
    let fixture = Fixture::new(1);
    assert!(fixture
        .batch
        .preview_upload_all(json!({
            "providerId":"fixture-provider","softwareIds":["software-0","software-0"],
        }))
        .await
        .is_err());
    assert!(fixture
        .batch
        .preview_upload_all(json!({
            "providerId":"fixture-provider","softwareIds":["not-tracked"],
        }))
        .await
        .is_err());
    fixture
        .batch
        .backend
        .hooks_ready
        .store(false, Ordering::Release);
    assert!(fixture
        .batch
        .preview_upload_all(json!({"providerId":"fixture-provider"}))
        .await
        .is_err());
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.reads.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_original_capture_work_errors_marks_dirty_and_never_recaptures_completed_source() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let (parent, child, plan, _) = fixture.commit_without_tracker_finalization(id).await;
    // Simulate a restart between actual source commit and tracker finalization.
    fixture.tracking.pending.lock().unwrap().clear();
    assert!(fixture
        .batch
        .backend
        .finalize_completed(&parent, &child)
        .await
        .is_err());
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.tracking.prepared.load(Ordering::SeqCst),
        1,
        "A missing original receipt may not call prepare_upload_scope on today's files"
    );
    assert_eq!(fixture.engine.submissions.lock().unwrap().len(), 1);
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture.state.snapshot().unwrap()["software"][0]["dirty"],
        true
    );
    assert!(fixture.batch.plans.finalization(&plan).unwrap().is_none());
    let status = fixture.batch.operation(&id.to_string()).await.unwrap();
    assert_eq!(status["state"], "interrupted");
    assert_eq!(status["phase"], "durable_finalization_required");
    assert_eq!(status["batch"]["reconciliationRequired"], true);
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        1,
        "Displaying a signed reconciliation gap must not mutate the tracker again"
    );
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_runtime_reattaches_signed_completed_history_without_duplicate_native_jobs() {
    let fixture = Fixture::new(2);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    let finalized = fixture
        .tracking
        .successful_finalizations
        .load(Ordering::SeqCst);
    let reopened = fixture.reopen(false);
    assert!(reopened.has_batch(&id.to_string()));
    let status = reopened.operation(&id.to_string()).await.unwrap();
    assert_eq!(status["state"], "completed");
    reopened.coordinator.drive(id).await.unwrap();
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions
    );
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        finalized
    );
    reopened.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn verifying_a_retained_mac_never_creates_missing_device_authority() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(MemoryVault::default());
    let base = temp.path().canonicalize().unwrap();
    let store = WorkspaceStore::open_with_vault(&base.join("state"), vault.clone()).unwrap();
    let signer = WorkspaceOperationSigner::new(store);
    let scope = json!({"domain":"isolated-retained-plan","id":Uuid::new_v4()});
    let before = vault.access_log().unwrap()["writes"].clone();
    let signature = json!({"version":1,"algorithm":"hmac-sha256","mac":"0".repeat(64)});
    assert!(
        signer.verify(&scope, &signature).is_err(),
        "Missing original device authority is not permission to mint a replacement key"
    );
    assert_eq!(vault.access_log().unwrap()["writes"], before);
    let legitimate = signer.seal(&scope).unwrap();
    let sealed_writes = vault.access_log().unwrap()["writes"].clone();
    assert!(signer.verify(&scope, &legitimate).unwrap());
    assert_eq!(vault.access_log().unwrap()["writes"], sealed_writes);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_status_is_secret_free_and_only_explicit_execution_and_retry_reauthenticate() {
    let fixture = Fixture::new(2);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    let source_ids = fixture
        .batch
        .ledger
        .load(id)
        .unwrap()
        .children()
        .map(|child| child.source_id)
        .collect::<Vec<_>>();
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    let preparations = fixture.tracking.prepared.load(Ordering::SeqCst);
    let accesses = fixture.state.provider_accesses.load(Ordering::SeqCst);
    let state_before = fixture.state.snapshot().unwrap();
    let reopened = fixture.reopen(true);

    assert!(reopened.has_batch(&id.to_string()));
    assert!(reopened.approval_scope(&id.to_string()).is_ok());
    for _ in 0..3 {
        let status = reopened
            .batch_status(&json!({"planSetId":id}))
            .await
            .unwrap();
        assert_eq!(status["state"], "running");
        assert_eq!(status["phase"], "native_status_unavailable");
        assert_eq!(status["batch"]["unknown"], 2);
    }
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    assert_eq!(
        fixture.state.provider_accesses.load(Ordering::SeqCst),
        accesses,
        "Read-only source polling must not request provider credentials"
    );
    assert_eq!(
        fixture.state.snapshot().unwrap(),
        state_before,
        "Unavailable restart proof is not a polling-triggered tracker mutation"
    );
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        0
    );

    reopened.execute(&id.to_string()).unwrap();
    assert_eq!(
        fixture.wait_finished_on(&reopened, id).await["state"],
        "completed"
    );
    assert_eq!(
        *fixture.engine.reauthentications.lock().unwrap(),
        source_ids
    );
    let count = fixture.engine.reauthentications.lock().unwrap().len();
    assert_eq!(
        reopened.operation(&id.to_string()).await.unwrap()["state"],
        "completed"
    );
    assert_eq!(
        fixture.engine.reauthentications.lock().unwrap().len(),
        count,
        "Terminal UI polling may not re-run explicit authentication"
    );

    reopened.retry(&id.to_string()).unwrap();
    assert_eq!(
        fixture.wait_finished_on(&reopened, id).await["state"],
        "completed"
    );
    assert_eq!(
        fixture.engine.reauthentications.lock().unwrap().len(),
        source_ids.len() * 2
    );
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions,
        "Even explicit retry can never replay a completed child"
    );
    assert_eq!(
        fixture.tracking.prepared.load(Ordering::SeqCst),
        preparations
    );
    reopened.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_restart_marks_current_unknown_without_erasing_the_previous_baseline_or_history() {
    let fixture = Fixture::new(1);
    let first = fixture.preview(None).await;
    let first_id = parse_id(first["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&first_id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(first_id).await["state"], "completed");
    let previous = fixture.state.snapshot().unwrap()["software"][0]["baseline"].clone();
    let history = fixture.state.snapshot().unwrap()["software"][0]["versionHistory"].clone();
    assert!(previous.is_object());

    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let (_, child, plan, _) = fixture.commit_without_tracker_finalization(id).await;
    fixture.tracking.pending.lock().unwrap().clear();
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    let preparations = fixture.tracking.prepared.load(Ordering::SeqCst);
    let reopened = fixture.reopen(true);
    assert_eq!(
        reopened.operation(&id.to_string()).await.unwrap()["phase"],
        "native_status_unavailable"
    );
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        0
    );
    reopened.execute(&id.to_string()).unwrap();
    let result = fixture.wait_finished_on(&reopened, id).await;
    assert_eq!(result["state"], "interrupted", "{result}");
    assert_eq!(result["phase"], "durable_finalization_required");
    assert!(!result["canRetry"].as_bool().unwrap());
    assert_eq!(
        *fixture.engine.reauthentications.lock().unwrap(),
        vec![child.source_id]
    );
    assert_eq!(
        fixture.tracking.prepared.load(Ordering::SeqCst),
        preparations,
        "Original work recovery failure must never capture today's files"
    );
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions
    );
    let current = fixture.state.snapshot().unwrap()["software"][0].clone();
    assert_eq!(current["dirty"], true);
    assert_eq!(current["reconciliationRequired"], true);
    assert!(current["lastConfirmedUploadedGeneration"].is_null());
    assert_eq!(current["baseline"], previous);
    assert_eq!(current["versionHistory"], history);
    assert!(fixture.batch.plans.finalization(&plan).unwrap().is_none());
    let dirty_count = fixture
        .tracking
        .dirty_reconciliations
        .load(Ordering::SeqCst);
    let reauth_count = fixture.engine.reauthentications.lock().unwrap().len();
    let retained = fixture.reopen(true);
    let status = retained.operation(&id.to_string()).await.unwrap();
    assert_eq!(status["state"], "interrupted");
    assert_eq!(status["phase"], "durable_finalization_required");
    assert_eq!(status["batch"]["reconciliationGapCount"], 1);
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        dirty_count
    );
    assert_eq!(
        fixture.engine.reauthentications.lock().unwrap().len(),
        reauth_count
    );
    retained.service.shutdown().await.unwrap();
    reopened.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

struct UnsupportedExecutionVerifier(FixtureVerifier);
impl BatchSourceVerifier for UnsupportedExecutionVerifier {
    fn require_supported(&self) -> Result<()> {
        self.0.require_supported()
    }
    fn authenticate<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        self.0.authenticate(parent, plan, capture, purpose)
    }
    // Intentionally no execution capability: the trait default must fail closed.
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_explicit_reauthentication_cannot_fall_back_to_guessed_verified_status() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    let runtime = fixture.reopen_with_source(Arc::new(UnsupportedExecutionVerifier(
        FixtureVerifier::new(fixture.engine.clone(), false),
    )));
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    runtime.retry(&id.to_string()).unwrap();
    let result = fixture.wait_finished_on(&runtime, id).await;
    assert_ne!(result["state"], "completed");
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions
    );
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    assert_eq!(
        fixture.state.snapshot().unwrap()["software"][0]["dirty"],
        true
    );
    runtime.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_capture_with_a_missing_original_source_is_a_gap_not_a_fresh_submission() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let (_, child, plan, _) = fixture.commit_without_tracker_finalization(id).await;
    assert!(fixture.engine.owners.lock().unwrap().is_empty());
    fixture.engine.rows.lock().unwrap().remove(&child.source_id);
    fixture.tracking.pending.lock().unwrap().clear();
    let preparations = fixture.tracking.prepared.load(Ordering::SeqCst);
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    let reopened = fixture.reopen(true);
    let before = fixture.state.snapshot().unwrap();
    assert_eq!(
        reopened.operation(&id.to_string()).await.unwrap()["phase"],
        "native_status_unavailable"
    );
    assert_eq!(fixture.state.snapshot().unwrap(), before);
    reopened.execute(&id.to_string()).unwrap();
    let result = fixture.wait_finished_on(&reopened, id).await;
    assert_eq!(result["state"], "interrupted", "{result}");
    assert_eq!(
        fixture.tracking.prepared.load(Ordering::SeqCst),
        preparations
    );
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions
    );
    assert_eq!(
        *fixture.engine.reauthentications.lock().unwrap(),
        vec![child.source_id]
    );
    assert_eq!(
        fixture.state.snapshot().unwrap()["software"][0]["reconciliationRequired"],
        true
    );
    assert!(fixture.batch.plans.finalization(&plan).unwrap().is_none());
    let status = reopened.operation(&id.to_string()).await.unwrap();
    assert_eq!(status["state"], "interrupted");
    assert_eq!(status["batch"]["reconciliationRequired"], true);
    reopened.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn native_capture_binding_rejects_partial_modes_changed_canonical_identity_and_duplicate_nodes(
) {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let child = fixture.batch.ledger.load(id).unwrap().jobs[0].children[0].clone();
    let plan = fixture.batch.plans.plan(id, &child).unwrap();
    let work = fixture
        .tracking
        .call(
            "prepare_upload_scope",
            &json!({
                "softwareId":plan.software_id,"providerId":plan.provider_id,
            }),
        )
        .unwrap();
    assert!(FrozenCaptureBinding::from_work(&plan, &work).is_ok());
    let mut partial = work.clone();
    partial["captureSource"]["selectionKind"] = json!("selected_nodes");
    assert!(FrozenCaptureBinding::from_work(&plan, &partial).is_err());
    let mut changed = work.clone();
    changed["sourceIdentity"]["app_id"] = json!("desktop:different.canonical");
    assert!(FrozenCaptureBinding::from_work(&plan, &changed).is_err());
    let mut duplicate = work.clone();
    let node = work["fileIds"][0].clone();
    duplicate["fileIds"] = json!([node, node]);
    assert!(FrozenCaptureBinding::from_work(&plan, &duplicate).is_err());
    fixture
        .tracking
        .call(
            "complete_upload",
            &json!({
                "workId":work["workId"],"generation":work["generation"],"success":false,
            }),
        )
        .unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_whole_root_batch_uses_verified_native_authority_not_a_placeholder_or_empty_selection(
) {
    let fixture = Fixture::new(1);
    std::fs::remove_file(fixture.base.join("software-0/state.dat")).unwrap();
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    let result = fixture.wait_finished(id).await;
    assert_eq!(result["state"], "completed", "{result}");
    assert_eq!(fixture.engine.reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        1
    );
    let parent = fixture.batch.ledger.load(id).unwrap();
    let child = &parent.jobs[0].children[0];
    let plan = fixture.batch.plans.plan(id, child).unwrap();
    let capture = fixture.batch.plans.capture(&plan).unwrap().unwrap();
    assert_eq!(capture.file_count, 0);
    assert!(capture.empty_full_scope_proof_digest.is_some());
    {
        let rows = fixture.engine.rows.lock().unwrap();
        let manifest = &rows.get(&child.source_id).unwrap().body["manifest"];
        assert_eq!(manifest["files"], json!([]));
        assert_eq!(manifest["coverage"], "full_approved_scope");
        assert_eq!(manifest["fullScope"]["rootCount"], 1);
        assert_eq!(manifest["roots"], plan.roots);
    }
    assert!(fixture.batch.plans.finalization(&plan).unwrap().is_some());
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn empty_capture_requires_the_actual_original_tracker_mac_and_legacy_zero_stays_invalid() {
    let fixture = Fixture::new(1);
    std::fs::remove_file(fixture.base.join("software-0/state.dat")).unwrap();
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let parent = fixture.batch.ledger.load(id).unwrap();
    let plan = fixture
        .batch
        .plans
        .plan(id, &parent.jobs[0].children[0])
        .unwrap();
    let work = fixture
        .tracking
        .call(
            "prepare_upload_scope",
            &json!({
                "softwareId":plan.software_id,"providerId":plan.provider_id,
            }),
        )
        .unwrap();
    assert!(
        FrozenCaptureBinding::from_work(&plan, &work).is_err(),
        "Zero metadata nodes alone cannot prove an empty whole-root snapshot"
    );
    let capture =
        FrozenCaptureBinding::from_native_work(&plan, &work, fixture.tracking.as_ref()).unwrap();
    assert!(capture.matches_work(&plan, &work).unwrap());
    let mut legacy = capture.clone();
    legacy.empty_full_scope_proof_digest = None;
    assert!(legacy.validate(&plan).is_err());
    let mut changed = work.clone();
    changed["captureSource"]["expectedFullScope"]["scope"]["generation"] = json!(99);
    assert!(
        FrozenCaptureBinding::from_native_work(&plan, &changed, fixture.tracking.as_ref()).is_err()
    );
    fixture
        .tracking
        .pending
        .lock()
        .unwrap()
        .get_mut(work["workId"].as_str().unwrap())
        .unwrap()
        .full_scope["expectedFullScope"]["grant"]["mac"] = json!("0".repeat(64));
    assert!(
        FrozenCaptureBinding::from_native_work(&plan, &work, fixture.tracking.as_ref()).is_err(),
        "A structural proof/envelope is not a valid native MAC"
    );
    assert!(crate::capture::CaptureController::new(fixture.tracking.clone(), &work).is_err());
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
    fixture
        .tracking
        .call(
            "complete_upload",
            &json!({
                "workId":work["workId"],"generation":work["generation"],"success":false,
            }),
        )
        .unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_installation_and_root_ids_with_at_are_preserved_through_the_real_service_path() {
    let fixture = Fixture::new(1);
    {
        let mut state = fixture.state.state.lock().unwrap();
        let record = &mut state["software"][0];
        record["appId"] = json!("steam:480@installation-one");
        record["sourceIdentity"]["app_id"] = json!("steam:480");
        record["roots"][0]["id"] = json!("save@root-one");
        record["trackingGrant"] = fixture.signer.seal(&tracking_scope(record)).unwrap();
    }
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    let result = fixture.wait_finished(id).await;
    assert_eq!(result["state"], "completed", "{result}");
    {
        let submissions = fixture.engine.submissions.lock().unwrap();
        assert_eq!(submissions[0].1["appId"], "steam:480@installation-one");
        assert_eq!(submissions[0].1["sourceIdentity"]["app_id"], "steam:480");
        assert_eq!(submissions[0].1["roots"][0]["id"], "save@root-one");
    }
    fixture.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_native_history_does_not_unlock_or_create_vault_authority() {
    let fixture = Fixture::new(0);
    let before = fixture.vault.access_log().unwrap();
    fixture.vault.deny_access(true).unwrap();
    assert!(fixture.batch.recent_activity(128).await.unwrap().is_empty());
    assert!(fixture.batch.recent_activity(0).await.unwrap().is_empty());
    assert_eq!(fixture.vault.access_log().unwrap(), before);
    assert!(fixture
        .engine
        .history_owner_pages
        .lock()
        .unwrap()
        .is_empty());
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    fixture.vault.deny_access(false).unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_dashboard_discovers_original_admitted_group_without_execution_credentials_or_scans(
) {
    let fixture = Fixture::new(2);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    let preview_only = fixture.preview(Some(vec!["software-0"])).await;
    let preview_id = parse_id(preview_only["planSetId"].as_str().unwrap()).unwrap();
    let original = fixture.batch.ledger.load(id).unwrap();
    let source_ids = original
        .children()
        .map(|child| child.source_id)
        .collect::<Vec<_>>();
    let preparations = fixture.tracking.prepared.load(Ordering::SeqCst);
    let metadata_checks = fixture.tracking.metadata_checks.load(Ordering::SeqCst);
    let reads = fixture.engine.reads.load(Ordering::SeqCst);
    let submissions = fixture.engine.submissions.lock().unwrap().len();
    let access = fixture.state.provider_accesses.load(Ordering::SeqCst);
    let vault = fixture.vault.access_log().unwrap();
    let restarted = fixture.reopen(true);
    assert!(restarted.service.operations.lock().unwrap().is_empty());
    // Current grants can be revoked without deleting legitimate immutable
    // activity history. This list must not claim the CURRENT data is Saved.
    for record in fixture.state.state.lock().unwrap()["software"]
        .as_array_mut()
        .unwrap()
    {
        record["tracked"] = json!(false);
        record["trackingGrant"] = Value::Null;
        record["dirty"] = json!(true);
        record["status"] = json!("needs_backup");
    }
    for _ in 0..3 {
        let activity = restarted.recent_activity(4096).await.unwrap();
        assert_eq!(activity.len(), 1);
        let group = &activity[0];
        assert_eq!(group["id"], id.to_string());
        assert_eq!(group["operationId"], id.to_string());
        assert_eq!(group["planSetId"], id.to_string());
        assert_eq!(group["startedAt"], original.created_at);
        assert_eq!(group["providerId"], "fixture-provider");
        assert_eq!(group["batch"]["historicalCompleted"], 2);
        assert_eq!(group["batch"]["sourceAppCount"], 1);
        assert_eq!(group["batch"]["currentDataStatus"], "not_evaluated");
        assert_eq!(group["batch"]["closeBlocked"], false);
        assert_ne!(group["id"], preview_id.to_string());
        assert!(group.get("roots").is_none());
    }
    for source in source_ids {
        assert!(restarted.is_group_source(&source.to_string()));
        assert!(!restarted.has_batch(&source.to_string()));
    }
    // Parent's actual activity/dashboard merge, not JS/local-storage discovery.
    let dashboard = restarted
        .service
        .query("dashboard", json!({}))
        .await
        .unwrap();
    let groups = dashboard["activity"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|activity| activity["planSetId"] == id.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        groups.len(),
        1,
        "The native group must be discoverable after restart"
    );
    assert!(dashboard["activity"]
        .as_array()
        .unwrap()
        .iter()
        .all(|activity| activity["planSetId"] != preview_id.to_string()));
    assert_eq!(
        fixture.tracking.prepared.load(Ordering::SeqCst),
        preparations
    );
    assert_eq!(
        fixture.tracking.metadata_checks.load(Ordering::SeqCst),
        metadata_checks
    );
    assert_eq!(fixture.engine.reads.load(Ordering::SeqCst), reads);
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        submissions
    );
    assert_eq!(
        fixture.state.provider_accesses.load(Ordering::SeqCst),
        access
    );
    let after_vault = fixture.vault.access_log().unwrap();
    assert_eq!(after_vault["writes"], vault["writes"]);
    let before_reads = vault["reads"].as_array().unwrap();
    let after_reads = after_vault["reads"].as_array().unwrap();
    assert_eq!(&after_reads[..before_reads.len()], before_reads.as_slice());
    // Historical MAC checks retain their cached device key, but must freshly
    // reject a legacy-state rollback after another process migrates the vault.
    // These presence checks never load provider/execution credentials.
    assert!(after_reads[before_reads.len()..]
        .iter()
        .all(|read| read[0] == quicksave_state::QUICKSAVE_VAULT_SERVICE
            && read[1] == "QuickSaveEncryptedStateVault.v1"));
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    assert!(fixture
        .engine
        .history_owner_pages
        .lock()
        .unwrap()
        .iter()
        .all(|size| *size <= 128));
    restarted.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_history_unknown_ownership_is_not_saved_or_retry_authority() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    assert_eq!(fixture.wait_finished(id).await["state"], "completed");
    let restarted = fixture.reopen(true);
    fixture
        .engine
        .history_owner_unknown
        .store(true, Ordering::Release);
    let access = fixture.state.provider_accesses.load(Ordering::SeqCst);
    let dirty = fixture
        .tracking
        .dirty_reconciliations
        .load(Ordering::SeqCst);
    let activity = restarted.recent_activity(128).await.unwrap();
    assert_eq!(activity[0]["id"], id.to_string());
    assert_eq!(activity[0]["state"], "interrupted");
    assert_eq!(activity[0]["phase"], "needs_native_reattachment");
    assert_eq!(activity[0]["canRetry"], false);
    assert_eq!(activity[0]["batch"]["unknown"], 1);
    assert_eq!(activity[0]["batch"]["closeBlocked"], true);
    assert_eq!(activity[0]["batch"]["historicalCompleted"], 1);
    assert_eq!(
        fixture.state.provider_accesses.load(Ordering::SeqCst),
        access
    );
    assert_eq!(
        fixture
            .tracking
            .dirty_reconciliations
            .load(Ordering::SeqCst),
        dirty
    );
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    fixture
        .engine
        .history_owner_unknown
        .store(false, Ordering::Release);
    restarted.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_never_captured_authoritatively_absent_history_advertises_the_supported_explicit_retry(
) {
    let fixture = Fixture::new(2);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    let original = fixture.batch.ledger.load(id).unwrap();
    let expected_sources = original
        .children()
        .map(|child| child.source_id)
        .collect::<Vec<_>>();
    fixture.batch.plans.admit(&original).unwrap();
    let restarted = fixture.reopen(true);
    let activity = restarted.recent_activity(128).await.unwrap();
    assert_eq!(activity[0]["state"], "interrupted");
    assert_eq!(activity[0]["phase"], "needs_native_reattachment");
    assert_eq!(activity[0]["batch"]["notStarted"], 2);
    assert_eq!(activity[0]["batch"]["closeBlocked"], false);
    assert_eq!(activity[0]["canRetry"], true);
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
    assert!(fixture.engine.rows.lock().unwrap().is_empty());
    assert!(fixture.engine.owners.lock().unwrap().is_empty());
    assert!(fixture.tracking.pending.lock().unwrap().is_empty());
    assert!(fixture.tracking.source_by_work.lock().unwrap().is_empty());
    for child in original.children() {
        let native = fixture.batch.plans.plan(id, child).unwrap();
        assert!(
            fixture.batch.plans.capture(&native).unwrap().is_none(),
            "This retry scenario must not contain original captured work"
        );
    }
    assert!(
        fixture.state.snapshot().unwrap()["software"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record.get("pendingWork").is_none_or(Value::is_null)),
        "This retry scenario must not replace any retained original native frame"
    );
    restarted.retry(&id.to_string()).unwrap();
    let finished = fixture.wait_finished_on(&restarted, id).await;
    let child_activity = {
        let operations = restarted.service.operations.lock().unwrap();
        expected_sources.iter().map(|source|json!({
            "sourceId":source,
            "activity":operations.get(&source.to_string()).map(|operation|operation.activity.clone()),
        })).collect::<Vec<_>>()
    };
    assert_eq!(
        finished["state"],
        "completed",
        "group={finished}; native child activity={}",
        json!(child_activity)
    );
    assert_eq!(fixture.engine.submissions.lock().unwrap().len(), 2);
    assert_eq!(
        fixture
            .engine
            .submissions
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        expected_sources
    );
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        2
    );
    assert!(
        fixture.engine.reauthentications.lock().unwrap().is_empty(),
        "Fresh native admissions must not be acknowledged as recovered source work"
    );
    assert!(fixture.tracking.pending.lock().unwrap().is_empty());
    assert!(
        fixture.state.snapshot().unwrap()["software"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record.get("pendingWork") == Some(&Value::Null)),
        "Complete native-record retirement must explicitly clear only this fresh work"
    );
    restarted.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_admission_after_reopen_still_requires_its_actual_synthetic_source_mac() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture
        .batch
        .plans
        .admit(&fixture.batch.ledger.load(id).unwrap())
        .unwrap();
    let restarted = fixture.reopen(true);
    fixture.engine.corrupt.store(true, Ordering::Release);
    restarted.retry(&id.to_string()).unwrap();
    let finished = fixture.wait_finished_on(&restarted, id).await;
    assert_ne!(finished["state"], "completed", "group={finished}");
    assert_eq!(
        fixture.engine.submissions.lock().unwrap().len(),
        1,
        "This must exercise fresh native admission, not a rejected replay"
    );
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .tracking
            .successful_finalizations
            .load(Ordering::SeqCst),
        0
    );
    assert_ne!(
        fixture.state.snapshot().unwrap()["software"][0]["status"],
        "saved"
    );
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    assert!(
        restarted.service.shutdown_blocked(),
        "A forged source completion may not acknowledge durable finalization"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fixture_preparation_cannot_replace_or_retire_an_original_native_work_pointer() {
    let fixture = Fixture::new(1);
    let work_id = Uuid::new_v4().to_string();
    {
        let mut state = fixture.state.state.lock().unwrap();
        // Rejection-only opaque reference: no JSON object is promoted into a
        // NativeFrozenWork/receipt capability or treated as successful recovery.
        state["software"][0]["pendingWork"] = json!({
            "fixtureOnly":"retained-original-reference","workId":work_id,"generation":7,
        });
    }
    let before = fixture.state.snapshot().unwrap();
    let error = fixture
        .tracking
        .call(
            "prepare_upload_scope",
            &json!({
                "softwareId":"software-0","providerId":"fixture-provider",
            }),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("original durable native work"),
        "{error}"
    );
    assert_eq!(
        fixture.state.snapshot().unwrap(),
        before,
        "Retained native work and complete record fields must remain untouched"
    );
    assert!(
        fixture
            .tracking
            .original_work(&before["software"][0], &work_id, 7)
            .is_err(),
        "This fixture does not implement authenticated original-frame recovery"
    );
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tracking.metadata_checks.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    assert!(fixture.tracking.pending.lock().unwrap().is_empty());
    assert!(fixture.engine.rows.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupted_cached_history_journal_is_an_error_not_a_hidden_unfinished_group() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture
        .batch
        .plans
        .admit(&fixture.batch.ledger.load(id).unwrap())
        .unwrap();
    let restarted = fixture.reopen(true);
    assert_eq!(restarted.recent_activity(128).await.unwrap().len(), 1);
    let path = fixture.base.join(format!(
        "batch/operation-bindings/operation-{id}/binding.json"
    ));
    std::fs::write(path, b"{invalid native journal").unwrap();
    assert!(restarted.recent_activity(1).await.is_err());
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mac_valid_but_unbound_root_digest_cannot_become_a_verified_history_frame() {
    let fixture = Fixture::new(1);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture
        .batch
        .plans
        .admit(&fixture.batch.ledger.load(id).unwrap())
        .unwrap();
    let path = fixture.base.join(format!(
        "batch/operation-bindings/operation-{id}/binding.json"
    ));
    let mut envelope: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["scope"]["payload"]["authorityRevision"] = json!("0".repeat(64));
    let scope = &envelope["scope"];
    // Deliberately produce a MAC-valid synthetic foreign frame. The real
    // original native header/child root digest must still reject it.
    envelope["signature"] = fixture
        .signer
        .seal(&json!({
            "domain":"quicksave-private-operation-bindings-v1",
            "operationId":scope["operationId"],"recordType":scope["recordType"],
            "recordName":scope["recordName"],
            "contentDigest":blake3::hash(&serde_json::to_vec(scope).unwrap()).to_hex().to_string(),
        }))
        .unwrap();
    std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let restarted = fixture.reopen(true);
    let error = restarted.recent_activity(128).await.unwrap_err();
    assert!(error.to_string().contains("ledger/root digest"), "{error}");
    assert!(fixture.engine.submissions.lock().unwrap().is_empty());
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_owner_lookup_is_paged_and_never_returns_a_native_child_inventory_to_js() {
    let fixture = Fixture::new(129);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture
        .batch
        .plans
        .admit(&fixture.batch.ledger.load(id).unwrap())
        .unwrap();
    let activity = fixture.batch.recent_activity(128).await.unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0]["batch"]["softwareCount"], 129);
    assert_eq!(
        *fixture.engine.history_owner_pages.lock().unwrap(),
        vec![128, 1]
    );
    assert!(activity[0]["batch"].get("children").is_none());
    assert!(activity[0]["batch"].get("fileIds").is_none());
    assert!(
        activity[0]["batch"]["sampleSourceAppIds"]
            .as_array()
            .unwrap()
            .len()
            <= 16
    );
    dto::bounded(&activity[0], 32 * 1024).unwrap();
    assert_eq!(fixture.tracking.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tracking.metadata_checks.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.provider_accesses.load(Ordering::SeqCst), 0);
    fixture.service.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recent_history_keeps_real_running_source_ownership_close_blocked() {
    let fixture = Fixture::new(1);
    fixture.engine.hold.store(true, Ordering::Release);
    let preview = fixture.preview(None).await;
    let id = parse_id(preview["planSetId"].as_str().unwrap()).unwrap();
    fixture.batch.execute(&id.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.engine.submissions.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let restarted = fixture.reopen(true);
    let access = fixture.state.provider_accesses.load(Ordering::SeqCst);
    let activity = restarted.recent_activity(128).await.unwrap();
    assert_eq!(activity[0]["state"], "running");
    assert_eq!(activity[0]["batch"]["active"], 1);
    assert_eq!(activity[0]["batch"]["closeBlocked"], true);
    assert_eq!(activity[0]["canRetry"], false);
    assert_eq!(
        fixture.state.provider_accesses.load(Ordering::SeqCst),
        access
    );
    assert!(fixture.engine.reauthentications.lock().unwrap().is_empty());
    fixture.batch.cancel(&id.to_string()).await.unwrap();
    fixture.wait_finished(id).await;
    restarted.service.shutdown().await.unwrap();
    fixture.service.shutdown().await.unwrap();
}
