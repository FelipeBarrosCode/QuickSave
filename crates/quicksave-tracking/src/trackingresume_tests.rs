// SPDX-License-Identifier: GPL-3.0-only
//! Isolated source/provider proof fixtures, never ambient state or real vaults.
use super::*;
use std::io::Read;

#[derive(Clone)]
struct Artifact {
    name: String,
    hash: String,
    mac: String,
}

#[derive(Clone)]
struct SourceLocator {
    provider: PathBuf,
    prepared: Artifact,
    committed: Option<Artifact>,
    key: Arc<Mutex<[u8; 32]>>,
}

/// A fresh owned receipt reloads ACTUAL immutable fixture-provider bytes and
/// keyed manifests. JSON status/completion flags cannot implement this owner.
struct ReloadedSource {
    locator: SourceLocator,
    evidence: Value,
    roots: Vec<ApprovedRoot>,
}

fn write_artifact(root: &quicksave_platform::SafeRoot, key: &[u8; 32], value: &Value) -> Artifact {
    let name = format!("proof-{}.json", uuid::Uuid::new_v4());
    let hash = bundle::write_local_json(root, &name, value).unwrap();
    let mac = blake3::keyed_hash(key, hash.as_bytes())
        .to_hex()
        .to_string();
    Artifact { name, hash, mac }
}

fn read_artifact(locator: &SourceLocator, artifact: &Artifact) -> Result<Value> {
    let root = quicksave_platform::SafeRoot::open(&locator.provider)?;
    let (mut file, stamp) = root.read_file(&artifact.name)?;
    ensure!(
        stamp.size <= model::MAX_BASELINE_BYTES,
        "fixture proof exceeds bound"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(model::MAX_BASELINE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.size
            && blake3::hash(&bytes).to_hex().as_str() == artifact.hash
            && blake3::keyed_hash(&*locator.key.lock().unwrap(), artifact.hash.as_bytes())
                .to_hex()
                .as_str()
                == artifact.mac,
        "actual fixture source/key/manifest authentication failed"
    );
    root.verify_file(&artifact.name, &stamp)?;
    Ok(serde_json::from_slice(&bytes)?)
}

impl ReloadedSource {
    fn capture(h: &Harness, work: &Value, commit: bool) -> SourceLocator {
        let actual = FixtureReceipt::capture(h, work); // The ONE actual source capture.
        let provider = h
            .home
            .join(format!("isolated-provider-{}", uuid::Uuid::new_v4()));
        quicksave_platform::ensure_private_directory(&provider).unwrap();
        let root = quicksave_platform::SafeRoot::open(&provider).unwrap();
        let key = Arc::new(Mutex::new([0xA9; 32])); // Explicit injected test vault only.
        let mut files = Vec::new();
        for (id, bytes) in &actual.captured_files {
            let name = format!("payload-{id}");
            root.write_new(&name, |file| {
                std::io::Write::write_all(file, bytes)?;
                Ok(())
            })
            .unwrap();
            files.push(json!({"id":id,"name":name,"hash":blake3::hash(bytes).to_hex().to_string(),"size":bytes.len()}));
        }
        let prepared = write_artifact(
            &root,
            &*key.lock().unwrap(),
            &json!({
                "kind":"actual_isolated_prepared_capture","evidence":actual.evidence,
                "roots":actual.roots,"files":files,
            }),
        );
        let committed = commit.then(|| write_artifact(&root,&*key.lock().unwrap(),&json!({
            "kind":"actual_isolated_committed_manifest","preparedHash":prepared.hash,
            "workId":work["workId"],"metadataIdentity":work["captureSource"]["snapshotIdentity"],
        })));
        SourceLocator {
            provider,
            prepared,
            committed,
            key,
        }
    }

    fn reload(locator: &SourceLocator) -> Result<Arc<Self>> {
        let prepared = read_artifact(locator, &locator.prepared)?;
        let owner = Arc::new(Self {
            locator: locator.clone(),
            evidence: prepared["evidence"].clone(),
            roots: serde_json::from_value(prepared["roots"].clone())?,
        });
        owner.revalidate()?;
        Ok(owner)
    }
}

impl NativeCaptureReceipt for ReloadedSource {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn immutable_prepared_capture(&self) -> bool {
        true
    }
    fn revalidate(&self) -> Result<()> {
        let prepared = read_artifact(&self.locator, &self.locator.prepared)?;
        ensure!(
            prepared["evidence"] == self.evidence,
            "fixture preparation identity changed"
        );
        let provider = quicksave_platform::SafeRoot::open(&self.locator.provider)?;
        for file in prepared["files"]
            .as_array()
            .context("fixture captured files are missing")?
        {
            let name = file["name"].as_str().unwrap();
            let (handle, stamp) = provider.read_file(name)?;
            ensure!(
                stamp.size == file["size"].as_u64().unwrap(),
                "fixture immutable captured length changed"
            );
            let mut bytes = Vec::new();
            handle
                .take(model::MAX_BASELINE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                blake3::hash(&bytes).to_hex().as_str() == file["hash"].as_str().unwrap(),
                "fixture immutable captured payload changed"
            );
            provider.verify_file(name, &stamp)?;
        }
        for root in &self.roots {
            scan::PinnedRoot::open(root)?.check()?;
        }
        Ok(())
    }
    fn verify_committed(&self) -> Result<()> {
        self.revalidate()?;
        let reference = self
            .locator
            .committed
            .as_ref()
            .context("actual COMMITTED fixture proof is absent")?;
        let committed = read_artifact(&self.locator, reference)?;
        ensure!(
            committed["kind"] == "actual_isolated_committed_manifest"
                && committed["preparedHash"] == self.locator.prepared.hash
                && committed["workId"] == self.evidence["workId"]
                && committed["metadataIdentity"] == self.evidence["metadataIdentity"],
            "actual COMMITTED fixture manifest does not bind this captured preparation"
        );
        Ok(())
    }
}

pub(super) fn actual_committed_fixture(h: &Harness, work: &Value) -> Arc<dyn NativeCaptureReceipt> {
    let locator = ReloadedSource::capture(h, work, true);
    ReloadedSource::reload(&locator).unwrap()
}

fn binding(work: &Value) -> String {
    bundle::digest(&work["authorization"]["trackingScope"]).unwrap()
}

fn load(tracker: &Tracker, work: &Value) -> Result<Arc<NativeFrozenWork>> {
    tracker.original_work(
        work["softwareId"].as_str().unwrap(),
        work["workId"].as_str().unwrap(),
        work["generation"].as_u64().unwrap(),
        &binding(work),
    )
}

fn restart(h: &Harness) -> Tracker {
    Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap()
}

fn original_index_scopes(record: &TrackedSoftware) -> Vec<(&'static str, Value, Value)> {
    let source = record.bundle_index_source.as_ref().unwrap();
    let manifest = source.certificate(record);
    let mut index = manifest["scope"].clone();
    index["kind"] = json!("index");
    index["name"] = json!(source.index.name);
    index["hash"] = json!(source.index.hash);
    vec![
        ("bundle_index", index, source.index.grant.clone()),
        (
            "bundle_manifest",
            manifest["scope"].clone(),
            source.manifest.grant.clone(),
        ),
    ]
}

#[test]
fn original_native_work_survives_restart_and_confirms_old_bytes_without_recapturing_today() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("slot"), b"original actually captured").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let before_capture = h.store.records.lock().unwrap()[&id]["pendingWork"].clone();
    assert_eq!(before_capture["scope"]["stage"], "metadata_frozen");
    let original_record = h.tracker.shared.apps().unwrap()[&id].record.clone();
    let original_indices = original_index_scopes(&original_record);
    let locator = ReloadedSource::capture(&h, &work, true);
    h.tracker
        .accept_capture_receipt(
            work["workId"].as_str().unwrap(),
            ReloadedSource::reload(&locator).unwrap(),
        )
        .unwrap();
    let accepted = h.store.records.lock().unwrap()[&id]["pendingWork"].clone();
    assert_eq!(accepted["scope"]["stage"], "source_receipt_accepted");
    let original = load(&h.tracker, &work).unwrap();
    let page = original.node_page(0, 500).unwrap();
    let full = original.full_scope_evidence().unwrap();
    fs::write(root.join("slot"), b"new local bytes must stay dirty").unwrap();
    h.tracker.scan_metadata(&id).unwrap(); // A REAL newer index, not removal of the mutation.
    assert_ne!(
        h.store.records.lock().unwrap()[&id]["bundleIndexSource"]["snapshotIdentity"],
        work["captureSource"]["snapshotIdentity"]
    );
    // Model the real store's current-index nonce rotation. No old grant is
    // rewritten/reissued: it must be expired while the independent frame stays
    // authoritative for its exact historical metadata.
    for (kind, scope, grant) in &original_indices {
        assert!(h.store.verify_grant(kind, scope, grant).unwrap());
        h.store.revoke_grant(kind, scope).unwrap();
        assert!(!h.store.verify_grant(kind, scope, grant).unwrap());
    }
    {
        let apps = h.tracker.shared.apps().unwrap();
        let current = &apps[&id].record;
        current
            .bundle_index_source
            .as_ref()
            .unwrap()
            .verify_reference_grants(&current.tracking_scope(), h.store.as_ref())
            .unwrap();
    }
    let reopened = restart(&h);
    let before = reopened.performance_counters();
    let restored = load(&reopened, &work).unwrap();
    assert_eq!(restored.work().unwrap(), work);
    assert_eq!(restored.node_page(0, 500).unwrap(), page);
    assert_eq!(restored.full_scope_evidence().unwrap(), full);
    assert_eq!(
        restored.record().unwrap()["bundleIndexSource"],
        serde_json::to_value(original_record.bundle_index_source.as_ref().unwrap()).unwrap()
    );
    assert_eq!(
        restored.header().unwrap()["metadataIdentity"],
        work["captureSource"]["snapshotIdentity"]
    );
    let patch = reopened
        .resume_pending(restored, ReloadedSource::reload(&locator).unwrap())
        .unwrap();
    assert_eq!(patch["generation"], work["generation"]);
    assert_eq!(
        patch["captureSource"]["snapshotIdentity"],
        work["captureSource"]["snapshotIdentity"]
    );
    let completed = reopened
        .complete_upload(
            work["workId"].as_str().unwrap(),
            work["generation"].as_u64().unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(completed["historicalBaselineConfirmed"], true);
    assert_eq!(completed["currentGenerationConfirmed"], false);
    assert_eq!(completed["software"]["dirty"], true);
    assert_eq!(completed["software"]["lastConfirmedUploadedGeneration"], 0);
    assert_eq!(reopened.performance_counters(), before); // NO source/tree read for restore or completion.
    let records = h.store.records.lock().unwrap();
    assert_eq!(records[&id]["pendingWork"], Value::Null);
    drop(records);
    assert!(load(&reopened, &work).is_err()); // Completed work cannot be rerun.
    assert_eq!(
        reopened.scan(&id).unwrap()["captureSource"]["changedDirty"],
        true
    );
    assert_eq!(
        fs::read(root.join("slot")).unwrap(),
        b"new local bytes must stay dirty"
    );
}

#[test]
fn independent_frozen_work_cannot_be_created_from_a_revoked_current_index() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"actual indexed source").unwrap();
    let id = h.approve(&root);
    h.tracker.scan_metadata(&id).unwrap();
    let record = h.tracker.shared.apps().unwrap()[&id].record.clone();
    let scopes = original_index_scopes(&record);
    for (kind, scope, _) in &scopes {
        h.store.revoke_grant(kind, scope).unwrap();
    }
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
    let apps = h.tracker.shared.apps().unwrap();
    assert!(apps[&id].pending.is_none());
    assert!(apps[&id].scheduler.flight.is_none());
    assert!(apps[&id].record.pending_work.is_none());
}

#[test]
fn prepared_checkpoint_recovery_is_not_a_json_completion_or_a_new_capture() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"one actual original preparation").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let locator = ReloadedSource::capture(&h, &work, false);
    let reopened = restart(&h);
    let original = load(&reopened, &work).unwrap();
    assert!(original.accepted_receipt().unwrap().is_none()); // Crash before Tracker accepted source proof.
    reopened
        .resume_pending(original, ReloadedSource::reload(&locator).unwrap())
        .unwrap();
    let baseline = h.store.records.lock().unwrap()[&id]["baseline"].clone();
    assert!(reopened
        .complete_upload(
            work["workId"].as_str().unwrap(),
            work["generation"].as_u64().unwrap(),
            true
        )
        .is_err());
    assert_eq!(h.store.records.lock().unwrap()[&id]["baseline"], baseline);
    assert!(reopened.shared.apps().unwrap()[&id].pending.is_some());
    // Commit is a newly written authenticated manifest, not a database boolean.
    let provider = quicksave_platform::SafeRoot::open(&locator.provider).unwrap();
    let mut committed = locator.clone();
    committed.committed = Some(write_artifact(
        &provider,
        &*locator.key.lock().unwrap(),
        &json!({
            "kind":"actual_isolated_committed_manifest","preparedHash":locator.prepared.hash,
            "workId":work["workId"],"metadataIdentity":work["captureSource"]["snapshotIdentity"],
        }),
    ));
    let original = load(&reopened, &work).unwrap();
    reopened
        .resume_pending(original, ReloadedSource::reload(&committed).unwrap())
        .unwrap();
    assert_eq!(
        reopened
            .complete_upload(
                work["workId"].as_str().unwrap(),
                work["generation"].as_u64().unwrap(),
                true
            )
            .unwrap()["historicalBaselineConfirmed"],
        true
    );
}

#[test]
fn corrupt_frames_revoked_authority_provider_or_source_key_never_install_recovered_work() {
    for failure in [
        "frame",
        "tracking",
        "provider",
        "source_key",
        "replaced_root",
    ] {
        let h = full_harness();
        let root = h.root("source");
        fs::write(root.join("data"), b"original").unwrap();
        let id = h.approve(&root);
        let work = h
            .tracker
            .prepare_upload_scope(&id, "provider-a", None)
            .unwrap();
        let locator = ReloadedSource::capture(&h, &work, true);
        let reopened = restart(&h);
        let before = reopened.performance_counters();
        let before_baseline = h.store.records.lock().unwrap()[&id]["baseline"].clone();
        match failure {
            "frame" => {
                let name = h.store.records.lock().unwrap()[&id]["pendingWork"]["name"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                fs::write(
                    reopened.shared.policy.bundle_dir().join(name),
                    b"{\"completed\":true}",
                )
                .unwrap();
            }
            "tracking" => h
                .store
                .revoke_grant("tracking", &work["authorization"]["trackingScope"])
                .unwrap(),
            "provider" => h.store.offline.store(true, Ordering::Release),
            "source_key" => *locator.key.lock().unwrap() = [0xAA; 32],
            _ => {
                fs::rename(&root, h.home.join("original-root")).unwrap();
                fs::create_dir(&root).unwrap();
            }
        }
        let result = load(&reopened, &work).and_then(|original| {
            ReloadedSource::reload(&locator)
                .and_then(|receipt| reopened.resume_pending(original, receipt))
        });
        assert!(
            result.is_err(),
            "accepted invalid original recovery: {failure}"
        );
        assert!(reopened.shared.apps().unwrap()[&id].pending.is_none());
        assert_eq!(reopened.performance_counters(), before);
        assert_eq!(
            h.store.records.lock().unwrap()[&id]["baseline"],
            before_baseline
        );
    }
}

#[test]
fn recovered_partial_work_preserves_unselected_baseline_and_original_selection() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("chosen"), b"old chosen").unwrap();
    fs::write(root.join("unselected"), b"old unselected").unwrap();
    let id = h.approve(&root);
    let initial = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&initial, true);
    fs::write(root.join("chosen"), b"original new chosen").unwrap();
    fs::write(root.join("unselected"), b"new unselected dirt").unwrap();
    h.tracker.scan_metadata(&id).unwrap();
    let file = h.tracker.file_listing(&id, None, 10).unwrap()["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["path"] == "chosen")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", Some(&[file]))
        .unwrap();
    let locator = ReloadedSource::capture(&h, &work, true);
    let reopened = restart(&h);
    let original = load(&reopened, &work).unwrap();
    assert!(original.full_scope_evidence().is_err());
    assert_eq!(
        original.node_page(0, 500).unwrap()["nodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    reopened
        .resume_pending(original, ReloadedSource::reload(&locator).unwrap())
        .unwrap();
    reopened
        .complete_upload(
            work["workId"].as_str().unwrap(),
            work["generation"].as_u64().unwrap(),
            true,
        )
        .unwrap();
    let apps = reopened.shared.apps().unwrap();
    let baseline = apps[&id].baseline.as_ref().unwrap();
    assert!(baseline.nodes.values().any(|node| node.path == "unselected"
        && node.hash.as_deref() == Some(blake3::hash(b"old unselected").to_hex().as_str())));
    assert!(apps[&id].scheduler.needs_reconcile && apps[&id].force_hash);
    drop(apps);
    assert_eq!(
        reopened.scan(&id).unwrap()["captureSource"]["changedDirty"],
        true
    );
}

#[test]
fn explicit_failed_metadata_only_work_retires_only_its_native_ref_and_preserves_history() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"previously confirmed").unwrap();
    let id = h.approve(&root);
    let initial = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&initial, true);
    let previous = h.store.records.lock().unwrap()[&id].clone();
    fs::write(root.join("data"), b"new bytes not yet captured by a source").unwrap();
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let reference = h.store.records.lock().unwrap()[&id]["pendingWork"].clone();
    let path = h
        .tracker
        .shared
        .policy
        .bundle_dir()
        .join(reference["name"].as_str().unwrap());
    let bytes = fs::read(&path).unwrap();
    let failed = h.finish(&work, false);
    assert_eq!(failed["sourceConfirmed"], false);
    assert_eq!(failed["software"]["dirty"], true);
    let after = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(after["pendingWork"], Value::Null);
    assert_eq!(after["baseline"], previous["baseline"]);
    assert_eq!(after["trackingGrant"], previous["trackingGrant"]);
    assert_eq!(
        after["lastConfirmedUploadedGeneration"],
        previous["lastConfirmedUploadedGeneration"]
    );
    assert!(!h
        .store
        .verify_grant(
            "tracking_frozen_work",
            &reference["scope"],
            &reference["grant"]
        )
        .unwrap());
    assert_eq!(fs::read(&path).unwrap(), bytes); // No artifact/history/payload deletion.
    assert_eq!(
        fs::read(root.join("data")).unwrap(),
        b"new bytes not yet captured by a source"
    );
    let reopened = restart(&h);
    assert!(load(&reopened, &work).is_err()); // Canceled metadata authority cannot replay.
    reopened
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
}
