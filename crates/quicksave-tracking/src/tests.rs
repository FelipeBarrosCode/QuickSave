// SPDX-License-Identifier: GPL-3.0-only
//! All fixtures are isolated local temporary files and an injected fake vault.

use super::*;
use notify::{event::ModifyKind, Event, EventKind};
use std::{fs, sync::mpsc::Receiver};
use tempfile::TempDir;

#[test]
fn epoch_increment_is_concurrent_and_never_wraps() {
    let epoch = Arc::new(AtomicU64::new(0));
    let workers = (0..8)
        .map(|_| {
            let epoch = epoch.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    increment_epoch(&epoch).unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(epoch.load(Ordering::Acquire), 8000);
    let exhausted = AtomicU64::new(u64::MAX);
    assert_eq!(increment_epoch(&exhausted), Err(u64::MAX));
    assert_eq!(exhausted.load(Ordering::Acquire), u64::MAX);
}

#[derive(Default)]
struct FakeVaultStore {
    records: Mutex<BTreeMap<String, Value>>,
    revisions: Mutex<BTreeMap<String, u64>>,
    offline: AtomicBool,
    fail_writes: AtomicBool,
    issued_grants: AtomicUsize,
    verification_calls: AtomicUsize,
    projection_changed: AtomicBool,
    failing_verification: Mutex<Option<(String, String)>>,
    deferred_tracking: Mutex<BTreeSet<String>>,
}

impl FakeVaultStore {
    fn scope_key(kind: &str, scope: &Value) -> String {
        format!("{kind}:{}", scope)
    }

    fn proof(&self, kind: &str, scope: &Value) -> Value {
        let key = Self::scope_key(kind, scope);
        let revision = self
            .revisions
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .unwrap_or(0);
        // This is a deterministic injected test authenticator, NOT a production
        // native vault/HMAC implementation or a fallback exported by the crate.
        let message = format!("{key}:{revision}");
        let tag = blake3::keyed_hash(&[0x53; 32], message.as_bytes())
            .to_hex()
            .to_string();
        json!({"revision": revision, "testAuthenticationTag": tag})
    }
}

impl TrackingStore for FakeVaultStore {
    fn load_records(&self) -> Result<Vec<Value>> {
        Ok(self.records.lock().unwrap().values().cloned().collect())
    }
    fn save_record(&self, record: &Value) -> Result<()> {
        ensure!(
            !self.fail_writes.load(Ordering::Acquire),
            "synthetic persistence failure"
        );
        self.records
            .lock()
            .unwrap()
            .insert(record["id"].as_str().unwrap().to_owned(), record.clone());
        Ok(())
    }
    fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
        self.issued_grants.fetch_add(1, Ordering::AcqRel);
        if kind == "tracking" {
            if let Some(id) = scope["softwareId"].as_str() {
                self.deferred_tracking.lock().unwrap().remove(id);
            }
        }
        Ok(self.proof(kind, scope))
    }
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
        self.verification_calls.fetch_add(1, Ordering::Relaxed);
        if self.projection_changed.load(Ordering::Acquire) {
            return Err(TrackingProjectionChanged.into());
        }
        if kind == "tracking"
            && scope["softwareId"]
                .as_str()
                .is_some_and(|id| self.deferred_tracking.lock().unwrap().contains(id))
        {
            return Err(DeferredLegacyAuthority.into());
        }
        if self
            .failing_verification
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(failed_kind, id)| {
                failed_kind == kind
                    && (scope["softwareId"].as_str() == Some(id.as_str())
                        || scope["tracking"]["softwareId"].as_str() == Some(id.as_str()))
            })
        {
            bail!("synthetic locked keychain");
        }
        Ok(grant == &self.proof(kind, scope))
    }
    fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
        *self
            .revisions
            .lock()
            .unwrap()
            .entry(Self::scope_key(kind, scope))
            .or_default() += 1;
        Ok(())
    }
    fn provider_writable(&self, provider_id: &str) -> Result<bool> {
        Ok(!self.offline.load(Ordering::Acquire)
            && matches!(provider_id, "provider-a" | "provider-b"))
    }
}

struct Harness {
    _temp: TempDir,
    home: PathBuf,
    store: Arc<FakeVaultStore>,
    tracker: Tracker,
    receiver: Receiver<native::Hint>,
}

#[test]
fn temporary_authority_failure_is_redacted_isolated_and_requires_explicit_recheck() {
    let h = Harness::new();
    let root = h.root("temporary-authority");
    fs::write(root.join("save"), b"synthetic bytes").unwrap();
    let id = h.approve(&root);
    h.tracker.scan(&id).unwrap();
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&work, true);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    let other = h.approve(&h.root("independent-authority"));
    let before = {
        let apps = h.tracker.shared.apps().unwrap();
        serde_json::to_value(&apps[&id].record).unwrap()
    };
    *h.store.failing_verification.lock().unwrap() = Some(("tracking".into(), id.clone()));
    let counters = h.tracker.performance_counters();
    let list = h.tracker.software().unwrap();
    let paused = list.iter().find(|value| value["id"] == id).unwrap();
    assert_eq!(paused["authorizationPending"], true);
    assert_eq!(paused["tracked"], false);
    assert_eq!(paused["status"], "needs_authorization");
    assert!(paused["bundle"].is_null());
    assert_eq!(paused["roots"], json!([]));
    assert!(list
        .iter()
        .any(|value| value["id"] == other && value["authorizationPending"] == false));
    assert!(h.tracker.file_listing(&id, None, 10).is_err());
    assert!(h.tracker.scan(&id).is_err());
    assert_eq!(h.tracker.performance_counters(), counters);
    {
        let apps = h.tracker.shared.apps().unwrap();
        let after = serde_json::to_value(&apps[&id].record).unwrap();
        for key in [
            "trackingGrant",
            "autosaveGrant",
            "autosave",
            "baseline",
            "baselineFullScope",
            "bundleIndexSource",
            "lastConfirmedUploadedGeneration",
        ] {
            assert_eq!(after[key], before[key], "{key}");
        }
    }
    *h.store.failing_verification.lock().unwrap() = None;
    // A successful poll is not permission to resume background uploads.
    assert_eq!(
        h.tracker
            .software()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap()["authorizationPending"],
        true
    );
    assert!(h.tracker.file_listing(&id, None, 10).is_err());
    h.tracker.scan(&id).unwrap();
    assert!(!h.tracker.shared.apps().unwrap()[&id].authorization_paused);
}

#[test]
fn temporary_autosave_verification_failure_keeps_native_opt_in() {
    let h = Harness::new();
    let id = h.approve(&h.root("autosave-authority"));
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    *h.store.failing_verification.lock().unwrap() = Some(("autosave".into(), id.clone()));
    assert_eq!(
        h.tracker.software().unwrap()[0]["authorizationPending"],
        true
    );
    let apps = h.tracker.shared.apps().unwrap();
    assert!(apps[&id].record.autosave);
    assert!(apps[&id].record.autosave_grant.is_some());
    assert!(apps[&id].scheduler.paused);
}

#[test]
fn restart_with_unavailable_authority_retains_persisted_references() {
    let h = Harness::new();
    let root = h.root("restart-authority");
    fs::write(root.join("save"), b"restart fixture").unwrap();
    let id = h.approve(&root);
    h.tracker.scan(&id).unwrap();
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&work, true);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    let before = h.store.records.lock().unwrap()[&id].clone();
    *h.store.failing_verification.lock().unwrap() = Some(("tracking".into(), id.clone()));
    let reopened = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    let list = reopened.software().unwrap();
    assert_eq!(list[0]["authorizationPending"], true);
    let apps = reopened.shared.apps().unwrap();
    let after = serde_json::to_value(&apps[&id].record).unwrap();
    for key in [
        "trackingGrant",
        "autosaveGrant",
        "autosave",
        "baseline",
        "baselineFullScope",
        "bundleIndexSource",
        "lastConfirmedUploadedGeneration",
    ] {
        assert_eq!(after[key], before[key], "{key}");
    }
}

#[test]
fn deferred_historical_authority_preserves_references_with_valid_current_tracking() {
    for kind in ["tracking_baseline", "bundle_manifest", "bundle_index"] {
        let h = Harness::new();
        let root = h.root("deferred-history");
        fs::write(root.join("save"), b"historical confirmed bytes").unwrap();
        let id = h.approve(&root);
        h.tracker.scan(&id).unwrap();
        let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
        h.finish(&work, true);
        h.tracker
            .configure_autosave(&id, "provider-a", true)
            .unwrap();
        let before = h.store.records.lock().unwrap()[&id].clone();
        assert!(!before["baseline"].is_null());
        assert!(!before["bundleIndexSource"].is_null());
        *h.store.failing_verification.lock().unwrap() = Some((kind.into(), id.clone()));
        {
            let apps = h.tracker.shared.apps().unwrap();
            let record = &apps[&id].record;
            assert!(h
                .store
                .verify_grant("tracking", &record.tracking_scope(), &record.tracking_grant)
                .unwrap());
        }
        let reopened = Tracker::open_impl(
            h.store.clone(),
            Arc::new(|_| Ok(())),
            h.tracker.shared.policy.clone(),
            false,
        )
        .unwrap();
        let list = reopened.software().unwrap();
        assert_eq!(list[0]["authorizationPending"], true, "{kind}");
        assert_eq!(list[0]["tracked"], false);
        assert_ne!(list[0]["status"], "saved");
        assert!(list[0]["bundle"].is_null());
        {
            let apps = reopened.shared.apps().unwrap();
            let app = &apps[&id];
            assert!(app.authorization_paused && app.scheduler.paused);
            assert!(app.current.is_none(), "{kind}");
            if kind == "tracking_baseline" {
                assert!(app.baseline.is_none());
            }
        }
        assert!(reopened.file_listing(&id, None, 10).is_err());
        assert!(reopened.root_authority(&id).is_err());
        assert!(reopened.begin_upload(&id, "provider-a", None).is_err());
        assert!(reopened.scan(&id).is_err());
        let after = h.store.records.lock().unwrap()[&id].clone();
        for key in [
            "roots",
            "trackingGrant",
            "autosaveGrant",
            "autosave",
            "baseline",
            "baselineFullScope",
            "bundleIndexSource",
            "captureReceipt",
            "lastSavedAt",
            "lastConfirmedUploadedGeneration",
        ] {
            assert_eq!(after[key], before[key], "{kind}: {key}");
        }
        *h.store.failing_verification.lock().unwrap() = None;
        assert_eq!(
            reopened.software().unwrap()[0]["authorizationPending"],
            true
        );
        assert!(reopened.file_listing(&id, None, 10).is_err());
        reopened.scan(&id).unwrap();
        assert_eq!(
            reopened.software().unwrap()[0]["authorizationPending"],
            false
        );
        assert!(reopened.file_listing(&id, None, 10).is_ok());
        assert!(
            !h.store.records.lock().unwrap()[&id]["authorizationPending"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(reopened.performance_counters()["filesHashed"], 1);
    }
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        // macOS /var can be a symlink; canonicalize ONLY our isolated test root.
        let home = fs::canonicalize(temp.path()).unwrap();
        let state = home.join("state");
        let policy = TrackingPolicy::new(state.clone());
        quicksave_platform::ensure_private_directory(&state).unwrap();
        quicksave_platform::ensure_private_directory(&policy.baseline_dir()).unwrap();
        let store = Arc::new(FakeVaultStore::default());
        let (wake, receiver) = sync_channel(native::QUEUE_CAPACITY);
        let shared = Arc::new(Shared {
            store: store.clone(),
            enqueue: Arc::new(|_| Ok(())),
            policy,
            apps: Mutex::new(BTreeMap::new()),
            routes: RwLock::new(Vec::new()),
            wake,
            stop: AtomicBool::new(false),
            reconfigure: AtomicBool::new(false),
            uncertainty_epoch: AtomicU64::new(0),
            index_entries: AtomicUsize::new(0),
            baseline_entries: AtomicUsize::new(0),
            index_path_bytes: AtomicUsize::new(0),
            baseline_path_bytes: AtomicUsize::new(0),
            frozen_indices: Mutex::new(metadata_index::FrozenIndices::default()),
            frozen_frames: Mutex::new(trackingresume::FrameQuota::default()),
            io: scan::IoCounters::default(),
            instance_nonce: uuid::Uuid::new_v4().to_string(),
            watch_reset_requested: AtomicU64::new(0),
            watch_reset_confirmed: AtomicU64::new(0),
            origin: Instant::now(),
        });
        Self {
            _temp: temp,
            home,
            store,
            tracker: Tracker {
                shared,
                worker: Mutex::new(None),
            },
            receiver,
        }
    }

    fn root(&self, name: &str) -> PathBuf {
        let path = self.home.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn approve(&self, root: &Path) -> String {
        let record = self
            .tracker
            .approve_software(&json!({
                "appId": "com.example.synthetic", "name": "Synthetic software",
                "providerId": "provider-a", "roots": [{"path": root, "role": "save"}]
            }))
            .unwrap();
        native::install_test_routes(&self.tracker.shared);
        record["id"].as_str().unwrap().to_owned()
    }

    fn finish(&self, work: &Value, success: bool) -> Value {
        self.tracker
            .complete_upload(
                work["workId"].as_str().unwrap(),
                work["generation"].as_u64().unwrap(),
                success,
            )
            .unwrap()
    }

    fn scan(&self, id: &str) -> Value {
        self.tracker.scan(id).unwrap()
    }
}

#[test]
fn scans_never_confirm_uploads_and_changed_dirty_is_since_last_confirmed_snapshot() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"one").unwrap();
    let id = h.approve(&root);
    for _ in 0..3 {
        let scan = h.scan(&id);
        assert_eq!(scan["captureSource"]["changedDirty"], true);
        assert_eq!(scan["software"]["status"], "needs_backup");
    }
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], false);
    fs::write(root.join("save.dat"), b"two").unwrap();
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], true);
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], true);
    assert_eq!(fs::read(root.join("save.dat")).unwrap(), b"two");
}

#[test]
fn changed_metadata_projection_does_not_latch_authorization_denial() {
    let h = Harness::new();
    let root = h.root("projection-source");
    fs::write(root.join("save.dat"), b"one").unwrap();
    let id = h.approve(&root);
    h.store.projection_changed.store(true, Ordering::Release);
    assert!(h
        .tracker
        .scan(&id)
        .unwrap_err()
        .is::<TrackingProjectionChanged>());
    {
        let apps = h.tracker.shared.apps().unwrap();
        let app = &apps[&id];
        assert!(!app.authorization_paused);
        assert!(!app.record.authorization_pending);
        assert!(!app.scheduler.paused);
    }
    h.store.projection_changed.store(false, Ordering::Release);
    assert!(h.tracker.scan(&id).is_ok());
}

#[test]
fn idle_native_ticks_skip_authority_io_but_audit_still_checks_denial() {
    let mut h = Harness::new();
    let root = h.root("idle-source");
    fs::write(root.join("save.dat"), b"one").unwrap();
    let id = h.approve(&root);
    h.scan(&id);
    let before = h.store.verification_calls.load(Ordering::Relaxed);
    for _ in 0..100 {
        assert!(native::tick(&h.tracker.shared, BTreeSet::new(), false, false).is_empty());
    }
    assert_eq!(h.store.verification_calls.load(Ordering::Relaxed), before);
    // Advance the injected worker clock beyond enrollment's quiet period.
    Arc::get_mut(&mut h.tracker.shared).unwrap().origin =
        Instant::now() - std::time::Duration::from_secs(10);
    *h.store.failing_verification.lock().unwrap() = Some(("tracking".into(), id));
    assert!(native::tick(&h.tracker.shared, BTreeSet::new(), false, true).is_empty());
    assert!(h.store.verification_calls.load(Ordering::Relaxed) > before);
    let after = h.store.verification_calls.load(Ordering::Relaxed);
    for _ in 0..10 {
        native::tick(&h.tracker.shared, BTreeSet::new(), false, true);
    }
    assert_eq!(h.store.verification_calls.load(Ordering::Relaxed), after);
}

#[test]
fn inflight_mutation_is_retained_for_a_followup_and_one_app_cannot_upload_twice() {
    let h = Harness::new();
    let root = h.root("source");
    let source = root.join("save.dat");
    fs::write(&source, b"before").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
    fs::write(&source, b"during upload").unwrap();
    native::inject_event(
        &h.tracker.shared,
        Ok(Event::new(EventKind::Modify(ModifyKind::Any)).add_path(source.clone())),
    );
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], false);
    let scan = h.scan(&id);
    assert_eq!(scan["captureSource"]["changedDirty"], true);
    assert_eq!(scan["software"]["lastConfirmedUploadedGeneration"], 0);
    assert_eq!(fs::read(source).unwrap(), b"during upload");
}

#[test]
fn partial_confirmation_does_not_clear_other_dirty_files_or_widen_selection() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("first.dat"), b"first").unwrap();
    fs::write(root.join("second.dat"), b"second").unwrap();
    let id = h.approve(&root);
    h.scan(&id);
    let listing = h.tracker.file_listing(&id, None, 10).unwrap();
    let first = listing["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["name"] == "first.dat")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let work = h
        .tracker
        .begin_upload(&id, "provider-a", Some(std::slice::from_ref(&first)))
        .unwrap();
    assert_eq!(work["fileIds"], json!([first]));
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    let scan = h.scan(&id);
    assert_eq!(scan["captureSource"]["changedDirty"], true);
    assert_eq!(scan["software"]["lastConfirmedUploadedGeneration"], 0);
    let page = h.tracker.file_listing(&id, None, 10).unwrap();
    let files = page["files"].as_array().unwrap();
    assert_eq!(
        files.iter().find(|f| f["name"] == "first.dat").unwrap()["status"],
        "saved"
    );
    assert_eq!(
        files.iter().find(|f| f["name"] == "second.dat").unwrap()["status"],
        "new"
    );
    assert!(h
        .tracker
        .begin_upload(&id, "provider-a", Some(&["outside-id".into()]))
        .is_err());
    assert!(h
        .tracker
        .begin_upload(&id, "provider-a", Some(&[]))
        .is_err());
    assert!(root.join("first.dat").exists() && root.join("second.dat").exists());
}

#[test]
fn deleted_file_is_a_dirty_tombstone_not_an_instruction_to_remove_data() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("removed.dat"), b"old").unwrap();
    fs::write(root.join("kept.dat"), b"must stay").unwrap();
    let id = h.approve(&root);
    let initial = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&initial, true);
    h.scan(&id);
    fs::remove_file(root.join("removed.dat")).unwrap(); // Simulated user deletion.
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], true);
    let page = h.tracker.file_listing(&id, None, 20).unwrap();
    assert!(page["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["status"] == "deleted"));
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
    assert_eq!(fs::read(root.join("kept.dat")).unwrap(), b"must stay");
    assert!(!root.join("removed.dat").exists()); // Tracking did not recreate it either.
}

#[test]
fn root_replacement_remount_requires_fresh_native_approval() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"approved").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    fs::rename(&root, h.home.join("original-source")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("save.dat"), b"unapproved replacement").unwrap();
    assert!(h.tracker.scan(&id).is_err());
    let software = h.tracker.software().unwrap();
    assert_eq!(software[0]["status"], "error");
    assert_eq!(software[0]["autosave"], false);
    assert!(h.tracker.root_authority(&id).is_err());
    assert_eq!(
        fs::read(root.join("save.dat")).unwrap(),
        b"unapproved replacement"
    );
}

#[test]
fn overflow_is_bounded_and_invalidates_even_a_byte_identical_inflight_capture() {
    let h = Harness::new();
    let root = h.root("source");
    let path = root.join("save.dat");
    fs::write(&path, b"content").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    for _ in 0..10_000 {
        native::inject_event(
            &h.tracker.shared,
            Ok(Event::new(EventKind::Modify(ModifyKind::Any)).add_path(path.clone())),
        );
    }
    assert!(h.tracker.shared.uncertainty_epoch.load(Ordering::Acquire) > 0);
    assert_eq!(h.receiver.try_iter().count(), native::QUEUE_CAPACITY);
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], false);
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], true);
}

#[test]
fn revoked_hmac_grants_and_plain_json_autosave_flags_do_not_authorize() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"data").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    let scope = {
        let apps = h.tracker.shared.apps().unwrap();
        apps[&id].record.autosave_scope()
    };
    h.store.revoke_grant("autosave", &scope).unwrap();
    assert_eq!(h.tracker.software().unwrap()[0]["autosave"], false);
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        let app = apps.get_mut(&id).unwrap();
        app.record.autosave = true; // Attacker-controlled plaintext flag.
        app.record.autosave_grant = Some(json!({"approved": true}));
        assert!(!h.tracker.shared.validate_autosave(app).unwrap());
    }
    let authority = h.tracker.root_authority(&id).unwrap();
    h.store
        .revoke_grant("tracking", &authority["scope"])
        .unwrap();
    assert!(h.tracker.scan(&id).is_err());
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
}

#[test]
fn changing_provider_revokes_autosave_and_requires_a_new_provider_baseline() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"data").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&work, true);
    assert_eq!(h.scan(&id)["software"]["dirty"], false);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    let changed = h.tracker.set_provider(&id, Some("provider-b")).unwrap();
    assert_eq!(changed["autosave"], false);
    assert_eq!(h.scan(&id)["software"]["dirty"], true);
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
    assert!(h
        .tracker
        .configure_autosave(&id, "provider-a", true)
        .is_err());
    h.tracker
        .configure_autosave(&id, "provider-b", true)
        .unwrap();
    let next = h.tracker.begin_upload(&id, "provider-b", None).unwrap();
    assert_eq!(next["providerId"], "provider-b");
}

#[test]
fn manual_leaves_preserve_root_ids_and_do_not_browse_or_capture_siblings() {
    let h = Harness::new();
    let parent = h.root("picked-files");
    fs::write(parent.join("one.txt"), b"one").unwrap();
    fs::write(parent.join("two.txt"), b"two").unwrap();
    fs::write(parent.join("credentials.json"), b"do not read").unwrap();
    let record = h
        .tracker
        .add_files(&json!({
            "name": "Manual", "providerId": "provider-a", "paths": [parent.join("one.txt")]
        }))
        .unwrap();
    let id = record["id"].as_str().unwrap();
    let authority = h.tracker.root_authority(id).unwrap();
    let root_id = authority["roots"][0]["id"].clone();
    let first_file_id = file_id(root_id.as_str().unwrap(), "one.txt");
    h.scan(id);
    let listing = h.tracker.file_listing(id, None, 10).unwrap();
    assert_eq!(listing["files"].as_array().unwrap().len(), 1);
    assert_eq!(listing["files"][0]["id"], first_file_id);
    h.tracker
        .add_files(&json!({
            "softwareId": id, "paths": [parent.join("two.txt")]
        }))
        .unwrap();
    let after = h.tracker.root_authority(id).unwrap();
    assert_eq!(after["roots"][0]["id"], root_id);
    h.scan(id);
    let page = h.tracker.file_listing(id, None, 10).unwrap();
    assert_eq!(page["files"].as_array().unwrap().len(), 2);
    assert!(!page["files"].to_string().contains("credentials"));
    let all = h.tracker.begin_upload(id, "provider-a", None).unwrap();
    assert_eq!(
        all["roots"][0]["allowedFiles"],
        json!(["one.txt", "two.txt"])
    );
    assert_eq!(all["fileIds"].as_array().unwrap().len(), 2);
    assert_eq!(
        all["captureSource"]["expectedFiles"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fs::read(parent.join("credentials.json")).unwrap(),
        b"do not read"
    );
}

#[test]
fn manual_file_sibling_events_do_not_expand_scope() {
    let h = Harness::new();
    let root = h.root("manual");
    let selected = root.join("selected.dat");
    fs::write(&selected, b"selected").unwrap();
    fs::write(root.join("other.dat"), b"other").unwrap();
    let record = h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [selected]
        }))
        .unwrap();
    let id = record["id"].as_str().unwrap();
    native::install_test_routes(&h.tracker.shared);
    native::inject_event(
        &h.tracker.shared,
        Ok(Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.join("other.dat"))),
    );
    let apps = h.tracker.shared.apps().unwrap();
    assert_eq!(apps[id].event_epoch.load(Ordering::Acquire), 0);
}

#[test]
fn paged_listing_is_bounded_stable_and_bound_to_the_snapshot_and_software() {
    let h = Harness::new();
    let root = h.root("source");
    for n in 0..7 {
        fs::write(root.join(format!("{n}.dat")), [n]).unwrap();
    }
    let id = h.approve(&root);
    h.scan(&id);
    assert!(h.tracker.file_listing(&id, None, MAX_PAGE + 1).is_err());
    let mut cursor = None;
    let mut ids = BTreeSet::new();
    loop {
        let page = h.tracker.file_listing(&id, cursor.as_deref(), 2).unwrap();
        let files = page["files"].as_array().unwrap();
        assert!(files.len() <= 2);
        for file in files {
            assert!(ids.insert(file["id"].as_str().unwrap().to_owned()));
        }
        cursor = page["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 7);
    let old = h.tracker.file_listing(&id, None, 2).unwrap()["nextCursor"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::write(root.join("new.dat"), b"new").unwrap();
    h.scan(&id);
    assert!(h.tracker.file_listing(&id, Some(&old), 2).is_err());
}

#[test]
fn persistence_failure_and_offline_provider_fail_closed_without_removing_sources() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"keep").unwrap();
    let id = h.approve(&root);
    h.store.offline.store(true, Ordering::Release);
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
    h.store.offline.store(false, Ordering::Release);
    h.store.fail_writes.store(true, Ordering::Release);
    assert!(h.tracker.scan(&id).is_err());
    assert_eq!(h.tracker.software().unwrap()[0]["status"], "error");
    assert_eq!(fs::read(root.join("save.dat")).unwrap(), b"keep");
}

#[test]
fn identity_is_not_inferred_from_a_basename_or_display_name() {
    let h = Harness::new();
    let first = h.root("app-one/saves");
    let second = h.root("app-two/saves");
    fs::write(first.join("same.dat"), b"one").unwrap();
    fs::write(second.join("same.dat"), b"two").unwrap();
    let one = h.approve(&first);
    let two = h.approve(&second);
    let first = h.tracker.root_authority(&one).unwrap();
    let second = h.tracker.root_authority(&two).unwrap();
    assert_ne!(first["roots"][0]["id"], second["roots"][0]["id"]);
    assert_ne!(
        file_id(first["roots"][0]["id"].as_str().unwrap(), "same.dat"),
        file_id(second["roots"][0]["id"].as_str().unwrap(), "same.dat"),
    );
}

#[test]
fn startup_requires_reconciliation_and_baseline_tampering_cannot_mark_clean() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"confirmed").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&work, true);
    h.scan(&id);
    let policy = h.tracker.shared.policy.clone();
    let restarted =
        Tracker::open_impl(h.store.clone(), Arc::new(|_| Ok(())), policy.clone(), false).unwrap();
    let state = restarted.software().unwrap();
    assert_eq!(state[0]["dirty"], true);
    assert_eq!(state[0]["status"], "checking");
    assert_eq!(restarted.scan(&id).unwrap()["software"]["dirty"], false);
    restarted.shutdown().unwrap();
    assert!(restarted.software().is_err());
    let raw = h.store.records.lock().unwrap()[&id].clone();
    let baseline_name = raw["baseline"]["name"].as_str().unwrap();
    fs::write(policy.baseline_dir().join(baseline_name), b"{}").unwrap();
    let corrupt = Tracker::open_impl(h.store.clone(), Arc::new(|_| Ok(())), policy, false).unwrap();
    assert!(corrupt.scan(&id).is_err());
    assert_eq!(corrupt.software().unwrap()[0]["authorizationPending"], true);
    assert_ne!(corrupt.software().unwrap()[0]["status"], "saved");
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["baseline"],
        raw["baseline"]
    );
    corrupt.shutdown().unwrap();
    assert_eq!(fs::read(root.join("save.dat")).unwrap(), b"confirmed");
}

#[test]
fn forbidden_roots_and_native_symlinks_are_not_followed() {
    let h = Harness::new();
    assert!(h
        .tracker
        .approve_software(&json!({
            "name": "Not authorized", "roots": [{"path": h.tracker.shared.policy.data_dir}]
        }))
        .is_err());
    let root = h.root("source");
    let keys = h.root("source/.ssh");
    fs::write(keys.join("private"), b"secret").unwrap();
    let id = h.approve(&root);
    assert!(h.tracker.scan(&id).is_err()); // Fail, do not silently skip unsafe entries.
    #[cfg(unix)]
    {
        let outside = h.root("outside");
        fs::write(outside.join("data"), b"outside").unwrap();
        let link = h.home.join("link");
        std::os::unix::fs::symlink(outside, &link).unwrap();
        assert!(h
            .tracker
            .approve_software(&json!({
                "name": "Symlink", "roots": [{"path": link}]
            }))
            .is_err());
    }
}

#[test]
fn logical_34_gib_counts_and_stable_ids_do_not_require_a_large_fixture() {
    let mut snapshot = Snapshot::default();
    let size = 34_u64 * 1024 * 1024 * 1024;
    let node = model::Node {
        root_id: "explicit-root".into(),
        path: "large.data".into(),
        directory: false,
        size,
        stamp: Some(quicksave_platform::FileStamp {
            device: 7,
            file_id: [11, 0],
            size,
            modified_seconds: 1,
            modified_nanoseconds: 0,
            changed_seconds: 2,
            changed_nanoseconds: 0,
        }),
        hash: Some("a".repeat(64)),
        link: None,
        metadata: None,
    };
    snapshot.nodes.insert(node.id(), node);
    assert_eq!(snapshot.counts().unwrap(), (1, size));
    assert_eq!(model::MAX_FILES, 250_000); // Accommodates 186k, never allocates that fixture.
    assert_ne!(file_id("root-a", "save"), file_id("root-b", "save"));
}

#[test]
fn native_worker_joins_and_explicit_shutdown_releases_the_event_routes() {
    let h = Harness::new();
    let tracker = Tracker::open(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
    )
    .unwrap();
    tracker.shutdown().unwrap();
    assert!(tracker.worker.lock().unwrap().is_none());
    assert!(tracker.shared.routes.read().unwrap().is_empty());
    assert!(tracker.software().is_err());
}

#[test]
fn queued_autosave_rechecks_original_selection_and_native_grant() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"data").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    let work = {
        let mut apps = h.tracker.shared.apps().unwrap();
        let app = apps.get_mut(&id).unwrap();
        app.watch_ok = true; // Deterministic native watcher fixture.
        h.tracker.shared.reconcile(app, true).unwrap();
        h.tracker
            .shared
            .prepare_upload(app, "provider-a", None, true)
            .unwrap()
    };
    assert_eq!(
        h.tracker.verify_autosave_work(&work).unwrap()["verified"],
        true
    );
    let mut widened = work.clone();
    widened["fileIds"] = json!(["different-file"]);
    assert!(h.tracker.verify_autosave_work(&widened).is_err());
    let mut changed_provider = work.clone();
    changed_provider["providerId"] = json!("provider-b");
    assert!(h.tracker.verify_autosave_work(&changed_provider).is_err());
    let mut changed_hash = work.clone();
    changed_hash["captureSource"]["expectedFiles"][0]["fileHash"] = json!("0".repeat(64));
    assert!(h.tracker.verify_autosave_work(&changed_hash).is_err());
    h.tracker
        .configure_autosave(&id, "provider-a", false)
        .unwrap();
    assert!(h.tracker.verify_autosave_work(&work).is_err());
}

#[test]
fn manual_file_at_a_common_parent_does_not_enumerate_excluded_or_symlinked_siblings() {
    let h = Harness::new();
    let selected = h.home.join("selected.txt");
    fs::write(&selected, b"selected").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(h.home.join("not-created"), h.home.join("unapproved-link")).unwrap();
    // Parent contains QuickSave's own state directory, but the fixed regular
    // leaf scope does not authorize it or the unapproved symlink.
    let record = h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [selected]
        }))
        .unwrap();
    let id = record["id"].as_str().unwrap();
    h.scan(id);
    let page = h.tracker.file_listing(id, None, 10).unwrap();
    assert_eq!(page["files"].as_array().unwrap().len(), 1);
    assert_eq!(page["files"][0]["name"], "selected.txt");
}

#[test]
fn empty_sources_fail_explicitly_without_consuming_an_inflight_slot() {
    let h = Harness::new();
    let root = h.root("empty");
    let id = h.approve(&root);
    assert!(h.tracker.begin_upload(&id, "provider-a", None).is_err());
    let apps = h.tracker.shared.apps().unwrap();
    assert!(apps[&id].pending.is_none());
    assert!(apps[&id].scheduler.flight.is_none());
    assert!(apps[&id].scheduler.content_dirty);
}

#[test]
fn native_watch_errors_and_identity_stability_checks_never_claim_success() {
    let h = Harness::new();
    let root = h.root("source");
    let path = root.join("save.dat");
    fs::write(&path, b"one").unwrap();
    let id = h.approve(&root);
    let authority = h.tracker.root_authority(&id).unwrap();
    let root: ApprovedRoot = serde_json::from_value(authority["roots"][0].clone()).unwrap();
    let pinned = scan::PinnedRoot::open(&root).unwrap();
    let (_, before) = pinned.safe.read_file("save.dat").unwrap();
    fs::write(&path, b"two, changed").unwrap();
    assert!(pinned.safe.verify_file("save.dat", &before).is_err());
    native::inject_event(
        &h.tracker.shared,
        Err(notify::Error::generic("synthetic permission loss")),
    );
    assert!(h.tracker.shared.uncertainty_epoch.load(Ordering::Acquire) > 0);
    let stop = AtomicBool::new(true);
    assert!(scan::capture(&[root], None, true, &h.tracker.shared.policy, &stop).is_err());
    assert_eq!(h.scan(&id)["captureSource"]["changedDirty"], true);
    assert_eq!(fs::read(path).unwrap(), b"two, changed");
}

#[test]
fn startup_with_an_unavailable_root_keeps_other_state_usable_and_reconciles_on_return() {
    let h = Harness::new();
    let root = h.root("removable");
    fs::write(root.join("save.dat"), b"keep local").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    let saved = h.store.records.lock().unwrap()[&id].clone();
    fs::rename(&root, h.home.join("temporarily-unmounted")).unwrap();
    let restarted = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    assert_eq!(restarted.software().unwrap()[0]["dirty"], true);
    assert!(restarted.scan(&id).is_err());
    fs::rename(h.home.join("temporarily-unmounted"), &root).unwrap();
    // Moving the approved directory can change its native ctime. Make a real
    // root metadata difference deterministic even on coarse-time filesystems.
    fs::File::open(&root)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_900_000_000),
            ),
        )
        .unwrap();
    let returned = restarted.scan(&id).unwrap();
    assert_eq!(returned["captureSource"]["changedDirty"], true);
    assert_eq!(
        returned["captureSource"]["contentState"],
        "content_verified"
    );
    assert_eq!(returned["software"]["status"], "needs_backup");
    let apps = restarted.shared.apps().unwrap();
    let app = &apps[&id];
    let current = app.current.as_ref().unwrap();
    let baseline = app.baseline.as_ref().unwrap();
    assert_eq!(current.nodes, baseline.nodes); // No file content/metadata changed.
    assert_ne!(current.root_stamps, baseline.root_stamps);
    assert!(!app.scheduler.needs_reconcile); // Real proof cleared uncertainty, not dirt.
    let stored = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(stored["baseline"], saved["baseline"]);
    assert_eq!(
        stored["lastConfirmedUploadedGeneration"],
        saved["lastConfirmedUploadedGeneration"]
    );
}

#[test]
fn returning_an_unchanged_subtree_clears_restart_uncertainty_only_after_real_capture() {
    let h = Harness::new();
    let root = h.root("synthetic-mount/removable");
    let mount = h.home.join("synthetic-mount");
    fs::write(root.join("save.dat"), b"unchanged native scope").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    let saved = h.store.records.lock().unwrap()[&id].clone();
    // Hide an ancestor, not the approved root itself: the approved root's
    // directory stamps and file metadata remain unchanged in this fixture.
    let absent = h.home.join("temporarily-absent-mount");
    fs::rename(&mount, &absent).unwrap();
    let restarted = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    assert_eq!(restarted.software().unwrap()[0]["dirty"], true);
    assert!(restarted.scan(&id).is_err());
    fs::rename(&absent, &mount).unwrap();
    assert_eq!(restarted.software().unwrap()[0]["dirty"], true);
    let returned = restarted.scan(&id).unwrap();
    assert_eq!(returned["captureSource"]["changedDirty"], false);
    assert_eq!(
        returned["captureSource"]["contentState"],
        "content_verified"
    );
    assert_eq!(returned["software"]["status"], "saved");
    assert_eq!(restarted.performance_counters()["filesHashed"], 1);
    assert_eq!(
        restarted.performance_counters()["bytesRead"],
        b"unchanged native scope".len() as u64
    );
    let apps = restarted.shared.apps().unwrap();
    assert_eq!(apps[&id].current, apps[&id].baseline);
    assert!(!apps[&id].scheduler.needs_reconcile);
    let stored = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(stored["baseline"], saved["baseline"]);
    assert_eq!(
        stored["lastConfirmedUploadedGeneration"],
        saved["lastConfirmedUploadedGeneration"]
    );
}

#[test]
fn an_old_provider_baseline_cannot_be_rebound_through_plaintext_state() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"data").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    h.finish(&work, true);
    let old = h.store.records.lock().unwrap()[&id]["baseline"].clone();
    h.tracker.set_provider(&id, Some("provider-b")).unwrap();
    h.store.records.lock().unwrap().get_mut(&id).unwrap()["baseline"] = old;
    let restarted = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    assert!(restarted.scan(&id).is_err());
    assert_eq!(
        restarted.software().unwrap()[0]["authorizationPending"],
        true
    );
    assert_ne!(restarted.software().unwrap()[0]["status"], "saved");
    assert!(restarted.begin_upload(&id, "provider-b", None).is_err());
}

fn directory_proof(path: &Path) -> Value {
    let root = quicksave_platform::SafeRoot::open(path).unwrap();
    json!({"path": path, "kind": "directory", "identity": root.identity().unwrap()})
}

fn file_proof(path: &Path) -> Value {
    let parent = quicksave_platform::SafeRoot::open(path.parent().unwrap()).unwrap();
    let leaf = path.file_name().unwrap().to_str().unwrap();
    let (_, stamp) = parent.read_file(leaf).unwrap();
    json!({
        "path": path, "kind": "file",
        "identity": {"device": stamp.device, "fileId": stamp.file_id},
        "stamp": stamp, "parentIdentity": parent.identity().unwrap(),
    })
}

#[test]
fn replacing_a_directory_after_native_prepare_cannot_issue_a_tracking_grant() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("save.dat"), b"original").unwrap();
    let proof = directory_proof(&root);
    fs::rename(&root, h.home.join("original-source")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("save.dat"), b"unapproved replacement").unwrap();
    assert!(h
        .tracker
        .approve_software(&json!({
            "name": "Prepared old source", "providerId": "provider-a",
            "roots": [{"path": root}], "_approvedPaths": [proof],
        }))
        .is_err());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), 0);
}

#[test]
fn changing_a_selected_file_after_prepare_cannot_create_a_manual_record() {
    let h = Harness::new();
    let root = h.root("source");
    let selected = root.join("picked.dat");
    fs::write(&selected, b"before").unwrap();
    let proof = file_proof(&selected);
    fs::write(&selected, b"different length, same native inode").unwrap();
    assert!(h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [selected], "_approvedPaths": [proof],
        }))
        .is_err());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), 0);
}

#[test]
fn replacing_an_individual_files_parent_after_prepare_is_rejected() {
    let h = Harness::new();
    let root = h.root("source");
    let selected = root.join("picked.dat");
    fs::write(&selected, b"same contents").unwrap();
    let proof = file_proof(&selected);
    fs::rename(&root, h.home.join("original-parent")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(&selected, b"same contents").unwrap();
    assert!(h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [selected], "_approvedPaths": [proof],
        }))
        .is_err());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), 0);
}

#[test]
fn native_proof_coverage_is_exact_and_file_picks_cannot_fall_back_to_parents() {
    let h = Harness::new();
    let root = h.root("source");
    let first = root.join("first.dat");
    let second = root.join("second.dat");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let first_proof = file_proof(&first);
    let second_proof = file_proof(&second);
    assert!(h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [first], "_approvedPaths": [],
        }))
        .is_err());
    assert!(h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [first],
            "_approvedPaths": [directory_proof(&root)],
        }))
        .is_err());
    assert!(h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [first],
            "_approvedPaths": [first_proof, second_proof],
        }))
        .is_err());
    let other = h.root("not-requested");
    assert!(h
        .tracker
        .approve_software(&json!({
            "name": "Exact root", "roots": [{"path": root}],
            "_approvedPaths": [directory_proof(&root), directory_proof(&other)],
        }))
        .is_err());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), 0);
}

#[test]
fn approved_file_stamps_survive_inner_approval_and_preserve_existing_root_ids() {
    let h = Harness::new();
    let root = h.root("source");
    let first = root.join("first.dat");
    let second = root.join("second.dat");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();
    let added = h
        .tracker
        .add_files(&json!({
            "providerId": "provider-a", "paths": [first],
            "_approvedPaths": [file_proof(&first)],
        }))
        .unwrap();
    let id = added["id"].as_str().unwrap();
    assert!(added["appId"]
        .as_str()
        .unwrap()
        .starts_with("quicksave.manual."));
    let root_id = h.tracker.root_authority(id).unwrap()["roots"][0]["id"].clone();
    h.tracker
        .add_files(&json!({
            "softwareId": id, "paths": [second],
            "_approvedPaths": [directory_proof(&root), file_proof(&second)],
        }))
        .unwrap();
    assert_eq!(
        h.tracker.root_authority(id).unwrap()["roots"][0]["id"],
        root_id
    );
    h.scan(id);
    let work = h.tracker.begin_upload(id, "provider-a", None).unwrap();
    assert_eq!(work["fileIds"].as_array().unwrap().len(), 2);
    assert_eq!(
        work["captureSource"]["expectedFiles"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn whole_software_work_freezes_exact_ids_and_compact_raw_file_hashes() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("one.dat"), b"one").unwrap();
    fs::write(root.join("two.dat"), b"two").unwrap();
    let id = h.approve(&root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    let ids = work["fileIds"].as_array().unwrap();
    let evidence = work["captureSource"]["expectedFiles"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(evidence.len(), 2);
    let apps = h.tracker.shared.apps().unwrap();
    let app = &apps[&id];
    for (id, file) in ids.iter().zip(evidence) {
        assert_eq!(file.as_object().unwrap().len(), 3);
        assert_eq!(&file["id"], id);
        let node = &app.current.as_ref().unwrap().nodes[id.as_str().unwrap()];
        let actual = fs::read(root.join(&node.path)).unwrap();
        assert_eq!(file["fileHash"], blake3::hash(&actual).to_hex().to_string());
        assert_eq!(file["size"], actual.len() as u64);
        assert!(file.get("stamp").is_none() && file.get("path").is_none());
    }
    validate_work_files(
        &work,
        &app.pending.as_ref().unwrap().selected,
        app.current.as_ref().unwrap(),
    )
    .unwrap();
}

#[test]
fn compact_186k_logical_evidence_fits_native_64_mib_without_large_fs_fixtures() {
    // Fixed-width IDs/hashes and the widest supported serialized size. This is
    // exact encoded-size arithmetic, not 186k files or a giant duplicate index.
    let id = file_id("native-root", "saves/slot.dat");
    let sample = json!({"id": id, "fileHash": "f".repeat(64), "size": u64::MAX});
    let per_file = serde_json::to_vec(&sample).unwrap().len();
    let per_id = serde_json::to_vec(&id).unwrap().len();
    let count = 186_000_usize;
    let encoded = count * (per_file + per_id + 2) + 1024 * 1024;
    assert!(encoded < 64 * 1024 * 1024);
    assert_eq!(model::MAX_PATH_BYTES, 32 * 1024 * 1024);
    assert_eq!(model::MAX_FILES, 250_000);
    assert!(model::bounded_serialized(&sample, 1).is_err());
}

#[path = "bundle_tests.rs"]
mod bundles;
