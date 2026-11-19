// SPDX-License-Identifier: GPL-3.0-only
//! Isolated local app/index/capture fixtures. No ambient discovery or vaults.

use super::*;

#[test]
fn explicit_refresh_can_reapprove_only_pristine_deferred_metadata_scopes() {
    for history in [false, true] {
        let h = full_harness();
        let base = h.root("legacy-refresh");
        let root = h.root("legacy-refresh/App.app");
        fs::write(root.join("actual"), b"isolated metadata only").unwrap();
        let plan = candidate("synthetic.deferred-refresh", &root);
        let sealed = authority(&h, &base, &[plan.clone()], true);
        let initial = h
            .tracker
            .materialize_bundles(&[plan.clone()], &sealed)
            .unwrap();
        let id = id_from(&initial);
        if history {
            h.tracker
                .shared
                .apps()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .record
                .last_saved_at = Some("2026-11-18T12:00:00Z".into());
        }
        let before = h.store.records.lock().unwrap()[&id].clone();
        h.store.deferred_tracking.lock().unwrap().insert(id.clone());
        assert_eq!(
            h.tracker.software().unwrap()[0]["authorizationPending"],
            true
        );
        let issued = h.store.issued_grants.load(Ordering::Acquire);
        let automatic = h
            .tracker
            .materialize_bundles(&[plan.clone()], &sealed)
            .unwrap();
        assert!(automatic["bundles"].as_array().unwrap().is_empty());
        assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
        let explicit = h.tracker.refresh_bundles(&[plan], &sealed).unwrap();
        if history {
            assert!(
                explicit["bundles"].as_array().unwrap().is_empty(),
                "{explicit}"
            );
            assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
            assert!(h.store.deferred_tracking.lock().unwrap().contains(&id));
        } else {
            assert_eq!(
                explicit["bundles"].as_array().unwrap().len(),
                1,
                "{explicit}"
            );
            assert!(!h.store.deferred_tracking.lock().unwrap().contains(&id));
            let after = h.store.records.lock().unwrap()[&id].clone();
            assert_eq!(after["roots"], before["roots"]);
            assert!(after["baseline"].is_null());
            assert!(after["previousBundleManifest"].is_null());
            assert_eq!(after["authorizationPending"], false);
            assert_eq!(after["autosave"], false);
            assert_ne!(after["status"], "saved");
        }
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    }
}

#[test]
fn deferred_metadata_refresh_cannot_widen_roots_or_replace_native_identity() {
    let h = full_harness();
    let base = h.root("legacy-exact");
    let root = h.root("legacy-exact/App.app");
    let extra = h.root("legacy-exact/Other.app");
    fs::write(root.join("actual"), b"unchanged").unwrap();
    let mut plan = candidate("synthetic.deferred-exact", &root);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    let initial = h
        .tracker
        .materialize_bundles(&[plan.clone()], &sealed)
        .unwrap();
    let id = id_from(&initial);
    let before = h.store.records.lock().unwrap()[&id].clone();
    h.store.deferred_tracking.lock().unwrap().insert(id.clone());
    h.tracker.software().unwrap();
    let mut another = candidate("synthetic.deferred-exact", &extra)["sourceRoots"][0].clone();
    another["rootId"] = json!("different-native-root");
    plan["sourceRoots"].as_array_mut().unwrap().push(another);
    let widened = authority(&h, &base, &[plan.clone()], true);
    let issued = h.store.issued_grants.load(Ordering::Acquire);
    let rejected = h.tracker.refresh_bundles(&[plan], &widened).unwrap();
    assert!(
        rejected["bundles"].as_array().unwrap().is_empty(),
        "{rejected}"
    );
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["roots"],
        before["roots"]
    );
    assert!(h.store.deferred_tracking.lock().unwrap().contains(&id));
}

#[test]
fn only_explicit_refresh_rechecks_paused_app_authority_and_reconciles_metadata() {
    let h = full_harness();
    let base = h.root("refresh-base");
    let root = h.root("refresh-base/App.app");
    fs::write(root.join("save"), b"synthetic saved bytes").unwrap();
    let plan = candidate("synthetic.explicit-refresh", &root);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    let initial = h
        .tracker
        .materialize_bundles(&[plan.clone()], &sealed)
        .unwrap();
    let id = id_from(&initial);
    let before = h.store.records.lock().unwrap()[&id].clone();
    *h.store.failing_verification.lock().unwrap() = Some(("tracking".into(), id.clone()));
    assert_eq!(
        h.tracker.software().unwrap()[0]["authorizationPending"],
        true
    );
    *h.store.failing_verification.lock().unwrap() = None;
    let automatic = h
        .tracker
        .materialize_bundles(&[plan.clone()], &sealed)
        .unwrap();
    assert!(automatic["bundles"].as_array().unwrap().is_empty());
    assert_eq!(
        h.tracker.software().unwrap()[0]["authorizationPending"],
        true
    );
    let explicit = h.tracker.refresh_bundles(&[plan], &sealed).unwrap();
    assert_eq!(
        explicit["bundles"].as_array().unwrap().len(),
        1,
        "{explicit}"
    );
    let after = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(after["authorizationPending"], false);
    assert_eq!(after["trackingGrant"], before["trackingGrant"]);
    assert_eq!(after["baseline"], before["baseline"]);
    assert_ne!(after["status"], "saved");
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
}

#[path = "container_scope_tests.rs"]
mod container_scope_tests;
#[path = "index_access_tests.rs"]
mod index_access_tests;
#[path = "trackingresume_tests.rs"]
mod trackingresume_tests;

fn full_harness() -> Harness {
    let mut h = Harness::new();
    let shared = Arc::get_mut(&mut h.tracker.shared).unwrap();
    shared.policy.supports_metadata_snapshots = true;
    shared.policy.supports_deletion_snapshots = true;
    h
}

fn native_identity(path: &Path) -> Value {
    let safe = quicksave_platform::SafeRoot::open(path).unwrap();
    let native = safe.identity().unwrap();
    json!({"platform": "unix", "device": native.device, "inode": native.file_id[0], "kind": "directory"})
}

fn candidate(app_id: &str, root: &Path) -> Value {
    let native = native_identity(root);
    let evidence = json!([{
        "kind": "native_installation_handle", "identifier": app_id,
        "metadataPath": null, "nativeIdentity": native,
    }]);
    json!({
        "appId": app_id, "productId": app_id, "displayName": "Isolated real app",
        "source": "isolated_native_fixture", "platform": "mac_os",
        "installationIdentity": native, "identityEvidence": evidence,
        "sourceRoots": [{
            "rootId": format!("native:{app_id}"), "path": root,
            "classification": "install", "roles": ["install"],
            "nativeIdentity": native, "status": "verified_candidate",
            "confidence": "native_installation", "evidence": evidence,
            "ownership": "exact_installation",
            "contentScanAuthorized": false, "trackingAuthorized": false,
            "uploadAuthorized": false,
        }],
        "unresolvedRoots": [], "unresolvedReasons": [{
            "code": "external_state_not_proven_complete", "message": "Only explicit evidenced roots are known."
        }],
        "rootsComplete": false, "trackingAuthorized": false,
    })
}

fn authority(h: &Harness, base: &Path, candidates: &[Value], new_apps: bool) -> Value {
    let safe = quicksave_platform::SafeRoot::open(base).unwrap();
    let allowed = candidates
        .first()
        .and_then(|value| value["appId"].as_str())
        .into_iter()
        .collect::<Vec<_>>();
    let scope = json!({
        "version": 1, "policyId": "isolated-native-policy", "rolePolicyVersion": 1,
        "source": "verified_native_discovery", "enabled": true,
        "baseDirectories": [{
            "id": "isolated-approved-app-base", "path": base, "identity": safe.identity().unwrap(),
            "allowedRoles": ["installation", "runtime", "save", "config", "container", "group_container", "data"],
            "ownershipRules": ["native_installation_handle"],
        }],
        "appIdentityPolicy": {
            "allowedAppIds": allowed, "allowNewVerifiedApps": new_apps,
            "allowedEvidenceKinds": ["native_installation_handle"],
            "allowNativeInstallationOnly": false,
        },
        "excludedPaths": [], "providerId": "provider-a",
    });
    sign_authority(h, scope, candidates)
}

fn sign_authority(h: &Harness, scope: Value, candidates: &[Value]) -> Value {
    let discovery = json!({
        "version": 1, "source": "verified_native_discovery",
        "policyHash": bundle::digest(&scope).unwrap(),
        "candidatesHash": bundle::digest(&json!(candidates)).unwrap(),
    });
    json!({
        "policyScope": scope,
        "policyGrant": h.store.issue_grant("app_tracking_policy", &scope).unwrap(),
        "discoveryScope": discovery,
        "discoveryGrant": h.store.issue_grant("bundle_discovery", &discovery).unwrap(),
    })
}

fn materialize(h: &Harness, base: &Path, candidates: &[Value]) -> Value {
    h.tracker
        .materialize_bundles(candidates, &authority(h, base, candidates, true))
        .unwrap()
}

fn id_from(report: &Value) -> String {
    report["bundles"][0]["id"].as_str().unwrap().to_owned()
}

fn indexed_candidate(instance: &str, canonical: &str, root: &Path) -> Value {
    let mut plan = candidate(instance, root);
    plan["sourceIdentity"] = json!({
        "app_id": canonical, "display_name": "Isolated source identity",
        "canonical_executable": null, "desktop_entry_id": null, "steam_app_id": null,
        "launcher": "native", "aliases": [], "identity_confidence": 1.0, "icon_path": null,
    });
    plan
}

struct FixtureReceipt {
    evidence: Value,
    roots: Vec<ApprovedRoot>,
    source_bytes_read: u64,
    validations: AtomicUsize,
    immutable: bool,
    captured_files: BTreeMap<String, Vec<u8>>,
}

impl FixtureReceipt {
    fn capture(h: &Harness, work: &Value) -> Self {
        let roots: Vec<ApprovedRoot> = serde_json::from_value(work["roots"].clone()).unwrap();
        let mut nodes = Vec::new();
        let mut source_bytes_read = 0_u64;
        let mut captured_files = BTreeMap::new();
        let mut cursor = None;
        loop {
            let page = h
                .tracker
                .prepared_node_listing(work["workId"].as_str().unwrap(), cursor.as_deref(), 2)
                .unwrap();
            for value in page["nodes"].as_array().unwrap() {
                let mut node = value.clone();
                let root = roots
                    .iter()
                    .find(|root| root.id == node["rootId"].as_str().unwrap())
                    .unwrap();
                let safe = quicksave_platform::SafeRoot::open(&root.path).unwrap();
                let path = node["path"].as_str().unwrap();
                match node["kind"].as_str().unwrap() {
                    "file" => {
                        let (mut file, stamp) = safe.read_file(path).unwrap();
                        let mut bytes = Vec::new();
                        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
                        source_bytes_read += bytes.len() as u64;
                        safe.verify_file(path, &stamp).unwrap(); // Real pre/post stable read.
                        node["fileHash"] = json!(blake3::hash(&bytes).to_hex().to_string());
                        node["stamp"] = json!(stamp);
                        captured_files.insert(node["id"].as_str().unwrap().to_owned(), bytes);
                    }
                    "symlink" => {
                        let link = safe.read_link(path).unwrap();
                        node["linkTargetHash"] =
                            json!(blake3::hash(link.target.as_bytes()).to_hex().to_string());
                        node["stamp"] = json!(link.stamp);
                    }
                    "directory" => {}
                    _ => unreachable!(),
                }
                nodes.push(node);
            }
            cursor = page["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        let manifest_hash = bundle::digest(&json!(nodes)).unwrap();
        Self {
            evidence: json!({
                "workId": work["workId"],
                "metadataIdentity": work["captureSource"]["snapshotIdentity"],
                "sourceSnapshotId": format!("isolated-native-source-{manifest_hash}"),
                "sourceExpectedManifestAuth": {
                    "testOnlyActualManifestHash": manifest_hash,
                    "authority": "isolated_injected_source_capture",
                },
                "nodes": nodes,
            }),
            roots,
            source_bytes_read,
            validations: AtomicUsize::new(0),
            immutable: false,
            captured_files,
        }
    }
}

impl NativeCaptureReceipt for FixtureReceipt {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        self.validations.fetch_add(1, Ordering::AcqRel);
        ensure!(
            self.evidence["sourceExpectedManifestAuth"]["testOnlyActualManifestHash"]
                == bundle::digest(&self.evidence["nodes"])?,
            "fixture source expected-manifest authentication failed"
        );
        for root in &self.roots {
            scan::PinnedRoot::open(root)?.check()?;
        }
        if self.immutable {
            // Isolated immutable prepared-byte fixture, not live-source reads.
            // Production uses the actual source's authenticated ciphertext and
            // prepared manifest rather than this small injected byte map.
            for node in self.evidence["nodes"].as_array().unwrap() {
                if node["kind"] == "file" {
                    let bytes = self
                        .captured_files
                        .get(node["id"].as_str().unwrap())
                        .context("fixture prepared bytes are missing")?;
                    ensure!(
                        node["fileHash"] == blake3::hash(bytes).to_hex().to_string()
                            && node["size"] == bytes.len() as u64,
                        "fixture prepared byte authentication failed"
                    );
                }
            }
            return Ok(());
        }
        for node in self.evidence["nodes"].as_array().unwrap() {
            let root = self
                .roots
                .iter()
                .find(|root| root.id == node["rootId"].as_str().unwrap())
                .unwrap();
            let safe = quicksave_platform::SafeRoot::open(&root.path)?;
            let path = node["path"].as_str().unwrap();
            let before: quicksave_platform::FileStamp =
                serde_json::from_value(node["stamp"].clone())?;
            match node["kind"].as_str().unwrap() {
                "file" => safe.verify_file(path, &before)?,
                "symlink" => {
                    let current = safe.read_link(path)?;
                    ensure!(current.stamp == before, "fixture source link changed");
                }
                "directory" => {
                    ensure!(
                        safe.metadata_entries()?
                            .iter()
                            .any(|entry| entry.relative_path == path && entry.stamp == before),
                        "fixture source directory changed"
                    );
                }
                _ => bail!("invalid fixture node kind"),
            }
        }
        Ok(())
    }
    fn immutable_prepared_capture(&self) -> bool {
        self.immutable
    }
}

fn accept(h: &Harness, work: &Value) -> Value {
    let receipt = Arc::new(FixtureReceipt::capture(h, work));
    h.tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), receipt)
        .unwrap()
}

#[test]
fn real_bundle_metadata_is_persisted_without_reading_installation_contents() {
    let h = Harness::new();
    let base = h.root("approved-applications");
    let root = h.root("approved-applications/Actual.app");
    fs::write(root.join("binary"), b"actual executable fixture").unwrap();
    fs::create_dir(root.join("empty-directory")).unwrap();
    let plan = candidate("synthetic.native.actual", &root);
    let report = materialize(&h, &base, &[plan]);
    assert!(report["diagnostics"].as_array().unwrap().is_empty());
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["tracked"], true);
    assert_eq!(raw["fileCount"], 1);
    assert_eq!(
        raw["logicalBytes"],
        b"actual executable fixture".len() as u64
    );
    assert_eq!(raw["bundleIndexSource"]["contentState"], "metadata_indexed");
    assert_eq!(raw["bundleIndexSource"]["coverage"], "partial");
    assert_eq!(raw["bundleIndexSource"]["roots"][0]["role"], "installation");
    let name = raw["bundleIndexSource"]["index"]["name"].as_str().unwrap();
    let bytes = fs::read(h.tracker.shared.policy.bundle_dir().join(name)).unwrap();
    let index: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(index["nodes"].as_object().unwrap().len(), 2);
    assert_eq!(index["rootMetadata"].as_object().unwrap().len(), 1);
    assert!(index["nodes"]
        .as_object()
        .unwrap()
        .values()
        .all(|node| node["metadata"].is_object()));
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    assert!(
        h.tracker.performance_counters()["fsWalks"]
            .as_u64()
            .unwrap()
            >= 2
    );
}

#[test]
fn status_bundle_pages_and_file_pages_reuse_the_committed_index_with_no_source_io() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Indexed.app");
    fs::write(root.join("one"), b"one").unwrap();
    fs::write(root.join("two"), b"two").unwrap();
    let report = materialize(&h, &base, &[candidate("synthetic.cached", &root)]);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    let expected_roots = json!([{
        "id": raw["roots"][0]["id"], "path": root,
        "role": "installation", "roles": ["installation"],
    }]);
    let before = h.tracker.performance_counters();
    for _ in 0..20 {
        let software = h.tracker.software().unwrap();
        assert_eq!(software.len(), 1);
        assert_eq!(software[0]["roots"], expected_roots);
        let bundles = h.tracker.bundles().unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0]["roots"], expected_roots);
        let listing = h.tracker.bundle_listing(None, 1).unwrap();
        assert_eq!(listing["bundles"].as_array().unwrap().len(), 1);
        assert_eq!(listing["bundles"][0]["roots"], expected_roots);
        assert_eq!(
            h.tracker.file_listing(&id, None, 1).unwrap()["files"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    assert_eq!(h.tracker.performance_counters(), before);
}

#[test]
fn sanitized_software_roots_expose_only_approved_display_metadata_not_private_authority() {
    let h = Harness::new();
    let saved = h.root("save-source");
    let settings = h.root("config-source");
    fs::write(saved.join("save.dat"), b"real save bytes").unwrap();
    fs::write(settings.join("preferences.ini"), b"real settings").unwrap();
    fs::write(
        settings.join("not-selected"),
        b"not in the approved leaf scope",
    )
    .unwrap();
    let approved = h
        .tracker
        .approve_software(&json!({
            "name": "Native approved roots", "providerId": "provider-a",
            "roots": [
                {"path": saved, "role": "save", "source": {
                    "roles": ["runtime"],
                    "provenancePath": h.home.join("private-source-reference"),
                }},
                {"path": settings, "role": "config", "allowedFiles": ["preferences.ini"]},
            ],
        }))
        .unwrap();
    let id = approved["id"].as_str().unwrap();
    assert_eq!(approved["tracked"], false);
    assert_eq!(approved["roots"], json!([])); // No unmaterialized UI placeholder.
    h.tracker.scan_metadata(id).unwrap();
    let raw = h.tracker.bundle_record(id).unwrap();
    let expected = raw["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| json!({"id": root["id"], "path": root["path"], "role": root["role"]}))
        .collect::<Vec<_>>();
    let before = h.tracker.performance_counters();
    // A cached display projection must not pin, enumerate or hash live roots.
    fs::rename(&saved, h.home.join("temporarily-absent-save")).unwrap();
    fs::rename(&settings, h.home.join("temporarily-absent-config")).unwrap();
    for _ in 0..20 {
        let software = h.tracker.software().unwrap();
        let public = &software[0];
        assert_eq!(public["tracked"], true);
        assert_eq!(public["fileCount"], 2);
        assert_eq!(public["roots"], json!(expected));
        for root in public["roots"].as_array().unwrap() {
            assert_eq!(root.as_object().unwrap().len(), 3);
            for private in [
                "roles", // Unsigned manual source labels cannot add roles.
                "identity",
                "allowedFiles",
                "source",
                "trackingGrant",
                "fileCount",
                "logicalBytes",
            ] {
                assert!(
                    root.get(private).is_none(),
                    "unexpected root field {private}"
                );
            }
        }
        for private in [
            "trackingGrant",
            "autosaveGrant",
            "baseline",
            "bundleIndexSource",
            "captureReceipt",
        ] {
            assert!(
                public.get(private).is_none(),
                "unexpected software field {private}"
            );
        }
        assert!(!public.to_string().contains("private-source-reference"));
    }
    assert_eq!(h.tracker.performance_counters(), before);
}

#[test]
fn plaintext_enrollment_and_unattested_candidate_changes_cannot_create_bundles() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"real").unwrap();
    let plan = candidate("synthetic.authenticated", &root);
    assert!(h
        .tracker
        .materialize_bundles(&[plan.clone()], &json!({"enabled": true}))
        .is_err());
    let sealed = authority(&h, &base, &[plan.clone()], true);
    let mut changed = plan;
    changed["appId"] = json!("synthetic.attacker");
    assert!(h.tracker.materialize_bundles(&[changed], &sealed).is_err());
    assert!(h.tracker.bundles().unwrap().is_empty());
    assert!(h.store.records.lock().unwrap().is_empty());
}

#[test]
fn sealed_policy_can_enroll_new_verified_apps_but_never_unknown_or_outside_roots() {
    let h = Harness::new();
    let base = h.root("apps");
    let first = h.root("apps/First.app");
    let second = h.root("apps/Second.app");
    let outside = h.root("outside-app");
    for path in [&first, &second, &outside] {
        fs::write(path.join("data"), b"real").unwrap();
    }
    let plans = vec![
        candidate("synthetic.first", &first),
        candidate("synthetic.second", &second),
    ];
    let only_first = h
        .tracker
        .materialize_bundles(&plans, &authority(&h, &base, &plans, false))
        .unwrap();
    assert_eq!(only_first["bundles"].as_array().unwrap().len(), 1);
    assert_eq!(only_first["diagnostics"].as_array().unwrap().len(), 1);
    let all = materialize(&h, &base, &plans);
    assert_eq!(all["bundles"].as_array().unwrap().len(), 2);
    let bad = materialize(&h, &base, &[candidate("synthetic.outside", &outside)]);
    assert!(bad["bundles"].as_array().unwrap().is_empty());
    assert_eq!(bad["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(h.tracker.bundles().unwrap().len(), 2);
}

#[test]
fn changed_native_base_or_plaintext_policy_cannot_widen_enrollment() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"real").unwrap();
    let plans = vec![candidate("synthetic.base", &root)];
    let sealed = authority(&h, &base, &plans, true);
    let mut forged = sealed.clone();
    forged["policyScope"]["baseDirectories"][0]["path"] = json!(h.home);
    assert!(h.tracker.materialize_bundles(&plans, &forged).is_err());
    fs::rename(&base, h.home.join("original-apps")).unwrap();
    fs::create_dir(&base).unwrap();
    assert!(h.tracker.materialize_bundles(&plans, &sealed).is_err());
    assert!(h.tracker.bundles().unwrap().is_empty());
}

#[test]
fn unknown_native_installation_is_explicit_policy_only_and_never_guesses_data() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Unsigned.app");
    fs::write(root.join("data"), b"native-only").unwrap();
    let mut plan = candidate("quicksave.observed:native-fixture", &root);
    plan["productId"] = Value::Null;
    let rejected = materialize(&h, &base, &[plan.clone()]);
    assert!(rejected["bundles"].as_array().unwrap().is_empty());
    let initial = authority(&h, &base, &[plan.clone()], true);
    let mut scope = initial["policyScope"].clone();
    scope["appIdentityPolicy"]["allowNativeInstallationOnly"] = json!(true);
    let accepted = h
        .tracker
        .materialize_bundles(
            &[plan.clone()],
            &sign_authority(&h, scope.clone(), &[plan.clone()]),
        )
        .unwrap();
    assert_eq!(accepted["bundles"].as_array().unwrap().len(), 1);
    plan["sourceRoots"][0]["classification"] = json!("data");
    plan["sourceRoots"][0]["roles"] = json!(["data"]);
    let denied = h
        .tracker
        .materialize_bundles(&[plan.clone()], &sign_authority(&h, scope, &[plan]))
        .unwrap();
    assert!(denied["bundles"].as_array().unwrap().is_empty());
    assert_eq!(denied["diagnostics"].as_array().unwrap().len(), 1);
}

#[test]
fn denied_or_unsafe_files_are_diagnostics_not_successful_empty_placeholders() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Blocked.app");
    fs::create_dir(root.join("Keychains")).unwrap();
    fs::write(root.join("Keychains/private"), b"excluded vault fixture").unwrap();
    let report = materialize(&h, &base, &[candidate("synthetic.blocked", &root)]);
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert!(!report["diagnostics"].as_array().unwrap().is_empty());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(
        fs::read(root.join("Keychains/private")).unwrap(),
        b"excluded vault fixture"
    );
}

#[test]
fn manual_approval_stays_untracked_until_its_actual_index_is_persisted() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("one"), b"one").unwrap();
    let id = h.approve(&root);
    assert_eq!(h.store.records.lock().unwrap()[&id]["tracked"], false);
    assert!(h.tracker.bundles().unwrap().is_empty());
    h.tracker.scan_metadata(&id).unwrap();
    assert_eq!(h.tracker.bundles().unwrap()[0]["tracked"], true);
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn authenticated_index_tampering_does_not_reappear_as_a_real_bundle_after_restart() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("one"), b"one").unwrap();
    let report = materialize(&h, &base, &[candidate("synthetic.tampering", &root)]);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    let name = raw["bundleIndexSource"]["index"]["name"].as_str().unwrap();
    fs::write(
        h.tracker.shared.policy.bundle_dir().join(name),
        b"{\"nodes\":{}}",
    )
    .unwrap();
    let reopened = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    assert!(reopened.bundles().unwrap().is_empty());
    assert_eq!(reopened.software().unwrap()[0]["tracked"], false);
    assert_eq!(fs::read(root.join("one")).unwrap(), b"one");
}

#[test]
fn real_capture_receipt_freezes_hashes_once_and_preserves_source_manifest_authentication() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("one"), b"one").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    assert!(work["captureSource"].get("expectedFiles").is_none());
    assert!(work["captureSource"].get("expectedMetadata").is_none());
    assert_eq!(work["captureSource"]["metadataSelection"]["nodeCount"], 1);
    let source = Arc::new(FixtureReceipt::capture(&h, &work));
    let receipt = h
        .tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), source.clone())
        .unwrap();
    assert_eq!(
        receipt["captureSource"]["expectedFiles"][0]["fileHash"],
        blake3::hash(b"one").to_hex().to_string()
    );
    assert!(receipt["captureSource"]["sourceExpectedManifestAuth"].is_object());
    assert_eq!(
        h.tracker
            .verify_capture_receipt(work["workId"].as_str().unwrap())
            .unwrap()["verified"],
        true
    );
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    assert_eq!(source.source_bytes_read, 3);
    assert_eq!(
        h.tracker.bundle_record(&id).unwrap()["bundleIndexSource"]["contentState"],
        "content_verified"
    );
}

#[test]
fn metadata_only_work_cannot_be_completed_or_published_without_actual_native_receipt() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"not captured").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    assert!(h
        .tracker
        .verify_capture_receipt(work["workId"].as_str().unwrap())
        .is_err());
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], false);
    assert!(h.tracker.shared.apps().unwrap()[&id].baseline.is_none());
}

#[test]
fn confined_links_and_empty_directories_have_real_typed_metadata_and_capture_evidence() {
    let h = full_harness();
    let root = h.root("source");
    fs::create_dir(root.join("Versions")).unwrap();
    fs::create_dir(root.join("Versions/A")).unwrap();
    fs::write(root.join("Versions/A/binary"), b"framework").unwrap();
    std::os::unix::fs::symlink("A", root.join("Versions/Current")).unwrap();
    std::os::unix::fs::symlink("Versions/Current/binary", root.join("binary")).unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let accepted = accept(&h, &work);
    let evidence = accepted["captureSource"]["expectedFiles"]
        .as_array()
        .unwrap();
    assert_eq!(
        evidence
            .iter()
            .filter(|node| node["kind"] == "directory")
            .count(),
        2
    );
    assert_eq!(
        evidence
            .iter()
            .filter(|node| node["kind"] == "symlink")
            .count(),
        2
    );
    assert!(evidence
        .iter()
        .filter(|node| node["kind"] == "symlink")
        .all(|node| node["linkTargetHash"].as_str().unwrap().len() == 64));
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(
        h.tracker.bundle_record(&id).unwrap()["bundleIndexSource"]["fileCount"],
        1
    );
    assert_eq!(
        h.tracker.bundle_record(&id).unwrap()["bundleIndexSource"]["symlinkCount"],
        2
    );
}

#[test]
fn escaping_link_is_rejected_without_reading_external_payloads_or_persisting_a_bundle() {
    let h = full_harness();
    let root = h.root("source");
    let external = h.root("outside");
    fs::write(external.join("secret"), b"never read").unwrap();
    let id = h.approve(&root);
    std::os::unix::fs::symlink("../outside/secret", root.join("escape")).unwrap();
    assert!(h.tracker.scan_metadata(&id).is_err());
    assert!(h.tracker.bundles().unwrap().is_empty());
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn additive_full_scope_deletion_can_capture_an_empty_root_without_physical_deletion() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("removed"), b"old version").unwrap();
    let id = h.approve(&root);
    let initial = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &initial);
    assert_eq!(h.finish(&initial, true)["sourceConfirmed"], true);
    let first_revision = h.tracker.bundle_record(&id).unwrap()["bundleIndexSource"]["manifest"]
        ["name"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::remove_file(root.join("removed")).unwrap(); // User/fixture deletion, not Tracker.
    let deletion = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    assert!(deletion["fileIds"].as_array().unwrap().is_empty());
    assert_eq!(deletion["deletedFileIds"].as_array().unwrap().len(), 1);
    assert_eq!(
        deletion["captureSource"]["expectedFullScope"]["scope"]["baselineKind"],
        "full"
    );
    assert_eq!(
        deletion["captureSource"]["expectedFullScope"]["scope"]["snapshotMode"],
        "additive_full_scope"
    );
    let accepted = accept(&h, &deletion);
    assert!(accepted["captureSource"]["expectedFiles"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(h.finish(&deletion, true)["sourceConfirmed"], true);
    assert!(h.tracker.shared.apps().unwrap()[&id]
        .baseline
        .as_ref()
        .unwrap()
        .nodes
        .is_empty());
    assert!(h
        .tracker
        .shared
        .policy
        .bundle_dir()
        .join(first_revision)
        .exists());
    assert!(root.exists() && !root.join("removed").exists());
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn selected_receipt_and_partial_baseline_never_clear_unselected_siblings() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("one"), b"one").unwrap();
    fs::write(root.join("two"), b"two").unwrap();
    let id = h.approve(&root);
    h.tracker.scan_metadata(&id).unwrap();
    let page = h.tracker.file_listing(&id, None, 10).unwrap();
    let selected = page["files"][0]["id"].as_str().unwrap().to_owned();
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", Some(&[selected]))
        .unwrap();
    assert!(work["captureSource"]["expectedFullScope"].is_null());
    accept(&h, &work);
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    let state = h.tracker.scan_metadata(&id).unwrap();
    assert_eq!(state["captureSource"]["baselineKind"], "partial");
    assert_eq!(state["captureSource"]["changedDirty"], true);
    assert_eq!(state["software"]["lastConfirmedUploadedGeneration"], 0);
    assert_eq!(
        h.tracker.shared.apps().unwrap()[&id]
            .baseline
            .as_ref()
            .unwrap()
            .nodes
            .len(),
        1
    );
}

#[test]
fn changes_and_new_files_during_receipt_upload_require_followup_and_keep_local_bytes() {
    let h = full_harness();
    let root = h.root("source");
    let path = root.join("data");
    fs::write(&path, b"one").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &work);
    fs::write(root.join("new"), b"added during upload").unwrap();
    native::inject_event(
        &h.tracker.shared,
        Ok(Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.join("new"))),
    );
    assert!(h
        .tracker
        .verify_capture_receipt(work["workId"].as_str().unwrap())
        .is_err());
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], false);
    assert_eq!(
        h.tracker.scan_metadata(&id).unwrap()["captureSource"]["changedDirty"],
        true
    );
    assert_eq!(fs::read(root.join("new")).unwrap(), b"added during upload");
    assert_eq!(fs::read(path).unwrap(), b"one");
}

#[test]
fn actual_source_receipt_with_wrong_selected_stamp_or_identity_is_rejected() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"one").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let mut receipt = FixtureReceipt::capture(&h, &work);
    receipt.evidence["metadataIdentity"] = json!("not-the-original-native-scope");
    assert!(h
        .tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), Arc::new(receipt))
        .is_err());
    assert!(
        h.tracker.shared.apps().unwrap()[&id]
            .pending
            .as_ref()
            .unwrap()
            .awaiting_receipt
    );
}

#[test]
fn prepared_native_pages_are_bounded_and_bound_to_exact_work_scope() {
    let h = full_harness();
    let root = h.root("source");
    for n in 0..5 {
        fs::write(root.join(format!("{n}")), [n]).unwrap();
    }
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let work_id = work["workId"].as_str().unwrap();
    let first = h.tracker.prepared_node_listing(work_id, None, 2).unwrap();
    assert_eq!(first["nodes"].as_array().unwrap().len(), 2);
    assert!(h
        .tracker
        .prepared_node_listing(work_id, Some("different:scope:2"), 2)
        .is_err());
    assert!(h
        .tracker
        .prepared_node_listing(work_id, None, MAX_PAGE + 1)
        .is_err());
    let second = h
        .tracker
        .prepared_node_listing(work_id, first["nextCursor"].as_str(), 2)
        .unwrap();
    assert_eq!(second["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn native_stamp_cache_hashes_only_changed_files_but_uncertainty_rehashes_every_file() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("one"), b"one").unwrap();
    fs::write(root.join("two"), b"two").unwrap();
    let id = h.approve(&root);
    h.scan(&id);
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        apps.get_mut(&id).unwrap().watch_ok = true; // Injected healthy native epoch.
    }
    let initial = h.tracker.performance_counters();
    let trusted = {
        let apps = h.tracker.shared.apps().unwrap();
        scan::can_reuse_content_cache(
            &apps[&id].record.roots,
            apps[&id].current.as_deref().unwrap(),
        )
        .unwrap()
    };
    fs::write(root.join("one"), b"changed").unwrap();
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        h.tracker
            .shared
            .reconcile(apps.get_mut(&id).unwrap(), false)
            .unwrap();
    }
    let incremental = h.tracker.performance_counters();
    assert_eq!(
        incremental["filesHashed"].as_u64().unwrap() - initial["filesHashed"].as_u64().unwrap(),
        if trusted { 1 } else { 2 }
    );
    assert_eq!(
        incremental["bytesRead"].as_u64().unwrap() - initial["bytesRead"].as_u64().unwrap(),
        b"changed".len() as u64 + if trusted { 0 } else { b"two".len() as u64 }
    );
    h.tracker
        .shared
        .uncertainty_epoch
        .fetch_add(1, Ordering::AcqRel);
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        h.tracker
            .shared
            .reconcile(apps.get_mut(&id).unwrap(), false)
            .unwrap();
    }
    let uncertain = h.tracker.performance_counters();
    assert_eq!(
        uncertain["filesHashed"].as_u64().unwrap() - incremental["filesHashed"].as_u64().unwrap(),
        2
    );
}

#[test]
fn failed_persistence_cannot_publish_a_tracked_bundle_or_dummy_counts() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"real").unwrap();
    let plan = candidate("synthetic.persist-failure", &root);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    h.store.fail_writes.store(true, Ordering::Release);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert_eq!(report["incomplete"], true);
    assert!(h.tracker.bundles().unwrap().is_empty());
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(fs::read(root.join("data")).unwrap(), b"real");
}

#[test]
fn native_policy_revocation_disables_auto_enrollment_and_source_proof_tampering() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"real").unwrap();
    let plan = candidate("synthetic.revocable", &root);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    let id = id_from(&report);
    h.store
        .revoke_grant("app_tracking_policy", &sealed["policyScope"])
        .unwrap();
    assert!(h.tracker.bundles().unwrap().is_empty());
    let software = h.tracker.software().unwrap();
    assert_eq!(software[0]["tracked"], false);
    assert_eq!(software[0]["roots"], json!([]));
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
}

#[test]
fn applications_is_a_valid_base_but_filesystem_and_home_roots_are_not() {
    // Pure lexical policy checks: never open the real /Applications or a home.
    assert!(!bundle::wide_home_base(Path::new("/Applications")));
    assert!(!bundle::wide_home_base(Path::new(
        "/Users/synthetic/Applications"
    )));
    assert!(bundle::wide_home_base(Path::new("/")));
    assert!(bundle::wide_home_base(Path::new("/Users/synthetic")));
    assert!(bundle::wide_home_base(Path::new("/home/synthetic")));
}

#[test]
fn duplicate_native_roots_are_indexed_once_with_all_verified_roles() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("binary"), b"one physical file").unwrap();
    let mut plan = candidate("synthetic.multi-role", &root);
    let mut runtime = plan["sourceRoots"][0].clone();
    runtime["rootId"] = json!("native-runtime-proof");
    runtime["classification"] = json!("runtime");
    runtime["roles"] = json!(["runtime"]);
    plan["sourceRoots"].as_array_mut().unwrap().push(runtime);
    let report = materialize(&h, &base, &[plan]);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["fileCount"], 1);
    assert_eq!(raw["roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        raw["roots"][0]["source"]["roles"],
        json!(["installation", "runtime"])
    );
    assert_eq!(
        raw["roots"][0]["source"]["normalizedRootProofs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let before = h.tracker.performance_counters();
    assert_eq!(
        h.tracker.software().unwrap()[0]["roots"],
        json!([{
            "id": raw["roots"][0]["id"], "path": root, "role": "installation",
            "roles": ["installation", "runtime"],
        }])
    );
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        let root = &mut apps.get_mut(&id).unwrap().record.roots[0];
        root.source.as_mut().unwrap()["roles"] = json!(["config"]);
    }
    // Normalized source roles are bound by appEvidenceHash, not a display flag.
    let altered = h.tracker.software().unwrap();
    assert_eq!(altered[0]["tracked"], false);
    assert_eq!(altered[0]["roots"], json!([]));
    assert_eq!(h.tracker.performance_counters(), before);
}

#[test]
fn container_children_keep_actual_roles_and_do_not_capture_unselected_siblings() {
    let h = Harness::new();
    let base = h.root("apps");
    let parent = h.root("apps/Container");
    let child = h.root("apps/Container/Data/Saves");
    fs::write(
        parent.join("unselected-sibling"),
        b"not a whole container grant",
    )
    .unwrap();
    fs::write(child.join("slot"), b"actual save").unwrap();
    let mut plan = candidate("synthetic.container", &parent);
    let mapping = json!([{
        "kind": "reviewed_exact_product_mapping", "identifier": "synthetic.container",
        "metadataPath": null, "nativeIdentity": native_identity(&parent),
    }]);
    plan["sourceRoots"][0]["classification"] = json!("container");
    plan["sourceRoots"][0]["roles"] = json!(["container"]);
    plan["sourceRoots"][0]["ownership"] = json!("reviewed_exact_product_mapping");
    plan["sourceRoots"][0]["evidence"] = mapping.clone();
    let mut saved = plan["sourceRoots"][0].clone();
    saved["rootId"] = json!("verified-save-child");
    saved["path"] = json!(child);
    saved["nativeIdentity"] = native_identity(&child);
    saved["classification"] = json!("save");
    saved["roles"] = json!(["save"]);
    plan["sourceRoots"].as_array_mut().unwrap().push(saved);
    plan["rootsComplete"] = json!(true);
    plan["unresolvedReasons"] = json!([]);
    let initial = authority(&h, &base, &[plan.clone()], true);
    let mut scope = initial["policyScope"].clone();
    scope["baseDirectories"][0]["ownershipRules"] = json!([
        "native_installation_handle",
        "reviewed_exact_product_mapping"
    ]);
    let sealed = sign_authority(&h, scope, &[plan.clone()]);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["fileCount"], 1);
    assert_eq!(raw["roots"].as_array().unwrap().len(), 1);
    assert_eq!(raw["roots"][0]["role"], "save");
    assert_eq!(raw["bundleIndexSource"]["coverage"], "partial");
    assert_eq!(
        raw["autoEnrollment"]["unresolvedRoots"][0]["code"],
        "container_boundary_indexed_via_verified_children"
    );
    assert_eq!(
        h.tracker.file_listing(&id, None, 10).unwrap()["files"][0]["name"],
        "slot"
    );
    assert_eq!(
        fs::read(parent.join("unselected-sibling")).unwrap(),
        b"not a whole container grant"
    );
}

#[test]
fn native_installation_identity_alone_never_authorizes_guessed_data_roots() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"do not associate by display name").unwrap();
    let mut plan = candidate("synthetic.no-guessed-data", &root);
    plan["sourceRoots"][0]["classification"] = json!("data");
    plan["sourceRoots"][0]["roles"] = json!(["data"]);
    let report = materialize(&h, &base, &[plan]);
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
}

#[test]
fn full_source_identity_and_coverage_are_authenticated_not_plaintext_state_options() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"real source").unwrap();
    let mut plan = candidate("synthetic.source-identity", &root);
    let source = json!({
        "app_id": "synthetic.source-identity", "display_name": "Native source app",
        "canonical_executable": null, "desktop_entry_id": null, "steam_app_id": null,
        "launcher": "native", "aliases": [], "identity_confidence": 1.0, "icon_path": null,
    });
    plan["sourceIdentity"] = source.clone();
    let report = materialize(&h, &base, &[plan]);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["sourceIdentity"], source);
    assert_eq!(
        h.tracker.root_authority(&id).unwrap()["scope"]["sourceIdentity"],
        source
    );
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        let app = apps.get_mut(&id).unwrap();
        app.record.auto_enrollment.as_mut().unwrap().roots_complete = true;
        app.record
            .auto_enrollment
            .as_mut()
            .unwrap()
            .unresolved_reasons = json!([]);
    }
    assert!(h.tracker.bundles().unwrap().is_empty());
    assert!(h.tracker.root_authority(&id).is_err());
}

#[test]
fn explicit_permission_failures_never_become_successful_zero_count_bundles() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Restricted.app");
    fs::write(root.join("data"), b"actual bytes").unwrap();
    let plan = candidate("synthetic.permissions", &root);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    // Deterministic even under elevated CI users: inject the actual native
    // EACCES category at the root approval boundary, not OS chmod assumptions.
    h.tracker
        .shared
        .policy
        .faults
        .deny(&root, "approve_directory_identity", None, 13);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
    let diagnostic = &report["diagnostics"][0]["rootDiagnostics"][0];
    assert_eq!(diagnostic["rootId"], "native:synthetic.permissions");
    assert_eq!(diagnostic["path"], json!(root));
    assert_eq!(diagnostic["stage"], "approve_directory_identity");
    assert_eq!(diagnostic["osError"], 13);
    assert!(diagnostic["message"].as_str().unwrap().contains("13"));
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn disabling_automatic_tracking_keeps_all_data_history_and_manual_scopes() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("data"), b"automatic bytes stay").unwrap();
    let report = materialize(&h, &base, &[candidate("synthetic.disable", &root)]);
    let id = id_from(&report);
    let manifest = h.tracker.bundle_record(&id).unwrap()["bundleIndexSource"]["manifest"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let manual = h.root("manual");
    fs::write(manual.join("data"), b"manual bytes stay").unwrap();
    let manual_id = h.approve(&manual);
    h.tracker.scan_metadata(&manual_id).unwrap();
    let result = h.tracker.disable_automatic_tracking().unwrap();
    assert_eq!(result["disabled"].as_array().unwrap().len(), 1);
    assert_eq!(result["keepsVersionHistory"], true);
    assert_eq!(h.tracker.bundles().unwrap().len(), 1);
    assert!(h.tracker.root_authority(&manual_id).is_ok());
    assert!(h.tracker.root_authority(&id).is_err());
    assert!(h.tracker.shared.policy.bundle_dir().join(manifest).exists());
    assert_eq!(
        fs::read(root.join("data")).unwrap(),
        b"automatic bytes stay"
    );
    assert_eq!(fs::read(manual.join("data")).unwrap(), b"manual bytes stay");
}

fn watch_covered(tracker: &Tracker, id: &str) {
    // Injected native watcher coverage. No ambient processes or actual watches.
    tracker.shared.apps().unwrap().get_mut(id).unwrap().watch_ok = true;
    native::install_test_routes(&tracker.shared);
}

#[test]
fn original_metadata_autosave_work_remains_valid_after_receipt_without_receipt_walks() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"one").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    watch_covered(&h.tracker, &id);
    let work = {
        let mut apps = h.tracker.shared.apps().unwrap();
        let app = apps.get_mut(&id).unwrap();
        h.tracker.shared.reconcile_mode(app, false, false).unwrap();
        h.tracker
            .shared
            .prepare_upload_mode(app, "provider-a", None, true, true)
            .unwrap()
    };
    assert_eq!(
        h.tracker.verify_autosave_work(&work).unwrap()["verified"],
        true
    );
    let source = Arc::new(FixtureReceipt::capture(&h, &work));
    h.tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), source.clone())
        .unwrap();
    let validations = source.validations.load(Ordering::Acquire);
    let io = h.tracker.performance_counters();
    for _ in 0..8 {
        assert_eq!(
            h.tracker.verify_autosave_work(&work).unwrap()["verified"],
            true
        );
    }
    assert_eq!(source.validations.load(Ordering::Acquire), validations);
    assert_eq!(h.tracker.performance_counters(), io);
    h.tracker
        .verify_capture_receipt(work["workId"].as_str().unwrap())
        .unwrap();
    assert!(source.validations.load(Ordering::Acquire) > validations);
    assert_eq!(source.source_bytes_read, 3);
    h.finish(&work, true);
}

#[test]
fn reuse_epoch_is_fresh_for_restart_gap_and_watch_error_and_stable_between_confirmed_captures() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"one").unwrap();
    let id = h.approve(&root);
    let first = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    assert!(h
        .tracker
        .capture_reuse_epoch(first["workId"].as_str().unwrap())
        .unwrap()
        .is_none());
    watch_covered(&h.tracker, &id);
    let qualified = {
        let apps = h.tracker.shared.apps().unwrap();
        scan::qualified_change_stamps(
            &apps[&id].record.roots,
            apps[&id].current.as_deref().unwrap(),
        )
        .unwrap()
    };
    let first_epoch = h
        .tracker
        .capture_reuse_epoch(first["workId"].as_str().unwrap())
        .unwrap();
    assert_eq!(first_epoch.is_some(), qualified);
    accept(&h, &first);
    h.finish(&first, true);
    let second = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let second_epoch = h
        .tracker
        .capture_reuse_epoch(second["workId"].as_str().unwrap())
        .unwrap();
    assert_eq!(second_epoch, first_epoch);
    accept(&h, &second);
    h.finish(&second, true);
    let before_poll = h.tracker.performance_counters();
    h.tracker.shared.uncertain(false); // Overflow/gap; old proof partitions expire.
    assert_eq!(h.tracker.software().unwrap()[0]["dirty"], true);
    assert_eq!(h.tracker.performance_counters(), before_poll);
    let third = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let third_epoch = h
        .tracker
        .capture_reuse_epoch(third["workId"].as_str().unwrap())
        .unwrap();
    if qualified {
        assert_ne!(third_epoch, first_epoch);
    }
    native::inject_event(
        &h.tracker.shared,
        Err(notify::Error::generic("isolated native watch error")),
    );
    assert!(h
        .tracker
        .capture_reuse_epoch(third["workId"].as_str().unwrap())
        .unwrap()
        .is_none());
    h.finish(&third, false);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["pendingWork"],
        Value::Null
    );
    assert!(h.tracker.shared.apps().unwrap()[&id].baseline.is_some());
    let reopened = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    assert_ne!(
        reopened.shared.instance_nonce,
        h.tracker.shared.instance_nonce
    );
    let restarted = reopened
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    watch_covered(&reopened, &id);
    let restarted_epoch = reopened
        .capture_reuse_epoch(restarted["workId"].as_str().unwrap())
        .unwrap();
    if qualified {
        assert_ne!(restarted_epoch, first_epoch);
    }
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(reopened.performance_counters()["bytesRead"], 0);
}

#[test]
fn autosave_freezes_the_entire_manifest_not_only_changed_files() {
    let mut h = full_harness();
    let root = h.root("source");
    fs::write(root.join("changed"), b"one").unwrap();
    fs::write(
        root.join("unchanged"),
        b"must remain in latest full version",
    )
    .unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    watch_covered(&h.tracker, &id);
    let initial = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &initial);
    h.finish(&initial, true);
    let original_ids = initial["fileIds"].as_array().unwrap().clone();
    fs::write(root.join("changed"), b"updated bytes").unwrap();
    // Advance the injected worker clock, never sleep or wait for live notify.
    Arc::get_mut(&mut h.tracker.shared).unwrap().origin = Instant::now()
        .checked_sub(std::time::Duration::from_secs(30))
        .unwrap();
    let requests = native::tick(&h.tracker.shared, BTreeSet::new(), false, false);
    assert_eq!(requests.len(), 1);
    let work = &requests[0];
    assert_eq!(work["automatic"], true);
    assert_eq!(work["fileIds"], json!(original_ids));
    assert_eq!(work["captureSource"]["metadataSelection"]["nodeCount"], 2);
    assert_eq!(work["captureSource"]["selectionKind"], "full_scope");
    assert_eq!(
        work["captureSource"]["expectedFullScope"]["scope"]["baselineKind"],
        "full"
    );
    assert!(work["captureSource"].get("expectedFiles").is_none());
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn unsupported_autosave_deletion_stays_explicitly_pending_without_losing_the_baseline() {
    let mut h = Harness::new(); // No unsupported writer capability is invented.
    let root = h.root("source");
    fs::write(root.join("removed"), b"retained historical bytes").unwrap();
    fs::write(root.join("kept"), b"local bytes stay").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    watch_covered(&h.tracker, &id);
    let initial = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &initial);
    h.finish(&initial, true);
    fs::remove_file(root.join("removed")).unwrap(); // User/fixture action only.
    Arc::get_mut(&mut h.tracker.shared).unwrap().origin = Instant::now()
        .checked_sub(std::time::Duration::from_secs(30))
        .unwrap();
    let requests = native::tick(&h.tracker.shared, BTreeSet::new(), false, false);
    assert!(requests.is_empty());
    let apps = h.tracker.shared.apps().unwrap();
    assert!(apps[&id].record.dirty);
    assert!(apps[&id]
        .record
        .error
        .as_deref()
        .unwrap()
        .contains("deleted files require"));
    assert_eq!(apps[&id].baseline.as_ref().unwrap().nodes.len(), 2);
    assert_eq!(fs::read(root.join("kept")).unwrap(), b"local bytes stay");
}

#[test]
fn authenticated_immutable_old_generation_can_publish_but_newer_local_bytes_stay_dirty() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"version A").unwrap();
    let id = h.approve(&root);
    h.tracker
        .configure_autosave(&id, "provider-a", true)
        .unwrap();
    watch_covered(&h.tracker, &id);
    let initial = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &initial);
    h.finish(&initial, true);
    let confirmed = h.tracker.shared.apps().unwrap()[&id]
        .scheduler
        .last_confirmed_uploaded_generation;
    fs::write(root.join("data"), b"version B").unwrap();
    let work = {
        let mut apps = h.tracker.shared.apps().unwrap();
        let app = apps.get_mut(&id).unwrap();
        h.tracker.shared.reconcile_mode(app, false, false).unwrap();
        h.tracker
            .shared
            .prepare_upload_mode(app, "provider-a", None, true, true)
            .unwrap()
    };
    let mut prepared = FixtureReceipt::capture(&h, &work);
    prepared.immutable = true;
    let prepared = Arc::new(prepared);
    h.tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), prepared.clone())
        .unwrap();
    fs::write(root.join("data"), b"new local version C").unwrap();
    native::inject_event(
        &h.tracker.shared,
        Ok(Event::new(EventKind::Modify(ModifyKind::Any)).add_path(root.join("data"))),
    );
    let validations = prepared.validations.load(Ordering::Acquire);
    assert_eq!(
        h.tracker.verify_autosave_work(&work).unwrap()["verified"],
        true
    );
    assert_eq!(prepared.validations.load(Ordering::Acquire), validations); // No 4Hz receipt walk.
    assert_eq!(
        h.tracker
            .verify_capture_receipt(work["workId"].as_str().unwrap())
            .unwrap()["verified"],
        true
    );
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], false);
    let state = h.tracker.scan_metadata(&id).unwrap();
    assert_eq!(state["captureSource"]["changedDirty"], true);
    assert_eq!(
        state["software"]["lastConfirmedUploadedGeneration"],
        confirmed
    );
    assert_eq!(fs::read(root.join("data")).unwrap(), b"new local version C");
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn all_app_path_quota_counts_link_text_and_rejects_new_indexes_without_placeholders() {
    let h = Harness::new();
    let manual = h.root("manual");
    fs::write(manual.join("data"), b"real").unwrap();
    let manual_id = h.approve(&manual);
    h.tracker.scan_metadata(&manual_id).unwrap();
    // Logical global budget fixture; no 32 MiB paths or enormous file tree.
    h.tracker
        .shared
        .index_path_bytes
        .store(model::MAX_PATH_BYTES - 2, Ordering::Release);
    let base = h.root("apps");
    let root = h.root("apps/App.app");
    fs::write(root.join("long-name"), b"real app").unwrap();
    let report = materialize(&h, &base, &[candidate("synthetic.path-budget", &root)]);
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(h.tracker.bundles().unwrap().len(), 1);
    let mut snapshot = h.tracker.shared.apps().unwrap()[&manual_id]
        .current
        .as_ref()
        .unwrap()
        .as_ref()
        .clone();
    let node = snapshot.nodes.values_mut().next().unwrap();
    let file_stamp = node.stamp.clone().unwrap();
    node.link = Some(quicksave_platform::NativeLinkStamp {
        stamp: file_stamp,
        target: "data-target".into(),
        target_is_directory: None,
    });
    assert_eq!(
        snapshot.path_bytes().unwrap(),
        "data".len() + "data-target".len()
    );
}

#[test]
fn full_scope_evidence_uses_frozen_proof_real_root_stamps_and_authenticated_prior_nodes() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("removed"), b"old bytes").unwrap();
    fs::write(root.join("kept"), b"kept").unwrap();
    let id = h.approve(&root);
    let initial = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &initial);
    h.finish(&initial, true);
    fs::remove_file(root.join("removed")).unwrap(); // Fixture/user action only.
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let grant_count = h.store.issued_grants.load(Ordering::Acquire);
    let counters = h.tracker.performance_counters();
    let evidence = h
        .tracker
        .full_scope_evidence(work["workId"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        evidence["expectedFullScope"],
        work["captureSource"]["expectedFullScope"]
    );
    assert_eq!(evidence["authorization"], work["authorization"]);
    assert_eq!(evidence["fullScope"], true);
    assert_eq!(evidence["completeFileList"], true);
    assert_eq!(evidence["keepsVersionHistory"], true);
    assert_eq!(evidence["deletedFileIds"], work["deletedFileIds"]);
    assert_eq!(evidence["deletedNodes"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["deletedNodes"][0]["path"], "removed");
    assert_eq!(evidence["deletedNodes"][0]["kind"], "file");
    assert_eq!(
        evidence["deletedNodes"][0]["size"],
        b"old bytes".len() as u64
    );
    assert_eq!(
        evidence["deletedNodes"][0]["fileHash"],
        blake3::hash(b"old bytes").to_hex().to_string()
    );
    assert_eq!(evidence["baseline"]["kind"], "full");
    assert!(h
        .store
        .verify_grant(
            "tracking_baseline",
            &evidence["baseline"]["scope"],
            &evidence["baseline"]["reference"]["grant"]
        )
        .unwrap());
    let root_id = work["roots"][0]["id"].as_str().unwrap();
    let stamp: quicksave_platform::FileStamp =
        serde_json::from_value(evidence["rootStamps"][root_id].clone()).unwrap();
    assert_eq!(
        stamp.device,
        work["roots"][0]["identity"]["device"].as_u64().unwrap()
    );
    assert_eq!(json!(stamp.file_id), work["roots"][0]["identity"]["fileId"]);
    assert_eq!(
        evidence,
        h.tracker
            .full_scope_evidence(work["workId"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), grant_count); // No re-MAC/nonce rotation.
    assert_eq!(h.tracker.performance_counters(), counters); // No index walk or payload rehash.
    assert_eq!(fs::read(root.join("kept")).unwrap(), b"kept");
}

#[test]
fn full_scope_evidence_rejects_partial_work_missing_roots_and_revoked_original_grants() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"real").unwrap();
    let id = h.approve(&root);
    h.tracker.scan_metadata(&id).unwrap();
    let file = h.tracker.file_listing(&id, None, 1).unwrap()["files"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let selected = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", Some(&[file]))
        .unwrap();
    assert!(h
        .tracker
        .full_scope_evidence(selected["workId"].as_str().unwrap())
        .is_err());
    accept(&h, &selected);
    h.finish(&selected, true);
    let full = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let evidence = h
        .tracker
        .full_scope_evidence(full["workId"].as_str().unwrap())
        .unwrap();
    assert_eq!(evidence["baseline"]["kind"], "partial");
    fs::rename(&root, h.home.join("missing-original")).unwrap();
    assert!(h
        .tracker
        .full_scope_evidence(full["workId"].as_str().unwrap())
        .is_err());
    fs::rename(h.home.join("missing-original"), &root).unwrap();
    h.store
        .revoke_grant(
            "tracking_full_capture",
            &evidence["expectedFullScope"]["scope"],
        )
        .unwrap();
    assert!(h
        .tracker
        .full_scope_evidence(full["workId"].as_str().unwrap())
        .is_err());
}

#[test]
fn genuine_empty_full_scope_has_native_root_evidence_not_an_empty_list_permission() {
    let h = full_harness();
    let root = h.root("empty");
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let evidence = h
        .tracker
        .full_scope_evidence(work["workId"].as_str().unwrap())
        .unwrap();
    assert!(work["fileIds"].as_array().unwrap().is_empty());
    assert!(evidence["deletedNodes"].as_array().unwrap().is_empty());
    assert_eq!(evidence["roots"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["rootMetadata"].as_object().unwrap().len(), 1);
    assert_eq!(evidence["rootStamps"].as_object().unwrap().len(), 1);
    assert_eq!(evidence["baseline"]["kind"], "none");
    assert!(h
        .store
        .verify_grant(
            "tracking_full_capture",
            &evidence["expectedFullScope"]["scope"],
            &evidence["expectedFullScope"]["grant"]
        )
        .unwrap());
    let defaults = TrackingPolicy::new(h.home.join("separate-config"));
    assert!(!defaults.supports_deletion_snapshots && !defaults.supports_metadata_snapshots);
}

#[test]
fn root_timestamp_changes_cannot_be_marked_clean_even_when_file_bytes_are_unchanged() {
    let h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"unchanged bytes").unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let mut receipt = FixtureReceipt::capture(&h, &work);
    receipt.immutable = true;
    h.tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), Arc::new(receipt))
        .unwrap();
    fs::File::open(&root)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_900_000_000),
            ),
        )
        .unwrap();
    // No injected notify hint: the actual root stamp must discover this itself.
    let result = h.finish(&work, true);
    assert_eq!(result["software"]["dirty"], true);
    assert_eq!(result["software"]["lastConfirmedUploadedGeneration"], 0);
    let apps = h.tracker.shared.apps().unwrap();
    assert_ne!(
        apps[&id].current.as_ref().unwrap().root_stamps,
        apps[&id].baseline.as_ref().unwrap().root_stamps
    );
}

#[test]
fn windows_metadata_wire_retains_high_ids_raw_times_and_has_no_unix_ownership_placeholders() {
    // Portable wire/arithmetic fixture only; it does not claim Windows runtime acceptance.
    let native = json!({
        "platform":"windows", "identity":{"device":17,"fileId":[0x1122_u64,0xfedc_ba98_7654_3210_u64]},
        "kind":"file","size":5,"creationTime":116444736000000001_i64,
        "lastAccessTime":116444736000000002_i64,"lastWriteTime":116444736000000003_i64,
        "changeTime":116444736000000004_i64,"attributes":128,"linkCount":1,"reparseTag":0,
    });
    let previous: model::NativeMetadata = serde_json::from_value(native.clone()).unwrap();
    let mut next = native.clone();
    next["lastAccessTime"] = json!(116444736000000900_i64);
    let mut next: model::NativeMetadata = serde_json::from_value(next).unwrap();
    assert_eq!(previous, next);
    next.retain_read_time(Some(&previous));
    let encoded = serde_json::to_value(&next).unwrap();
    assert_eq!(encoded, native);
    assert!(
        encoded.get("owner").is_none()
            && encoded.get("group").is_none()
            && encoded.get("mode").is_none()
    );
    let model::NativeMetadata::Windows(metadata) = &next else {
        panic!("Windows wire was mistaken for Unix metadata");
    };
    let stamp = metadata.stamp().unwrap();
    assert_eq!(stamp.file_id[1], 0xfedc_ba98_7654_3210);
    assert_eq!(
        (stamp.modified_seconds, stamp.modified_nanoseconds),
        (0, 300)
    );
    assert_eq!((stamp.changed_seconds, stamp.changed_nanoseconds), (0, 400));
    next.validate("file", Some(&stamp)).unwrap();
    let mut wrong = stamp;
    wrong.file_id[1] = 0; // Never accept the old 64-bit-index approximation.
    assert!(next.validate("file", Some(&wrong)).is_err());
    let bytes = (1_u8..=16).collect::<Vec<_>>();
    let decoded = bundle::decode_windows_identity(&json!({
        "volume_serial":17,"file_id":bytes,
    }))
    .unwrap();
    assert_eq!(
        decoded.file_id,
        [0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09]
    );
}

fn saved_fixture(h: &Harness, root: &Path) -> String {
    let id = h.approve(root);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(h.scan(&id)["software"]["dirty"], false);
    id
}

#[test]
fn mark_unknown_dirty_persists_a_real_transition_without_source_io_or_authority_changes() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("data"), b"confirmed bytes").unwrap();
    let id = saved_fixture(&h, &root);
    let before = h.store.records.lock().unwrap()[&id].clone();
    let io = h.tracker.performance_counters();
    let grants = h.store.issued_grants.load(Ordering::Acquire);
    let receipt = h.tracker.mark_unknown_dirty(&id).unwrap();
    let after = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(receipt["dirty"], true);
    assert_eq!(receipt["reconciliationRequired"], true);
    assert!(
        receipt["dirtyGeneration"].as_u64().unwrap() > before["dirtyGeneration"].as_u64().unwrap()
    );
    assert_eq!(receipt["unknownGeneration"], 1);
    assert_eq!(receipt["status"], "checking");
    assert_eq!(after["dirty"], true);
    for field in [
        "roots",
        "trackingGrant",
        "autosaveGrant",
        "sourceIdentity",
        "appId",
        "providerId",
        "baseline",
        "baselineFullScope",
        "bundleIndexSource",
        "lastSavedAt",
        "lastConfirmedUploadedGeneration",
    ] {
        assert_eq!(
            after[field], before[field],
            "unknown transition changed {field}"
        );
    }
    assert_eq!(h.tracker.performance_counters(), io);
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), grants);
    let apps = h.tracker.shared.apps().unwrap();
    assert!(apps[&id].force_hash && apps[&id].scheduler.needs_reconcile);
    assert_eq!(
        apps[&id].scheduler.last_confirmed_uploaded_generation,
        before["lastConfirmedUploadedGeneration"].as_u64().unwrap()
    );
}

#[test]
fn signed_missing_and_replaced_roots_can_be_marked_unknown_without_pinning_them() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("data"), b"original native data").unwrap();
    let id = saved_fixture(&h, &root);
    let baseline = h.store.records.lock().unwrap()[&id]["baseline"].clone();
    let io = h.tracker.performance_counters();
    fs::rename(&root, h.home.join("original-root")).unwrap();
    let missing = h.tracker.mark_unknown_dirty(&id).unwrap();
    assert_eq!(missing["unknownGeneration"], 1);
    fs::create_dir(&root).unwrap();
    fs::write(root.join("data"), b"unapproved replacement").unwrap();
    let replaced = h.tracker.mark_unknown_dirty(&id).unwrap();
    assert_eq!(replaced["unknownGeneration"], 2);
    assert!(
        replaced["dirtyGeneration"].as_u64().unwrap()
            > missing["dirtyGeneration"].as_u64().unwrap()
    );
    assert_eq!(h.tracker.performance_counters(), io);
    assert_eq!(h.store.records.lock().unwrap()[&id]["baseline"], baseline);
    assert_eq!(
        fs::read(h.home.join("original-root/data")).unwrap(),
        b"original native data"
    );
    assert_eq!(
        fs::read(root.join("data")).unwrap(),
        b"unapproved replacement"
    );
    assert!(h.tracker.root_authority(&id).is_err()); // Marking unknown did not reapprove it.
}

#[test]
fn unknown_transition_rejects_unsigned_tracking_and_revoked_policy_without_fake_receipts() {
    let h = Harness::new();
    let root = h.root("manual");
    fs::write(root.join("data"), b"actual").unwrap();
    let id = saved_fixture(&h, &root);
    let before = h.store.records.lock().unwrap()[&id].clone();
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        apps.get_mut(&id).unwrap().record.tracking_grant = json!({"approved":true});
    }
    assert!(h.tracker.mark_unknown_dirty(&id).is_err());
    assert_eq!(h.store.records.lock().unwrap()[&id], before);
    let base = h.root("apps");
    let app = h.root("apps/Real.app");
    fs::write(app.join("data"), b"real application").unwrap();
    let plan = candidate("synthetic.unknown-revoked-policy", &app);
    let sealed = authority(&h, &base, &[plan.clone()], true);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    let auto = id_from(&report);
    let before_auto = h.store.records.lock().unwrap()[&auto].clone();
    h.store
        .revoke_grant("app_tracking_policy", &sealed["policyScope"])
        .unwrap();
    assert!(h.tracker.mark_unknown_dirty(&auto).is_err());
    assert_eq!(h.store.records.lock().unwrap()[&auto], before_auto);
}

#[test]
fn mark_unknown_preserves_pending_old_work_but_it_cannot_confirm_the_new_generation_saved() {
    let mut h = full_harness();
    let root = h.root("source");
    fs::write(root.join("data"), b"actual captured bytes").unwrap();
    let id = h.approve(&root);
    watch_covered(&h.tracker, &id);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let old_epoch = h
        .tracker
        .capture_reuse_epoch(work["workId"].as_str().unwrap())
        .unwrap();
    let source = trackingresume_tests::actual_committed_fixture(&h, &work);
    h.tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), source.clone())
        .unwrap();
    let io = h.tracker.performance_counters();
    let unknown = h.tracker.mark_unknown_dirty(&id).unwrap();
    assert_eq!(unknown["pendingWorkId"], work["workId"]);
    assert!(unknown["dirtyGeneration"].as_u64().unwrap() > work["generation"].as_u64().unwrap());
    assert_eq!(h.tracker.performance_counters(), io);
    assert!(h
        .tracker
        .capture_reuse_epoch(work["workId"].as_str().unwrap())
        .unwrap()
        .is_none());
    let result = h.finish(&work, true); // A drained owner can report its older immutable durable version.
    assert_eq!(result["sourceConfirmed"], false);
    assert_eq!(result["software"]["dirty"], true);
    assert_eq!(result["software"]["lastConfirmedUploadedGeneration"], 0);
    {
        let apps = h.tracker.shared.apps().unwrap();
        assert!(apps[&id].baseline.is_none());
        assert!(apps[&id].force_hash && apps[&id].scheduler.needs_reconcile);
    }
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
    let original = h
        .tracker
        .original_work(
            &id,
            work["workId"].as_str().unwrap(),
            work["generation"].as_u64().unwrap(),
            &bundle::digest(&work["authorization"]["trackingScope"]).unwrap(),
        )
        .unwrap();
    h.tracker.resume_pending(original, source).unwrap();
    let historical = h.finish(&work, true);
    assert_eq!(historical["historicalBaselineConfirmed"], true);
    assert_eq!(historical["currentGenerationConfirmed"], false);
    assert_eq!(historical["software"]["dirty"], true);
    assert_eq!(historical["software"]["lastConfirmedUploadedGeneration"], 0);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["pendingWork"],
        Value::Null
    );
    Arc::get_mut(&mut h.tracker.shared).unwrap().origin = Instant::now()
        .checked_sub(std::time::Duration::from_secs(30))
        .unwrap();
    let next = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let next_epoch = h
        .tracker
        .capture_reuse_epoch(next["workId"].as_str().unwrap())
        .unwrap();
    if old_epoch.is_some() {
        assert_ne!(old_epoch, next_epoch);
    }
}

#[test]
fn unknown_generation_counters_are_checked_before_mutating_or_persisting() {
    let h = Harness::new();
    let root = h.root("source");
    fs::write(root.join("data"), b"actual").unwrap();
    let id = saved_fixture(&h, &root);
    let before = h.store.records.lock().unwrap()[&id].clone();
    let epoch = h.tracker.shared.apps().unwrap()[&id]
        .event_epoch
        .load(Ordering::Acquire);
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        apps.get_mut(&id).unwrap().record.unknown_generation = u64::MAX;
    }
    assert!(h.tracker.mark_unknown_dirty(&id).is_err());
    assert_eq!(h.store.records.lock().unwrap()[&id], before);
    assert_eq!(
        h.tracker.shared.apps().unwrap()[&id]
            .event_epoch
            .load(Ordering::Acquire),
        epoch
    );
}

#[test]
fn frozen_native_index_reuses_actual_metadata_arc_and_never_issues_capture_or_saved_proofs() {
    let h = full_harness();
    let base = h.root("apps");
    let root = h.root("apps/Actual.app");
    fs::write(root.join("binary"), b"real unscanned executable").unwrap();
    fs::create_dir(root.join("empty-directory")).unwrap();
    std::os::unix::fs::symlink("binary", root.join("relative-link")).unwrap();
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.installation.instance",
            "desktop:ExactCase.desktop",
            &root,
        )],
    );
    let id = id_from(&report);
    let before_record = h.store.records.lock().unwrap()[&id].clone();
    let before_io = h.tracker.performance_counters();
    let before_grants = h.store.issued_grants.load(Ordering::Acquire);
    let references = {
        let apps = h.tracker.shared.apps().unwrap();
        Arc::strong_count(apps[&id].current.as_ref().unwrap())
    };
    let frozen = h.tracker.freeze_metadata_index(&id).unwrap();
    let repeated = h.tracker.freeze_metadata_index(&id).unwrap();
    assert!(Arc::ptr_eq(&frozen, &repeated));
    {
        let apps = h.tracker.shared.apps().unwrap();
        assert_eq!(
            Arc::strong_count(apps[&id].current.as_ref().unwrap()),
            references + 1
        );
        assert!(apps[&id].scheduler.needs_reconcile && apps[&id].force_hash);
        assert!(apps[&id].pending.is_none() && apps[&id].baseline.is_none());
    }
    let header = frozen.header().unwrap();
    assert_eq!(header["softwareId"], id);
    assert_eq!(header["appId"], "desktop:ExactCase.desktop");
    assert_eq!(header["instanceId"], "synthetic.installation.instance");
    assert_eq!(
        header["revisionId"],
        before_record["bundleIndexSource"]["revisionId"]
    );
    assert_eq!(
        header["snapshotIdentity"],
        before_record["bundleIndexSource"]["snapshotIdentity"]
    );
    assert_eq!(
        header["trackingScopeHash"],
        before_record["bundleIndexSource"]["trackingScopeHash"]
    );
    assert_eq!(header["nodeCount"], 3);
    assert_eq!(header["metadataOnly"], true);
    assert_eq!(header["fileStateTrust"], "VERIFY_REQUIRED");
    assert_eq!(header["reconciliationRequired"], true);
    assert_eq!(header["saved"], false);
    assert_eq!(header["coverageTrusted"], false);
    let page = frozen.node_page(0, 500).unwrap();
    assert_eq!(page["nextOffset"], Value::Null);
    let nodes = page["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3);
    for node in nodes {
        let apps = h.tracker.shared.apps().unwrap();
        let actual = &apps[&id].current.as_ref().unwrap().nodes[node["id"].as_str().unwrap()];
        assert_eq!(
            node,
            &receipt::indexed_metadata_node(node["id"].as_str().unwrap(), actual).unwrap()
        );
        let stamp: quicksave_platform::FileStamp =
            serde_json::from_value(node["stamp"].clone()).unwrap();
        assert_eq!(Some(&stamp), actual.stamp.as_ref());
        assert_eq!(node["rootId"], actual.root_id);
        assert_eq!(node["path"], actual.path);
        assert!(node.get("fileHash").is_none());
    }
    assert_eq!(h.tracker.performance_counters(), before_io);
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), before_grants);
    assert_eq!(h.store.records.lock().unwrap()[&id], before_record);

    // Explicit preparation may reconcile metadata/create capture authority.
    // The frozen index itself must not do either, and its wire shape is shared.
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let prepared = h
        .tracker
        .prepared_node_listing(work["workId"].as_str().unwrap(), None, 500)
        .unwrap();
    assert_eq!(
        frozen.node_page(0, 500).unwrap()["nodes"],
        prepared["nodes"]
    );
    assert!(Arc::ptr_eq(
        &frozen,
        &h.tracker.freeze_metadata_index(&id).unwrap()
    ));
}

#[test]
fn frozen_native_index_pages_use_sparse_checkpoints_and_exact_terminal_bounds() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Paged.app");
    for number in 0..1003 {
        fs::write(root.join(format!("node-{number:04}")), b"metadata only").unwrap();
    }
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.paged",
            "native:canonical-paged",
            &root,
        )],
    );
    let id = id_from(&report);
    let before = h.tracker.performance_counters();
    let frozen = h.tracker.freeze_metadata_index(&id).unwrap();
    let expected = {
        let apps = h.tracker.shared.apps().unwrap();
        let snapshot = apps[&id].current.as_ref().unwrap();
        receipt::expected_metadata(&snapshot.nodes.keys().cloned().collect(), snapshot).unwrap()
    };
    for offset in [0, 1, 499, 500, 501, 998, 1000, 1003] {
        for limit in [1, 257, 500] {
            let page = frozen.node_page(offset, limit).unwrap();
            let end = (offset + limit).min(1003);
            assert_eq!(
                page["nodes"],
                json!(&expected.as_array().unwrap()[offset..end])
            );
            assert_eq!(page["offset"], offset);
            assert_eq!(page["nodeCount"], 1003);
            assert_eq!(
                page["nextOffset"],
                if end < 1003 { json!(end) } else { Value::Null }
            );
        }
    }
    assert!(frozen.node_page(0, 0).is_err());
    assert!(frozen.node_page(0, 501).is_err());
    assert!(frozen.node_page(1004, 1).is_err());
    assert!(frozen.node_page(usize::MAX, 1).is_err());
    assert_eq!(h.tracker.performance_counters(), before);
    assert_eq!(before["filesHashed"], 0);
}

#[test]
fn frozen_startup_or_unknown_index_is_always_verify_required_and_keeps_confirmed_history() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Restarted.app");
    fs::write(root.join("data"), b"actually captured old baseline").unwrap();
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.restart",
            "native:canonical-restart",
            &root,
        )],
    );
    let id = id_from(&report);
    let work = h.tracker.begin_upload(&id, "provider-a", None).unwrap();
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(h.scan(&id)["software"]["dirty"], false);
    let saved = h.store.records.lock().unwrap()[&id].clone();
    let restarted = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    let before = restarted.performance_counters();
    let grants = h.store.issued_grants.load(Ordering::Acquire);
    let index = restarted.freeze_metadata_index(&id).unwrap();
    assert_eq!(index.header().unwrap()["fileStateTrust"], "VERIFY_REQUIRED");
    assert_eq!(index.header().unwrap()["reconciliationRequired"], true);
    assert_eq!(index.header().unwrap()["saved"], false);
    assert!(index.node_page(0, 500).unwrap()["nodes"][0]
        .get("fileHash")
        .is_none());
    restarted.mark_unknown_dirty(&id).unwrap();
    index.revalidate().unwrap(); // Authentic cached metadata, NOT current-content trust.
    fs::rename(&root, h.home.join("temporarily-unavailable")).unwrap();
    // Reading immutable cached metadata does not open a source path. The
    // parent's separate source/root authority guard must still reject absence.
    assert_eq!(
        index.node_page(0, 500).unwrap()["nodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(restarted.root_authority(&id).is_err());
    assert_eq!(restarted.performance_counters(), before);
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), grants);
    let actual = h.store.records.lock().unwrap()[&id].clone();
    assert_eq!(actual["baseline"], saved["baseline"]);
    assert_eq!(
        actual["lastConfirmedUploadedGeneration"],
        saved["lastConfirmedUploadedGeneration"]
    );
    assert_eq!(actual["dirty"], true);
    assert_eq!(restarted.software().unwrap()[0]["dirty"], true);
}

#[test]
fn frozen_native_index_rejects_changed_revisions_and_original_mac_revocation() {
    for kind in ["tracking", "app_tracking_policy", "bundle_manifest"] {
        let h = Harness::new();
        let base = h.root("apps");
        let root = h.root("apps/Revoked.app");
        fs::write(root.join("data"), b"real native metadata").unwrap();
        let report = materialize(
            &h,
            &base,
            &[indexed_candidate(
                "synthetic.revoked",
                "native:canonical-revoked",
                &root,
            )],
        );
        let id = id_from(&report);
        let frozen = h.tracker.freeze_metadata_index(&id).unwrap();
        let scope = {
            let apps = h.tracker.shared.apps().unwrap();
            let record = &apps[&id].record;
            match kind {
                "tracking" => record.tracking_scope(),
                "app_tracking_policy" => record
                    .auto_enrollment
                    .as_ref()
                    .unwrap()
                    .policy_scope
                    .clone(),
                _ => record
                    .bundle_index_source
                    .as_ref()
                    .unwrap()
                    .certificate(record)["scope"]
                    .clone(),
            }
        };
        let before = h.tracker.performance_counters();
        let grants = h.store.issued_grants.load(Ordering::Acquire);
        h.store.revoke_grant(kind, &scope).unwrap();
        let failure = frozen.revalidate().unwrap_err();
        assert!(
            !failure.is::<crate::MetadataIndexRevisionChanged>(),
            "revoked {kind} must not be classified as an ordinary revision race"
        );
        assert!(frozen.header().is_err());
        assert!(frozen.node_page(0, 1).is_err());
        assert!(h.tracker.freeze_metadata_index(&id).is_err());
        assert_eq!(h.tracker.performance_counters(), before);
        assert_eq!(h.store.issued_grants.load(Ordering::Acquire), grants);
    }
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Changed.app");
    fs::write(root.join("data"), b"old").unwrap();
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.changed",
            "native:canonical-changed",
            &root,
        )],
    );
    let id = id_from(&report);
    let old = h.tracker.freeze_metadata_index(&id).unwrap();
    let header = old.header().unwrap();
    fs::write(root.join("data"), b"actually changed native file").unwrap();
    h.tracker.scan_metadata(&id).unwrap();
    assert!(old
        .header()
        .unwrap_err()
        .is::<crate::MetadataIndexRevisionChanged>());
    let current = h.tracker.freeze_metadata_index(&id).unwrap();
    assert_ne!(
        current.header().unwrap()["revisionId"],
        header["revisionId"]
    );
    assert_eq!(
        current.node_page(0, 1).unwrap()["nodes"][0]["size"],
        b"actually changed native file".len() as u64
    );
    h.tracker.shutdown().unwrap();
    assert!(current.revalidate().is_err());
    assert!(current.node_page(0, 1).is_err());
}

#[test]
fn native_index_refuses_placeholders_missing_canonical_identity_and_unsigned_leaf_widening() {
    let h = Harness::new();
    let root = h.root("manual");
    fs::write(root.join("chosen"), b"chosen file").unwrap();
    fs::write(root.join("other"), b"never approved").unwrap();
    let id = h.approve(&root);
    assert!(h.tracker.freeze_metadata_index(&id).is_err()); // No actual index yet.
    h.tracker.scan_metadata(&id).unwrap();
    assert!(h.tracker.freeze_metadata_index(&id).is_err()); // No canonical source ID.
    let unconfirmed = h
        .tracker
        .approve_software(&json!({
            "name": "Unconfirmed native identity", "appId": "synthetic.unconfirmed",
            "sourceIdentity": {"app_id": "quicksave.observed:unconfirmed"},
            "roots": [{"path": root, "role": "manual"}],
        }))
        .unwrap();
    let unconfirmed = unconfirmed["id"].as_str().unwrap();
    h.tracker.scan_metadata(unconfirmed).unwrap();
    assert!(h.tracker.freeze_metadata_index(unconfirmed).is_err());
    let approved = h
        .tracker
        .approve_software(&json!({
            "name":"Native selected file", "appId":"synthetic.selected.instance",
            "sourceIdentity":{"app_id":"native:canonical-selected"},
            "roots":[{"path":root,"role":"config","allowedFiles":["chosen"]}],
        }))
        .unwrap();
    let selected = approved["id"].as_str().unwrap();
    h.tracker.scan_metadata(selected).unwrap();
    let frozen = h.tracker.freeze_metadata_index(selected).unwrap();
    assert_eq!(frozen.header().unwrap()["nodeCount"], 1);
    assert_eq!(
        frozen.node_page(0, 500).unwrap()["nodes"][0]["path"],
        "chosen"
    );
    {
        let mut apps = h.tracker.shared.apps().unwrap();
        apps.get_mut(selected).unwrap().record.roots[0]
            .allowed_files
            .as_mut()
            .unwrap()
            .insert("other".into());
    }
    let before = h.tracker.performance_counters();
    assert!(frozen.revalidate().is_err());
    assert!(h.tracker.freeze_metadata_index(selected).is_err());
    assert_eq!(h.tracker.performance_counters(), before);
}

#[test]
fn genuine_empty_native_index_has_actual_root_evidence_and_a_terminal_zero_node_page() {
    let h = Harness::new();
    let base = h.root("apps");
    let root = h.root("apps/Empty.app");
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.empty.index",
            "native:canonical-empty",
            &root,
        )],
    );
    let id = id_from(&report);
    let before = h.tracker.performance_counters();
    let frozen = h.tracker.freeze_metadata_index(&id).unwrap();
    assert_eq!(frozen.header().unwrap()["nodeCount"], 0);
    assert_eq!(frozen.header().unwrap()["saved"], false);
    let page = frozen.node_page(0, 500).unwrap();
    assert_eq!(page["nodes"], json!([]));
    assert_eq!(page["nextOffset"], Value::Null);
    assert!(frozen.node_page(1, 1).is_err());
    let apps = h.tracker.shared.apps().unwrap();
    let current = apps[&id].current.as_ref().unwrap();
    assert_eq!(current.root_metadata.len(), 1);
    assert_eq!(current.root_stamps.len(), 1);
    assert_eq!(h.tracker.performance_counters(), before);
}

struct CompletionEvidenceOnce {
    actual: FixtureReceipt,
    evidence_calls: AtomicUsize,
}

impl NativeCaptureReceipt for CompletionEvidenceOnce {
    fn evidence(&self) -> Result<Value> {
        ensure!(
            self.evidence_calls.fetch_add(1, Ordering::AcqRel) == 0,
            "full source evidence must not be requested at finalization"
        );
        self.actual.evidence()
    }
    fn revalidate(&self) -> Result<()> {
        self.actual.revalidate()
    }
    fn immutable_prepared_capture(&self) -> bool {
        true
    }
}

#[test]
fn capture_completion_binding_is_native_compact_original_and_never_reloads_full_evidence() {
    let h = full_harness();
    let base = h.root("apps");
    let root = h.root("apps/Completion.app");
    fs::write(root.join("data"), b"actually prepared old bytes").unwrap();
    let report = materialize(
        &h,
        &base,
        &[indexed_candidate(
            "synthetic.completion.instance",
            "desktop:ExactCase.desktop",
            &root,
        )],
    );
    let id = id_from(&report);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    assert!(h
        .tracker
        .capture_completion_binding(work["workId"].as_str().unwrap())
        .is_err());
    let mut actual = FixtureReceipt::capture(&h, &work);
    actual.immutable = true;
    let receipt = Arc::new(CompletionEvidenceOnce {
        actual,
        evidence_calls: AtomicUsize::new(0),
    });
    let accepted = h
        .tracker
        .accept_capture_receipt(work["workId"].as_str().unwrap(), receipt.clone())
        .unwrap();
    let before = h.tracker.performance_counters();
    fs::write(root.join("data"), b"new local bytes remain dirty").unwrap();
    h.tracker.mark_unknown_dirty(&id).unwrap();
    for _ in 0..3 {
        let binding = h
            .tracker
            .capture_completion_binding(work["workId"].as_str().unwrap())
            .unwrap();
        assert_eq!(binding["softwareId"], id);
        assert_eq!(binding["appId"], "desktop:ExactCase.desktop");
        assert_eq!(
            binding["softwareInstanceId"],
            "synthetic.completion.instance"
        );
        assert_eq!(binding["providerId"], "provider-a");
        assert_eq!(binding["workId"], work["workId"]);
        assert_eq!(binding["generation"], work["generation"]);
        assert_eq!(
            binding["metadataIdentity"],
            work["captureSource"]["snapshotIdentity"]
        );
        assert_eq!(
            binding["sourceExpectedManifestAuth"],
            accepted["captureSource"]["sourceExpectedManifestAuth"]
        );
        assert_eq!(
            binding["captureReceipt"]["scope"],
            accepted["captureSource"]["captureReceipt"]["scope"]
        );
        assert!(binding["captureReceipt"].get("reference").is_none());
        assert!(binding.get("verified").is_none()); // Must still pass actual engine COMMITTED proof.
        model::bounded_serialized(&binding, 128 * 1024).unwrap();
    }
    assert_eq!(receipt.evidence_calls.load(Ordering::Acquire), 1);
    assert_eq!(h.tracker.performance_counters(), before);
    assert_eq!(h.tracker.software().unwrap()[0]["dirty"], true);
}

#[test]
fn capture_completion_binding_rejects_tampered_cache_reference_mac_and_provider_authority() {
    for failure in [
        "envelope",
        "sidecar_hash",
        "sidecar_mac",
        "capture_mac",
        "capture_revoked",
        "provider",
        "tracking",
    ] {
        let h = full_harness();
        let base = h.root("apps");
        let root = h.root("apps/Bound.app");
        fs::write(root.join("data"), b"real source").unwrap();
        let report = materialize(
            &h,
            &base,
            &[indexed_candidate(
                "synthetic.bound",
                "native:canonical-bound",
                &root,
            )],
        );
        let id = id_from(&report);
        let work = h
            .tracker
            .prepare_upload_scope(&id, "provider-a", None)
            .unwrap();
        accept(&h, &work);
        let before = h.tracker.performance_counters();
        match failure {
            "provider" => {
                h.tracker.set_provider(&id, Some("provider-b")).unwrap();
            }
            "tracking" => h
                .store
                .revoke_grant("tracking", &work["authorization"]["trackingScope"])
                .unwrap(),
            "capture_revoked" => {
                let scope = h.tracker.shared.apps().unwrap()[&id]
                    .pending
                    .as_ref()
                    .unwrap()
                    .receipt_evidence
                    .as_ref()
                    .unwrap()["scope"]
                    .clone();
                h.store
                    .revoke_grant("tracking_capture_receipt", &scope)
                    .unwrap();
            }
            _ => {
                let mut apps = h.tracker.shared.apps().unwrap();
                let pending = apps.get_mut(&id).unwrap().pending.as_mut().unwrap();
                match failure {
                    "envelope" => {
                        pending.source_expected_manifest_auth.as_mut().unwrap()["forged"] =
                            json!(true)
                    }
                    "sidecar_hash" => {
                        pending.receipt_evidence.as_mut().unwrap()["reference"]["hash"] =
                            json!("0".repeat(64))
                    }
                    "sidecar_mac" => {
                        pending.receipt_evidence.as_mut().unwrap()["reference"]["grant"] =
                            json!({"completed":true})
                    }
                    _ => {
                        pending.receipt_evidence.as_mut().unwrap()["grant"] =
                            json!({"completed":true})
                    }
                }
            }
        }
        assert!(
            h.tracker
                .capture_completion_binding(work["workId"].as_str().unwrap())
                .is_err(),
            "accepted invalid completion binding: {failure}"
        );
        assert_eq!(h.tracker.performance_counters(), before);
    }
}

#[derive(Debug, Default)]
struct ControlledTrackingClock(AtomicU64);
impl TrackingClock for ControlledTrackingClock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

#[test]
fn frozen_native_clock_isolates_cached_polls_without_disabling_required_source_reconciliation() {
    let mut h = Harness::new();
    let clock = Arc::new(ControlledTrackingClock::default());
    let shared = Arc::get_mut(&mut h.tracker.shared).unwrap();
    shared.policy = shared.policy.clone().with_clock(clock.clone());
    let root = h.root("source");
    fs::write(root.join("data"), b"real metadata").unwrap();
    let id = h.approve(&root);
    h.tracker.scan_metadata(&id).unwrap();
    // Model the real initial watch-registration coverage gap. It must require
    // an audit, not silently treat an already indexed root as observed clean.
    h.tracker
        .shared
        .apps()
        .unwrap()
        .get_mut(&id)
        .unwrap()
        .scheduler
        .require_reconcile();
    let before = h.tracker.performance_counters();
    for _ in 0..20 {
        h.tracker.software().unwrap();
        h.tracker.file_listing(&id, None, 10).unwrap();
        assert!(native::tick(&h.tracker.shared, BTreeSet::new(), false, false).is_empty());
    }
    assert_eq!(h.tracker.performance_counters(), before);
    assert!(
        h.tracker.shared.apps().unwrap()[&id]
            .scheduler
            .needs_reconcile
    );
    clock.0.store(scheduler::QUIET_MS, Ordering::Release);
    assert!(native::tick(&h.tracker.shared, BTreeSet::new(), false, false).is_empty());
    assert_eq!(
        h.tracker.performance_counters()["fsWalks"]
            .as_u64()
            .unwrap(),
        before["fsWalks"].as_u64().unwrap() + 2
    );
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    assert!(
        !h.tracker.shared.apps().unwrap()[&id]
            .scheduler
            .needs_reconcile
    );
    h.tracker.shared.uncertain(false);
    assert_eq!(h.tracker.software().unwrap()[0]["dirty"], true);
    assert!(
        h.tracker.shared.apps().unwrap()[&id]
            .scheduler
            .needs_reconcile
    );
}
