// SPDX-License-Identifier: GPL-3.0-only
//! Only isolated files and native-boundary fault injection; no ambient apps,
//! production vaults/providers, OS permission changes outside the test root,
//! or dependence on whether the test runner can bypass mode bits.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn two_root_plan(app: &str, first: &Path, second: &Path) -> Value {
    let mut plan = indexed_candidate(app, app, first);
    let mut other = candidate(app, second)["sourceRoots"][0].clone();
    other["rootId"] = json!("native:independent-second-root");
    plan["sourceRoots"].as_array_mut().unwrap().push(other);
    plan["rootsComplete"] = json!(true);
    plan["unresolvedReasons"] = json!([]);
    plan
}

fn assert_prior_authority_and_baseline(h: &Harness, id: &str, before: &Value) {
    let after = h.store.records.lock().unwrap()[id].clone();
    for field in [
        "roots",
        "trackingGrant",
        "autosaveGrant",
        "baseline",
        "baselineFullScope",
        "bundleIndexSource",
        "autoEnrollment",
        "captureReceipt",
        "pendingWork",
        "lastSavedAt",
        "lastConfirmedUploadedGeneration",
        "fileCount",
        "logicalBytes",
    ] {
        assert_eq!(after[field], before[field], "refresh altered {field}");
    }
    let apps = h.tracker.shared.apps().unwrap();
    let record = &apps[id].record;
    assert!(h
        .store
        .verify_grant("tracking", &record.tracking_scope(), &record.tracking_grant)
        .unwrap());
    record
        .bundle_index_source
        .as_ref()
        .unwrap()
        .verify_reference_grants(&record.tracking_scope(), h.store.as_ref())
        .unwrap();
    let baseline = record.baseline.as_ref().unwrap();
    assert!(h
        .store
        .verify_grant(
            "tracking_baseline",
            &record.baseline_scope(&baseline.name, &baseline.hash),
            &baseline.grant
        )
        .unwrap());
}

#[test]
fn unavailable_child_discards_its_entire_root_not_just_unknown_files() {
    let h = full_harness();
    let base = h.root("apps");
    let good = h.root("apps/Good.app");
    let failed = h.root("apps/Failed.app");
    fs::write(good.join("kept"), b"independently indexed bytes").unwrap();
    fs::write(
        failed.join("first-enumerated"),
        b"must not leak out as a partial subtree",
    )
    .unwrap();
    fs::write(failed.join("zz-blocked"), b"unknown metadata fixture").unwrap();
    let plan = two_root_plan("synthetic.root-partial", &good, &failed);
    h.tracker
        .shared
        .policy
        .faults
        .deny(&failed, "read_required_metadata", Some("zz-blocked"), 13);
    let report = materialize(&h, &base, std::slice::from_ref(&plan));
    assert_eq!(report["bundles"].as_array().unwrap().len(), 1);
    assert_eq!(report["partialBundles"], 1);
    assert_eq!(report["incomplete"], true);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "bundle_materialization_partial"
    );
    let diagnostic = &report["diagnostics"][0]["rootDiagnostics"][0];
    assert_eq!(diagnostic["path"], json!(failed));
    assert_eq!(diagnostic["stage"], "read_required_metadata");
    assert_eq!(diagnostic["relativePath"], "zz-blocked");
    assert_eq!(diagnostic["osError"], 13);
    assert_eq!(diagnostic["preventsFullScopeCapture"], true);
    assert!(diagnostic["message"].as_str().unwrap().contains("13"));
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["roots"].as_array().unwrap().len(), 1);
    assert_eq!(raw["roots"][0]["path"], json!(good));
    assert_eq!(raw["fileCount"], 1);
    assert_eq!(
        raw["logicalBytes"],
        b"independently indexed bytes".len() as u64
    );
    assert_eq!(raw["autoEnrollment"]["rootsComplete"], false);
    assert_eq!(raw["autoEnrollment"]["unresolvedRoots"][0], *diagnostic);
    assert_eq!(raw["bundleIndexSource"]["coverage"], "partial");
    assert_eq!(raw["baselineFullScope"], false);
    assert_eq!(raw["baseline"], Value::Null);
    assert_eq!(raw["lastSavedAt"], Value::Null);
    let page = h.tracker.file_listing(&id, None, 10).unwrap();
    assert_eq!(page["files"].as_array().unwrap().len(), 1);
    assert_eq!(page["files"][0]["path"], "kept");
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    let index = h.tracker.freeze_metadata_index(&id).unwrap();
    assert_eq!(index.header().unwrap()["saved"], false);
    assert_eq!(index.header().unwrap()["complete"], false);
    assert_eq!(
        index.header().unwrap()["payloadReadability"],
        "not_established"
    );

    // No additive full head/omission authority can be minted after losing a
    // known root. An explicitly selected custom partial capture still works.
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
    let status = &h.tracker.software().unwrap()[0];
    assert_eq!(status["fullScopeCaptureBlocked"], true);
    assert_ne!(status["status"], "saved");
    assert!(status["error"].as_str().unwrap().contains("13"));
    let selected = vec![page["files"][0]["id"].as_str().unwrap().to_owned()];
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", Some(&selected))
        .unwrap();
    assert_eq!(work["captureSource"]["selectionKind"], "selected_nodes");
    assert_eq!(work["captureSource"]["expectedFullScope"], Value::Null);
    assert!(h
        .tracker
        .full_scope_evidence(work["workId"].as_str().unwrap())
        .is_err());
    accept(&h, &work);
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["baselineFullScope"],
        false
    );
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["lastConfirmedUploadedGeneration"],
        0
    );
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["lastSavedAt"],
        Value::Null
    );

    // A genuine successful retry—not ignoring the denial or rewriting its
    // evidence—is required before the complete root set may return.
    h.tracker.shared.policy.faults.clear();
    let retry = materialize(&h, &base, &[plan]);
    assert!(retry["diagnostics"].as_array().unwrap().is_empty());
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["roots"].as_array().unwrap().len(), 2);
    assert_eq!(raw["fileCount"], 3);
    assert_eq!(raw["bundleIndexSource"]["coverage"], "complete");
    assert_eq!(raw["autoEnrollment"]["unresolvedRoots"], json!([]));
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn root_preparation_eacces_retains_only_independent_roots_and_never_guesses_authority() {
    let h = Harness::new();
    let base = h.root("apps");
    let good = h.root("apps/Good.app");
    let failed = h.root("apps/Denied.app");
    fs::write(good.join("one"), b"one").unwrap();
    fs::write(failed.join("two"), b"two").unwrap();
    let plan = two_root_plan("synthetic.prepare-partial", &good, &failed);
    h.tracker
        .shared
        .policy
        .faults
        .deny(&failed, "approve_directory_identity", None, 13);
    let report = materialize(&h, &base, &[plan]);
    let id = id_from(&report);
    assert_eq!(
        report["diagnostics"][0]["rootDiagnostics"][0]["stage"],
        "approve_directory_identity"
    );
    assert_eq!(
        report["diagnostics"][0]["rootDiagnostics"][0]["rootId"],
        "native:independent-second-root"
    );
    assert_eq!(
        h.tracker.bundle_record(&id).unwrap()["roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A syntactically valid but ungranted role must fail before an injected
    // availability error, not become a way to skip policy validation.
    let mut denied_policy = two_root_plan("synthetic.policy-not-availability", &good, &failed);
    denied_policy["sourceRoots"][1]["classification"] = json!("data");
    denied_policy["sourceRoots"][1]["roles"] = json!(["data"]);
    let report = materialize(&h, &base, &[denied_policy]);
    assert!(report["bundles"].as_array().unwrap().is_empty());
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("ownership"));
    assert_eq!(h.tracker.bundles().unwrap().len(), 1);
}

#[test]
fn failed_refresh_keeps_original_index_roots_baseline_and_grants() {
    let h = full_harness();
    let base = h.root("apps");
    let first = h.root("apps/First.app");
    let second = h.root("apps/Second.app");
    fs::write(first.join("first"), b"first actual source").unwrap();
    fs::write(second.join("second"), b"second actual source").unwrap();
    let plan = two_root_plan("synthetic.refresh-failure", &first, &second);
    let report = materialize(&h, &base, std::slice::from_ref(&plan));
    let id = id_from(&report);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    accept(&h, &work);
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    let before = h.store.records.lock().unwrap()[&id].clone();
    assert!(before["baseline"].is_object());
    let (current, baseline) = {
        let apps = h.tracker.shared.apps().unwrap();
        (
            apps[&id].current.as_ref().unwrap().clone(),
            apps[&id].baseline.as_ref().unwrap().clone(),
        )
    };
    let initial_issues = h.store.issued_grants.load(Ordering::Acquire);
    let sealed = authority(&h, &base, std::slice::from_ref(&plan), true);
    let after_attestation = h.store.issued_grants.load(Ordering::Acquire);
    assert_eq!(after_attestation, initial_issues + 2);
    h.tracker
        .shared
        .policy
        .faults
        .deny(&second, "read_required_metadata", Some("second"), 13);
    let failed = h
        .tracker
        .materialize_bundles(std::slice::from_ref(&plan), &sealed)
        .unwrap();
    assert!(failed["bundles"].as_array().unwrap().is_empty());
    assert_eq!(
        failed["diagnostics"][0]["rootDiagnostics"][0]["path"],
        json!(second)
    );
    assert_eq!(
        h.store.issued_grants.load(Ordering::Acquire),
        after_attestation
    );
    assert_prior_authority_and_baseline(&h, &id, &before);
    {
        let apps = h.tracker.shared.apps().unwrap();
        assert!(Arc::ptr_eq(&current, apps[&id].current.as_ref().unwrap()));
        assert!(Arc::ptr_eq(&baseline, apps[&id].baseline.as_ref().unwrap()));
    }

    // Also exercise the noncached candidate path and a failure before scanning.
    h.tracker.shared.policy.faults.clear();
    h.tracker
        .shared
        .policy
        .faults
        .deny(&second, "approve_directory_identity", None, 13);
    let mut changed = plan;
    changed["displayName"] = json!("New authenticated discovery report");
    let sealed = authority(&h, &base, &[changed.clone()], true);
    let before_issues = h.store.issued_grants.load(Ordering::Acquire);
    let failed = h.tracker.materialize_bundles(&[changed], &sealed).unwrap();
    assert!(failed["bundles"].as_array().unwrap().is_empty());
    assert_eq!(
        failed["diagnostics"][0]["rootDiagnostics"][0]["stage"],
        "approve_directory_identity"
    );
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), before_issues);
    assert_prior_authority_and_baseline(&h, &id, &before);
}

#[test]
fn chmod_zero_regular_payload_is_metadata_only_not_readability_or_saved_proof() {
    for manual in [false, true] {
        let mut h = full_harness();
        let clock = Arc::new(ControlledTrackingClock(AtomicU64::new(0)));
        Arc::get_mut(&mut h.tracker.shared).unwrap().policy.clock = Some(clock.clone());
        let root = h.root("source");
        let name = "data:literal\\name";
        let path = root.join(name);
        let bytes = b"actual denied payload, not a metadata hash";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Only payload access is denied. Metadata succeeds even if the runner
        // can otherwise bypass mode bits; capture denial remains deterministic.
        h.tracker
            .shared
            .policy
            .faults
            .deny(&root, "open_payload", Some(name), 13);
        let input = json!({
            "appId":"synthetic.unreadable","name":"Metadata-only permission fixture",
            "providerId":"provider-a","roots":[{
                "path":root,"role":"save",
                "allowedFiles":if manual {json!([name])} else {Value::Null},
            }],
        });
        let mut input = input;
        if !manual {
            input["roots"][0]
                .as_object_mut()
                .unwrap()
                .remove("allowedFiles");
        }
        let approval = h.tracker.approve_software(&input).unwrap();
        let id = approval["id"].as_str().unwrap();
        let metadata = h.tracker.scan_metadata(id).unwrap();
        assert_eq!(
            metadata["captureSource"]["payloadReadability"],
            "not_established"
        );
        assert_eq!(
            metadata["captureSource"]["contentState"],
            "metadata_indexed_unknown_content"
        );
        let snapshot = h.tracker.shared.apps().unwrap()[id]
            .current
            .as_ref()
            .unwrap()
            .clone();
        assert!(!snapshot.content_captured && !snapshot.content_verified());
        assert_eq!(snapshot.nodes.len(), 1);
        let node = snapshot.nodes.values().next().unwrap();
        assert_eq!(node.path, name);
        assert_eq!(node.size, bytes.len() as u64);
        assert!(node.hash.is_none());
        let model::NativeMetadata::Unix(native) = node.metadata.as_ref().unwrap() else {
            panic!("Unix fixture")
        };
        assert_eq!(native.mode & 0o777, 0);
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
        let error = h.tracker.scan(id).unwrap_err();
        let diagnostic = diagnostics::root_failure(&error).unwrap();
        assert_eq!(diagnostic["stage"], "open_payload");
        assert_eq!(diagnostic["relativePath"], name);
        assert_eq!(diagnostic["osError"], 13);
        assert!(h.tracker.begin_upload(id, "provider-a", None).is_err());
        // The real failed payload attempts correctly enter retry backoff. Move
        // only the fixture's monotonic clock; never remove the production gate.
        clock.0.store(10_000, Ordering::Release);
        let prepared = h
            .tracker
            .prepare_upload_scope(id, "provider-a", None)
            .unwrap();
        assert_eq!(
            prepared["captureSource"]["stage"],
            "awaiting_native_capture_receipt"
        );
        assert_eq!(h.finish(&prepared, true)["sourceConfirmed"], false);
        let raw = h.store.records.lock().unwrap()[id].clone();
        assert_eq!(raw["baseline"], Value::Null);
        assert_eq!(raw["lastSavedAt"], Value::Null);
        assert_eq!(raw["lastConfirmedUploadedGeneration"], 0);
        assert_ne!(raw["status"], "saved");
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        h.tracker.shared.policy.faults.clear();
        h.tracker.scan(id).unwrap();
        let current = h.tracker.shared.apps().unwrap()[id]
            .current
            .as_ref()
            .unwrap()
            .clone();
        let actual_hash = blake3::hash(bytes).to_hex().to_string();
        assert_eq!(
            current.nodes.values().next().unwrap().hash.as_ref(),
            Some(&actual_hash)
        );
        assert_eq!(
            h.tracker.performance_counters()["bytesRead"],
            bytes.len() as u64
        );
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 1);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn native_unix_literal_names_and_confined_link_text_survive_original_work_exactly() {
    let h = full_harness();
    let root = h.root("source");
    let literal = "prefs:current\\leaf";
    let link = "alias:current\\leaf";
    fs::write(root.join(literal), b"literal native file bytes").unwrap();
    symlink(literal, root.join(link)).unwrap();
    let id = h.approve(&root);
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .unwrap();
    let expected_id = file_id(work["roots"][0]["id"].as_str().unwrap(), literal);
    assert!(work["fileIds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == &expected_id));
    let reference_before = h.store.records.lock().unwrap()[&id]["pendingWork"].clone();
    let reopened = Tracker::open_impl(
        h.store.clone(),
        Arc::new(|_| Ok(())),
        h.tracker.shared.policy.clone(),
        false,
    )
    .unwrap();
    let original = reopened
        .original_work(
            &id,
            work["workId"].as_str().unwrap(),
            work["generation"].as_u64().unwrap(),
            &bundle::digest(&work["authorization"]["trackingScope"]).unwrap(),
        )
        .unwrap();
    assert_eq!(original.work().unwrap(), work);
    let page = original.node_page(0, 10).unwrap();
    let nodes = page["nodes"].as_array().unwrap();
    let file = nodes.iter().find(|node| node["kind"] == "file").unwrap();
    assert_eq!(file["path"], literal);
    assert_eq!(file["id"], expected_id);
    let linked = nodes.iter().find(|node| node["kind"] == "symlink").unwrap();
    assert_eq!(linked["path"], link);
    assert_eq!(
        linked["linkTargetHash"],
        blake3::hash(literal.as_bytes()).to_hex().to_string()
    );
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["pendingWork"],
        reference_before
    );
    assert_ne!(
        file_id("same-root", literal),
        file_id("same-root", &literal.replace('\\', "/"))
    );
    assert_eq!(reopened.performance_counters()["bytesRead"], 0);
    assert_eq!(reopened.performance_counters()["filesHashed"], 0);
    assert_eq!(
        fs::read_link(root.join(link)).unwrap(),
        PathBuf::from(literal)
    );
}
