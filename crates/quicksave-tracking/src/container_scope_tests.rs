// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic macOS-shaped container scaffolds only; no ambient home/app/state.

use super::*;
use std::os::unix::fs::symlink;

fn container_plan(
    h: &Harness,
    base: &Path,
    installation: &Path,
    container: &Path,
    children: &[(&Path, &str)],
) -> (Value, Value) {
    let app = "synthetic.owned-container";
    let mut plan = indexed_candidate(app, app, installation);
    for (index, (path, role)) in std::iter::once((container, "container"))
        .chain(children.iter().copied())
        .enumerate()
    {
        let mut source = candidate(app, path)["sourceRoots"][0].clone();
        source["rootId"] = json!(format!("native:owned-container-{index}"));
        source["classification"] = json!(role);
        source["roles"] = json!([role]);
        source["ownership"] = json!("reviewed_exact_product_mapping");
        source["evidence"] = json!([{
            "kind":"reviewed_exact_product_mapping","identifier":app,
            "metadataPath":null,"nativeIdentity":native_identity(path),
        }]);
        plan["sourceRoots"].as_array_mut().unwrap().push(source);
    }
    plan["rootsComplete"] = json!(true);
    plan["unresolvedReasons"] = json!([]);
    let initial = authority(h, base, &[plan.clone()], true);
    let mut scope = initial["policyScope"].clone();
    scope["baseDirectories"][0]["ownershipRules"] = json!([
        "native_installation_handle",
        "reviewed_exact_product_mapping",
    ]);
    let sealed = sign_authority(h, scope, &[plan.clone()]);
    (plan, sealed)
}

#[test]
fn container_normalization_discards_scaffold_before_any_full_tree_policy_audit() {
    let h = full_harness();
    let base = h.root("apps");
    let installation = h.root("apps/Owned.app");
    let container = h.root("apps/Containers/synthetic.owned-container");
    let documents = h.root("apps/Containers/synthetic.owned-container/Data/Documents");
    let support =
        h.root("apps/Containers/synthetic.owned-container/Data/Library/Application Support");
    let preferences = h.root("apps/Containers/synthetic.owned-container/Data/Library/Preferences");
    let outside = h.root("unapproved-synthetic-home");
    // If the discarded parent or an escaping link were treated as a content
    // scope, these entries would reject it. Never follow Desktop/Downloads.
    fs::create_dir(outside.join("Keychains")).unwrap();
    fs::write(
        outside.join("Keychains/sentinel"),
        b"outside every approved capture",
    )
    .unwrap();
    symlink(&outside, container.join("Data/Desktop")).unwrap();
    symlink(&outside, container.join("Data/Downloads")).unwrap();
    fs::write(
        container.join("unselected-sibling"),
        b"not a whole-container grant",
    )
    .unwrap();
    for (path, name) in [
        (&installation, "binary"),
        (&documents, "save"),
        (&support, "support"),
        (&preferences, "prefs"),
    ] {
        fs::write(path.join(name), name.as_bytes()).unwrap();
    }
    let (plan, sealed) = container_plan(
        &h,
        &base,
        &installation,
        &container,
        &[
            (&documents, "save"),
            (&support, "data"),
            (&preferences, "config"),
        ],
    );
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert_eq!(report["bundles"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["partialBundles"], 1);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["fileCount"], 4);
    assert_eq!(raw["roots"].as_array().unwrap().len(), 4);
    assert!(!raw["roots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|root| root["path"] == json!(container)));
    assert_eq!(raw["bundleIndexSource"]["coverage"], "partial");
    assert_eq!(raw["autoEnrollment"]["rootsComplete"], false);
    let unresolved = &raw["autoEnrollment"]["unresolvedRoots"][0];
    assert_eq!(unresolved["path"], json!(container));
    assert_eq!(
        unresolved["code"],
        "container_boundary_indexed_via_verified_children"
    );
    assert_eq!(unresolved["preventsFullScopeCapture"], true);
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
    let listed = h.tracker.file_listing(&id, None, 10).unwrap();
    let saved = listed["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "save")
        .unwrap();
    let selected = vec![saved["id"].as_str().unwrap().to_owned()];
    let work = h
        .tracker
        .prepare_upload_scope(&id, "provider-a", Some(&selected))
        .unwrap();
    assert_eq!(work["fileIds"], json!(selected));
    assert_eq!(work["captureSource"]["expectedFullScope"], Value::Null);
    assert_eq!(work["captureSource"]["selectionKind"], "selected_nodes");
    accept(&h, &work);
    assert_eq!(h.finish(&work, true)["sourceConfirmed"], true);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["baselineFullScope"],
        false
    );
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["lastSavedAt"],
        Value::Null
    );
    assert_eq!(
        fs::read(outside.join("Keychains/sentinel")).unwrap(),
        b"outside every approved capture"
    );
}

#[test]
fn protected_root_failures_are_not_mislabeled_or_omitted_as_denied_application_roots() {
    for stage in ["pin_policy_protected_anchor", "pin_policy_protected_root"] {
        let mut h = full_harness();
        let base = h.root("apps");
        let root = h.root("apps/Owned.app");
        let protected = h.root("protected-repository");
        fs::write(root.join("actual"), b"actual app metadata").unwrap();
        Arc::get_mut(&mut h.tracker.shared)
            .unwrap()
            .policy
            .excluded_paths
            .push(protected.clone());
        h.tracker
            .shared
            .policy
            .faults
            .deny(&protected, stage, None, 13);
        let plan = candidate("synthetic.protection-proof", &root);
        let sealed = authority(&h, &base, &[plan.clone()], true);
        let issued = h.store.issued_grants.load(Ordering::Acquire);
        let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
        assert!(report["bundles"].as_array().unwrap().is_empty(), "{report}");
        let diagnostic = &report["diagnostics"][0]["rootDiagnostics"][0];
        assert_eq!(diagnostic["code"], "native_policy_root_inspection_failed");
        assert_eq!(diagnostic["inspectionSide"], "protected");
        assert_eq!(diagnostic["path"], json!(protected));
        assert_eq!(diagnostic["selectedRootPath"], json!(root));
        assert_eq!(diagnostic["protectedRootPath"], json!(protected));
        assert_eq!(diagnostic["stage"], stage);
        assert_eq!(diagnostic["osError"], 13);
        assert!(diagnostic["message"].as_str().unwrap().contains("13"));
        assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
        assert!(h.store.records.lock().unwrap().is_empty());
        assert_eq!(h.tracker.performance_counters()["fsWalks"], 0);
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    }
}

#[test]
fn full_policy_audit_uses_directory_identity_proof_not_protected_capture_semantics() {
    let mut h = full_harness();
    let root = h.root("source");
    let protected = h.root("protected-repository");
    let outside = h.root("unapproved-synthetic-home");
    fs::write(root.join("actual"), b"real selected source").unwrap();
    fs::create_dir(protected.join("target")).unwrap();
    fs::write(
        protected.join("target/compiled-fixture"),
        b"not selected or payload-read",
    )
    .unwrap();
    symlink(&outside, protected.join("external-scaffold")).unwrap();
    Arc::get_mut(&mut h.tracker.shared)
        .unwrap()
        .policy
        .excluded_paths
        .push(protected.clone());
    let selected = quicksave_platform::SafeRoot::open(&root).unwrap();
    let excluded = quicksave_platform::SafeRoot::open(&protected).unwrap();
    // The capture API is deliberately still strict. Policy approval instead
    // uses the purpose-specific complete native directory-ID census.
    assert!(selected.overlaps(&excluded).is_err());
    assert!(!selected.overlaps_directory_identities(&excluded).unwrap());
    let id = h.approve(&root);
    let metadata = h.tracker.scan_metadata(&id).unwrap();
    assert_eq!(metadata["software"]["fileCount"], 1);
    assert_eq!(
        metadata["captureSource"]["payloadReadability"],
        "not_established"
    );
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);

    // Identity-only approval never makes selected escaping links capturable.
    symlink(&outside, root.join("Desktop")).unwrap();
    assert!(h.tracker.scan_metadata(&id).is_err());
    assert_eq!(h.store.records.lock().unwrap()[&id]["fileCount"], 1);
    assert_eq!(
        h.store.records.lock().unwrap()[&id]["baseline"],
        Value::Null
    );
    assert_ne!(h.store.records.lock().unwrap()[&id]["status"], "saved");
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
}

#[test]
fn typed_native_overlap_side_stage_and_relative_path_survive_tracking_context() {
    use quicksave_platform::{
        DirectoryIdentityInspectionFailure, DirectoryIdentityInspectionSide as Side,
        DirectoryIdentityInspectionStage as Stage,
    };
    for side in [Side::Selected, Side::Protected] {
        let h = full_harness();
        let selected_path = h.root("selected");
        let protected_path = h.root("protected");
        let selected = quicksave_platform::SafeRoot::open(&selected_path).unwrap();
        let protected = quicksave_platform::SafeRoot::open(&protected_path).unwrap();
        let failed_path = match side {
            Side::Selected => &selected_path,
            Side::Protected => &protected_path,
        };
        // Obtain the opaque native error context from the actual owned-handle
        // API, never from a private constructor or a parsed English message.
        fs::rename(failed_path, h.home.join("retained-original-directory")).unwrap();
        let native_error = selected
            .overlaps_directory_identities(&protected)
            .unwrap_err();
        let native = native_error
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .unwrap()
            .clone();
        assert_eq!(native.side, side);
        assert_eq!(native.stage, Stage::ValidatePinnedRoot);
        assert_eq!(native.relative_path, None);
        let candidate = json!({"rootId":"native:typed-fixture","path":selected_path,"classification":"install"});
        let annotate = |error: anyhow::Error| {
            let cause = diagnostics::PolicyRootFailure::new(
                &selected_path,
                Some(&protected_path),
                diagnostics::InspectionSide::Both,
                "inspect_policy_overlap",
            )
            .run(&h.tracker.shared.policy, || -> Result<()> { Err(error) })
            .unwrap_err();
            diagnostics::RootContext::candidate(&candidate, "audit_normalized_root_policy")
                .attach(cause)
                .context("additional native caller context")
        };
        let error = annotate(native_error);
        let diagnostic = diagnostics::root_failure(&error).unwrap();
        assert_eq!(
            diagnostic["inspectionSide"],
            match side {
                Side::Selected => "selected",
                Side::Protected => "protected",
            }
        );
        assert_eq!(diagnostic["path"], json!(failed_path));
        assert_eq!(diagnostic["selectedRootPath"], json!(selected_path));
        assert_eq!(diagnostic["protectedRootPath"], json!(protected_path));
        assert_eq!(diagnostic["stage"], "inspect_policy_overlap");
        assert_eq!(diagnostic["nativeInspectionStage"], "validate_pinned_root");
        assert_eq!(diagnostic["relativePath"], Value::Null);

        // Deterministic EACCES injection under the real typed context. These
        // are failures only, never simulated native capabilities or success.
        let mut denied = native.clone();
        denied.stage = Stage::RecordDirectories;
        denied.relative_path = Some(PathBuf::from("Data:literal/known\\directory"));
        let error =
            annotate(anyhow::Error::new(std::io::Error::from_raw_os_error(13)).context(denied));
        let diagnostic = diagnostics::root_failure(&error).unwrap();
        assert_eq!(diagnostic["nativeInspectionStage"], "record_directories");
        assert_eq!(diagnostic["relativePath"], "Data:literal/known\\directory");
        assert_eq!(diagnostic["osError"], 13);
        assert!(diagnostic["message"].as_str().unwrap().len() <= 1024);
        assert_eq!(diagnostics::unavailable(&error), side == Side::Selected);
        assert!(!diagnostics::unavailable(
            &error.context(scan::AuthorityChanged)
        ));

        let explicit_protected = diagnostics::PolicyRootFailure::new(
            &selected_path,
            Some(&protected_path),
            diagnostics::InspectionSide::Protected,
            "verify_policy_protected_root",
        )
        .run(&h.tracker.shared.policy, || -> Result<()> {
            Err(anyhow::Error::new(std::io::Error::from_raw_os_error(13)).context(native))
        })
        .unwrap_err();
        assert!(!diagnostics::unavailable(&explicit_protected));
    }
}
