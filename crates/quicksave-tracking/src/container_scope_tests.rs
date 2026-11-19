// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic macOS-shaped container scaffolds only; no ambient home/app/state.

use super::*;
use std::os::unix::fs::symlink;

#[test]
fn unsupported_container_child_is_omitted_whole_without_blocking_independent_settings() {
    let h = full_harness();
    let base = h.root("partial-container");
    let installation = h.root("partial-container/Owned.app");
    let container = h.root("partial-container/Containers/synthetic.owned");
    let support =
        h.root("partial-container/Containers/synthetic.owned/Data/Library/Application Support");
    let preferences =
        h.root("partial-container/Containers/synthetic.owned/Data/Library/Preferences");
    let outside = h.root("unapproved-outside");
    fs::write(outside.join("private"), b"never indexed or read").unwrap();
    fs::write(
        support.join("otherwise-readable"),
        b"must omit the entire root",
    )
    .unwrap();
    fs::write(preferences.join("owned.plist"), b"verified settings").unwrap();
    symlink(
        "../../../../../../unapproved-outside",
        support.join("system-scaffold"),
    )
    .unwrap();
    let (plan, sealed) = container_plan(
        &h,
        &base,
        &installation,
        &container,
        &[(&support, "save"), (&preferences, "config")],
    );
    let sealed = data_only_authority(&h, &sealed, &plan);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert_eq!(report["bundles"].as_array().unwrap().len(), 1, "{report}");
    let record = h.tracker.bundle_record(&id_from(&report)).unwrap();
    assert_eq!(record["roots"].as_array().unwrap().len(), 1);
    assert_eq!(record["roots"][0]["path"], json!(preferences));
    assert_eq!(record["fileCount"], 1);
    assert_eq!(report["bundles"][0]["fullScopeCaptureBlocked"], true);
    assert_eq!(record["bundleIndexSource"]["coverage"], "partial");
    assert!(report
        .to_string()
        .contains("native_root_link_layout_unsupported"));
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_ne!(record["status"], "saved");
}

#[cfg(target_os = "macos")]
#[test]
fn native_data_approval_indexes_owned_children_without_censusing_opaque_policy_contents() {
    use std::os::unix::fs::PermissionsExt;
    let mut h = full_harness();
    let base = h.root("native-proof-apps");
    let installation = h.root("native-proof-apps/Owned.app");
    let container = h.root("native-proof-apps/Containers/synthetic.owned-container");
    let documents = h.root("native-proof-apps/Containers/synthetic.owned-container/Data/Documents");
    fs::write(documents.join("actual-save"), b"owned data").unwrap();
    let protected = h.root("native-proof-private");
    let opaque = protected.join("id_rsa");
    fs::create_dir(&opaque).unwrap();
    fs::set_permissions(&opaque, fs::Permissions::from_mode(0o000)).unwrap();
    let overlap_control = quicksave_platform::SafeRoot::open(&documents)
        .unwrap()
        .overlaps_for_approval(&quicksave_platform::SafeRoot::open(&protected).unwrap());
    Arc::get_mut(&mut h.tracker.shared)
        .unwrap()
        .policy
        .excluded_paths
        .push(protected);
    let (plan, sealed) = container_plan(
        &h,
        &base,
        &installation,
        &container,
        &[(&documents, "save")],
    );
    let sealed = data_only_authority(&h, &sealed, &plan);
    let result = h.tracker.materialize_bundles(&[plan], &sealed);
    fs::remove_dir(&opaque).unwrap();
    let result = result.unwrap();
    if let Err(error) = overlap_control {
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)),
            "unexpected native proof failure: {error:#}"
        );
        // On unsupported boot mount layouts the same real permission denial
        // must reject enrollment entirely. This is a negative safety test, not
        // a skipped claim of optimized APFS support.
        assert!(result["bundles"].as_array().unwrap().is_empty(), "{result}");
        assert!(
            result["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|item| item["rootDiagnostics"].as_array().into_iter().flatten())
                .any(
                    |item| item["code"] == "native_policy_root_inspection_failed"
                        && item["inspectionSide"] == "protected"
                        && item["osError"] == 13
                ),
            "{result}"
        );
        assert!(h.tracker.shared.apps().unwrap().is_empty());
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
        return;
    }
    assert_eq!(result["bundles"].as_array().unwrap().len(), 1, "{result}");
    let record = h.tracker.bundle_record(&id_from(&result)).unwrap();
    assert_eq!(record["fileCount"], 1);
    assert_eq!(record["roots"].as_array().unwrap().len(), 1);
    assert_eq!(record["roots"][0]["path"], json!(documents));
    assert!(record["error"].is_null(), "{record}");
    assert_ne!(record["status"], "saved");
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
}

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

fn data_only_authority(h: &Harness, sealed: &Value, plan: &Value) -> Value {
    let mut scope = sealed["policyScope"].clone();
    scope["baseDirectories"][0]["allowedRoles"] = json!(["save", "config"]);
    sign_authority(h, scope, std::slice::from_ref(plan))
}

#[test]
fn data_only_roles_omit_unrequested_outside_installation_without_probing_it() {
    let h = full_harness();
    let base = h.root("data-only-apps");
    // This root is deliberately outside the approved data base. Its known role
    // is not requested; neither existence nor accessibility grants anything.
    let installation = h.root("unapproved-installation/Owned.app");
    let container = h.root("data-only-apps/Containers/synthetic.owned-container");
    let documents = h.root("data-only-apps/Containers/synthetic.owned-container/Data/Documents");
    let preferences =
        h.root("data-only-apps/Containers/synthetic.owned-container/Data/Library/Preferences");
    let outside = h.root("outside-data-only");
    symlink(&outside, container.join("Data/Desktop")).unwrap();
    fs::write(documents.join("save"), b"owned save").unwrap();
    fs::write(preferences.join("config"), b"owned config").unwrap();
    fs::write(installation.join("not-selected"), b"not selected").unwrap();
    let (plan, sealed) = container_plan(
        &h,
        &base,
        &installation,
        &container,
        &[(&documents, "save"), (&preferences, "config")],
    );
    // The earliest native operation must never run for the unselected role.
    // EINVAL is intentionally not an omittable availability error.
    h.tracker
        .shared
        .policy
        .faults
        .deny(&installation, "prepare_native_root", None, 22);
    let sealed = data_only_authority(&h, &sealed, &plan);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert_eq!(report["bundles"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["partialBundles"], 1);
    let id = id_from(&report);
    let raw = h.tracker.bundle_record(&id).unwrap();
    assert_eq!(raw["fileCount"], 2);
    assert!(
        raw["error"].is_null(),
        "a policy omission is partial coverage, not an OS error: {raw}"
    );
    assert_eq!(raw["roots"].as_array().unwrap().len(), 2);
    assert!(raw["roots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|root| root["path"] == json!(documents) || root["path"] == json!(preferences)));
    let omissions = raw["autoEnrollment"]["unresolvedRoots"].as_array().unwrap();
    assert!(omissions
        .iter()
        .any(|root| root["code"] == "unselected_role"
            && root["path"] == json!(installation)
            && root["trackingAuthorized"] == false));
    assert!(omissions.iter().any(
        |root| root["code"] == "data_only_container_boundary_omitted"
            && root["path"] == json!(container)
    ));
    assert!(report["diagnostics"][0]["rootDiagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .all(|root| root["omitted"] == true));
    assert!(h
        .tracker
        .prepare_upload_scope(&id, "provider-a", None)
        .is_err());
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
}

#[test]
fn every_tree_role_keeps_protected_inspection_failures_fail_closed() {
    for role in ["install", "save", "config", "runtime"] {
        let mut h = full_harness();
        let base = h.root("ruleset-apps");
        let root = h.root("ruleset-apps/actual-owned-root");
        let protected = h.root("protected-policy");
        fs::write(root.join("actual-data"), b"synthetic only").unwrap();
        Arc::get_mut(&mut h.tracker.shared)
            .unwrap()
            .policy
            .excluded_paths
            .push(protected.clone());
        h.tracker
            .shared
            .policy
            .faults
            .deny(&protected, "pin_policy_protected_root", None, 13);
        let app = format!("synthetic.policy-{role}");
        let mut plan = candidate(&app, &root);
        plan["sourceRoots"][0]["classification"] = json!(role);
        plan["sourceRoots"][0]["roles"] = json!([role]);
        plan["sourceRoots"][0]["ownership"] = json!("reviewed_exact_product_mapping");
        plan["sourceRoots"][0]["evidence"] = json!([{
            "kind":"reviewed_exact_product_mapping","identifier":app,
            "metadataPath":null,"nativeIdentity":native_identity(&root),
        }]);
        let sealed = authority(&h, &base, std::slice::from_ref(&plan), true);
        let mut scope = sealed["policyScope"].clone();
        scope["baseDirectories"][0]["ownershipRules"] = json!(["reviewed_exact_product_mapping"]);
        let sealed = sign_authority(&h, scope, &[plan.clone()]);
        let issued = h.store.issued_grants.load(Ordering::Acquire);
        let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
        assert!(
            report["bundles"].as_array().unwrap().is_empty(),
            "{role}: {report}"
        );
        assert_eq!(
            report["diagnostics"][0]["rootDiagnostics"][0]["inspectionSide"], "protected",
            "{role}: {report}"
        );
        assert!(h.store.records.lock().unwrap().is_empty());
        assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
        assert_eq!(h.tracker.performance_counters()["filesHashed"], 0);
    }
}

#[test]
fn data_only_container_without_owned_selected_children_never_becomes_a_bundle() {
    let h = full_harness();
    let base = h.root("no-children-apps");
    let installation = h.root("no-children-apps/Owned.app");
    let container = h.root("no-children-apps/Containers/synthetic.owned-container");
    let data = h.root("no-children-apps/Containers/synthetic.owned-container/Data");
    let outside = h.root("unapproved-container-target");
    symlink(&outside, data.join("Desktop")).unwrap();
    fs::write(
        container.join("unselected-boundary-sibling"),
        b"not an owned child root",
    )
    .unwrap();
    let (plan, sealed) = container_plan(&h, &base, &installation, &container, &[]);
    let sealed = data_only_authority(&h, &sealed, &plan);
    let issued = h.store.issued_grants.load(Ordering::Acquire);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert!(report["bundles"].as_array().unwrap().is_empty(), "{report}");
    assert_eq!(report["diagnostics"][0]["code"], "no_selected_source_roots");
    assert!(!report["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("unavailable root"));
    let notes = report["diagnostics"][0]["rootDiagnostics"]
        .as_array()
        .unwrap();
    assert!(notes
        .iter()
        .any(|root| root["code"] == "data_only_container_boundary_omitted"));
    assert!(h.store.records.lock().unwrap().is_empty());
    assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
    assert_eq!(h.tracker.performance_counters()["fsWalks"], 0);
    assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
}

#[test]
fn full_policy_can_still_capture_a_verified_whole_container_without_children() {
    let h = full_harness();
    let base = h.root("full-container-apps");
    let installation = h.root("full-container-apps/Owned.app");
    let container = h.root("full-container-apps/Containers/synthetic.owned-container");
    fs::write(installation.join("binary"), b"explicit installation").unwrap();
    fs::write(
        container.join("owned-container-file"),
        b"explicit full container",
    )
    .unwrap();
    let (plan, sealed) = container_plan(&h, &base, &installation, &container, &[]);
    let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
    assert_eq!(report["bundles"].as_array().unwrap().len(), 1, "{report}");
    let raw = h.tracker.bundle_record(&id_from(&report)).unwrap();
    assert_eq!(raw["fileCount"], 2);
    assert!(raw["roots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|root| root["path"] == json!(container)));
    assert_eq!(raw["autoEnrollment"]["unresolvedRoots"], json!([]));
}

#[test]
fn data_only_selected_root_violations_reject_instead_of_becoming_omissions() {
    for violation in [
        "outside_base",
        "identity_mismatch",
        "protected_path",
        "unsafe_selected_file",
    ] {
        let mut h = full_harness();
        let base = h.root("selected-data-apps");
        let installation = h.root("selected-data-apps/Owned.app");
        let container = h.root("selected-data-apps/Containers/synthetic.owned-container");
        let documents =
            h.root("selected-data-apps/Containers/synthetic.owned-container/Data/Documents");
        let outside = h.root("outside-selected-data");
        fs::write(documents.join("owned"), b"real selected data").unwrap();
        let (mut plan, sealed) = container_plan(
            &h,
            &base,
            &installation,
            &container,
            &[(&documents, "save")],
        );
        match violation {
            "outside_base" => {
                plan["sourceRoots"][2]["path"] = json!(outside);
                plan["sourceRoots"][2]["nativeIdentity"] = native_identity(&outside);
            }
            "identity_mismatch" => {
                plan["sourceRoots"][2]["nativeIdentity"] = native_identity(&installation)
            }
            "protected_path" => Arc::get_mut(&mut h.tracker.shared)
                .unwrap()
                .policy
                .excluded_paths
                .push(documents.clone()),
            "unsafe_selected_file" => {
                symlink(&outside, documents.join("escaping-selected-link")).unwrap()
            }
            _ => unreachable!(),
        }
        let sealed = data_only_authority(&h, &sealed, &plan);
        let issued = h.store.issued_grants.load(Ordering::Acquire);
        let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
        assert!(
            report["bundles"].as_array().unwrap().is_empty(),
            "{violation}: {report}"
        );
        assert!(h.store.records.lock().unwrap().is_empty());
        assert_eq!(h.store.issued_grants.load(Ordering::Acquire), issued);
        assert_eq!(h.tracker.performance_counters()["bytesRead"], 0);
    }
}

#[test]
fn unselected_roles_still_require_valid_declarations_and_catalog_attestation() {
    for violation in [
        "unknown_role",
        "malformed_roles",
        "malformed_identity",
        "catalog_attestation",
    ] {
        let h = full_harness();
        let base = h.root("declaration-apps");
        let installation = h.root("outside-declaration-apps/Owned.app");
        let container = h.root("declaration-apps/Containers/synthetic.owned-container");
        let documents =
            h.root("declaration-apps/Containers/synthetic.owned-container/Data/Documents");
        let (mut plan, sealed) = container_plan(
            &h,
            &base,
            &installation,
            &container,
            &[(&documents, "save")],
        );
        match violation {
            "unknown_role" => plan["sourceRoots"][0]["classification"] = json!("unknown"),
            "malformed_roles" => plan["sourceRoots"][0]["roles"] = json!("installation"),
            "malformed_identity" => plan["sourceRoots"][0]["nativeIdentity"] = json!({}),
            "catalog_attestation" => {}
            _ => unreachable!(),
        }
        let mut sealed = data_only_authority(&h, &sealed, &plan);
        if violation == "catalog_attestation" {
            sealed["discoveryGrant"] = json!({"unsigned":true});
            assert!(h.tracker.materialize_bundles(&[plan], &sealed).is_err());
        } else {
            let report = h.tracker.materialize_bundles(&[plan], &sealed).unwrap();
            assert!(
                report["bundles"].as_array().unwrap().is_empty(),
                "{violation}: {report}"
            );
        }
        assert!(h.store.records.lock().unwrap().is_empty());
        assert_eq!(h.tracker.performance_counters()["fsWalks"], 0);
    }
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
        let sealed = authority(&h, &base, std::slice::from_ref(&plan), true);
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
