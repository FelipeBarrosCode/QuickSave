// SPDX-License-Identifier: GPL-3.0-only
//! Every filesystem record in these tests is synthetic and confined to a
//! temporary sandbox. Never invoke ambient discovery or real Security APIs.
use super::*;
use crate::parsers::macos;
use crate::profiles::ProfilePath;
use anyhow::Result;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn temporary() -> tempfile::TempDir {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn app(path: &Path, id: &str) {
    fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
    fs::write(path.join("Contents/Info.plist"), format!(
        "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleName</key><string>Same display title</string><key>CFBundleExecutable</key><string>fixture-executable</string></dict></plist>"
    )).unwrap();
    executable(&path.join("Contents/MacOS/fixture-executable"));
}

fn executable(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Never executed. The test concerns OS file identity, not a pretend binary
    // signature, runtime probe or a fabricated content inventory.
    fs::write(path, b"synthetic native executable identity fixture").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn container(path: &Path, id: &str) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join(".com.apple.containermanagerd.metadata.plist"), format!(
        "<plist version=\"1.0\"><dict><key>MCMMetadataIdentifier</key><string>{id}</string></dict></plist>"
    )).unwrap();
}

fn mac_scope(root: &Path) -> BundleInventoryScope {
    BundleInventoryScope {
        application_directories: vec![root.join("Applications")],
        home: Some(root.join("home")),
        ..BundleInventoryScope::default()
    }
}

fn run(backend: &mut dyn SoftwareBundleBackend, scope: &BundleInventoryScope) -> Value {
    discover_software_bundles_with_backend(backend, scope, BundlePlanLimits::default()).unwrap()
}

fn plans(report: &Value) -> &[Value] {
    report["bundlePlans"].as_array().unwrap()
}
fn unresolved(report: &Value) -> &[Value] {
    report["unresolvedApplications"].as_array().unwrap()
}
fn roots(plan: &Value) -> &[Value] {
    plan["sourceRoots"].as_array().unwrap()
}
fn has_path(plan: &Value, path: &Path) -> bool {
    roots(plan)
        .iter()
        .any(|root| root["path"].as_str() == path.to_str())
}
fn has_reason(plan: &Value, code: &str) -> bool {
    plan["unresolvedReasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == code)
}
fn product<'a>(report: &'a Value, product_id: &str) -> &'a Value {
    plans(report)
        .iter()
        .chain(unresolved(report))
        .find(|plan| plan["productId"] == product_id)
        .unwrap()
}

#[test]
fn protected_products_are_not_enrolled_or_treated_as_unresolved_apps() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    for (name, id) in [
        ("Unrelated filename.app", "com.noland.connect"),
        ("Another filename.app", "app.quicksave.desktop"),
    ] {
        let bundle = root.join("Applications").join(name);
        app(&bundle, id);
        // Protected products are excluded before executable validation.
        fs::remove_file(bundle.join("Contents/MacOS/fixture-executable")).unwrap();
    }
    let ordinary = root.join("Applications/Ordinary.app");
    app(&ordinary, "org.fixture.Ordinary");
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 1);
    assert_eq!(
        plans(&report)[0]["productId"],
        "mac-bundle:org.fixture.Ordinary"
    );
    assert!(unresolved(&report).is_empty());
    assert_eq!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["code"] == "protected_application_excluded")
            .count(),
        2
    );
}

#[test]
fn real_native_install_and_exact_bundle_data_not_title_folders() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/Unrelated filename.app");
    app(&bundle, "org.fixture.One");
    let support = root.join("home/Library/Application Support/org.fixture.One");
    let preferences = root.join("home/Library/Preferences/org.fixture.One.plist");
    let wrong = root.join("home/Library/Application Support/Same display title");
    fs::create_dir_all(&support).unwrap();
    fs::create_dir_all(&wrong).unwrap();
    fs::create_dir_all(preferences.parent().unwrap()).unwrap();
    fs::write(&preferences, b"private config fixture; must not be read").unwrap();
    fs::write(
        support.join("actual-save"),
        b"fixture content for later engine index",
    )
    .unwrap();
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 1);
    let plan = &plans(&report)[0];
    assert!(has_path(plan, &bundle));
    assert!(has_path(plan, &support));
    assert!(has_path(plan, &preferences));
    assert!(!has_path(plan, &wrong));
    let native = fs::metadata(&bundle).unwrap();
    assert_eq!(plan["installationIdentity"]["inode"], native.ino());
    assert_eq!(plan["installationIdentity"]["device"], native.dev());
    let source_identity = &plan["sourceIdentity"];
    assert_eq!(source_identity["app_id"], "mac-bundle:org.fixture.One");
    assert_eq!(source_identity["display_name"], plan["displayName"]);
    assert_eq!(
        source_identity["canonical_executable"].as_str(),
        bundle.join("Contents/MacOS/fixture-executable").to_str()
    );
    assert_eq!(source_identity["launcher"], "native");
    assert!(source_identity["steam_app_id"].is_null());
    assert!(source_identity["desktop_entry_id"].is_null());
    assert_eq!(source_identity["aliases"], serde_json::json!([]));
    assert_eq!(
        plan["profileMatchPolicy"]["titlesAndBasenamesAuthorizeOwnership"],
        false
    );
    assert_eq!(plan["rootsComplete"], false);
    assert!(!report.to_string().contains("fileCount"));
    assert!(!report.to_string().contains("\"tracked\":true"));
}

#[test]
fn each_discovered_app_is_verified_plan_or_diagnostic_never_placeholder_bundle() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    for (name, id) in [
        ("One.app", "org.fixture.One"),
        ("Two.app", "org.fixture.Two"),
        ("Category/Three.app", "org.fixture.Three"),
    ] {
        app(&root.join("Applications").join(name), id);
    }
    fs::create_dir_all(root.join("Applications/Invalid.app/Contents")).unwrap();
    fs::write(
        root.join("Applications/Invalid.app/Contents/Info.plist"),
        b"not a plist",
    )
    .unwrap();
    app(
        &root.join("Applications/MissingExecutable.app"),
        "org.fixture.Missing",
    );
    fs::remove_file(
        root.join("Applications/MissingExecutable.app/Contents/MacOS/fixture-executable"),
    )
    .unwrap();
    symlink("One.app", root.join("Applications/Linked.app")).unwrap();
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(report["discoveredApplications"], 6);
    assert_eq!(plans(&report).len(), 3);
    assert_eq!(unresolved(&report).len(), 3);
    assert!(plans(&report).iter().all(|plan| !roots(plan).is_empty()));
    assert!(unresolved(&report)
        .iter()
        .all(|plan| roots(plan).is_empty()));
    assert!(report["inventoryIncomplete"].as_bool().unwrap());
    assert!(unresolved(&report)
        .iter()
        .all(|plan| plan["sourceIdentity"].is_null()));
}

#[test]
fn stable_ids_follow_native_installation_not_display_name() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/One.app");
    app(&bundle, "org.fixture.One");
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let first = run(&mut backend, &scope);
    let bytes = fs::read_to_string(bundle.join("Contents/Info.plist")).unwrap();
    fs::write(
        bundle.join("Contents/Info.plist"),
        bytes.replace("Same display title", "A different title"),
    )
    .unwrap();
    let second = run(&mut backend, &scope);
    assert_eq!(plans(&first)[0]["appId"], plans(&second)[0]["appId"]);
    assert_eq!(
        roots(&plans(&first)[0])[0]["rootId"],
        roots(&plans(&second)[0])[0]["rootId"]
    );
    assert_ne!(
        plans(&first)[0]["displayName"],
        plans(&second)[0]["displayName"]
    );
}

#[test]
fn duplicate_bundle_id_refuses_data_association_for_both_installations() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    app(&root.join("Applications/One.app"), "org.fixture.Duplicate");
    app(&root.join("Applications/Two.app"), "org.fixture.Duplicate");
    fs::create_dir_all(root.join("home/Library/Application Support/org.fixture.Duplicate"))
        .unwrap();
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 2);
    for plan in plans(&report) {
        assert_eq!(roots(plan).len(), 1);
        assert_eq!(roots(plan)[0]["classification"], "install");
        assert!(has_reason(plan, "ambiguous_bundle_identifier"));
    }
}

#[test]
fn container_metadata_and_validated_signed_groups_bind_exact_owners() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/One.app");
    app(&bundle, "org.fixture.One");
    let data = root.join("home/Library/Containers/org.fixture.One");
    container(&data, "org.fixture.One");
    for relative in [
        "Data/Documents",
        "Data/Library/Preferences",
        "Data/Library/Application Support",
    ] {
        fs::create_dir_all(data.join(relative)).unwrap();
    }
    let group = root.join("home/Library/Group Containers/group.org.fixture.shared");
    container(&group, "group.org.fixture.shared");
    let unrelated = root.join("home/Library/Group Containers/group.org.fixture.other");
    container(&unrelated, "group.org.fixture.other");
    let entitlement_xml = br#"<plist version="1.0"><dict><key>com.apple.security.application-groups</key><array><string>group.org.fixture.shared</string></array></dict></plist>"#;
    let groups = macos::parse_application_groups(entitlement_xml).unwrap();
    // Exercise the same parser with binary metadata too.
    let value = plist::Value::from_reader(std::io::Cursor::new(entitlement_xml)).unwrap();
    let mut binary = Vec::new();
    value.to_writer_binary(&mut binary).unwrap();
    assert_eq!(macos::parse_application_groups(&binary).unwrap(), groups);
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    backend
        .set_mac_signing(
            bundle,
            MacSigningEvidence {
                signing_identifier: Some("org.fixture.One".into()),
                application_groups: groups,
                signature_validated: true,
            },
        )
        .unwrap();
    let report = run(&mut backend, &scope);
    let plan = &plans(&report)[0];
    assert!(has_path(plan, &data));
    assert!(has_path(plan, &data.join("Data/Documents")));
    assert!(has_path(plan, &group));
    assert!(!has_path(plan, &unrelated));
    let group_root = roots(plan)
        .iter()
        .find(|item| item["path"].as_str() == group.to_str())
        .unwrap();
    assert_eq!(group_root["confidence"], "signed_application_group");
    assert_eq!(
        group_root["ownership"],
        "shared_signed_application_group_not_exclusive"
    );
    assert!(plan["identityEvidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "validated_signed_bundle_identifier"));
}

#[test]
fn wrong_container_identifier_and_unsigned_or_mismatched_groups_are_refused() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/One.app");
    app(&bundle, "org.fixture.One");
    let data = root.join("home/Library/Containers/org.fixture.One");
    container(&data, "org.fixture.Other");
    let group = root.join("home/Library/Group Containers/group.org.fixture.shared");
    container(&group, "group.org.fixture.shared");
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    for (validated, signing_id) in [(false, "org.fixture.One"), (true, "org.fixture.Other")] {
        backend
            .set_mac_signing(
                bundle.clone(),
                MacSigningEvidence {
                    signing_identifier: Some(signing_id.into()),
                    application_groups: vec!["group.org.fixture.shared".into()],
                    signature_validated: validated,
                },
            )
            .unwrap();
        let report = run(&mut backend, &scope);
        let plan = &plans(&report)[0];
        assert!(!has_path(plan, &data));
        assert!(!has_path(plan, &group));
        assert!(has_reason(plan, "signed_groups_unavailable"));
        assert!(has_reason(
            plan,
            "container_identifier_mismatch_or_unreadable"
        ));
    }
}

#[test]
fn relative_framework_link_is_not_walked_and_requires_engine_metadata_capability() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/One.app");
    app(&bundle, "org.fixture.One");
    fs::create_dir_all(bundle.join("Contents/Frameworks/Fixture.framework/Versions/A")).unwrap();
    symlink(
        "A",
        bundle.join("Contents/Frameworks/Fixture.framework/Versions/Current"),
    )
    .unwrap();
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    let install = &roots(&plans(&report)[0])[0];
    assert!(install["requiredRootCapabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "safe_relative_link_metadata_without_traversal"));
    assert_eq!(install["exclusions"]["symlinkAndReparseTraversal"], true);
    assert_eq!(report["trackingAuthorized"], false);
}

#[test]
fn fixture_scope_symlinks_and_native_replacement_fail_closed() {
    let temp = temporary();
    let root = temp.path().join("sandbox");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("private"), b"outside fixture scope").unwrap();
    symlink(&outside, root.join("escape")).unwrap();
    fs::hard_link(outside.join("private"), root.join("hardlink")).unwrap();
    let mut backend = FixtureBundleBackend::new(&root, Platform::MacOs).unwrap();
    assert!(backend.read_metadata(&outside.join("private"), 64).is_err());
    assert!(backend
        .read_metadata(&root.join("escape/private"), 64)
        .is_err());
    assert!(backend.read_metadata(&root.join("hardlink"), 64).is_err());
    assert!(backend.inspect_native(&root.join("../outside")).is_err());
    fs::rename(&root, temp.path().join("moved")).unwrap();
    fs::create_dir(&root).unwrap();
    assert!(backend.list_directory(&root, 8).is_err());
}

#[test]
fn protected_quicksave_vault_and_caches_are_not_sources() {
    let temp = temporary();
    let root = temp.path();
    let mut scope = mac_scope(root);
    app(&root.join("Applications/One.app"), "org.fixture.One");
    let support = root.join("home/Library/Application Support/org.fixture.One");
    fs::create_dir_all(&support).unwrap();
    scope.protected_roots.push(support.clone());
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let report = run(&mut backend, &scope);
    let plan = &plans(&report)[0];
    assert!(!has_path(plan, &support));
    assert!(has_reason(plan, "protected_source_root"));
    let exclusions = &roots(plan)[0]["exclusions"];
    for component in ["caches", "logs", "vaults", "keychains", "quicksave"] {
        assert!(exclusions["caseInsensitivePathComponents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == component));
    }
}

fn steam_app(root: &Path, id: u32, name: &str) {
    fs::create_dir_all(root.join("steamapps/common").join(name)).unwrap();
    fs::write(
        root.join("steamapps/common").join(name).join("actual-file"),
        b"fixture game data",
    )
    .unwrap();
    fs::write(
        root.join(format!("steamapps/appmanifest_{id}.acf")),
        format!(r#""AppState" {{ "appid" "{id}" "name" "Same title" "installdir" "{name}" }}"#),
    )
    .unwrap();
}

#[test]
fn steam_userdata_uses_only_inventory_approved_exact_id_and_numeric_account_key() {
    let temp = temporary();
    let root = temp.path();
    let steam = root.join("Steam");
    steam_app(&steam, 480, "InstallA");
    steam_app(&steam, 481, "InstallB");
    for relative in [
        "userdata/100/480/remote",
        "userdata/100/481/remote",
        "userdata/Same title/480/remote",
    ] {
        fs::create_dir_all(steam.join(relative)).unwrap();
    }
    let mut scope = BundleInventoryScope {
        steam_roots: vec![steam.clone()],
        ..BundleInventoryScope::default()
    };
    scope.inventory_approved_steam_app_ids.insert(480);
    let mut backend = FixtureBundleBackend::new(root, Platform::Linux).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 2);
    let approved = product(&report, "steam:480");
    let other = product(&report, "steam:481");
    assert!(has_path(approved, &steam.join("userdata/100/480")));
    assert!(has_path(approved, &steam.join("userdata/100/480/remote")));
    assert_eq!(approved["sourceIdentity"]["app_id"], "steam:480");
    assert_eq!(approved["sourceIdentity"]["steam_app_id"], 480);
    assert_eq!(approved["sourceIdentity"]["launcher"], "steam");
    assert!(approved["sourceIdentity"]["canonical_executable"].is_null());
    assert!(!has_path(
        approved,
        &steam.join("userdata/Same title/480/remote")
    ));
    assert!(!has_path(other, &steam.join("userdata/100/481/remote")));
    assert!(has_reason(
        other,
        "steam_userdata_app_id_not_inventory_approved"
    ));
    // Borrow the same launcher root for every manifest, rather than consuming
    // the set on the first inventory-approved app.
    scope.inventory_approved_steam_app_ids.insert(481);
    let report = run(&mut backend, &scope);
    assert!(has_path(
        product(&report, "steam:480"),
        &steam.join("userdata/100/480/remote")
    ));
    assert!(has_path(
        product(&report, "steam:481"),
        &steam.join("userdata/100/481/remote")
    ));
    assert_eq!(
        product(&report, "steam:481")["sourceIdentity"]["app_id"],
        "steam:481"
    );
}

#[test]
fn linux_exact_xdg_and_flatpak_ids_not_exec_parent_or_title_ownership() {
    let temp = temporary();
    let root = temp.path();
    let desktop = root.join("desktop");
    fs::create_dir_all(&desktop).unwrap();
    let runtime = root.join("bin/fixture");
    executable(&runtime);
    fs::write(
        desktop.join("org.fixture.Native.desktop"),
        format!(
            "[Desktop Entry]\nType=Application\nName=Same title\nExec=\"{}\" --open %U\n",
            runtime.display()
        ),
    )
    .unwrap();
    fs::write(desktop.join("org.fixture.Flatpak.desktop"), "[Desktop Entry]\nType=Application\nName=Same title\nX-Flatpak=org.fixture.Flatpak\nExec=/usr/bin/flatpak run org.fixture.Flatpak\n").unwrap();
    fs::write(
        desktop.join("org.fixture.Mismatch.desktop"),
        "[Desktop Entry]\nType=Application\nName=Same title\nX-Flatpak=org.fixture.Other\n",
    )
    .unwrap();
    fs::write(
        desktop.join("simple-name.desktop"),
        "[Desktop Entry]\nType=Application\nName=Same title\nExec=fixture\n",
    )
    .unwrap();
    for relative in [
        "data/org.fixture.Native",
        "config/org.fixture.Native",
        "home/.var/app/org.fixture.Flatpak/data",
        "home/.var/app/org.fixture.Flatpak/config",
        "data/Same title",
        "home/.var/app/org.fixture.Other/data",
    ] {
        fs::create_dir_all(root.join(relative)).unwrap();
    }
    let scope = BundleInventoryScope {
        desktop_directories: vec![desktop],
        home: Some(root.join("home")),
        xdg_data_home: Some(root.join("data")),
        xdg_config_home: Some(root.join("config")),
        ..BundleInventoryScope::default()
    };
    let mut backend = FixtureBundleBackend::new(root, Platform::Linux).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(report["discoveredApplications"], 4);
    assert_eq!(plans(&report).len(), 2);
    assert_eq!(unresolved(&report).len(), 2);
    let native = product(&report, "xdg-desktop:org.fixture.Native.desktop");
    assert!(has_path(native, &runtime));
    assert!(has_path(native, &root.join("data/org.fixture.Native")));
    assert!(!has_path(native, runtime.parent().unwrap()));
    assert!(!has_path(native, &root.join("data/Same title")));
    assert_eq!(
        native["sourceIdentity"]["app_id"],
        "desktop:org.fixture.Native.desktop"
    );
    assert_eq!(
        native["sourceIdentity"]["desktop_entry_id"],
        "org.fixture.Native.desktop"
    );
    assert_eq!(
        native["sourceIdentity"]["canonical_executable"].as_str(),
        runtime.to_str()
    );
    let flatpak = product(&report, "xdg-desktop:org.fixture.Flatpak.desktop");
    assert!(has_path(
        flatpak,
        &root.join("home/.var/app/org.fixture.Flatpak/data")
    ));
    assert_eq!(flatpak["sourceIdentity"]["launcher"], "flatpak");
    assert!(flatpak["sourceIdentity"]["canonical_executable"].is_null());
    assert!(has_reason(
        product(&report, "xdg-desktop:org.fixture.Mismatch.desktop"),
        "ambiguous_flatpak_desktop_identifier"
    ));
    assert!(has_reason(
        product(&report, "xdg-desktop:simple-name.desktop"),
        "desktop_id_has_no_exact_data_namespace"
    ));
}

#[test]
fn windows_explicit_identity_adapter_uses_known_folder_package_and_exact_reviewed_owner() {
    let temp = temporary();
    let root = temp.path();
    let local = root.join("known-local");
    let saves = root.join("known-saved-games");
    let install = root.join("installed-product");
    fs::create_dir_all(&install).unwrap();
    fs::write(install.join("real-file"), b"fixture package file").unwrap();
    let package = WindowsProductIdentity::PackageFamily {
        family_name: "Fixture.Product_abc123def4567".into(),
    };
    for relative in ["LocalState", "RoamingState", "Settings"] {
        fs::create_dir_all(
            local
                .join("Packages/Fixture.Product_abc123def4567")
                .join(relative),
        )
        .unwrap();
    }
    fs::create_dir_all(saves.join("ExactProfile")).unwrap();
    fs::create_dir_all(saves.join("Same title")).unwrap();
    let record = WindowsInstallation {
        identity: package.clone(),
        display_name: "Same title".into(),
        installation_path: Some(install.clone()),
        executable_path: None,
        reviewed_mappings: vec![
            WindowsReviewedMapping {
                exact_owner_id: package.stable_key().unwrap(),
                known_folder: WindowsKnownFolder::SavedGames,
                relative_path: ProfilePath::new("ExactProfile").unwrap(),
                classification: RootClassification::Save,
                profile_id: "fixture-reviewed-profile".into(),
            },
            WindowsReviewedMapping {
                exact_owner_id: "Same title".into(),
                known_folder: WindowsKnownFolder::SavedGames,
                relative_path: ProfilePath::new("Same title").unwrap(),
                classification: RootClassification::Save,
                profile_id: "not-an-identity-match".into(),
            },
        ],
    };
    let scope = BundleInventoryScope {
        windows_known_folders: [
            (WindowsKnownFolder::LocalAppData, local.clone()),
            (WindowsKnownFolder::SavedGames, saves.clone()),
        ]
        .into_iter()
        .collect(),
        ..BundleInventoryScope::default()
    };
    let mut backend = FixtureBundleBackend::new(root, Platform::Windows).unwrap();
    backend.set_windows_installations(vec![record]).unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 1);
    let plan = &plans(&report)[0];
    assert!(has_path(plan, &install));
    assert!(has_path(
        plan,
        &local.join("Packages/Fixture.Product_abc123def4567/LocalState")
    ));
    assert!(has_path(plan, &saves.join("ExactProfile")));
    assert!(!has_path(plan, &saves.join("Same title")));
    assert!(has_reason(plan, "reviewed_mapping_owner_mismatch"));
    assert_eq!(report["backend"], "isolated_fixture");
    assert_eq!(report["nativePackagingAcceptance"], false);
    assert_eq!(plan["installationIdentity"]["platform"], "unix"); // Not a fake Windows handle.
}

#[test]
fn windows_registry_identity_is_exact_not_title_and_missing_adapter_errors() {
    let temp = temporary();
    let root = temp.path();
    let scope = BundleInventoryScope::default();
    let mut backend = FixtureBundleBackend::new(root, Platform::Windows).unwrap();
    assert!(discover_software_bundles_with_backend(
        &mut backend,
        &scope,
        BundlePlanLimits::default()
    )
    .is_err());
    let install = root.join("installed");
    fs::create_dir_all(&install).unwrap();
    let good = WindowsProductIdentity::UninstallRegistry {
        hive: "HKEY_CURRENT_USER".into(),
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{12345}".into(),
    };
    let bad = WindowsProductIdentity::UninstallRegistry {
        hive: "Same title".into(),
        key: "Same title".into(),
    };
    backend
        .set_windows_installations(vec![
            WindowsInstallation {
                identity: good,
                display_name: "Same title".into(),
                installation_path: Some(install.clone()),
                executable_path: None,
                reviewed_mappings: Vec::new(),
            },
            WindowsInstallation {
                identity: bad,
                display_name: "Same title".into(),
                installation_path: Some(install),
                executable_path: None,
                reviewed_mappings: Vec::new(),
            },
        ])
        .unwrap();
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 1);
    assert_eq!(unresolved(&report).len(), 1);
    assert!(has_reason(
        &unresolved(&report)[0],
        "windows_product_identity_invalid"
    ));
}

struct AuditedBackend {
    inner: FixtureBundleBackend,
    read_paths: Vec<PathBuf>,
    mutate_executable_during_signing: Option<PathBuf>,
    deny_native_path: Option<PathBuf>,
}

impl SoftwareBundleBackend for AuditedBackend {
    fn platform(&self) -> Platform {
        self.inner.platform()
    }
    fn kind(&self) -> BackendKind {
        BackendKind::IsolatedFixture
    }
    fn inspect_native(&mut self, path: &Path) -> Result<Option<NativeNode>> {
        if self.deny_native_path.as_deref() == Some(path) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
        }
        self.inner.inspect_native(path)
    }
    fn list_directory(&mut self, path: &Path, maximum: usize) -> Result<Option<DirectoryEntries>> {
        self.inner.list_directory(path, maximum)
    }
    fn read_metadata(&mut self, path: &Path, maximum: usize) -> Result<Option<MetadataDocument>> {
        self.read_paths.push(path.to_owned());
        self.inner.read_metadata(path, maximum)
    }
    fn mac_signing_evidence(&mut self, path: &Path) -> Result<MacSigningEvidence> {
        if let Some(executable) = self.mutate_executable_during_signing.take() {
            fs::write(
                executable,
                b"changed executable fixture after its native observation",
            )
            .unwrap();
        }
        self.inner.mac_signing_evidence(path)
    }
}

#[test]
fn reads_only_installation_container_metadata_not_save_preferences_vault_or_account_contents() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    app(&root.join("Applications/One.app"), "org.fixture.One");
    fs::create_dir_all(root.join("home/Library/Preferences")).unwrap();
    fs::write(
        root.join("home/Library/Preferences/org.fixture.One.plist"),
        b"must not read private config",
    )
    .unwrap();
    fs::create_dir_all(root.join("home/Library/Application Support/org.fixture.One/vault"))
        .unwrap();
    fs::write(
        root.join("home/Library/Application Support/org.fixture.One/vault/master-key"),
        b"must not read",
    )
    .unwrap();
    let mut backend = AuditedBackend {
        inner: FixtureBundleBackend::new(root, Platform::MacOs).unwrap(),
        read_paths: Vec::new(),
        mutate_executable_during_signing: None,
        deny_native_path: None,
    };
    let report = run(&mut backend, &scope);
    assert_eq!(plans(&report).len(), 1);
    assert!(backend.read_paths.iter().all(|path| {
        matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some("Info.plist" | ".com.apple.containermanagerd.metadata.plist")
        )
    }));
    for plan in plans(&report) {
        assert_eq!(plan["backupAuthority"], "not_granted");
        assert_eq!(plan["contentScanAuthorized"], false);
        assert_eq!(plan["trackingAuthorized"], false);
        assert_eq!(plan["uploadAuthorized"], false);
    }
}

#[test]
fn changed_executable_during_signing_refuses_verified_bundle_plan() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    let bundle = root.join("Applications/One.app");
    app(&bundle, "org.fixture.One");
    let mut inner = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    inner
        .set_mac_signing(
            bundle.clone(),
            MacSigningEvidence {
                signing_identifier: Some("org.fixture.One".into()),
                application_groups: Vec::new(),
                signature_validated: true,
            },
        )
        .unwrap();
    let mut backend = AuditedBackend {
        inner,
        read_paths: Vec::new(),
        mutate_executable_during_signing: Some(bundle.join("Contents/MacOS/fixture-executable")),
        deny_native_path: None,
    };
    let report = run(&mut backend, &scope);
    assert!(plans(&report).is_empty());
    assert_eq!(unresolved(&report).len(), 1);
    assert!(has_reason(
        &unresolved(&report)[0],
        "installation_changed_during_signing"
    ));
}

#[test]
fn metadata_entries_paths_and_root_budgets_are_hard_bounded() {
    let temp = temporary();
    let root = temp.path();
    let mut scope = mac_scope(root);
    app(&root.join("Applications/One.app"), "org.fixture.One");
    app(&root.join("Applications/Two.app"), "org.fixture.Two");
    let mut backend = FixtureBundleBackend::new(root, Platform::MacOs).unwrap();
    let limits = BundlePlanLimits {
        max_entries_per_directory: 1,
        max_total_entries: 1,
        ..BundlePlanLimits::default()
    };
    let report = discover_software_bundles_with_backend(&mut backend, &scope, limits).unwrap();
    assert_eq!(report["examinedEntries"], 1);
    assert_eq!(report["inventoryIncomplete"], true);
    assert!(report["discoveredApplications"].as_u64().unwrap() <= 1);
    let limits = BundlePlanLimits {
        max_metadata_bytes_per_file: 1,
        max_total_metadata_bytes: 1,
        ..BundlePlanLimits::default()
    };
    let report = discover_software_bundles_with_backend(&mut backend, &scope, limits).unwrap();
    assert!(plans(&report).is_empty());
    assert_eq!(unresolved(&report).len(), 2);
    assert_eq!(report["inventoryIncomplete"], true);
    let limits = BundlePlanLimits {
        max_total_plan_bytes: 1,
        ..BundlePlanLimits::default()
    };
    let report = discover_software_bundles_with_backend(&mut backend, &scope, limits).unwrap();
    assert!(plans(&report).is_empty());
    assert_eq!(report["discoveredApplications"], 2);
    assert_eq!(report["omittedApplications"], 2);
    assert_eq!(report["inventoryIncomplete"], true);
    scope.application_directories = vec![root.join("../outside")];
    assert!(discover_software_bundles_with_backend(
        &mut backend,
        &scope,
        BundlePlanLimits::default()
    )
    .is_err());
}

#[test]
fn native_permission_gap_is_distinct_from_absent_root_and_never_counted_as_source() {
    let temp = temporary();
    let root = temp.path();
    let scope = mac_scope(root);
    app(&root.join("Applications/One.app"), "org.fixture.One");
    let denied = root.join("home/Library/Application Support/org.fixture.One");
    fs::create_dir_all(&denied).unwrap();
    let mut backend = AuditedBackend {
        inner: FixtureBundleBackend::new(root, Platform::MacOs).unwrap(),
        read_paths: Vec::new(),
        mutate_executable_during_signing: None,
        deny_native_path: Some(denied.clone()),
    };
    let report = run(&mut backend, &scope);
    let plan = &plans(&report)[0];
    assert!(has_reason(plan, "native_permission_denied"));
    assert!(!has_path(plan, &denied));
    assert_eq!(plan["rootsComplete"], false);
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "native_permission_denied"));
}
