// SPDX-License-Identifier: GPL-3.0-only
//! Native-only enrollment policy construction; no webview candidate authority.

use anyhow::{ensure, Context, Result};
use quicksave_platform::SafeRoot;
use quicksave_state::WorkspaceStore;
use quicksave_tracking::Tracker;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path};

const OWNERSHIP: &[&str] = &[
    "native_installation_handle",
    "native_executable_handle",
    "cf_bundle_identifier",
    "cf_bundle_executable_native_handle",
    "validated_signed_bundle_identifier",
    "exact_cf_bundle_identifier_path",
    "cf_bundle_identifier_and_executable_handle",
    "container_metadata_identifier",
    "validated_signed_application_group",
    "xdg_desktop_file_id",
    "exact_flatpak_desktop_identifier",
    "exact_namespaced_desktop_id_path",
    "xdg_desktop_or_flatpak_identifier",
    "exact_numeric_steam_app_id",
    "exact_steam_appmanifest_id_and_installdir",
    "inventory_approved_exact_steam_app_id_userdata_path",
    "windows_registry_or_package_identity",
    "reviewed_exact_windows_product_mapping",
    "reviewed_exact_product_mapping",
];

fn diagnostic_message(diagnostic: &Value) -> &str {
    fn message(value: &Value) -> Option<&str> {
        value.as_str().filter(|text| {
            !text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control)
        })
    }
    message(&diagnostic["message"])
        .or_else(|| diagnostic["unresolvedReasons"].as_array()
            .and_then(|reasons| reasons.iter().take(32)
                .find_map(|reason| message(&reason["message"]))))
        .unwrap_or("Native ownership, root permissions, or application coverage needs review. No placeholder bundle was created.")
}

fn project_diagnostics(input: &Value) -> Vec<Value> {
    fn clean(value: &Value, limit: usize) -> Option<&str> {
        value.as_str().filter(|text| {
            !text.is_empty() && text.len() <= limit && !text.chars().any(char::is_control)
        })
    }
    let mut output = Vec::new();
    for diagnostic in input.as_array().into_iter().flatten().take(256) {
        if output.len() == 256 {
            break;
        }
        let mut item = super::boundary::copy_fields(diagnostic, &["appId", "code"]);
        if let Some(name) = diagnostic
            .get("displayName")
            .or_else(|| diagnostic.get("name"))
            .and_then(|value| clean(value, 512))
        {
            item["name"] = json!(name);
        }
        item["message"] = json!(diagnostic_message(diagnostic));
        output.push(item.clone());
        for root in diagnostic["rootDiagnostics"]
            .as_array()
            .into_iter()
            .flatten()
            .take(48)
        {
            if output.len() == 256 {
                break;
            }
            let role = clean(&root["role"], 64).unwrap_or("application");
            let stage = clean(&root["stage"], 128).unwrap_or("native metadata");
            let reason = clean(&root["reason"], 1024)
                .unwrap_or("Native access or root identity could not be verified.");
            let subject = match clean(&root["inspectionSide"], 32) {
                Some("protected") => "Protected-folder safety check".to_owned(),
                Some("both" | "undetermined") => "Folder-overlap safety check".to_owned(),
                _ => format!("{role} root"),
            };
            let mut detail = super::boundary::copy_fields(&item, &["appId", "name"]);
            detail["code"] = json!("native_root_unavailable");
            detail["message"] = json!(match clean(&root["relativePath"], 1024) {
                Some(relative) => format!("{subject}, {stage}: {reason} Entry: {relative}"),
                None => format!("{subject}, {stage}: {reason}"),
            });
            if let Some(path) = clean(&root["path"], 4096) {
                detail["path"] = json!(path);
            } else if let Some(path) = clean(&root["protectedRootPath"], 4096) {
                detail["path"] = json!(path);
            }
            output.push(detail);
        }
    }
    output
}

/// `input` is assembled solely from trusted Rust discovery and the spent native
/// tracking ticket. This helper is not an IPC dispatcher.
pub(super) fn materialize(
    store: &WorkspaceStore,
    tracker: &Tracker,
    input: &Value,
) -> Result<Value> {
    let report = input
        .get("report")
        .context("Native discovery report is missing")?;
    let candidates = report["bundlePlans"]
        .as_array()
        .context("Verified native plans are missing")?;
    ensure!(
        candidates.len() <= 4096,
        "Native application plan count exceeds its bound"
    );
    let policy = enrollment_policy(store, input)?;
    let scope = &policy["policyScope"];
    let discovery_scope = json!({"version":1,"source":"verified_native_discovery",
        "policyHash":blake3::hash(&serde_json::to_vec(scope)?).to_hex().to_string(),
        "candidatesHash":blake3::hash(&serde_json::to_vec(candidates)?).to_hex().to_string(),
    });
    let grant = store.issue_grant("bundle_discovery", &discovery_scope)?;
    let authority = json!({"policyScope":scope,"policyGrant":policy["policyGrant"],
        "discoveryScope":discovery_scope,"discoveryGrant":grant});
    let mut output = tracker.materialize_bundles(candidates, &authority)?;
    let diagnostics = output["diagnostics"]
        .as_array_mut()
        .context("Materialization diagnostics are unavailable")?;
    for diagnostic in report
        .get("diagnostics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            report
                .get("unresolvedApplications")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .take(256usize.saturating_sub(diagnostics.len()))
    {
        diagnostics.push(super::boundary::copy_fields(
            diagnostic,
            &[
                "appId",
                "displayName",
                "code",
                "message",
                "unresolvedReasons",
            ],
        ));
    }
    output["incomplete"] = json!(
        output["incomplete"] == true
            || report["inventoryIncomplete"] == true
            || report["unresolvedApplications"]
                .as_array()
                .is_some_and(|apps| !apps.is_empty())
    );
    output["enabled"] = json!(true);
    Ok(output)
}

/// Create/verify the real persistent policy before any inventory metadata read,
/// not merely after discovery when materialization happens.
pub(super) fn enrollment_policy(store: &WorkspaceStore, input: &Value) -> Result<Value> {
    let policy = if input["replacePolicy"] == true {
        let native = input
            .get("nativeScope")
            .context("The native tracking scope is missing")?;
        let paths = native["baseDirectories"]
            .as_array()
            .context("Native tracking bases are missing")?;
        ensure!(
            !paths.is_empty() && paths.len() <= 32,
            "Native tracking base count is invalid"
        );
        let requested = input.get("roles").and_then(Value::as_array);
        let mut roles: BTreeSet<String> = match requested {
            Some(roles) => roles
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .context("Invalid native root role")
                })
                .collect::<Result<_>>()?,
            None => ["installation", "save", "config", "runtime"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        };
        ensure!(
            !roles.is_empty()
                && roles
                    .iter()
                    .all(|role| ["installation", "save", "config", "runtime"]
                        .contains(&role.as_str())),
            "Invalid native role policy"
        );
        // Exact app-owned container/data mappings belong to save/config coverage,
        // not arbitrary permission to read all of AppData/Application Support.
        if roles.contains("save") || roles.contains("config") {
            roles.extend(
                ["container", "group_container", "data"]
                    .into_iter()
                    .map(str::to_owned),
            );
        }
        let mut bases = Vec::new();
        let mut seen = BTreeSet::new();
        for path in paths {
            let path = Path::new(path.as_str().context("Invalid native base path")?);
            ensure!(path.is_absolute(), "Native tracking base must be absolute");
            let pinned = match SafeRoot::open(path) {
                Ok(pinned) => pinned,
                Err(_) => continue, // Absent/denied bases create no authority.
            };
            let identity = pinned.identity()?;
            if input["replacePolicy"] == true {
                let proofs = input["_approvedPaths"]
                    .as_array()
                    .context("Native enrollment base proofs are missing")?;
                let proof = proofs
                    .iter()
                    .find(|proof| proof["path"].as_str() == path.to_str())
                    .context("A native enrollment base was not approved")?;
                ensure!(
                    proof["kind"] == "directory"
                        && proof["identity"] == serde_json::to_value(&identity)?,
                    "Native-approved enrollment base identity changed"
                );
            }
            if !seen.insert((identity.device, identity.file_id)) {
                continue;
            }
            let id = format!(
                "base-{}",
                blake3::hash(
                    path.as_os_str()
                        .to_str()
                        .context("Non-UTF8 native base")?
                        .as_bytes()
                )
                .to_hex()
            );
            bases.push(json!({"id":id,"path":path,"identity":identity,
                "allowedRoles":roles,"ownershipRules":OWNERSHIP}));
        }
        ensure!(
            !bases.is_empty(),
            "No eligible native installation/data bases are available for tracking"
        );
        let scope = json!({
            "version":1,"policyId":uuid::Uuid::new_v4().to_string(),"rolePolicyVersion":1,
            "source":"verified_native_discovery","enabled":true,"baseDirectories":bases,
            "appIdentityPolicy":{"allowedAppIds":[],"allowNewVerifiedApps":true,
                "allowedEvidenceKinds":OWNERSHIP,"allowNativeInstallationOnly":true},
            "excludedPaths":native["excludedPaths"],
            "providerId":input.get("defaultProviderId").unwrap_or(&Value::Null),
        });
        let grant = store.issue_grant("app_tracking_policy", &scope)?;
        let policy = json!({"policyScope":scope,"policyGrant":grant});
        store.set_app_tracking_policy(&policy)?;
        policy
    } else {
        store
            .app_tracking_policy()?
            .context("Automatic app tracking is disabled or its native policy was revoked")?
    };
    Ok(policy)
}

pub(super) fn discovery_authority(store: &WorkspaceStore, input: &Value) -> Result<Value> {
    let policy = enrollment_policy(store, input)?;
    let bases = policy["policyScope"]["baseDirectories"]
        .as_array()
        .context("Native enrollment policy has no approved bases")?;
    let mut proofs = Vec::new();
    for base in bases {
        let path = Path::new(
            base["path"]
                .as_str()
                .context("Native policy base path is missing")?,
        );
        let root = SafeRoot::open(path)?;
        ensure!(
            serde_json::to_value(root.identity()?)? == base["identity"],
            "The approved discovery base identity changed"
        );
        proofs.push(json!({"path":path,"kind":"directory","identity":base["identity"]}));
    }
    Ok(
        json!({"baseDirectories":proofs,"excludedPaths":policy["policyScope"]["excludedPaths"],
        "policyId":policy["policyScope"]["policyId"]}),
    )
}

impl super::WorkspaceService {
    pub(super) fn app_tracking_status(&self) -> Result<Value> {
        let mut status = self
            .app_tracking
            .lock()
            .map_err(|_| anyhow::anyhow!("Native tracking status lock failed"))?
            .clone();
        let completed = status["completedApplications"].as_u64().unwrap_or(0);
        let total = status["totalApplications"]
            .as_u64()
            .unwrap_or(completed)
            .max(completed);
        status["completedApps"] = json!(completed);
        status["totalApps"] = json!(total);
        let diagnostics = project_diagnostics(&status["diagnostics"]);
        status["diagnostics"] = json!(diagnostics);
        Ok(status)
    }

    pub(super) fn start_app_tracking(&self, params: Value, replace_policy: bool) -> Result<Value> {
        let native_scope = self.discovery.tracking_scope()?;
        let service = self.strong()?;
        let active = super::Active::acquire(&self.lifetime, false)?;
        {
            let mut status = self
                .app_tracking
                .lock()
                .map_err(|_| anyhow::anyhow!("Native tracking status lock failed"))?;
            ensure!(
                status["scanning"] != true,
                "Application indexing is already active"
            );
            *status = json!({"enabled":true,"state":"scanning","scanning":true,"canRefresh":false,
                "phase":"discovering_verified_roots","completedApplications":0,"diagnostics":[]});
        }
        let task = tokio::spawn(async move {
            let _active = active;
            let result = async {
                let mut policy = json!({"nativeScope":native_scope,"replacePolicy":replace_policy});
                for field in ["roles", "defaultProviderId", "_approvedPaths"] {
                    if let Some(value) = params.get(field) {
                        policy[field] = value.clone();
                    }
                }
                let authority = service
                    .tracking_call("app_discovery_authority", policy)
                    .await?;
                let discovery = service.discovery.clone();
                let report = tokio::task::spawn_blocking(move || {
                    discovery.software_bundles_approved(&authority)
                })
                .await
                .context("Native inventory worker failed")??;
                super::boundary::bounded(&report, 64 * 1024 * 1024)?;
                if let Ok(mut status) = service.app_tracking.lock() {
                    status["phase"] = json!("materializing_real_file_indices");
                    status["totalApplications"] =
                        json!(report["bundlePlans"].as_array().map_or(0, Vec::len));
                }
                let input = json!({"report":report,"replacePolicy":false});
                service.tracking_call("materialize_bundles", input).await
            }
            .await;
            let status = match result {
                Ok(result) => {
                    let count = result["bundles"].as_array().map_or(0, Vec::len);
                    json!({"enabled":true,"state":"ready","scanning":false,"canRefresh":true,
                        "phase":"indexed","completedApplications":count,"indexedApplications":count,
                        "incomplete":result["incomplete"],"diagnostics":result["diagnostics"],
                        "observation":result["observation"]})
                }
                Err(_) => json!({"enabled":true,"state":"error","scanning":false,"canRefresh":true,
                    "phase":"reconciliation_required","error":"Native application indexing could not complete safely. Existing revisions are retained; no placeholder bundles were created.",
                    "diagnostics":[{"code":"native_index_reconciliation_required","message":"Review native filesystem permissions and the approved application-root policy before refreshing."}]}),
            };
            if let Ok(mut stored) = service.app_tracking.lock() {
                *stored = status;
            }
        });
        self.remember_task(task)?;
        Ok(json!({"appTracking":self.app_tracking_status()?}))
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn unresolved_apps_preserve_the_actual_native_reason_instead_of_generic_fallback() {
        let diagnostic = json!({"displayName":"Synthetic.app","unresolvedReasons":[
            {"code":"installation_identity_unverified",
             "message":"App installation is linked, missing, denied or not a real directory."}
        ]});
        assert_eq!(
            diagnostic_message(&diagnostic),
            "App installation is linked, missing, denied or not a real directory."
        );
        assert_eq!(
            diagnostic_message(&json!({"message":"Explicit native reason"})),
            "Explicit native reason"
        );
    }

    #[test]
    fn invalid_native_reason_text_is_not_forwarded() {
        let diagnostic = json!({"message":"bad\nmessage","unresolvedReasons":[
            {"message":"x".repeat(4097)},{"message":"Bounded native diagnosis"}
        ]});
        assert_eq!(diagnostic_message(&diagnostic), "Bounded native diagnosis");
    }

    #[test]
    fn protected_policy_failures_are_not_presented_as_an_unreadable_application() {
        let projected = project_diagnostics(&json!([{
            "displayName":"Synthetic application","message":"Policy inspection failed",
            "rootDiagnostics":[{"role":"install","inspectionSide":"protected",
                "stage":"inspect_policy_overlap","reason":"Permission denied",
                "path":"/synthetic/protected","selectedRootPath":"/synthetic/app"}],
        }]));
        assert_eq!(projected[1]["path"], "/synthetic/protected");
        assert!(projected[1]["message"]
            .as_str()
            .unwrap()
            .starts_with("Protected-folder safety check"));
        assert!(!projected[1]["message"]
            .as_str()
            .unwrap()
            .contains("install root"));
    }

    #[test]
    fn root_denials_reach_the_ui_with_name_stage_and_approved_path() {
        let result = project_diagnostics(&json!([{
            "appId":"native-instance","displayName":"Synthetic",
            "message":"Independent-root coverage is partial.",
            "rootDiagnostics":[{"role":"save","stage":"enumerate_metadata",
                "reason":"Permission denied (os error 13)",
                "path":"/synthetic/approved","relativePath":"private-directory",
                "grant":{"mustNeverReachUi":true}}],
        }]));
        assert_eq!(result.len(), 2);
        assert_eq!(result[1]["name"], "Synthetic");
        assert_eq!(result[1]["path"], "/synthetic/approved");
        assert!(result[1]["message"]
            .as_str()
            .unwrap()
            .contains("enumerate_metadata"));
        assert!(result[1]["message"]
            .as_str()
            .unwrap()
            .contains("private-directory"));
        assert!(result[1].get("grant").is_none());
        let oversized = project_diagnostics(&json!(vec![
            json!({
                "message":"Synthetic","rootDiagnostics":vec![json!({
                    "reason":"Denied","path":"/synthetic","role":"save","stage":"metadata",
                });48],
            });
            256
        ]));
        assert_eq!(oversized.len(), 256);
    }
}
