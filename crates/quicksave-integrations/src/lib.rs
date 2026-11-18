// SPDX-License-Identifier: GPL-3.0-only
//! Native installed-software inventory and source-root plans, not backup grants.
//!
//! Discovery never grants filesystem, backup, restore, credential or network
//! authority. Installation metadata is not evidence of ownership of similarly
//! named save/config folders. The engine must separately approve and pin roots.

pub mod bundles;
mod discovery;
pub mod native;
pub mod parsers;
pub mod profiles;
pub mod providers;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod reader;

pub use bundles::{
    discover_software_bundles, discover_software_bundles_in_scope,
    discover_software_bundles_with_approved_bases, discover_software_bundles_with_backend,
    ApprovedBundleBase, ApprovedDiscoveryBase, BundleInventoryScope, BundlePlanLimits,
    NativeApprovedBundleBackend, SoftwareBundleBackend, SoftwareBundlePlan, SoftwareBundleReport,
    SourceAppIdentity, SourceLauncherKind,
};
pub use discovery::{
    discover_applications, DiscoveredApplication, DiscoveredRoot, DiscoveryAuthority,
    DiscoveryDiagnostic, DiscoveryLimits, DiscoveryReport, DiscoverySource,
};
pub use profiles::{AppIdentity, Architecture, Platform};
pub use providers::TypedProviderConfig;

/// Reports implemented capabilities separately from planned integration contracts.
/// No probes, processes, keychain access or network requests are performed.
pub fn integration_capabilities() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "discovery": discovery::capabilities(),
        "bundle_planning": {
            "status": if cfg!(any(target_os = "macos", target_os = "linux")) { "implemented_read_only" } else { "explicit_adapter_required" },
            "entry_point": "discover_software_bundles",
            "tracking_policy_entry_point": "discover_software_bundles_with_approved_bases",
            "tracking_proofs": "retained native Rust SafeRoot capabilities; not deserializable authority",
            "external_steam_libraries": "require separate retained exact native library/base proofs",
            "verified_native_source_roots": true,
            "unresolved_apps_are_not_bundles": true,
            "real_content_index": "required_from_engine_after_native_consent",
            "display_names_authorize_ownership": false,
            "macos_group_evidence": "validated_existing_signature_entitlements_via_security_api",
            "approved_macos_group_evidence": "unconfirmed; path-only Security APIs are not called across native capability boundaries",
            "macos_framework_links": "engine_must_preserve_safe_relative_link_metadata_without_traversal",
            "windows": "explicit_registry_package_known_folder_adapter_only",
            "limits": bundles::BundlePlanLimits::default(),
            "content_scan_authorized": false,
            "tracking_authorized": false,
            "upload_authorized": false
        },
        "profiles": profiles::static_profiles(),
        "providers": providers::capabilities(),
        "native_helpers": native::capabilities(),
        "backup_authority": DiscoveryAuthority::NotGranted,
        "requires_explicit_root_approval": true,
        "application_atomic_capture": false,
        "automatic_cloud_deletion": false,
        "limitations": [
            "Discovery reads bounded installation/container metadata and native source identities, never backup authority or save/config contents.",
            "No title/basename matching is used to infer save or config ownership.",
            "Exact platform-ID and signed-container mappings are proposed automatically; unresolved external save/config ownership requires a reviewed exact mapping.",
            "A stable-file folder capture is not an application-consistent snapshot.",
            "Only the native engine's local filesystem repository is currently available.",
            "OS vaults, observers, snapshot helpers and cloud transports are not implemented."
        ]
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn capability_report_does_not_claim_cloud_or_authority() {
        let report = super::integration_capabilities();
        assert_eq!(report["backup_authority"], "not_granted");
        assert_eq!(report["application_atomic_capture"], false);
        assert_eq!(report["requires_explicit_root_approval"], true);
        assert_eq!(report["providers"][0]["status"], "available");
        for provider in report["providers"].as_array().unwrap().iter().skip(1) {
            assert_eq!(provider["status"], "planned");
        }
    }
}
