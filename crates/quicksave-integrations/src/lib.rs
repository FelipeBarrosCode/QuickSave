// SPDX-License-Identifier: GPL-3.0-only
//! Read-only metadata discovery, not an application-backup implementation.
//!
//! Discovery never grants filesystem, backup, restore, credential or network
//! authority. Installation metadata is not evidence of ownership of similarly
//! named save/config folders. The engine must separately approve and pin roots.

mod discovery;
pub mod native;
pub mod parsers;
pub mod profiles;
pub mod providers;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod reader;

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
        "profiles": profiles::static_profiles(),
        "providers": providers::capabilities(),
        "native_helpers": native::capabilities(),
        "backup_authority": DiscoveryAuthority::NotGranted,
        "requires_explicit_root_approval": true,
        "application_atomic_capture": false,
        "automatic_cloud_deletion": false,
        "limitations": [
            "Discovery reads installation metadata only and never grants backup authority.",
            "No title/basename matching is used to infer save or config ownership.",
            "Save/config directories require an explicit manual mapping and approval.",
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
