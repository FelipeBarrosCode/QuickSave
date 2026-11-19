// SPDX-License-Identifier: GPL-3.0-only
//! Identity-based, read-only installed-software bundle plans. A plan is not a grant.

mod approved;
mod backend;
#[cfg(target_os = "macos")]
pub(crate) mod mac_inventory;
#[cfg(target_os = "macos")]
mod mac_security;
mod planner;
#[cfg(test)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests;

pub use approved::{
    discover_software_bundles_with_approved_bases, ApprovedBundleBase, ApprovedDiscoveryBase,
    NativeApprovedBundleBackend,
};
pub use backend::{
    BackendKind, DirectoryEntries, FixtureBundleBackend, MacApplicationInventory,
    MacSigningEvidence, MetadataDocument, NativeIdentity, NativeNode, NativeNodeKind,
    SoftwareBundleBackend, WindowsInstallation, WindowsKnownFolder, WindowsProductIdentity,
    WindowsReviewedMapping,
};
pub use planner::{
    discover_software_bundles, discover_software_bundles_in_scope,
    discover_software_bundles_with_backend,
};

use crate::profiles::Platform;
use crate::DiscoveryAuthority;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleInventoryScope {
    pub application_directories: Vec<PathBuf>,
    pub desktop_directories: Vec<PathBuf>,
    pub steam_roots: Vec<PathBuf>,
    pub home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    /// Permission to inspect *metadata/path identities* for these numeric IDs,
    /// never approval to scan/save their contents. No account metadata is read.
    pub inventory_approved_steam_app_ids: BTreeSet<u32>,
    pub windows_known_folders: BTreeMap<WindowsKnownFolder, PathBuf>,
    /// Include the service's state, repositories, vaults and staging roots.
    pub protected_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundlePlanLimits {
    pub max_applications: usize,
    pub max_directories: usize,
    pub max_entries_per_directory: usize,
    pub max_total_entries: usize,
    pub max_metadata_bytes_per_file: usize,
    pub max_total_metadata_bytes: usize,
    pub max_roots_per_application: usize,
    pub max_total_planned_roots: usize,
    pub max_total_plan_bytes: usize,
    pub max_diagnostics: usize,
    pub max_installation_depth: usize,
}

impl Default for BundlePlanLimits {
    fn default() -> Self {
        Self {
            max_applications: 4096,
            max_directories: 1024,
            max_entries_per_directory: 4096,
            max_total_entries: 65536,
            max_metadata_bytes_per_file: 1024 * 1024,
            max_total_metadata_bytes: 64 * 1024 * 1024,
            max_roots_per_application: 48,
            max_total_planned_roots: 32768,
            max_total_plan_bytes: 32 * 1024 * 1024,
            max_diagnostics: 256,
            max_installation_depth: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootClassification {
    Installer,
    Install,
    Runtime,
    Save,
    Config,
    Container,
    GroupContainer,
    Data,
    UserReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedRootStatus {
    VerifiedCandidate,
    Unresolved,
    Ambiguous,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    NativeInstallation,
    ExactPlatformIdentifier,
    SignedApplicationGroup,
    ReviewedExactProductMapping,
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityEvidence {
    pub kind: &'static str,
    pub identifier: String,
    pub metadata_path: Option<PathBuf>,
    pub native_identity: Option<NativeIdentity>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnresolvedReason {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootExclusions {
    /// Denial rules, not positive ownership heuristics. Consumers must enforce
    /// them handle-relatively, including in descendants, before content capture.
    pub case_insensitive_path_components: Vec<&'static str>,
    /// The actual absolute paths appear once in the report rather than being
    /// replicated into every root (which could otherwise expand without bound).
    pub protected_root_policy: &'static str,
    pub symlink_and_reparse_traversal: bool,
    pub credential_and_vault_material: bool,
    pub quicksave_state: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSoftwareRoot {
    pub root_id: String,
    pub path: Option<PathBuf>,
    pub classification: RootClassification,
    pub roles: Vec<RootClassification>,
    pub native_identity: Option<NativeIdentity>,
    pub status: PlannedRootStatus,
    pub confidence: IdentityConfidence,
    pub evidence: Vec<IdentityEvidence>,
    pub unresolved_reasons: Vec<UnresolvedReason>,
    pub exclusions: RootExclusions,
    /// Containers describe a boundary; choose reviewed non-overlapping child
    /// roots rather than automatically selecting every container and child.
    pub ownership: &'static str,
    pub required_root_capabilities: Vec<&'static str>,
    pub requires_user_review: bool,
    pub content_scan_authorized: bool,
    pub tracking_authorized: bool,
    pub upload_authorized: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileMatchPolicy {
    pub policy_id: &'static str,
    pub allowed_identity_evidence: Vec<&'static str>,
    pub titles_and_basenames_authorize_ownership: bool,
    pub inferred_executable_parent_authorizes_ownership: bool,
    pub exact_product_match_required: bool,
    pub ambiguous_identity_policy: &'static str,
    pub selection_policy: &'static str,
}

impl Default for ProfileMatchPolicy {
    fn default() -> Self {
        Self {
            policy_id: "native-exact-identity-bundle-v1",
            allowed_identity_evidence: vec![
                "native_installation_handle",
                "cf_bundle_identifier_and_executable_handle",
                "container_metadata_identifier",
                "validated_signed_application_group",
                "xdg_desktop_or_flatpak_identifier",
                "exact_numeric_steam_app_id",
                "windows_registry_or_package_identity",
                "reviewed_exact_product_mapping",
            ],
            titles_and_basenames_authorize_ownership: false,
            inferred_executable_parent_authorizes_ownership: false,
            exact_product_match_required: true,
            ambiguous_identity_policy: "refuse_data_root_association",
            selection_policy: "explicit_native_approval_of_non_overlapping_roots",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareBundlePlan {
    pub app_id: String,
    pub product_id: Option<String>,
    /// Untrusted UI text, not an ownership key.
    pub display_name: String,
    pub source: &'static str,
    pub platform: Platform,
    pub installation_identity: Option<NativeIdentity>,
    pub executable_identity: Option<NativeIdentity>,
    /// No Land AppIdentity-compatible snake_case payload. Present only for a
    /// plan backed by verified native source roots; never an incoming grant.
    pub source_identity: Option<SourceAppIdentity>,
    /// Actual verified native source identities, not a content index or a
    /// materialized No Land/Tracker bundle. Engine indexing requires consent.
    pub source_roots: Vec<PlannedSoftwareRoot>,
    /// Diagnostic proposals only; never counted as verified source roots.
    pub unresolved_roots: Vec<PlannedSoftwareRoot>,
    pub identity_evidence: Vec<IdentityEvidence>,
    pub unresolved_reasons: Vec<UnresolvedReason>,
    pub roots_complete: bool,
    pub profile_match_policy: ProfileMatchPolicy,
    pub backup_authority: DiscoveryAuthority,
    pub content_scan_authorized: bool,
    pub tracking_authorized: bool,
    pub upload_authorized: bool,
}

/// Dependency-free wire equivalent of No Land's AppIdentity. Product identity
/// is separate from SoftwareBundlePlan.appId's installation-specific native ID.
/// `canonical_executable` means the exact no-follow verified native file path;
/// no `canonicalize`, executable-parent inference, title matching or launch is
/// performed. Unknown launcher/executable/icon/aliases are not fabricated.
#[derive(Debug, Clone, Serialize)]
pub struct SourceAppIdentity {
    pub app_id: String,
    pub display_name: String,
    pub canonical_executable: Option<PathBuf>,
    pub desktop_entry_id: Option<String>,
    pub steam_app_id: Option<u32>,
    pub launcher: Option<SourceLauncherKind>,
    pub aliases: Vec<String>,
    /// Deterministic exact-match score, not a measured probability, content
    /// completeness claim, process verification or backup authority.
    pub identity_confidence: f32,
    pub icon_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLauncherKind {
    Steam,
    Flatpak,
    Native,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundlePlanDiagnostic {
    pub code: &'static str,
    pub path: Option<PathBuf>,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareBundleReport {
    pub schema_version: u32,
    pub platform: Platform,
    pub backend: BackendKind,
    /// Nonempty verified source plans only. There is deliberately no
    /// "tracked/backed-up bundle count" in a metadata inventory response.
    pub bundle_plans: Vec<SoftwareBundlePlan>,
    /// Every discovered app lacking a verified installation/runtime/data root
    /// remains visible here, not as a placeholder bundle.
    pub unresolved_applications: Vec<SoftwareBundlePlan>,
    pub discovered_applications: usize,
    pub omitted_applications: usize,
    pub protected_source_roots: Vec<PathBuf>,
    pub diagnostics: Vec<BundlePlanDiagnostic>,
    pub omitted_diagnostics: usize,
    pub inventory_incomplete: bool,
    pub examined_entries: usize,
    /// Bytes accepted from stable bounded metadata reads, not a physical-I/O or
    /// hashing benchmark (failed/rejected native reads are not measured here).
    pub accepted_metadata_bytes: usize,
    pub limits: BundlePlanLimits,
    pub backup_authority: DiscoveryAuthority,
    pub content_scan_authorized: bool,
    pub tracking_authorized: bool,
    pub upload_authorized: bool,
    pub application_atomic_capture: bool,
    pub native_packaging_acceptance: bool,
}
