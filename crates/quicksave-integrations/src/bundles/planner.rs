// SPDX-License-Identifier: GPL-3.0-only
use super::backend::{validate_path, NativeFilesystemBackend};
use super::*;
use crate::parsers::{desktop, macos, steam};
use anyhow::{ensure, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// Ambient read-only metadata inventory. The caller is responsible for native
/// inventory consent before invoking this, and for consent-backed engine
/// indexing before calling a result a tracked bundle. No content grant is made.
pub fn discover_software_bundles() -> Result<serde_json::Value> {
    let scope = BundleInventoryScope::from_environment()?;
    discover_software_bundles_in_scope(&scope)
}

pub fn discover_software_bundles_in_scope(
    scope: &BundleInventoryScope,
) -> Result<serde_json::Value> {
    ensure!(
        cfg!(any(target_os = "macos", target_os = "linux")),
        "native Windows registry/package/Known Folder discovery and no-reparse inventory handles are not implemented; supply an explicit native adapter"
    );
    discover_software_bundles_with_backend(
        &mut NativeFilesystemBackend,
        scope,
        BundlePlanLimits::default(),
    )
}

/// Injection point for trusted native adapters and isolated filesystem fixtures.
/// This returns plans, not an index, tracked bundles, or backup success.
pub fn discover_software_bundles_with_backend(
    backend: &mut dyn SoftwareBundleBackend,
    scope: &BundleInventoryScope,
    limits: BundlePlanLimits,
) -> Result<serde_json::Value> {
    validate_scope(scope, limits)?;
    ensure!(
        backend.platform() != Platform::Unknown,
        "unknown inventory platform"
    );
    let mut planner = Planner::new(backend, scope, limits);
    match planner.report.platform {
        Platform::MacOs => planner.scan_mac(),
        Platform::Linux => planner.scan_desktop(),
        Platform::Windows => planner.scan_windows()?,
        Platform::Unknown => unreachable!(),
    }
    planner.scan_steam();
    planner
        .report
        .bundle_plans
        .sort_by(|a, b| a.app_id.cmp(&b.app_id));
    planner
        .report
        .unresolved_applications
        .sort_by(|a, b| a.app_id.cmp(&b.app_id));
    Ok(serde_json::to_value(planner.report)?)
}

impl BundleInventoryScope {
    /// Reads location variables only, never real application/account/vault data.
    pub fn from_environment() -> Result<Self> {
        let mut scope = Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            ..Self::default()
        };
        if let Some(home) = &scope.home {
            validate_path(home)?;
        }
        match Platform::current() {
            Platform::MacOs => {
                scope.application_directories = [
                    "/Applications",
                    "/System/Applications",
                    "/System/Library/CoreServices/Applications",
                ]
                .into_iter()
                .map(PathBuf::from)
                .collect();
                if let Some(home) = &scope.home {
                    scope
                        .application_directories
                        .push(home.join("Applications"));
                    scope
                        .steam_roots
                        .push(home.join("Library/Application Support/Steam"));
                }
            }
            Platform::Linux => {
                scope.xdg_data_home = std::env::var_os("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .or_else(|| scope.home.as_ref().map(|p| p.join(".local/share")));
                scope.xdg_config_home = std::env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .or_else(|| scope.home.as_ref().map(|p| p.join(".config")));
                if let Some(data) = &scope.xdg_data_home {
                    scope.desktop_directories.push(data.join("applications"));
                }
                let directories = std::env::var_os("XDG_DATA_DIRS")
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
                ensure!(
                    directories.len() <= 16384,
                    "XDG_DATA_DIRS exceeds input limit"
                );
                for (index, path) in std::env::split_paths(&directories).enumerate() {
                    ensure!(index < 16, "too many XDG data directories");
                    validate_path(&path)?;
                    let applications = path.join("applications");
                    if !scope.desktop_directories.contains(&applications) {
                        scope.desktop_directories.push(applications);
                    }
                }
                if let Some(home) = &scope.home {
                    scope
                        .desktop_directories
                        .push(home.join(".local/share/flatpak/exports/share/applications"));
                    for path in [
                        ".local/share/Steam",
                        ".steam/steam",
                        ".steam/debian-installation",
                        ".var/app/com.valvesoftware.Steam/data/Steam",
                    ] {
                        scope.steam_roots.push(home.join(path));
                    }
                }
                scope
                    .desktop_directories
                    .push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
                scope.steam_roots.push(PathBuf::from("/usr/share/steam"));
            }
            _ => anyhow::bail!(
                "ambient native software bundle inventory is unsupported on this platform"
            ),
        }
        Ok(scope)
    }
}

fn validate_scope(scope: &BundleInventoryScope, limits: BundlePlanLimits) -> Result<()> {
    let hard = BundlePlanLimits::default();
    ensure!(
        limits.max_applications > 0
            && limits.max_applications <= hard.max_applications
            && limits.max_directories > 0
            && limits.max_directories <= hard.max_directories
            && limits.max_entries_per_directory > 0
            && limits.max_entries_per_directory <= hard.max_entries_per_directory
            && limits.max_total_entries > 0
            && limits.max_total_entries <= hard.max_total_entries
            && limits.max_metadata_bytes_per_file > 0
            && limits.max_metadata_bytes_per_file <= hard.max_metadata_bytes_per_file
            && limits.max_total_metadata_bytes > 0
            && limits.max_total_metadata_bytes <= hard.max_total_metadata_bytes
            && limits.max_roots_per_application >= 2
            && limits.max_roots_per_application <= hard.max_roots_per_application
            && limits.max_total_planned_roots > 0
            && limits.max_total_planned_roots <= hard.max_total_planned_roots
            && limits.max_total_plan_bytes > 0
            && limits.max_total_plan_bytes <= hard.max_total_plan_bytes
            && limits.max_diagnostics > 0
            && limits.max_diagnostics <= hard.max_diagnostics
            && limits.max_installation_depth <= hard.max_installation_depth,
        "bundle inventory limits must be positive and within hard bounds"
    );
    let paths: Vec<&PathBuf> = scope
        .application_directories
        .iter()
        .chain(&scope.desktop_directories)
        .chain(&scope.steam_roots)
        .chain(scope.home.iter())
        .chain(scope.xdg_data_home.iter())
        .chain(scope.xdg_config_home.iter())
        .chain(scope.windows_known_folders.values())
        .chain(&scope.protected_roots)
        .collect();
    ensure!(
        paths.len() <= 128 && scope.inventory_approved_steam_app_ids.len() <= 4096,
        "inventory scope exceeds bounds"
    );
    for path in paths {
        validate_path(path)?;
    }
    ensure!(
        !scope.inventory_approved_steam_app_ids.contains(&0),
        "zero is not a Steam product ID"
    );
    Ok(())
}

struct Planner<'a> {
    backend: &'a mut dyn SoftwareBundleBackend,
    scope: &'a BundleInventoryScope,
    report: SoftwareBundleReport,
    remaining_entries: usize,
    remaining_metadata: usize,
    directories: usize,
    planned_roots: usize,
    remaining_plan_bytes: usize,
    protected: Vec<PathBuf>,
    seen_installations: BTreeSet<(String, NativeIdentity)>,
}

struct MacInstallation {
    plan: SoftwareBundlePlan,
    bundle: PathBuf,
    bundle_id: Option<String>,
    executable_node: Option<NativeNode>,
}

enum NativeProbe {
    Verified(NativeNode),
    Missing,
    PermissionDenied,
    Rejected,
}

impl<'a> Planner<'a> {
    fn new(
        backend: &'a mut dyn SoftwareBundleBackend,
        scope: &'a BundleInventoryScope,
        limits: BundlePlanLimits,
    ) -> Self {
        let mut protected = scope.protected_roots.clone();
        if let Some(home) = &scope.home {
            for relative in [
                "Library/Keychains",
                "Library/Application Support/com.noland.connect",
                "Library/Containers/com.noland.connect",
                "Library/Application Support/QuickSave",
                ".local/share/com.noland.connect",
                ".config/com.noland.connect",
                ".quicksave",
                ".config/quicksave",
                ".local/share/quicksave",
                ".ssh",
                ".gnupg",
                ".aws",
                ".azure",
                ".config/gcloud",
            ] {
                protected.push(home.join(relative));
            }
        }
        for anchor in scope
            .xdg_data_home
            .iter()
            .chain(scope.xdg_config_home.iter())
            .chain(scope.windows_known_folders.values())
        {
            protected.push(anchor.join("com.noland.connect"));
            protected.push(anchor.join("QuickSave"));
        }
        protected.sort();
        protected.dedup();
        Self {
            report: SoftwareBundleReport {
                schema_version: 1,
                platform: backend.platform(),
                backend: backend.kind(),
                bundle_plans: Vec::new(),
                unresolved_applications: Vec::new(),
                discovered_applications: 0,
                omitted_applications: 0,
                protected_source_roots: protected.clone(),
                diagnostics: Vec::new(),
                omitted_diagnostics: 0,
                inventory_incomplete: false,
                examined_entries: 0,
                accepted_metadata_bytes: 0,
                limits,
                backup_authority: DiscoveryAuthority::NotGranted,
                content_scan_authorized: false,
                tracking_authorized: false,
                upload_authorized: false,
                application_atomic_capture: false,
                native_packaging_acceptance: false,
            },
            backend,
            scope,
            remaining_entries: limits.max_total_entries,
            remaining_metadata: limits.max_total_metadata_bytes,
            directories: 0,
            planned_roots: 0,
            remaining_plan_bytes: limits.max_total_plan_bytes,
            protected,
            seen_installations: BTreeSet::new(),
        }
    }

    fn diagnostic(&mut self, code: &'static str, path: Option<&Path>, message: &'static str) {
        self.report.inventory_incomplete = true;
        self.notice(code, path, message);
    }

    // Expected policy exclusions are not missing inventory coverage. Dropped
    // notices still make the report incomplete rather than hiding truncation.
    fn notice(&mut self, code: &'static str, path: Option<&Path>, message: &'static str) {
        if self.report.diagnostics.len() < self.report.limits.max_diagnostics {
            self.report.diagnostics.push(BundlePlanDiagnostic {
                code,
                path: path.map(Path::to_owned),
                message,
            });
        } else {
            self.report.omitted_diagnostics += 1;
            self.report.inventory_incomplete = true;
        }
    }

    fn excluded(&self, path: &Path) -> bool {
        self.protected.iter().any(|p| path.starts_with(p))
            || path.components().any(|part| {
                let part = part.as_os_str().to_string_lossy().to_ascii_lowercase();
                exclusion_components().contains(&part.as_str())
            })
    }

    fn entries(&mut self, path: &Path) -> Vec<String> {
        if validate_path(path).is_err() {
            self.diagnostic(
                "invalid_inventory_path",
                None,
                "An invalid or overlong inventory path was rejected.",
            );
            return Vec::new();
        }
        if self.excluded(path) {
            self.notice(
                "protected_inventory_path",
                Some(path),
                "Inventory does not enter protected state, caches, logs or vaults.",
            );
            return Vec::new();
        }
        if self.directories >= self.report.limits.max_directories || self.remaining_entries == 0 {
            self.diagnostic(
                "directory_or_entry_limit",
                Some(path),
                "Inventory directory/entry bound reached; coverage is incomplete.",
            );
            return Vec::new();
        }
        self.directories += 1;
        let maximum = self
            .remaining_entries
            .min(self.report.limits.max_entries_per_directory);
        self.remaining_entries -= maximum;
        match self.backend.list_directory(path, maximum) {
            Ok(Some(mut listing)) => {
                if listing.names.len() > maximum
                    || listing.names.iter().any(|name| !valid_entry(name))
                {
                    self.diagnostic(
                        "invalid_adapter_listing",
                        Some(path),
                        "Adapter exceeded a listing bound or returned an unsafe entry.",
                    );
                    return Vec::new();
                }
                self.remaining_entries += maximum - listing.names.len();
                self.report.examined_entries += listing.names.len();
                listing.names.sort();
                listing.names.dedup();
                if listing.truncated {
                    self.diagnostic(
                        "entry_limit",
                        Some(path),
                        "Directory listing is truncated; undiscovered apps are not counted.",
                    );
                }
                listing.names
            }
            Ok(None) => {
                self.remaining_entries += maximum;
                Vec::new()
            }
            Err(_) => {
                self.diagnostic(
                    "unsafe_or_denied_directory",
                    Some(path),
                    "Directory is unreadable, linked, outside scope or unsupported.",
                );
                Vec::new()
            }
        }
    }

    fn read(&mut self, path: &Path, bound: usize) -> Option<MetadataDocument> {
        if validate_path(path).is_err() {
            self.diagnostic(
                "invalid_metadata_path",
                None,
                "An invalid or overlong metadata path was rejected.",
            );
            return None;
        }
        if self.excluded(path) {
            self.notice(
                "protected_metadata",
                Some(path),
                "Protected metadata is not read.",
            );
            return None;
        }
        let maximum = bound
            .min(self.report.limits.max_metadata_bytes_per_file)
            .min(self.remaining_metadata);
        if maximum == 0 {
            self.diagnostic(
                "metadata_limit",
                Some(path),
                "Total metadata budget exhausted.",
            );
            return None;
        }
        self.remaining_metadata -= maximum;
        match self.backend.read_metadata(path, maximum) {
            Ok(Some(document))
                if document.bytes.len() <= maximum
                    && document.native_identity.kind() == NativeNodeKind::RegularFile =>
            {
                self.remaining_metadata += maximum - document.bytes.len();
                self.report.accepted_metadata_bytes += document.bytes.len();
                Some(document)
            }
            Ok(None) => {
                self.remaining_metadata += maximum;
                None
            }
            _ => {
                self.diagnostic(
                    "unsafe_or_denied_metadata",
                    Some(path),
                    "Metadata was denied, changed, linked, oversized or invalid.",
                );
                None
            }
        }
    }

    fn probe(&mut self, path: &Path) -> NativeProbe {
        if validate_path(path).is_err() {
            self.diagnostic(
                "invalid_native_path",
                None,
                "An invalid or overlong source path was rejected without an existence fallback.",
            );
            return NativeProbe::Rejected;
        }
        if self.excluded(path) {
            return NativeProbe::Rejected;
        }
        match self.backend.inspect_native(path) {
            Ok(Some(node)) => NativeProbe::Verified(node),
            Ok(None) => NativeProbe::Missing,
            Err(error) if permission_denied(&error) => {
                self.diagnostic(
                    "native_permission_denied",
                    Some(path),
                    "Native OS permission denied this exact path; its contents are not scanned or treated as saved.",
                );
                NativeProbe::PermissionDenied
            }
            Err(_) => {
                self.diagnostic(
                    "unsafe_or_denied_native_identity",
                    Some(path),
                    "Native identity could not be verified; no path/exists fallback is allowed.",
                );
                NativeProbe::Rejected
            }
        }
    }

    fn inspect(&mut self, path: &Path) -> Option<NativeNode> {
        match self.probe(path) {
            NativeProbe::Verified(node) => Some(node),
            _ => None,
        }
    }

    fn room(&mut self, path: &Path) -> bool {
        if self.report.discovered_applications < self.report.limits.max_applications {
            true
        } else {
            self.diagnostic(
                "application_limit",
                Some(path),
                "Application bound reached; omitted installations are not counted or tracked.",
            );
            false
        }
    }

    fn exclusions(&self) -> RootExclusions {
        RootExclusions {
            case_insensitive_path_components: exclusion_components(),
            protected_root_policy: "exclude_report_protected_source_roots_and_descendants",
            symlink_and_reparse_traversal: true,
            credential_and_vault_material: true,
            quicksave_state: true,
        }
    }

    fn new_plan(
        &self,
        source: &'static str,
        path: &Path,
        product: Option<String>,
        native: Option<NativeIdentity>,
    ) -> SoftwareBundlePlan {
        let app_id = match (&product, &native) {
            (Some(product), Some(native)) => format!("{product}@{}", native.stable_key()),
            (None, Some(native)) => format!("unresolved-installation@{}", native.stable_key()),
            (Some(product), None) => format!("{product}@unresolved:{}", path.display()),
            (None, None) => format!("unresolved-installation:{}", path.display()),
        };
        SoftwareBundlePlan {
            app_id,
            product_id: product,
            display_name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Unresolved application")
                .to_owned(),
            source,
            platform: self.report.platform,
            installation_identity: native,
            executable_identity: None,
            source_identity: None,
            source_roots: Vec::new(),
            unresolved_roots: Vec::new(),
            identity_evidence: Vec::new(),
            unresolved_reasons: Vec::new(),
            roots_complete: false,
            profile_match_policy: ProfileMatchPolicy::default(),
            backup_authority: DiscoveryAuthority::NotGranted,
            content_scan_authorized: false,
            tracking_authorized: false,
            upload_authorized: false,
        }
    }

    fn root(
        &self,
        path: Option<PathBuf>,
        classification: RootClassification,
        identity: Option<NativeIdentity>,
        status: PlannedRootStatus,
        confidence: IdentityConfidence,
        evidence: Vec<IdentityEvidence>,
        reason: Option<UnresolvedReason>,
        ownership: &'static str,
    ) -> PlannedSoftwareRoot {
        let key = identity
            .as_ref()
            .map(NativeIdentity::stable_key)
            .unwrap_or_else(|| {
                format!(
                    "unresolved:{}",
                    path.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| format!("{classification:?}"))
                )
            });
        let mut capabilities = vec![
            "native_handle_identity_revalidation",
            "bounded_real_file_index_after_consent",
            "protected_descendant_exclusions",
            "reject_symlink_traversal_and_external_links",
        ];
        if classification == RootClassification::Install && self.report.platform == Platform::MacOs
        {
            capabilities.push("safe_relative_link_metadata_without_traversal");
        }
        PlannedSoftwareRoot {
            root_id: format!("{classification:?}:{key}"),
            path,
            classification,
            roles: vec![classification],
            native_identity: identity,
            status,
            confidence,
            evidence,
            unresolved_reasons: reason.into_iter().collect(),
            exclusions: self.exclusions(),
            ownership,
            required_root_capabilities: capabilities,
            requires_user_review: true,
            content_scan_authorized: false,
            tracking_authorized: false,
            upload_authorized: false,
        }
    }

    fn missing(
        &mut self,
        plan: &mut SoftwareBundlePlan,
        path: Option<PathBuf>,
        classification: RootClassification,
        code: &'static str,
        message: &'static str,
    ) {
        add_reason(plan, code, message);
        if plan.source_roots.len() + plan.unresolved_roots.len()
            >= self.report.limits.max_roots_per_application
        {
            add_reason(
                plan,
                "root_limit",
                "Additional root proposals exceeded the configured bound.",
            );
            self.diagnostic(
                "root_limit",
                path.as_deref(),
                "Root bound reached; coverage is incomplete.",
            );
            return;
        }
        let root = self.root(
            path,
            classification,
            None,
            PlannedRootStatus::Unresolved,
            IdentityConfidence::Unresolved,
            Vec::new(),
            Some(UnresolvedReason { code, message }),
            "unresolved",
        );
        self.append_root(plan, root);
    }

    fn append_root(&mut self, plan: &mut SoftwareBundlePlan, root: PlannedSoftwareRoot) -> bool {
        // Bound the serialized expansion, not just the number of inputs. Paths,
        // evidence and policy strings can be repeated across many app plans.
        let cost = serde_json::to_vec(&root)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        if self.planned_roots >= self.report.limits.max_total_planned_roots
            || cost > self.remaining_plan_bytes
        {
            add_reason(plan, "total_plan_output_limit", "The bounded plan-output budget was exhausted; remaining roots were not counted as verified sources.");
            self.diagnostic(
                "total_plan_output_limit",
                root.path.as_deref(),
                "Root/serialized output bound reached; coverage is incomplete.",
            );
            return false;
        }
        self.planned_roots += 1;
        self.remaining_plan_bytes -= cost;
        if root.status == PlannedRootStatus::VerifiedCandidate {
            plan.source_roots.push(root);
        } else {
            plan.unresolved_roots.push(root);
        }
        true
    }

    fn candidate(
        &mut self,
        plan: &mut SoftwareBundlePlan,
        path: &Path,
        classification: RootClassification,
        expected_kind: NativeNodeKind,
        confidence: IdentityConfidence,
        evidence: Vec<IdentityEvidence>,
        ownership: &'static str,
    ) -> bool {
        if validate_path(path).is_err() {
            self.missing(plan, None, classification, "invalid_source_path",
                "The exact mapped path is invalid or exceeds the path bound; no source root was granted.");
            return false;
        }
        if plan.source_roots.len() + plan.unresolved_roots.len()
            >= self.report.limits.max_roots_per_application
        {
            add_reason(
                plan,
                "root_limit",
                "Additional source roots exceeded the configured bound.",
            );
            self.diagnostic(
                "root_limit",
                Some(path),
                "Root bound reached; coverage is incomplete.",
            );
            return false;
        }
        if self.excluded(path) {
            add_reason(
                plan,
                "protected_source_root",
                "A protected, credential, vault, cache, log or QuickSave root was excluded.",
            );
            let root = self.root(
                Some(path.to_owned()),
                classification,
                None,
                PlannedRootStatus::Excluded,
                IdentityConfidence::Unresolved,
                evidence,
                Some(UnresolvedReason {
                    code: "protected_source_root",
                    message: "This root is excluded from content capture.",
                }),
                "excluded",
            );
            self.append_root(plan, root);
            return false;
        }
        let node = match self.probe(path) {
            NativeProbe::Verified(node) => node,
            NativeProbe::Missing => {
                self.missing(plan, Some(path.to_owned()), classification, "exact_root_absent",
                    "The exact identity-bound path is absent; it is not counted as a verified source root.");
                return false;
            }
            NativeProbe::PermissionDenied => {
                self.missing(plan, Some(path.to_owned()), classification, "native_permission_denied",
                    "Native OS permission denied this exact root. Tracking policy does not bypass the permission gap.");
                return false;
            }
            NativeProbe::Rejected => {
                self.missing(plan, Some(path.to_owned()), classification, "root_identity_rejected",
                    "The root is linked, outside scope, unsafe or otherwise unverifiable; it is not counted as a source root.");
                return false;
            }
        };
        if node.identity.kind() != expected_kind {
            self.missing(
                plan,
                Some(path.to_owned()),
                classification,
                "root_type_mismatch",
                "The native source type does not match its exact mapping.",
            );
            return false;
        }
        if classification == RootClassification::Install
            && plan
                .installation_identity
                .as_ref()
                .is_some_and(|id| *id != node.identity)
        {
            self.missing(plan, Some(path.to_owned()), classification, "installation_identity_changed",
                "The verified native installation changed during planning; the replacement is not adopted.");
            return false;
        }
        if classification == RootClassification::Runtime
            && plan
                .executable_identity
                .as_ref()
                .is_some_and(|id| *id != node.identity)
        {
            self.missing(plan, Some(path.to_owned()), classification, "executable_identity_changed",
                "The verified native executable changed during planning; the replacement is not adopted.");
            return false;
        }
        if evidence.iter().any(|item| {
            item.kind == "native_mapping_root_handle"
                && item.native_identity.as_ref() != Some(&node.identity)
        }) {
            self.missing(
                plan,
                Some(path.to_owned()),
                classification,
                "mapping_root_identity_changed",
                "The native root changed after ownership metadata inspection.",
            );
            return false;
        }
        if plan
            .source_roots
            .iter()
            .any(|root| root.path.as_deref() == Some(path) && root.classification == classification)
        {
            return true;
        }
        let root = self.root(
            Some(path.to_owned()),
            classification,
            Some(node.identity),
            PlannedRootStatus::VerifiedCandidate,
            confidence,
            evidence,
            None,
            ownership,
        );
        self.append_root(plan, root)
    }

    fn retain(&mut self, mut plan: SoftwareBundlePlan) {
        self.report.discovered_applications += 1;
        // No generic profile can establish that an app has no other external
        // state. Never claim completeness or invent file counts.
        add_reason(&mut plan, "external_state_not_proven_complete",
            "Identity-based source roots are real, but arbitrary external saves, permissions and app-wide consistency are not proven complete.");
        plan.roots_complete = false;
        plan.source_identity = verified_source_identity(&plan);
        let sources = std::mem::take(&mut plan.source_roots);
        let unresolved = std::mem::take(&mut plan.unresolved_roots);
        let cost = serde_json::to_vec(&plan)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
        plan.source_roots = sources;
        plan.unresolved_roots = unresolved;
        if cost > self.remaining_plan_bytes {
            self.report.omitted_applications += 1;
            self.diagnostic("total_plan_output_limit", None, "An observed application could not fit the bounded output; it was explicitly omitted, not counted as a bundle.");
            return;
        }
        self.remaining_plan_bytes -= cost;
        if plan.source_roots.is_empty() {
            self.report.inventory_incomplete = true;
            self.report.unresolved_applications.push(plan);
        } else {
            self.report.bundle_plans.push(plan);
        }
    }

    fn scan_mac(&mut self) {
        if self.scope.application_directories.is_empty() {
            return;
        }
        let inventory = self.backend.mac_application_inventory(
            &self.scope.application_directories,
            self.report.limits.max_applications,
        );
        let native = match inventory {
            Ok(Some(inventory)) => {
                if inventory.incomplete {
                    self.diagnostic("native_application_inventory_incomplete",None,
                        "Apple application metadata gathering was incomplete, limited or unavailable; running/registered candidates do not prove a complete installed inventory.");
                }
                self.notice("native_application_inventory_sources",None,
                    "Candidates come from Spotlight and NSWorkspace/Launch Services. Unindexed, unregistered and non-running installations may be absent; discovery grants no data access.");
                Some(inventory.paths)
            }
            Ok(None) if self.backend.kind() == BackendKind::IsolatedFixture => None,
            Err(error)
                if error
                    .downcast_ref::<super::backend::MacInventoryFailure>()
                    .is_some() =>
            {
                let failure = error
                    .downcast_ref::<super::backend::MacInventoryFailure>()
                    .unwrap();
                self.diagnostic(failure.0, None, failure.message());
                return;
            }
            _ => {
                self.diagnostic("native_application_inventory_unavailable",None,
                    "Apple application inventory is unavailable. No recursive folder-scan fallback or placeholder apps were created.");
                return;
            }
        };
        let mut installations = Vec::new();
        if let Some(paths) = native {
            if paths.len() > self.report.limits.max_applications {
                self.diagnostic(
                    "native_application_inventory_limit",
                    None,
                    "Native application inventory exceeds its bound; no candidates were admitted.",
                );
                return;
            }
            let mut seen = BTreeSet::new();
            let mut bytes = 0usize;
            for path in paths {
                if self.remaining_entries == 0 {
                    self.diagnostic(
                        "native_application_inventory_limit",
                        None,
                        "Native application hints exhausted the inventory entry budget.",
                    );
                    break;
                }
                self.remaining_entries -= 1;
                self.report.examined_entries += 1;
                if validate_path(&path).is_err()
                    || !path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
                    || !self
                        .scope
                        .application_directories
                        .iter()
                        .any(|base| path != *base && path.starts_with(base))
                    || self.excluded(&path)
                {
                    self.diagnostic("native_application_candidate_rejected",None,
                        "A native application hint was invalid, protected or outside approved bases; it was not opened.");
                    continue;
                }
                bytes = bytes.saturating_add(path.as_os_str().len());
                if bytes > 2 * 1024 * 1024 {
                    self.diagnostic(
                        "native_application_inventory_limit",
                        None,
                        "Native application path bytes exceed their bound.",
                    );
                    break;
                }
                if seen.insert(path.clone()) {
                    installations.push(self.mac_installation(&path));
                }
            }
        } else {
            // Isolated synthetic legacy fixtures only; never production discovery.
            let mut queue: VecDeque<(PathBuf, usize)> = self
                .scope
                .application_directories
                .iter()
                .cloned()
                .map(|p| (p, 0))
                .collect();
            let mut seen = BTreeSet::new();
            while let Some((root, depth)) = queue.pop_front() {
                if !seen.insert(root.clone()) {
                    continue;
                }
                for name in self.entries(&root) {
                    let path = root.join(&name);
                    if name.to_ascii_lowercase().ends_with(".app") {
                        if self.report.discovered_applications + installations.len()
                            >= self.report.limits.max_applications
                        {
                            self.diagnostic("application_limit", Some(&path), "Application bound reached; remaining discovered names are not fake bundles.");
                            break;
                        }
                        installations.push(self.mac_installation(&path));
                    } else if depth < self.report.limits.max_installation_depth {
                        // Only installation scopes, never a recursive home/data scan.
                        if self
                            .inspect(&path)
                            .is_some_and(|node| node.identity.kind() == NativeNodeKind::Directory)
                        {
                            if queue.len() + self.directories < self.report.limits.max_directories {
                                queue.push_back((path, depth + 1));
                            } else {
                                self.diagnostic("installation_directory_limit", Some(&path),
                                "The bounded installation queue is full; nested app coverage is incomplete.");
                            }
                        }
                    } else if self
                        .inspect(&path)
                        .is_some_and(|node| node.identity.kind() == NativeNodeKind::Directory)
                    {
                        self.diagnostic(
                        "installation_depth_limit",
                        Some(&path),
                        "Nested installation scope exceeds depth bound; coverage is incomplete.",
                    );
                    }
                }
            }
        }
        // Registry, metadata and running-app sources may spell the SAME native
        // installation differently. Only native identities plus the observed
        // product/executable can deduplicate it; distinct installations remain
        // ambiguous even when Launch Services prefers one of their URLs.
        let mut native_installations = BTreeSet::new();
        installations.retain(|installation| {
            installation
                .plan
                .installation_identity
                .as_ref()
                .is_none_or(|identity| {
                    native_installations.insert((
                        identity.stable_key(),
                        installation.bundle_id.clone(),
                        installation.plan.executable_identity.clone(),
                    ))
                })
        });
        let mut ids = BTreeMap::<String, usize>::new();
        for installation in &installations {
            if let Some(id) = &installation.bundle_id {
                *ids.entry(id.clone()).or_default() += 1;
            }
        }
        for mut installation in installations {
            if let Some(id) = &installation.bundle_id {
                if protected_mac_bundle(id) {
                    self.notice(
                        "protected_application_excluded",
                        None,
                        "QuickSave and No Land are excluded from automatic application tracking. No Land import requires its separate read-only consent.",
                    );
                    continue;
                }
                if ids.get(id).copied().unwrap_or(0) != 1 {
                    self.missing(&mut installation.plan, None, RootClassification::Data, "ambiguous_bundle_identifier",
                        "Multiple installations claim this bundle ID; shared data ownership is refused.");
                    for root in &mut installation.plan.unresolved_roots {
                        if root
                            .unresolved_reasons
                            .iter()
                            .any(|r| r.code == "ambiguous_bundle_identifier")
                        {
                            root.status = PlannedRootStatus::Ambiguous;
                        }
                    }
                } else if installation.plan.executable_identity.is_some()
                    && !installation.plan.source_roots.is_empty()
                {
                    self.mac_data(
                        &mut installation.plan,
                        &installation.bundle,
                        id,
                        installation.executable_node.as_ref(),
                    );
                }
            }
            self.retain(installation.plan);
        }
    }

    fn mac_installation(&mut self, bundle: &Path) -> MacInstallation {
        let node = self
            .inspect(bundle)
            .filter(|n| n.identity.kind() == NativeNodeKind::Directory);
        let mut plan = self.new_plan(
            "mac_application_bundle",
            bundle,
            None,
            node.as_ref().map(|n| n.identity.clone()),
        );
        let mut result = MacInstallation {
            plan: plan.clone(),
            bundle: bundle.to_owned(),
            bundle_id: None,
            executable_node: None,
        };
        let Some(node) = node else {
            self.missing(
                &mut plan,
                Some(bundle.to_owned()),
                RootClassification::Install,
                "installation_identity_unverified",
                "App installation is linked, missing, denied or not a real directory.",
            );
            result.plan = plan;
            return result;
        };
        let metadata_path = bundle.join("Contents/Info.plist");
        let metadata = self
            .read(&metadata_path, macos::MAX_PLIST_BYTES)
            .and_then(|document| {
                macos::parse_info_plist(&document.bytes)
                    .ok()
                    .map(|parsed| (document, parsed))
            });
        let Some((document, metadata)) = metadata else {
            self.missing(&mut plan, Some(bundle.to_owned()), RootClassification::Install, "invalid_bundle_identity_metadata",
                "CFBundleIdentifier metadata is missing, denied or invalid; no name-based fallback is permitted.");
            result.plan = plan;
            return result;
        };
        let id = metadata.bundle_identifier.clone();
        result.bundle_id = Some(id.clone());
        plan.product_id = Some(format!("mac-bundle:{id}"));
        plan.app_id = format!("mac-bundle:{id}@{}", node.identity.stable_key());
        plan.display_name = metadata.display_name.unwrap_or_else(|| id.clone());
        plan.identity_evidence.push(IdentityEvidence {
            kind: "cf_bundle_identifier",
            identifier: id.clone(),
            metadata_path: Some(metadata_path.clone()),
            native_identity: Some(document.native_identity.clone()),
        });
        // Identity metadata is enough to exclude these products. Never inspect
        // their executable, entitlements or app-data associations for enrollment.
        if protected_mac_bundle(&id) {
            result.plan = plan;
            return result;
        }
        let Some(executable_name) = metadata.executable_name else {
            self.missing(&mut plan, None, RootClassification::Runtime, "bundle_executable_not_declared",
                "CFBundleExecutable is absent; an installation bundle is not fabricated from its name.");
            result.plan = plan;
            return result;
        };
        let executable = bundle.join("Contents/MacOS").join(executable_name);
        let executable_node = self
            .inspect(&executable)
            .filter(|n| n.identity.kind() == NativeNodeKind::RegularFile && n.executable);
        let Some(executable_node) = executable_node else {
            self.missing(&mut plan, Some(executable), RootClassification::Runtime, "bundle_executable_unverified",
                "The declared app executable is missing, denied, linked or not an executable native file.");
            result.plan = plan;
            return result;
        };
        // Bind path-based plist metadata to the same bundle handle identity.
        if self
            .inspect(bundle)
            .is_none_or(|current| current.identity != node.identity)
        {
            self.missing(&mut plan, Some(bundle.to_owned()), RootClassification::Install, "installation_identity_changed",
                "The bundle changed during identity discovery; retry before granting any source root.");
            result.plan = plan;
            return result;
        }
        plan.executable_identity = Some(executable_node.identity.clone());
        result.executable_node = Some(executable_node.clone());
        plan.identity_evidence.push(IdentityEvidence {
            kind: "cf_bundle_executable_native_handle",
            identifier: id,
            metadata_path: Some(executable),
            native_identity: Some(executable_node.identity),
        });
        let evidence = plan.identity_evidence.clone();
        self.candidate(
            &mut plan,
            bundle,
            RootClassification::Install,
            NativeNodeKind::Directory,
            IdentityConfidence::NativeInstallation,
            evidence,
            "exact_installation",
        );
        result.plan = plan;
        result
    }

    fn mac_data(
        &mut self,
        plan: &mut SoftwareBundlePlan,
        bundle: &Path,
        id: &str,
        expected_executable: Option<&NativeNode>,
    ) {
        let signing = self.backend.mac_signing_evidence(bundle);
        let current_executable = plan
            .identity_evidence
            .iter()
            .find(|e| e.kind == "cf_bundle_executable_native_handle")
            .and_then(|e| e.metadata_path.clone());
        let unchanged = self.inspect(bundle).map(|n| n.identity) == plan.installation_identity
            && current_executable
                .as_deref()
                .and_then(|p| self.inspect(p))
                .as_ref()
                == expected_executable;
        let groups = match signing {
            Ok(evidence)
                if unchanged
                    && evidence.signature_validated
                    && evidence.signing_identifier.as_deref() == Some(id)
                    && evidence.application_groups.len() <= 64
                    && evidence
                        .application_groups
                        .iter()
                        .all(|g| macos::validate_identifier(g).is_ok())
                    && evidence
                        .application_groups
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        == evidence.application_groups.len() =>
            {
                plan.identity_evidence.push(IdentityEvidence {
                    kind: "validated_signed_bundle_identifier",
                    identifier: id.to_owned(),
                    metadata_path: Some(bundle.to_owned()),
                    native_identity: plan.executable_identity.clone(),
                });
                Some(evidence.application_groups)
            }
            _ => {
                if self.report.backend == BackendKind::NativeApprovedBases {
                    self.missing(plan, None, RootClassification::GroupContainer, "signed_groups_not_handle_confirmable",
                        "Public path-only Security APIs cannot be confined to the retained native base handle; they were not called and signed-group ownership is unconfirmed.");
                } else {
                    self.missing(plan, None, RootClassification::GroupContainer, "signed_groups_unavailable",
                        "A validated matching signature/application-group entitlement set was not available; group ownership is not guessed.");
                }
                None
            }
        };
        if !unchanged {
            // Already proposed installation identities are no longer usable.
            plan.source_roots.clear();
            self.missing(plan, Some(bundle.to_owned()), RootClassification::Install, "installation_changed_during_signing",
                "The installation changed around signing metadata inspection; no verified plan is emitted.");
            return;
        }
        let Some(home) = self.scope.home.clone() else {
            self.missing(
                plan,
                None,
                RootClassification::Data,
                "home_anchor_unavailable",
                "No approved home anchor was supplied for precise app data paths.",
            );
            return;
        };
        let evidence = vec![IdentityEvidence {
            kind: "exact_cf_bundle_identifier_path",
            identifier: id.to_owned(),
            metadata_path: Some(bundle.join("Contents/Info.plist")),
            native_identity: plan.executable_identity.clone(),
        }];
        self.candidate(
            plan,
            &home.join("Library/Application Support").join(id),
            RootClassification::Data,
            NativeNodeKind::Directory,
            IdentityConfidence::ExactPlatformIdentifier,
            evidence.clone(),
            "exact_bundle_identifier",
        );
        self.candidate(
            plan,
            &home.join("Library/Preferences").join(format!("{id}.plist")),
            RootClassification::Config,
            NativeNodeKind::RegularFile,
            IdentityConfidence::ExactPlatformIdentifier,
            evidence,
            "exact_bundle_identifier",
        );
        self.mac_container(plan, &home.join("Library/Containers").join(id), id, false);
        if let Some(groups) = groups {
            for group in groups {
                self.mac_container(
                    plan,
                    &home.join("Library/Group Containers").join(&group),
                    &group,
                    true,
                );
            }
        }
        self.missing(plan, None, RootClassification::Save, "non_container_save_layout_unproven",
            "Additional non-container saves require an exact reviewed product mapping, not title matching or a user-folder copy.");
    }

    fn mac_container(
        &mut self,
        plan: &mut SoftwareBundlePlan,
        container: &Path,
        expected_id: &str,
        group: bool,
    ) {
        let classification = if group {
            RootClassification::GroupContainer
        } else {
            RootClassification::Container
        };
        let Some(before) = self
            .inspect(container)
            .filter(|n| n.identity.kind() == NativeNodeKind::Directory)
        else {
            self.missing(
                plan,
                Some(container.to_owned()),
                classification,
                "container_missing_or_denied",
                "The exact container root is absent, unsafe or denied.",
            );
            return;
        };
        let metadata_path = container.join(".com.apple.containermanagerd.metadata.plist");
        let document = self.read(&metadata_path, macos::MAX_PLIST_BYTES);
        let exact = document
            .as_ref()
            .and_then(|d| macos::parse_container_identifier(&d.bytes).ok())
            .as_deref()
            == Some(expected_id);
        let unchanged = self
            .inspect(container)
            .is_some_and(|n| n.identity == before.identity);
        if !exact || !unchanged {
            self.missing(plan, Some(container.to_owned()), classification, "container_identifier_mismatch_or_unreadable",
                "Container metadata does not prove the exact owner/group identifier on a stable native root.");
            return;
        }
        let evidence = vec![
            IdentityEvidence {
                kind: "container_metadata_identifier",
                identifier: expected_id.to_owned(),
                metadata_path: Some(metadata_path),
                native_identity: document.map(|d| d.native_identity),
            },
            IdentityEvidence {
                kind: if group {
                    "validated_signed_application_group"
                } else {
                    "cf_bundle_identifier_and_executable_handle"
                },
                identifier: expected_id.to_owned(),
                metadata_path: None,
                native_identity: plan.executable_identity.clone(),
            },
            IdentityEvidence {
                kind: "native_mapping_root_handle",
                identifier: expected_id.to_owned(),
                metadata_path: Some(container.to_owned()),
                native_identity: Some(before.identity.clone()),
            },
        ];
        let ownership = if group {
            "shared_signed_application_group_not_exclusive"
        } else {
            "exact_container_metadata_identifier"
        };
        let confidence = if group {
            IdentityConfidence::SignedApplicationGroup
        } else {
            IdentityConfidence::ExactPlatformIdentifier
        };
        if !self.candidate(
            plan,
            container,
            classification,
            NativeNodeKind::Directory,
            confidence,
            evidence.clone(),
            ownership,
        ) {
            return;
        }
        if group {
            // Group layout is app-defined. Its exact signed boundary is real;
            // classification does not invent generic Documents/Preferences.
            return;
        }
        for (relative, classification) in [
            ("Data/Documents", RootClassification::Save),
            ("Data/Library/Application Support", RootClassification::Data),
            ("Data/Library/Preferences", RootClassification::Config),
        ] {
            // The native_mapping_root_handle applies to the container boundary,
            // not to a child's distinct identity.
            let child_evidence = evidence
                .iter()
                .filter(|e| e.kind != "native_mapping_root_handle")
                .cloned()
                .collect();
            self.candidate(
                plan,
                &container.join(relative),
                classification,
                NativeNodeKind::Directory,
                confidence,
                child_evidence,
                ownership,
            );
        }
        if self
            .inspect(container)
            .is_none_or(|current| current.identity != before.identity)
        {
            plan.source_roots.retain(|root| {
                !root
                    .path
                    .as_ref()
                    .is_some_and(|path| path.starts_with(container))
            });
            self.missing(plan, Some(container.to_owned()), classification, "container_identity_changed",
                "The container changed while child identities were inspected; its entire proposed mapping was refused.");
        }
    }

    fn scan_desktop(&mut self) {
        let mut seen = BTreeSet::new();
        for root in self.scope.desktop_directories.clone() {
            for name in self.entries(&root) {
                if !name.ends_with(".desktop") || !seen.insert(name.clone()) {
                    continue;
                }
                let path = root.join(&name);
                if !self.room(&path) {
                    return;
                }
                let mut plan = self.new_plan(
                    "xdg_desktop_entry",
                    &path,
                    Some(format!("xdg-desktop:{name}")),
                    None,
                );
                let document = self.read(&path, desktop::MAX_DESKTOP_BYTES);
                let metadata = document
                    .as_ref()
                    .and_then(|document| std::str::from_utf8(&document.bytes).ok())
                    .and_then(|text| desktop::parse_desktop_entry(text).ok());
                let Some(metadata) = metadata else {
                    self.missing(&mut plan, Some(path), RootClassification::Runtime, "desktop_metadata_unverified",
                        "Desktop metadata is invalid, denied or linked; no placeholder app is tracked.");
                    self.retain(plan);
                    continue;
                };
                if metadata.hidden {
                    continue;
                } // XDG override is an explicit mask, not an installed app.
                plan.app_id = format!("xdg-desktop:{name}");
                plan.display_name = metadata.display_name.unwrap_or_else(|| name.clone());
                plan.identity_evidence.push(IdentityEvidence {
                    kind: "xdg_desktop_file_id",
                    identifier: name.clone(),
                    metadata_path: Some(path.clone()),
                    native_identity: document.map(|d| d.native_identity),
                });
                if let Some(executable) = metadata.absolute_executable {
                    if let Some(node) = self.inspect(&executable).filter(|n| {
                        n.executable && n.identity.kind() == NativeNodeKind::RegularFile
                    }) {
                        plan.executable_identity = Some(node.identity.clone());
                        plan.installation_identity = Some(node.identity);
                        let evidence = plan.identity_evidence.clone();
                        self.candidate(
                            &mut plan,
                            &executable,
                            RootClassification::Runtime,
                            NativeNodeKind::RegularFile,
                            IdentityConfidence::NativeInstallation,
                            evidence,
                            "literal_executable_only_not_parent_directory",
                        );
                    } else {
                        self.missing(&mut plan, Some(executable), RootClassification::Runtime, "desktop_executable_unverified",
                            "Literal executable metadata did not resolve to a real native executable; no PATH or shell lookup is performed.");
                    }
                } else {
                    self.missing(&mut plan, None, RootClassification::Runtime, "desktop_runtime_not_proven",
                        "Launcher command/wrapper is not a verified installation directory or runtime file.");
                }
                let stem = name.strip_suffix(".desktop").unwrap_or("");
                if macos::validate_identifier(stem).is_ok() && stem.split('.').count() >= 3 {
                    if let Some(flatpak) = metadata.flatpak_id {
                        if flatpak == stem {
                            if let Some(home) = self.scope.home.clone() {
                                let base = home.join(".var/app").join(&flatpak);
                                let evidence = vec![IdentityEvidence {
                                    kind: "exact_flatpak_desktop_identifier",
                                    identifier: flatpak,
                                    metadata_path: Some(path.clone()),
                                    native_identity: None,
                                }];
                                for (relative, classification) in [
                                    ("data", RootClassification::Data),
                                    ("config", RootClassification::Config),
                                ] {
                                    self.candidate(
                                        &mut plan,
                                        &base.join(relative),
                                        classification,
                                        NativeNodeKind::Directory,
                                        IdentityConfidence::ExactPlatformIdentifier,
                                        evidence.clone(),
                                        "exact_flatpak_identifier",
                                    );
                                }
                            } else {
                                self.missing(&mut plan, None, RootClassification::Data, "flatpak_home_anchor_unavailable", "An approved home anchor is required for exact Flatpak data paths.");
                            }
                        } else {
                            self.missing(&mut plan, None, RootClassification::Data, "ambiguous_flatpak_desktop_identifier",
                                "X-Flatpak and desktop file ID disagree; data-root association is refused.");
                        }
                    } else {
                        for (anchor, classification) in [
                            (self.scope.xdg_data_home.clone(), RootClassification::Data),
                            (
                                self.scope.xdg_config_home.clone(),
                                RootClassification::Config,
                            ),
                        ] {
                            if let Some(anchor) = anchor {
                                let evidence = vec![IdentityEvidence {
                                    kind: "exact_namespaced_desktop_id_path",
                                    identifier: stem.to_owned(),
                                    metadata_path: Some(path.clone()),
                                    native_identity: None,
                                }];
                                self.candidate(
                                    &mut plan,
                                    &anchor.join(stem),
                                    classification,
                                    NativeNodeKind::Directory,
                                    IdentityConfidence::ExactPlatformIdentifier,
                                    evidence,
                                    "exact_xdg_desktop_identifier",
                                );
                            } else {
                                self.missing(
                                    &mut plan,
                                    None,
                                    classification,
                                    "xdg_anchor_unavailable",
                                    "The approved XDG anchor was not supplied.",
                                );
                            }
                        }
                    }
                } else {
                    self.missing(&mut plan, None, RootClassification::Data, "desktop_id_has_no_exact_data_namespace",
                        "This desktop ID supplies no precise namespaced data mapping; display-title/basename guesses are refused.");
                }
                self.missing(&mut plan, None, RootClassification::Save, "desktop_save_layout_unproven",
                    "A desktop entry does not describe arbitrary save-file locations; only exact identity mappings are proposed.");
                self.retain(plan);
            }
        }
    }

    fn scan_steam(&mut self) {
        let mut libraries = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
        for root in self.scope.steam_roots.clone() {
            if self.inspect(&root).is_none() {
                continue;
            }
            libraries
                .entry(root.join("steamapps"))
                .or_default()
                .insert(root.clone());
            let metadata_path = root.join("steamapps/libraryfolders.vdf");
            if let Some(document) = self.read(&metadata_path, steam::MAX_VDF_BYTES) {
                let parsed = std::str::from_utf8(&document.bytes)
                    .ok()
                    .and_then(|text| steam::parse_libraryfolders(text).ok());
                if let Some(entries) = parsed {
                    for entry in entries {
                        if libraries.len() >= 64 {
                            self.diagnostic(
                                "steam_library_limit",
                                Some(&metadata_path),
                                "Steam library bound reached.",
                            );
                            break;
                        }
                        let library = PathBuf::from(entry.path);
                        if validate_path(&library).is_ok() {
                            if library != root
                                && self
                                    .backend
                                    .require_discovered_steam_library(&library)
                                    .is_err()
                            {
                                self.diagnostic("steam_library_not_separately_approved", Some(&library),
                                    "An external Steam library was named by metadata but has no separate retained native base proof; it was not opened.");
                                continue;
                            }
                            libraries
                                .entry(library.join("steamapps"))
                                .or_default()
                                .insert(root.clone());
                        } else {
                            self.diagnostic("foreign_or_invalid_steam_library", Some(&metadata_path), "A Steam library path is invalid for this native host and was not followed.");
                        }
                    }
                } else {
                    self.diagnostic(
                        "invalid_steam_libraries",
                        Some(&metadata_path),
                        "Steam library metadata is invalid or over the parser bound.",
                    );
                }
            }
        }
        for (library, launchers) in libraries {
            for name in self.entries(&library) {
                let Some(raw_id) = name
                    .strip_prefix("appmanifest_")
                    .and_then(|s| s.strip_suffix(".acf"))
                else {
                    continue;
                };
                let Ok(filename_id) = raw_id.parse::<u32>() else {
                    continue;
                };
                if filename_id == 0 || filename_id.to_string() != raw_id {
                    continue;
                }
                let metadata_path = library.join(&name);
                if !self.room(&metadata_path) {
                    return;
                }
                let mut plan = self.new_plan(
                    "steam_app_manifest",
                    &metadata_path,
                    Some(format!("steam:{filename_id}")),
                    None,
                );
                let document = self.read(&metadata_path, steam::MAX_VDF_BYTES);
                let metadata = document
                    .as_ref()
                    .and_then(|d| std::str::from_utf8(&d.bytes).ok())
                    .and_then(|text| steam::parse_appmanifest(text).ok())
                    .filter(|m| m.app_id == filename_id);
                let Some(metadata) = metadata else {
                    self.missing(&mut plan, Some(metadata_path), RootClassification::Install, "steam_manifest_identity_unverified",
                        "Steam metadata is invalid, denied or does not match its exact filename app ID.");
                    self.retain(plan);
                    continue;
                };
                let install = library
                    .join("common")
                    .join(metadata.install_subdirectory.as_str());
                let node = self
                    .inspect(&install)
                    .filter(|n| n.identity.kind() == NativeNodeKind::Directory);
                if let Some(node) = &node {
                    if !self
                        .seen_installations
                        .insert((format!("steam:{filename_id}"), node.identity.clone()))
                    {
                        continue;
                    }
                }
                plan.app_id = node
                    .as_ref()
                    .map(|n| format!("steam:{filename_id}@{}", n.identity.stable_key()))
                    .unwrap_or_else(|| {
                        format!("steam:{filename_id}@unresolved:{}", install.display())
                    });
                plan.installation_identity = node.map(|n| n.identity);
                plan.display_name = metadata.display_name;
                let evidence = vec![IdentityEvidence {
                    kind: "exact_steam_appmanifest_id_and_installdir",
                    identifier: filename_id.to_string(),
                    metadata_path: Some(metadata_path.clone()),
                    native_identity: document.map(|d| d.native_identity),
                }];
                plan.identity_evidence = evidence.clone();
                self.candidate(
                    &mut plan,
                    &install,
                    RootClassification::Install,
                    NativeNodeKind::Directory,
                    IdentityConfidence::NativeInstallation,
                    evidence,
                    "exact_steam_app_id_and_manifest_install_path",
                );
                if self
                    .scope
                    .inventory_approved_steam_app_ids
                    .contains(&filename_id)
                    && launchers.len() == 1
                {
                    if let Some(launcher) = launchers.iter().next() {
                        self.steam_userdata(&mut plan, launcher, filename_id);
                    }
                } else {
                    self.missing(&mut plan, None, RootClassification::Save,
                        if launchers.len() != 1 { "ambiguous_steam_userdata_launcher" } else { "steam_userdata_app_id_not_inventory_approved" },
                        "Steam userdata requires an exact inventory-approved numeric app ID and one unambiguous launcher root; usernames/accounts are not read.");
                }
                self.missing(&mut plan, None, RootClassification::Config, "steam_external_data_layout_unproven",
                    "Game-specific external saves/config and compatibility prefixes are not inferred from a title or copied wholesale.");
                self.retain(plan);
            }
        }
    }

    fn steam_userdata(&mut self, plan: &mut SoftwareBundlePlan, launcher: &Path, app_id: u32) {
        let userdata = launcher.join("userdata");
        let mut matched = false;
        for account in self.entries(&userdata) {
            // Numeric directory key only. No loginusers.vdf, account names,
            // localconfig, credentials or cloud APIs are ever read.
            let Ok(number) = account.parse::<u64>() else {
                continue;
            };
            if number == 0 || number.to_string() != account {
                continue;
            }
            let path = userdata.join(account).join(app_id.to_string());
            if self.inspect(&path).is_none() {
                continue;
            }
            matched = true;
            let evidence = vec![IdentityEvidence {
                kind: "inventory_approved_exact_steam_app_id_userdata_path",
                identifier: app_id.to_string(),
                metadata_path: None,
                native_identity: plan.installation_identity.clone(),
            }];
            self.candidate(
                plan,
                &path,
                RootClassification::Data,
                NativeNodeKind::Directory,
                IdentityConfidence::ExactPlatformIdentifier,
                evidence.clone(),
                "exact_numeric_steam_app_id_not_username",
            );
            self.candidate(
                plan,
                &path.join("remote"),
                RootClassification::Save,
                NativeNodeKind::Directory,
                IdentityConfidence::ExactPlatformIdentifier,
                evidence,
                "exact_numeric_steam_app_id_remote_directory",
            );
        }
        if !matched {
            self.missing(
                plan,
                None,
                RootClassification::Save,
                "approved_steam_userdata_absent_or_denied",
                "No exact app-ID userdata root was verified; this is not a completed save mapping.",
            );
        }
    }

    fn scan_windows(&mut self) -> Result<()> {
        // Native Windows backends must source these records from Windows APIs.
        // On Unix, only an explicit portable/fixture adapter can supply them.
        let installations = self
            .backend
            .windows_installations(self.report.limits.max_applications)?;
        ensure!(
            installations.len() <= self.report.limits.max_applications,
            "Windows adapter exceeded inventory bound"
        );
        let mut identity_counts = BTreeMap::<String, usize>::new();
        for installation in &installations {
            if let Ok(identity) = installation.identity.stable_key() {
                *identity_counts.entry(identity).or_default() += 1;
            }
        }
        let mut seen = BTreeSet::new();
        for installation in installations {
            let identity = installation.identity.stable_key();
            let path = installation
                .installation_path
                .as_ref()
                .filter(|path| validate_path(path).is_ok())
                .cloned()
                .unwrap_or_default();
            let mut plan = self.new_plan(
                "windows_native_identity_adapter",
                &path,
                identity.as_ref().ok().cloned(),
                None,
            );
            let Ok(identity) = identity else {
                self.missing(&mut plan, None, RootClassification::Install, "windows_product_identity_invalid",
                    "An exact valid registry/package identity was not supplied; DisplayName is not ownership evidence.");
                self.retain(plan);
                continue;
            };
            ensure!(
                installation.display_name.len() <= 4096
                    && !installation.display_name.chars().any(char::is_control),
                "invalid Windows display metadata"
            );
            plan.display_name = installation.display_name;
            plan.product_id = Some(identity.clone());
            plan.app_id = identity.clone();
            let evidence = vec![IdentityEvidence {
                kind: "windows_registry_or_package_identity",
                identifier: identity.clone(),
                metadata_path: None,
                native_identity: None,
            }];
            plan.identity_evidence = evidence.clone();
            if let Some(path) = installation.installation_path {
                if let Some(node) = self
                    .inspect(&path)
                    .filter(|n| n.identity.kind() == NativeNodeKind::Directory)
                {
                    plan.installation_identity = Some(node.identity);
                }
                self.candidate(
                    &mut plan,
                    &path,
                    RootClassification::Install,
                    NativeNodeKind::Directory,
                    IdentityConfidence::NativeInstallation,
                    evidence.clone(),
                    "exact_windows_registry_or_package_identity",
                );
                if let Some(native) = &plan.installation_identity {
                    plan.app_id = format!("{identity}@{}", native.stable_key());
                }
            } else {
                self.missing(
                    &mut plan,
                    None,
                    RootClassification::Install,
                    "windows_installation_path_unavailable",
                    "The native product record did not provide a verified installation path.",
                );
            }
            if let Some(executable) = installation.executable_path {
                if let Some(node) = self
                    .inspect(&executable)
                    .filter(|n| n.identity.kind() == NativeNodeKind::RegularFile)
                {
                    plan.executable_identity = Some(node.identity);
                    self.candidate(
                        &mut plan,
                        &executable,
                        RootClassification::Runtime,
                        NativeNodeKind::RegularFile,
                        IdentityConfidence::NativeInstallation,
                        evidence.clone(),
                        "exact_native_adapter_executable",
                    );
                } else {
                    self.missing(
                        &mut plan,
                        Some(executable),
                        RootClassification::Runtime,
                        "windows_executable_unverified",
                        "Native executable identity is unavailable or unsafe.",
                    );
                }
            }
            if !seen.insert(plan.app_id.clone()) {
                self.diagnostic("duplicate_windows_installation_record", None, "The adapter returned the same native installation more than once; it is not counted twice.");
                continue;
            }
            if identity_counts.get(&identity).copied().unwrap_or(0) != 1 {
                self.missing(&mut plan, None, RootClassification::Data, "ambiguous_windows_product_identity",
                    "Multiple native installations claim the same product identity; data-root association is refused for all of them.");
                self.retain(plan);
                continue;
            }
            if let WindowsProductIdentity::PackageFamily { family_name } = installation.identity {
                if let Some(local) = self
                    .scope
                    .windows_known_folders
                    .get(&WindowsKnownFolder::LocalAppData)
                    .cloned()
                {
                    let package = local.join("Packages").join(family_name);
                    for (relative, classification) in [
                        ("LocalState", RootClassification::Data),
                        ("RoamingState", RootClassification::Save),
                        ("Settings", RootClassification::Config),
                    ] {
                        self.candidate(
                            &mut plan,
                            &package.join(relative),
                            classification,
                            NativeNodeKind::Directory,
                            IdentityConfidence::ExactPlatformIdentifier,
                            evidence.clone(),
                            "exact_windows_package_family",
                        );
                    }
                } else {
                    self.missing(&mut plan, None, RootClassification::Data, "windows_known_folder_unavailable",
                        "LocalAppData must be supplied by a native Known Folder adapter, not reconstructed from a username.");
                }
            }
            ensure!(
                installation.reviewed_mappings.len()
                    <= self.report.limits.max_roots_per_application,
                "Windows reviewed mappings exceed root bound"
            );
            for mapping in installation.reviewed_mappings {
                if mapping.exact_owner_id != identity
                    || mapping.profile_id.is_empty()
                    || mapping.profile_id.len() > 255
                    || !matches!(
                        mapping.classification,
                        RootClassification::Data
                            | RootClassification::Save
                            | RootClassification::Config
                    )
                {
                    self.missing(&mut plan, None, mapping.classification, "reviewed_mapping_owner_mismatch",
                        "A reviewed root mapping did not match the exact native product identity and was refused.");
                    continue;
                }
                if let Some(anchor) = self
                    .scope
                    .windows_known_folders
                    .get(&mapping.known_folder)
                    .cloned()
                {
                    let evidence = vec![IdentityEvidence {
                        kind: "reviewed_exact_windows_product_mapping",
                        identifier: format!("{identity}:{}", mapping.profile_id),
                        metadata_path: None,
                        native_identity: None,
                    }];
                    self.candidate(
                        &mut plan,
                        &anchor.join(mapping.relative_path.as_str()),
                        mapping.classification,
                        NativeNodeKind::Directory,
                        IdentityConfidence::ReviewedExactProductMapping,
                        evidence,
                        "reviewed_exact_windows_product_mapping",
                    );
                } else {
                    self.missing(&mut plan, None, mapping.classification, "windows_known_folder_unavailable",
                        "The exact native Known Folder anchor required by the mapping was not supplied.");
                }
            }
            self.retain(plan);
        }
        Ok(())
    }
}

fn verified_source_identity(plan: &SoftwareBundlePlan) -> Option<SourceAppIdentity> {
    if plan.source_roots.is_empty() {
        return None;
    }
    let product = plan.product_id.as_deref()?;
    let executable = plan.executable_identity.as_ref().and_then(|identity| {
        if plan.source == "mac_application_bundle" {
            plan.identity_evidence
                .iter()
                .find(|item| {
                    item.kind == "cf_bundle_executable_native_handle"
                        && item.native_identity.as_ref() == Some(identity)
                })
                .and_then(|item| item.metadata_path.clone())
        } else {
            plan.source_roots
                .iter()
                .find(|root| {
                    root.classification == RootClassification::Runtime
                        && root.status == PlannedRootStatus::VerifiedCandidate
                        && root.native_identity.as_ref() == Some(identity)
                })
                .and_then(|root| root.path.clone())
        }
    });
    let (app_id, steam_app_id, desktop_entry_id, launcher) = match plan.source {
        "steam_app_manifest" => {
            let raw_id = product.strip_prefix("steam:")?;
            let id = raw_id
                .parse::<u32>()
                .ok()
                .filter(|id| *id > 0 && id.to_string() == raw_id)?;
            if !plan.identity_evidence.iter().any(|item| {
                item.kind == "exact_steam_appmanifest_id_and_installdir"
                    && item.identifier == raw_id
                    && item.native_identity.is_some()
            }) {
                return None;
            }
            (
                format!("steam:{id}"),
                Some(id),
                None,
                Some(SourceLauncherKind::Steam),
            )
        }
        "mac_application_bundle" => {
            let id = product.strip_prefix("mac-bundle:")?;
            if executable.is_none()
                || !plan.identity_evidence.iter().any(|item| {
                    item.kind == "cf_bundle_identifier"
                        && item.identifier == id
                        && item.native_identity.is_some()
                })
                || !plan.source_roots.iter().any(|root| {
                    root.classification == RootClassification::Install
                        && root.native_identity == plan.installation_identity
                })
            {
                return None;
            }
            (
                product.to_owned(),
                None,
                None,
                Some(SourceLauncherKind::Native),
            )
        }
        "xdg_desktop_entry" => {
            let id = product.strip_prefix("xdg-desktop:")?;
            if !plan.identity_evidence.iter().any(|item| {
                item.kind == "xdg_desktop_file_id"
                    && item.identifier == id
                    && item.native_identity.is_some()
            }) {
                return None;
            }
            let launcher = if plan.source_roots.iter().any(|root| {
                root.evidence.iter().any(|item| {
                    item.kind == "exact_flatpak_desktop_identifier"
                        && id.strip_suffix(".desktop") == Some(item.identifier.as_str())
                })
            }) {
                SourceLauncherKind::Flatpak
            } else {
                SourceLauncherKind::Native
            };
            // Preserve the exact XDG file ID, including case. No Land's lossy
            // display/desktop normalization is not an ownership key.
            (
                format!("desktop:{id}"),
                None,
                Some(id.to_owned()),
                Some(launcher),
            )
        }
        "windows_native_identity_adapter" => {
            if !plan.identity_evidence.iter().any(|item| {
                item.kind == "windows_registry_or_package_identity" && item.identifier == product
            }) {
                return None;
            }
            (
                product.to_owned(),
                None,
                None,
                executable.as_ref().map(|_| SourceLauncherKind::Native),
            )
        }
        _ => return None,
    };
    Some(SourceAppIdentity {
        app_id,
        display_name: plan.display_name.clone(),
        canonical_executable: executable,
        desktop_entry_id,
        steam_app_id,
        launcher,
        aliases: Vec::new(),
        identity_confidence: 1.0,
        icon_path: None,
    })
}

fn add_reason(plan: &mut SoftwareBundlePlan, code: &'static str, message: &'static str) {
    if plan.unresolved_reasons.len() < 64
        && !plan
            .unresolved_reasons
            .iter()
            .any(|reason| reason.code == code)
    {
        plan.unresolved_reasons
            .push(UnresolvedReason { code, message });
    }
}

fn valid_entry(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

fn permission_denied(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

fn protected_mac_bundle(id: &str) -> bool {
    matches!(id, "com.noland.connect" | "app.quicksave.desktop")
}

fn exclusion_components() -> Vec<&'static str> {
    vec![
        "cache",
        "caches",
        "logs",
        "log",
        "keychain",
        "com.noland.connect",
        "keychains",
        "vault",
        "vaults",
        "credentials",
        "credentialmanager",
        "secrets",
        "keyrings",
        "kwallet",
        "kwalletd",
        ".password-store",
        "quicksave",
        ".quicksave",
        "quicksave.app",
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
    ]
}
