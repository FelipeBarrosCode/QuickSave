// SPDX-License-Identifier: GPL-3.0-only
//! Lossless bounded projections from ACTUAL No Land catalog/deletion types.
//!
//! # Parent integration API
//!
//! `catalog_projection(provider_id, &CatalogDocument, &CatalogEvidence)` keeps
//! original app identity, per-mode heads, parents/commits/source instances,
//! completeness/readiness and real freshness; it does not infer full-app coverage
//! from a mode alone. `catalog_projection_from_rpc(provider_id, &Value, evidence)`
//! validates the actual source `ListCloudCatalog` JSON before projecting.
//! `deletion_projection(&FullDeletionPlan, requested)` preserves exact requested/dependent
//! app/bundle/commit IDs; `validate_deletion_ack` compares those exact identities.
//! The native parent must load/authenticate plans using source storage functions,
//! never construct `FullDeletionPlan` from incoming JS or bypass repository guards.
//! Prefer `BundleEvidence::from_authenticated_manifest` when loading a manifest:
//! it reads explicit signed native capture coverage, never infers it from mode.
//! Source-compatible subset publication uses existing `BackupMode::Custom`, not
//! PersonalState (which filters app content during restore). The parent source
//! adapter must choose that mode before its HMAC admission, then preserve it
//! through capture/prepared retry/catalog publication.
//!
//! Provenance: models/semantics were inspected in the unmodified No Land snapshot
//! e81238a7536aae201540956ce76981364fd36595, `state-agent/crates/
//! noland-state-core/src/{catalog,manifest}.rs` and `noland-storage/src/
//! reclamation.rs`, and the active fork's corresponding source. This is original
//! GPL-3.0-only adapter code, not an alternative storage/deletion implementation.
//! `FullDeletionPlan::requested_count` DOES NOT identify which sorted targets were
//! requested. Supply the original pinned selection; absent that, dependencies are
//! explicitly unknown, not the first N targets. Never synthesize writer liveness,
//! force-unlock a repository, or automatically execute/retire a deletion here.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(any(unix, windows))]
use noland_state_core::{BackupMode, BundleManifest, CatalogDocument};
#[cfg(any(unix, windows))]
use noland_storage::FullDeletionPlan;

pub const MAX_CATALOG_APPS: usize = 4096;
pub const MAX_CATALOG_BUNDLES: usize = 100_000;
pub const MAX_CATALOG_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DELETION_TARGETS: usize = 10_000;

/// An explicit coverage proof from the native approved capture/manifest adapter.
/// A catalog's `complete_application` mode alone is NOT this proof.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    #[default]
    Unknown,
    SelectedFiles,
    /// Complete capture of approved roots, but no whole-application proof.
    ApprovedSoftware,
    PersonalState,
    CompleteApplication,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleEvidence {
    pub app_id: String,
    pub bundle_id: String,
    pub commit_id: String,
    pub coverage: Coverage,
    pub file_count: u64,
    pub tombstone_count: u64,
    pub platform: Option<String>,
    /// Only set after native executable/prerequisite/mapping acceptance.
    pub reconstruction_ready: bool,
}

#[cfg(any(unix, windows))]
impl BundleEvidence {
    /// Preferred parent adapter: coverage comes from the original native scope
    /// embedded in the authenticated committed manifest, never the catalog mode.
    pub fn from_authenticated_manifest(
        manifest: &BundleManifest,
        reconstruction_ready: bool,
    ) -> Result<Self> {
        Self::from_manifest(
            manifest,
            coverage_from_manifest(manifest)?,
            reconstruction_ready,
        )
    }
    /// `manifest` must be the source's authenticated committed manifest, never
    /// webview JSON. `coverage` is supplied from the approved native plan.
    pub fn from_manifest(
        manifest: &BundleManifest,
        coverage: Coverage,
        reconstruction_ready: bool,
    ) -> Result<Self> {
        ensure!(
            manifest.files.len() <= 1_000_000 && manifest.tombstones.len() <= 1_000_000,
            "Manifest browse evidence exceeds its native bound"
        );
        ensure!(
            coverage != Coverage::CompleteApplication
                || manifest.mode == BackupMode::CompleteApplication,
            "Complete-app coverage differs from the actual source mode"
        );
        ensure!(
            coverage != Coverage::PersonalState || manifest.mode == BackupMode::PersonalState,
            "Personal-state coverage differs from the actual source mode"
        );
        ensure!(
            !reconstruction_ready
                || coverage == Coverage::CompleteApplication && !manifest.files.is_empty(),
            "A partial or empty bundle cannot be application-ready"
        );
        let platform = manifest.environment["quicksave_native"]
            .get("platform")
            .or_else(|| manifest.environment.get("platform"))
            .and_then(Value::as_str)
            .map(|value| bounded_text(value, 64).map(str::to_owned))
            .transpose()?;
        Ok(Self {
            app_id: manifest.app.app_id.to_string(),
            bundle_id: manifest.bundle_id.to_string(),
            commit_id: manifest.commit_id.to_string(),
            coverage,
            file_count: manifest.files.len() as u64,
            tombstone_count: manifest.tombstones.len() as u64,
            platform,
            reconstruction_ready,
        })
    }
}

/// Wire-compatible metadata: `NativeSelection.coverage` is included in source
/// submission HMAC and mirrored in the authenticated manifest environment.
/// Until the source adapter writes this explicit proof, legacy rows are unknown.
/// In particular `mode`, `capture_scope_version`, exact file-key presence and
/// logical_size alone cannot distinguish a subset from a whole application.
#[cfg(any(unix, windows))]
pub fn coverage_from_manifest(manifest: &BundleManifest) -> Result<Coverage> {
    let mut observed = None;
    for native in [
        &manifest.environment["quicksave_native"],
        &manifest.environment["quicksaveNative"],
    ] {
        for value in [
            &native["coverage"],
            &native["selection"]["coverage"],
            // Read the earlier optional extension without promoting legacy mode.
            &native["selection"]["capture_scope"]["coverage"],
        ]
        .into_iter()
        .filter(|value| !value.is_null())
        {
            let coverage = match value
                .as_str()
                .context("Authenticated native coverage is malformed")?
            {
                "unknown" | "legacy_exact_selection" => Coverage::Unknown,
                "selected_nodes" | "selected_files" => Coverage::SelectedFiles,
                "full_scope"
                | "full_approved_scope"
                | "approved_software"
                | "whole_approved_software" => Coverage::ApprovedSoftware,
                "personal_state" => Coverage::PersonalState,
                "complete_application" => Coverage::CompleteApplication,
                _ => anyhow::bail!("Authenticated native coverage is unsupported"),
            };
            ensure!(
                observed.is_none_or(|previous| previous == coverage),
                "Authenticated native coverage mirror differs from its original selection"
            );
            observed = Some(coverage);
        }
    }
    let coverage = observed.unwrap_or(Coverage::Unknown);
    ensure!(
        coverage != Coverage::CompleteApplication
            || manifest.mode == BackupMode::CompleteApplication,
        "Authenticated whole-application scope differs from source mode"
    );
    ensure!(
        coverage != Coverage::PersonalState || manifest.mode == BackupMode::PersonalState,
        "Authenticated personal-state scope differs from source mode"
    );
    Ok(coverage)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogFreshness {
    pub source: String,
    pub refresh_started_at: Option<String>,
    pub observed_at: Option<String>,
    pub coalesced: bool,
}

/// Only native verified evidence belongs here. Missing manifest details remain
/// unknown and do not trigger history-wide manifest reads during UI refresh.
#[derive(Clone, Debug, Default)]
pub struct CatalogEvidence {
    pub freshness: CatalogFreshness,
    pub bundles: BTreeMap<String, BundleEvidence>,
    pub pending_deletions: Vec<FrozenFullDeletionPlan>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleIdentity {
    pub app_id: String,
    pub bundle_id: String,
    pub commit_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeletionSelection {
    pub app_id: String,
    pub bundle_id: String,
}

/// Non-secret projection, NOT an executable source plan or authorization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenFullDeletionPlan {
    pub plan_id: String,
    pub operation_id: String,
    pub digest: String,
    pub requested_count: usize,
    /// None on a foreign/legacy pending plan whose original selection is absent.
    pub requested: Option<Vec<BundleIdentity>>,
    pub targets: Vec<BundleIdentity>,
    pub dependencies: Option<Vec<BundleIdentity>>,
    pub names: Vec<String>,
    pub logical_bytes: u64,
    pub physical_bytes: u64,
    pub pack_count: usize,
    pub metadata_object_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeletionAcknowledgement {
    pub plan_id: String,
    pub digest: String,
    pub affected: Vec<BundleIdentity>,
    pub dependencies: Vec<BundleIdentity>,
}

#[cfg(any(unix, windows))]
pub fn deletion_projection(
    plan: &FullDeletionPlan,
    requested: Option<&[DeletionSelection]>,
) -> Result<FrozenFullDeletionPlan> {
    ensure!(
        !plan.automatic,
        "Automatic generation retirement is not authorized"
    );
    ensure!(
        !plan.targets.is_empty()
            && plan.targets.len() <= MAX_DELETION_TARGETS
            && plan.requested_count > 0
            && plan.requested_count <= plan.targets.len()
            && plan.packs.len() <= 200_000
            && plan.metadata.len() <= MAX_DELETION_TARGETS * 16,
        "Source full-deletion plan exceeds its native bounds"
    );
    let mut targets = Vec::with_capacity(plan.targets.len());
    let mut names = Vec::with_capacity(plan.targets.len());
    let mut ids = BTreeSet::new();
    let mut logical_bytes = 0u64;
    let mut physical_bytes = 0u64;
    for target in &plan.targets {
        safe_app_id(target.deletion.app_id.as_str())?;
        ensure!(
            ids.insert(target.deletion.bundle_id),
            "Source full-deletion plan has duplicate target IDs"
        );
        names.push(bounded_text(&target.name, 1024)?.to_owned());
        targets.push(BundleIdentity {
            app_id: target.deletion.app_id.to_string(),
            bundle_id: target.deletion.bundle_id.to_string(),
            commit_id: target.deletion.commit_id.to_string(),
        });
        logical_bytes = logical_bytes
            .checked_add(target.logical_bytes)
            .context("Deletion logical byte count overflow")?;
    }
    for size in plan.packs.values().chain(plan.metadata.values()) {
        physical_bytes = physical_bytes
            .checked_add(*size)
            .context("Deletion physical byte count overflow")?;
    }
    targets.sort();
    let target_index = targets
        .iter()
        .map(|target| ((target.app_id.as_str(), target.bundle_id.as_str()), target))
        .collect::<BTreeMap<_, _>>();
    let requested = requested
        .map(|selection| {
            ensure!(
                selection.len() == plan.requested_count,
                "Original deletion selection count differs from the frozen source plan"
            );
            let mut selected = BTreeSet::new();
            for item in selection {
                safe_app_id(&item.app_id)?;
                canonical_uuid(&item.bundle_id)?;
                let target = target_index
                    .get(&(item.app_id.as_str(), item.bundle_id.as_str()))
                    .copied()
                    .context("Original deletion selection is outside the frozen source plan")?;
                ensure!(
                    selected.insert(target.clone()),
                    "Original deletion selection contains duplicates"
                );
            }
            Ok::<_, anyhow::Error>(selected.into_iter().collect::<Vec<_>>())
        })
        .transpose()?;
    let dependencies = requested.as_ref().map(|requested| {
        targets
            .iter()
            .filter(|target| requested.binary_search(target).is_err())
            .cloned()
            .collect()
    });
    let projection = FrozenFullDeletionPlan {
        plan_id: plan.plan_id.to_string(),
        operation_id: plan.operation_id.to_string(),
        digest: blake3::hash(&bounded_json(plan, MAX_CATALOG_BYTES)?)
            .to_hex()
            .to_string(),
        requested_count: plan.requested_count,
        requested,
        targets,
        dependencies,
        names,
        logical_bytes,
        physical_bytes,
        pack_count: plan.packs.len(),
        metadata_object_count: plan.metadata.len(),
    };
    projection.validate()?;
    Ok(projection)
}

impl FrozenFullDeletionPlan {
    pub fn validate(&self) -> Result<()> {
        canonical_uuid(&self.plan_id)?;
        canonical_uuid(&self.operation_id)?;
        digest(&self.digest)?;
        ensure!(
            !self.targets.is_empty()
                && self.targets.len() <= MAX_DELETION_TARGETS
                && self.requested_count > 0
                && self.requested_count <= self.targets.len()
                && self.names.len() == self.targets.len()
                && self.pack_count <= 200_000
                && self.metadata_object_count <= MAX_DELETION_TARGETS * 16,
            "Deletion projection has invalid bounds"
        );
        let mut target_ids = BTreeSet::new();
        for target in &self.targets {
            validate_bundle_identity(target)?;
            ensure!(
                target_ids.insert(&target.bundle_id),
                "Deletion projection has duplicate target IDs"
            );
        }
        ensure!(
            self.targets.windows(2).all(|pair| pair[0] < pair[1]),
            "Deletion projection targets must be unique and ordered"
        );
        for name in &self.names {
            bounded_text(name, 1024)?;
        }
        match (&self.requested, &self.dependencies) {
            (None, None) => {}
            (Some(requested), Some(dependencies)) => {
                ensure!(
                    requested.len() == self.requested_count
                        && requested.windows(2).all(|pair| pair[0] < pair[1])
                        && dependencies.windows(2).all(|pair| pair[0] < pair[1]),
                    "Deletion projection selection is ambiguous"
                );
                let selected = requested.iter().collect::<BTreeSet<_>>();
                let dependent = dependencies.iter().collect::<BTreeSet<_>>();
                ensure!(
                    selected.is_disjoint(&dependent)
                        && selected.union(&dependent).copied().collect::<BTreeSet<_>>()
                            == self.targets.iter().collect(),
                    "Deletion dependency identities do not cover the exact source plan"
                );
            }
            _ => anyhow::bail!("Deletion dependencies are incomplete"),
        }
        Ok(())
    }
}

/// Only after this succeeds may the native parent set the source's boolean
/// `native_dependency_ack`. UI booleans alone cannot acknowledge a changed plan.
pub fn validate_deletion_ack(
    plan: &FrozenFullDeletionPlan,
    ack: &DeletionAcknowledgement,
) -> Result<()> {
    plan.validate()?;
    ensure!(
        ack.plan_id == plan.plan_id && ack.digest == plan.digest,
        "Deletion acknowledgement belongs to another frozen source plan"
    );
    let dependencies = plan
        .dependencies
        .as_ref()
        .context("Original requested identities are unavailable; obtain a new native preview")?;
    let mut affected = ack.affected.clone();
    let mut acknowledged = ack.dependencies.clone();
    ensure!(
        affected.len() <= MAX_DELETION_TARGETS && acknowledged.len() <= MAX_DELETION_TARGETS,
        "Deletion acknowledgement exceeds its bounded scope"
    );
    affected.sort();
    acknowledged.sort();
    ensure!(
        affected == plan.targets && &acknowledged == dependencies,
        "Acknowledge every exact affected and dependent app/bundle/commit identity"
    );
    Ok(())
}

#[cfg(any(unix, windows))]
pub fn catalog_projection(
    provider_id: &str,
    catalog: &CatalogDocument,
    evidence: &CatalogEvidence,
) -> Result<Value> {
    safe_provider_id(provider_id)?;
    ensure!(
        catalog.schema_version == 1
            && catalog.apps.len() <= MAX_CATALOG_APPS
            && catalog.instances.len() <= MAX_CATALOG_APPS
            && catalog.heads.len() <= MAX_CATALOG_APPS
            && evidence.bundles.len() <= MAX_CATALOG_BUNDLES
            && evidence.pending_deletions.len() <= MAX_DELETION_TARGETS,
        "Source catalog exceeds its schema or native bounds"
    );
    validate_freshness(&evidence.freshness)?;
    let mut apps = Vec::with_capacity(catalog.apps.len());
    let mut bundles = Vec::new();
    let mut app_ids = BTreeSet::new();
    let head_ids = catalog
        .heads
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut bundle_ids = BTreeSet::new();
    let mut commit_ids = BTreeSet::new();
    for app in &catalog.apps {
        safe_app_id(app.app_id.as_str())?;
        ensure!(
            app_ids.insert(app.app_id.as_str()),
            "Duplicate catalog app identity"
        );
        bounded_text(&app.display_name, 256)?;
        ensure!(
            !app.bundles.is_empty() && app.aliases.len() <= 128,
            "A catalog app must have real history and bounded aliases"
        );
        for alias in &app.aliases {
            bounded_text(alias, 256)?;
        }
        for path in [&app.canonical_executable, &app.icon_path]
            .into_iter()
            .flatten()
        {
            bounded_text(
                path.to_str().context("Non-UTF8 catalog identity path")?,
                32_768,
            )?;
        }
        if let Some(entry) = &app.desktop_entry_id {
            bounded_text(entry, 1024)?;
        }
        let belongs = |id| app.bundles.iter().any(|bundle| bundle.bundle_id == id);
        ensure!(
            belongs(app.latest_bundle_id),
            "Catalog latest head is outside app history"
        );
        for head in [
            app.latest_complete_bundle_id,
            app.latest_personal_state_bundle_id,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(belongs(head), "Catalog mode head is outside app history");
        }
        let parents = app
            .bundles
            .iter()
            .filter_map(|bundle| bundle.parent_bundle_id)
            .collect::<BTreeSet<_>>();
        let mut divergent = app
            .bundles
            .iter()
            .filter(|bundle| !parents.contains(&bundle.bundle_id))
            .map(|bundle| bundle.bundle_id)
            .collect::<Vec<_>>();
        divergent.sort();
        // Preserve the actual source heads. Do not reinterpret partial captures
        // as whole-app heads or silently rewrite a legacy catalog's fields.
        apps.push(json!({
            "appId":app.app_id, "name":app.display_name, "aliases":app.aliases,
            "catalogHead":head_ids.contains(app.app_id.as_str()),
            "desktopEntryId":app.desktop_entry_id, "steamAppId":app.steam_app_id,
            "launcher":app.launcher, "canonicalExecutable":app.canonical_executable,
            "iconPath":app.icon_path, "latestBundleId":app.latest_bundle_id,
            "headsByMode":{
                "completeApplication":app.latest_complete_bundle_id,
                "personalState":app.latest_personal_state_bundle_id,
            },
            "latestCompleteCapturedAt":app.latest_complete_captured_at,
            "latestPersonalStateCapturedAt":app.latest_personal_state_captured_at,
            "divergentHeads":divergent, "bundleCount":app.bundles.len(),
        }));
        for bundle in &app.bundles {
            ensure!(
                bundles.len() < MAX_CATALOG_BUNDLES
                    && bundle_ids.insert(bundle.bundle_id)
                    && commit_ids.insert(bundle.commit_id),
                "Catalog history is oversized or has duplicate bundle/commit identities"
            );
            let detail = evidence.bundles.get(&bundle.bundle_id.to_string());
            if let Some(detail) = detail {
                ensure!(
                    detail.app_id == app.app_id.as_str()
                        && detail.bundle_id == bundle.bundle_id.to_string()
                        && detail.commit_id == bundle.commit_id.to_string()
                        && detail.file_count <= 1_000_000
                        && detail.tombstone_count <= 1_000_000
                        && (detail.coverage != Coverage::CompleteApplication
                            || bundle.mode == BackupMode::CompleteApplication)
                        && (detail.coverage != Coverage::PersonalState
                            || bundle.mode == BackupMode::PersonalState)
                        && (!detail.reconstruction_ready
                            || detail.coverage == Coverage::CompleteApplication
                                && detail.file_count > 0),
                    "Manifest evidence differs from its exact catalog revision"
                );
                if let Some(platform) = &detail.platform {
                    bounded_text(platform, 64)?;
                }
            }
            let coverage = detail.map_or(Coverage::Unknown, |detail| detail.coverage);
            let complete = coverage == Coverage::CompleteApplication
                && detail.is_some_and(|detail| detail.file_count > 0);
            bundles.push(json!({
                "id":bundle.bundle_id, "appId":app.app_id, "name":app.display_name,
                "providerId":provider_id, "createdAt":bundle.captured_at,
                "commitId":bundle.commit_id, "parentBundleId":bundle.parent_bundle_id,
                "sourceInstanceId":bundle.source_instance_id, "mode":bundle.mode,
                "logicalBytes":bundle.logical_size,
                "storedIncrementalBytes":bundle.stored_incremental_size,
                "fileCount":detail.map(|detail|detail.file_count),
                "tombstoneCount":detail.map(|detail|detail.tombstone_count),
                "platform":detail.and_then(|detail|detail.platform.as_ref()),
                "completeness":coverage, "completeApplication":complete,
                "captureScopeLabel":match coverage {
                    Coverage::CompleteApplication => "complete_application",
                    Coverage::ApprovedSoftware => "approved_full_scope",
                    Coverage::SelectedFiles => "selected_custom_scope",
                    Coverage::PersonalState => "personal_state",
                    Coverage::Unknown if bundle.mode == BackupMode::Custom => "selected_custom_scope",
                    Coverage::Unknown => "unknown",
                },
                "subset":match coverage {
                    Coverage::SelectedFiles => Some(true),
                    Coverage::CompleteApplication | Coverage::ApprovedSoftware => Some(false),
                    Coverage::Unknown if bundle.mode == BackupMode::Custom => Some(true),
                    _ => None,
                },
                "readiness":{
                    "metadataVerified":detail.is_some(),
                    "filesAvailable":detail.is_some_and(|detail|detail.file_count>0),
                    "applicationReady":detail.is_some_and(|detail|detail.reconstruction_ready),
                    "requiresNativeRestorePreview":true,
                },
                "currentHead":app.latest_bundle_id==bundle.bundle_id,
                "currentCompleteHead":app.latest_complete_bundle_id==Some(bundle.bundle_id),
                "currentPersonalStateHead":app.latest_personal_state_bundle_id==Some(bundle.bundle_id),
                "format":"No Land NLNE/NLZ1/NLPK",
                "compatibility":if detail.is_some_and(|detail|detail.reconstruction_ready) {
                    "native_verified_application"
                } else { "requires_native_validation" },
            }));
        }
    }
    for head in &catalog.heads {
        ensure!(
            app_ids.contains(head.as_str()),
            "Catalog app head has no application"
        );
    }
    ensure!(
        catalog.heads.iter().collect::<BTreeSet<_>>().len() == catalog.heads.len(),
        "Duplicate catalog app heads"
    );
    let mut instances = Vec::with_capacity(catalog.instances.len());
    let mut instance_ids = BTreeSet::new();
    for instance in &catalog.instances {
        ensure!(
            instance_ids.insert(instance.instance_id),
            "Duplicate source instance ID"
        );
        bounded_text(&instance.image_id, 256)?;
        if let Some(seal) = &instance.last_seal {
            safe_app_id(seal.app_id.as_str())?;
        }
        instances.push(json!({
            "instanceId":instance.instance_id, "imageId":instance.image_id,
            "lastSeal":instance.last_seal,
        }));
    }
    let mut pending = evidence.pending_deletions.clone();
    let mut pending_ids = BTreeSet::new();
    for plan in &pending {
        plan.validate()?;
        ensure!(
            pending_ids.insert(&plan.plan_id),
            "Duplicate pending deletion plan ID"
        );
    }
    pending.sort_by(|a, b| a.plan_id.cmp(&b.plan_id));
    apps.sort_by(|a, b| a["appId"].as_str().cmp(&b["appId"].as_str()));
    bundles.sort_by(|a, b| {
        b["createdAt"]
            .as_str()
            .cmp(&a["createdAt"].as_str())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    instances.sort_by(|a, b| a["instanceId"].as_str().cmp(&b["instanceId"].as_str()));
    let mut heads = catalog.heads.clone();
    heads.sort();
    let mut out = json!({
        "projectionVersion":1, "providerId":provider_id,
        "schemaVersion":catalog.schema_version, "catalogCommitId":catalog.catalog_commit_id,
        "createdAt":catalog.created_at, "heads":heads, "apps":apps, "bundles":bundles,
        "instances":instances, "pendingDeletions":pending,
    });
    // Revision includes heads, actual history, pending identities and native
    // coverage/readiness evidence, but not per-request timestamps/metrics.
    out["revision"] = json!(blake3::hash(&bounded_json(&out, MAX_CATALOG_BYTES)?)
        .to_hex()
        .to_string());
    out["freshness"] = serde_json::to_value(&evidence.freshness)?;
    out["authoritativeForExecution"] = json!(false);
    bounded_json(&out, MAX_CATALOG_BYTES)?;
    Ok(out)
}

/// The actual source RPC extends CatalogDocument with freshness/pending fields.
/// Deserialize the typed document, then explicitly preserve those extensions;
/// deserializing only CatalogDocument silently drops both.
#[cfg(any(unix, windows))]
pub fn catalog_projection_from_rpc(
    provider_id: &str,
    raw: &Value,
    evidence: &CatalogEvidence,
) -> Result<Value> {
    bounded_json(raw, MAX_CATALOG_BYTES)?;
    let catalog: CatalogDocument =
        serde_json::from_value(raw.clone()).context("Authenticated source catalog is malformed")?;
    let mut evidence = evidence.clone();
    let freshness = raw.get("catalog_freshness").context(
        "Source RPC lacks actual catalog freshness; do not substitute a flattened catalog",
    )?;
    evidence.freshness = CatalogFreshness {
        source: freshness["source"]
            .as_str()
            .context("Source catalog freshness lacks its evidence origin")?
            .to_owned(),
        refresh_started_at: Some(
            freshness["refresh_started_at"]
                .as_str()
                .context("Source refresh start evidence is missing")?
                .to_owned(),
        ),
        observed_at: Some(
            freshness["observed_at"]
                .as_str()
                .context("Source observation evidence is missing")?
                .to_owned(),
        ),
        coalesced: freshness["coalesced"]
            .as_bool()
            .context("Source coalescing evidence is missing")?,
    };
    let mut output = catalog_projection(provider_id, &catalog, &evidence)?;
    let pending = raw
        .get("pending_deletions")
        .context("Source RPC lacks actual pending deletion evidence")?;
    {
        let pending = pending
            .as_array()
            .context("Source pending deletions are malformed")?;
        ensure!(
            pending.len() <= MAX_DELETION_TARGETS,
            "Too many pending source deletions"
        );
        let known = evidence
            .pending_deletions
            .iter()
            .map(|plan| plan.plan_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut summaries = Vec::new();
        let mut seen = BTreeSet::new();
        for plan in pending {
            let id = plan["plan_id"]
                .as_str()
                .context("Pending source plan ID is missing")?;
            canonical_uuid(id)?;
            ensure!(seen.insert(id), "Duplicate pending source deletion ID");
            if !known.contains(id) {
                let names = plan["names"]
                    .as_array()
                    .context("Pending source names missing")?;
                ensure!(
                    names.len() <= MAX_DELETION_TARGETS,
                    "Pending deletion names exceed bound"
                );
                let names = names
                    .iter()
                    .map(|name| {
                        Ok(bounded_text(
                            name.as_str().context("Invalid pending deletion name")?,
                            1024,
                        )?
                        .to_owned())
                    })
                    .collect::<Result<Vec<_>>>()?;
                summaries.push(json!({
                    "planId":id, "names":names, "detailsAvailable":false,
                    "requiresNativePlanLoad":true, "dependenciesKnown":false,
                }));
            }
        }
        // A rich plan is retained only if it is in the actual fresh pending set.
        output["pendingDeletions"] = json!(evidence
            .pending_deletions
            .iter()
            .filter(|plan| seen.contains(plan.plan_id.as_str()))
            .collect::<Vec<_>>());
        output["pendingDeletionSummaries"] = json!(summaries);
    }
    // Extensions affect the revision too (including a pending plan before its
    // catalog tombstones changed the catalog commit ID).
    let mut revision_source = output.clone();
    for field in ["revision", "freshness", "authoritativeForExecution"] {
        revision_source.as_object_mut().unwrap().remove(field);
    }
    output["revision"] = json!(
        blake3::hash(&bounded_json(&revision_source, MAX_CATALOG_BYTES)?)
            .to_hex()
            .to_string()
    );
    bounded_json(&output, MAX_CATALOG_BYTES)?;
    Ok(output)
}

pub(crate) fn safe_app_id(value: &str) -> Result<()> {
    bounded_text(value, 512)?;
    ensure!(
        !matches!(value, "." | ".." | "*" | "_all")
            && !value.contains(['/', '\\', '*', '?', '[', ']', '\0']),
        "Application identity cannot be used as an exact source selection"
    );
    Ok(())
}

fn safe_provider_id(value: &str) -> Result<()> {
    bounded_text(value, 128)?;
    ensure!(
        !value.contains(['/', '\\', '\0']),
        "Invalid provider identity"
    );
    Ok(())
}

fn bounded_text(value: &str, max: usize) -> Result<&str> {
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "Catalog text is empty, invalid or oversized"
    );
    Ok(value)
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid native catalog/deletion digest"
    );
    Ok(())
}

fn canonical_uuid(value: &str) -> Result<()> {
    #[cfg(any(unix, windows))]
    ensure!(
        uuid::Uuid::parse_str(value)
            .ok()
            .is_some_and(|id| id.to_string() == value),
        "Invalid canonical source identity"
    );
    #[cfg(not(any(unix, windows)))]
    {
        ensure!(
            value.len() == 36
                && value.bytes().enumerate().all(|(i, byte)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                    }
                }),
            "Invalid canonical source identity"
        );
    }
    Ok(())
}

fn validate_bundle_identity(identity: &BundleIdentity) -> Result<()> {
    safe_app_id(&identity.app_id)?;
    canonical_uuid(&identity.bundle_id)?;
    canonical_uuid(&identity.commit_id)
}

fn validate_freshness(freshness: &CatalogFreshness) -> Result<()> {
    if !freshness.source.is_empty() {
        bounded_text(&freshness.source, 128)?;
    }
    for date in [&freshness.refresh_started_at, &freshness.observed_at]
        .into_iter()
        .flatten()
    {
        bounded_text(date, 64)?;
        #[cfg(any(unix, windows))]
        chrono::DateTime::parse_from_rfc3339(date)
            .context("Invalid catalog freshness timestamp")?;
    }
    Ok(())
}

fn bounded_json(value: &impl Serialize, max: usize) -> Result<Vec<u8>> {
    // Counting before allocation also bounds oversize source strings/arrays.
    struct Counter(usize, usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("Native catalog JSON size overflow"))?;
            if self.0 > self.1 {
                return Err(std::io::Error::other(
                    "Native catalog JSON exceeds its bound",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0, max);
    serde_json::to_writer(&mut count, value)?;
    Ok(serde_json::to_vec(value)?)
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use chrono::Utc;
    use noland_state_core::{AppId, CatalogApp, CatalogBundle, CatalogInstance, LauncherKind};
    use uuid::Uuid;

    fn fixture() -> CatalogDocument {
        let source = Uuid::new_v4();
        let full = Uuid::new_v4();
        let personal = Uuid::new_v4();
        let now = Utc::now();
        CatalogDocument {
            schema_version: 1,
            catalog_commit_id: Uuid::new_v4(),
            created_at: now,
            heads: vec![AppId("desktop:original.game".into())],
            apps: vec![CatalogApp {
                app_id: AppId("desktop:original.game".into()),
                display_name: "Original Game".into(),
                aliases: vec!["Prior Name".into()],
                desktop_entry_id: Some("original.game.desktop".into()),
                steam_app_id: None,
                launcher: Some(LauncherKind::Native),
                canonical_executable: Some("/fixture/Game/game".into()),
                icon_path: Some("/fixture/Game/icon.png".into()),
                latest_bundle_id: personal,
                latest_complete_bundle_id: Some(full),
                latest_personal_state_bundle_id: Some(personal),
                latest_complete_captured_at: Some(now),
                latest_personal_state_captured_at: Some(now + chrono::Duration::seconds(1)),
                bundles: vec![
                    CatalogBundle {
                        bundle_id: full,
                        commit_id: Uuid::new_v4(),
                        parent_bundle_id: None,
                        captured_at: now,
                        source_instance_id: source,
                        mode: BackupMode::CompleteApplication,
                        logical_size: 100,
                        stored_incremental_size: 80,
                    },
                    CatalogBundle {
                        bundle_id: personal,
                        commit_id: Uuid::new_v4(),
                        parent_bundle_id: Some(full),
                        captured_at: now + chrono::Duration::seconds(1),
                        source_instance_id: source,
                        mode: BackupMode::PersonalState,
                        logical_size: 30,
                        stored_incremental_size: 10,
                    },
                ],
            }],
            instances: vec![CatalogInstance {
                instance_id: source,
                image_id: "fixture-image".into(),
                last_seal: None,
            }],
        }
    }

    #[test]
    fn rich_catalog_keeps_original_identity_heads_lineage_and_unknown_coverage() {
        let source = fixture();
        let output =
            catalog_projection("fixture-provider", &source, &CatalogEvidence::default()).unwrap();
        let app = &output["apps"][0];
        assert_eq!(app["appId"], source.apps[0].app_id.as_str());
        assert_eq!(app["aliases"][0], "Prior Name");
        assert_eq!(app["desktopEntryId"], "original.game.desktop");
        assert_eq!(
            app["headsByMode"]["completeApplication"],
            source.apps[0]
                .latest_complete_bundle_id
                .unwrap()
                .to_string()
        );
        assert_eq!(
            app["headsByMode"]["personalState"],
            source.apps[0]
                .latest_personal_state_bundle_id
                .unwrap()
                .to_string()
        );
        let history = output["bundles"].as_array().unwrap();
        assert_eq!(history[0]["parentBundleId"], history[1]["id"]);
        assert_eq!(
            history[1]["commitId"],
            source.apps[0].bundles[0].commit_id.to_string()
        );
        assert_eq!(
            history[1]["sourceInstanceId"],
            source.instances[0].instance_id.to_string()
        );
        assert_eq!(history[1]["mode"], "complete_application");
        assert_eq!(history[1]["completeness"], "unknown");
        assert_eq!(history[1]["completeApplication"], false);
        assert_eq!(history[1]["fileCount"], Value::Null);
        assert_eq!(history[1]["readiness"]["applicationReady"], false);
        assert_eq!(output["authoritativeForExecution"], false);
    }

    #[test]
    fn a_selected_file_bundle_in_complete_mode_stays_partial() {
        let source = fixture();
        let bundle = &source.apps[0].bundles[0];
        let mut evidence = CatalogEvidence::default();
        evidence.bundles.insert(
            bundle.bundle_id.to_string(),
            BundleEvidence {
                app_id: source.apps[0].app_id.to_string(),
                bundle_id: bundle.bundle_id.to_string(),
                commit_id: bundle.commit_id.to_string(),
                coverage: Coverage::SelectedFiles,
                file_count: 2,
                tombstone_count: 0,
                platform: Some("fixture-platform".into()),
                reconstruction_ready: false,
            },
        );
        let output = catalog_projection("fixture-provider", &source, &evidence).unwrap();
        let row = &output["bundles"][1];
        assert_eq!(row["subset"], true);
        assert_eq!(row["completeApplication"], false);
        assert_eq!(
            row["currentCompleteHead"], true,
            "keep source heads without inventing full coverage"
        );
        assert_eq!(row["fileCount"], 2);
        evidence
            .bundles
            .get_mut(&bundle.bundle_id.to_string())
            .unwrap()
            .commit_id = Uuid::new_v4().to_string();
        assert!(catalog_projection("fixture-provider", &source, &evidence).is_err());
    }

    #[test]
    fn custom_history_never_replaces_complete_head_and_has_explicit_scope_label() {
        let mut source = fixture();
        let real_complete = source.apps[0].latest_complete_bundle_id;
        let mut custom = source.apps[0].bundles[0].clone();
        custom.bundle_id = Uuid::new_v4();
        custom.commit_id = Uuid::new_v4();
        custom.parent_bundle_id = real_complete;
        custom.captured_at += chrono::Duration::seconds(2);
        custom.mode = BackupMode::Custom;
        source.apps[0].latest_bundle_id = custom.bundle_id;
        source.apps[0].bundles.push(custom.clone());
        let mut evidence = CatalogEvidence::default();
        let output = catalog_projection("fixture-provider", &source, &evidence).unwrap();
        assert_eq!(
            output["apps"][0]["headsByMode"]["completeApplication"],
            real_complete.unwrap().to_string()
        );
        let row = &output["bundles"][0];
        assert_eq!(row["mode"], "custom");
        assert_eq!(row["captureScopeLabel"], "selected_custom_scope");
        assert_eq!(
            row["completeness"], "unknown",
            "legacy custom still has no coverage proof"
        );
        assert_eq!(row["completeApplication"], false);
        assert_eq!(row["currentCompleteHead"], false);
        assert_eq!(row["subset"], true);
        evidence.bundles.insert(
            custom.bundle_id.to_string(),
            BundleEvidence {
                app_id: source.apps[0].app_id.to_string(),
                bundle_id: custom.bundle_id.to_string(),
                commit_id: custom.commit_id.to_string(),
                coverage: Coverage::ApprovedSoftware,
                file_count: 2,
                tombstone_count: 0,
                platform: None,
                reconstruction_ready: false,
            },
        );
        let full_approved = catalog_projection("fixture-provider", &source, &evidence).unwrap();
        assert_eq!(
            full_approved["bundles"][0]["captureScopeLabel"],
            "approved_full_scope"
        );
        assert_eq!(
            full_approved["bundles"][0]["completeApplication"], false,
            "all approved roots alone are not an application reconstruction proof"
        );
        assert_eq!(full_approved["bundles"][0]["currentCompleteHead"], false);
    }

    #[test]
    fn authenticated_manifest_coverage_is_explicit_and_legacy_modes_remain_unknown() {
        use noland_state_core::{AppIdentity, ManifestApp, ManifestSource};
        let identity = AppIdentity::new(AppId("desktop:fixture".into()), "Fixture");
        let mut manifest = BundleManifest::new(
            ManifestApp::from(&identity),
            ManifestSource {
                instance_id: Uuid::new_v4(),
                image_id: "fixture-image".into(),
                captured_at: Utc::now(),
            },
            BackupMode::CompleteApplication,
        );
        manifest.environment["capture_scope_version"] = json!(1);
        assert_eq!(
            BundleEvidence::from_authenticated_manifest(&manifest, false)
                .unwrap()
                .coverage,
            Coverage::Unknown,
            "mode, logical size and legacy scope-version flags are not coverage proof"
        );
        manifest.mode = BackupMode::Custom;
        manifest.environment["quicksave_native"] = json!({
            "platform":"fixture-platform",
            "selection":{"capture_scope":{"coverage":"selected_nodes"}},
        });
        let subset = BundleEvidence::from_authenticated_manifest(&manifest, false).unwrap();
        assert_eq!(subset.coverage, Coverage::SelectedFiles);
        assert_eq!(subset.platform.as_deref(), Some("fixture-platform"));
        assert!(BundleEvidence::from_authenticated_manifest(&manifest, true).is_err());
        manifest.environment["quicksave_native"] = json!({
            "coverage":"selected_nodes","selection":{"coverage":"selected_nodes"},
        });
        assert_eq!(
            coverage_from_manifest(&manifest).unwrap(),
            Coverage::SelectedFiles
        );
        manifest.environment["quicksave_native"]["coverage"] = json!("full_scope");
        assert!(
            coverage_from_manifest(&manifest).is_err(),
            "mirror must match HMAC-bound selection"
        );
        manifest.environment["quicksave_native"]["selection"]["coverage"] = json!("full_scope");
        assert_eq!(
            coverage_from_manifest(&manifest).unwrap(),
            Coverage::ApprovedSoftware
        );
        manifest.environment["quicksave_native"] = json!({
            "selection":{"capture_scope":{"coverage":"approved_software"}},
        });
        manifest.environment["quicksave_native"]["selection"]["capture_scope"]["coverage"] =
            json!("approved_software");
        assert_eq!(
            BundleEvidence::from_authenticated_manifest(&manifest, false)
                .unwrap()
                .coverage,
            Coverage::ApprovedSoftware,
            "all approved roots still do not prove a whole application"
        );
        manifest.environment["quicksave_native"]["selection"]["capture_scope"]["coverage"] =
            json!("complete_application");
        assert!(
            BundleEvidence::from_authenticated_manifest(&manifest, false).is_err(),
            "whole-app proof cannot disagree with the source Custom mode"
        );
    }

    #[test]
    fn rpc_extensions_preserve_freshness_pending_ids_and_change_revision() {
        let source = fixture();
        let mut raw = serde_json::to_value(&source).unwrap();
        let pending = Uuid::new_v4();
        raw["pending_deletions"] = json!([{"plan_id":pending,"names":["Fixture retained backup"]}]);
        raw["catalog_freshness"] = json!({
            "source":"live_remote_validation", "refresh_started_at":Utc::now(),
            "observed_at":Utc::now(), "coalesced":true, "authoritative_for_execution":false,
        });
        let first =
            catalog_projection_from_rpc("fixture-provider", &raw, &CatalogEvidence::default())
                .unwrap();
        assert_eq!(first["freshness"]["source"], "live_remote_validation");
        assert_eq!(first["freshness"]["coalesced"], true);
        assert_eq!(
            first["pendingDeletionSummaries"][0]["planId"],
            pending.to_string()
        );
        assert_eq!(
            first["pendingDeletionSummaries"][0]["dependenciesKnown"],
            false
        );
        raw["catalog_freshness"]["observed_at"] = json!(Utc::now());
        let later =
            catalog_projection_from_rpc("fixture-provider", &raw, &CatalogEvidence::default())
                .unwrap();
        assert_eq!(
            first["revision"], later["revision"],
            "refresh time is not a content revision"
        );
        raw["pending_deletions"] = json!([]);
        let changed =
            catalog_projection_from_rpc("fixture-provider", &raw, &CatalogEvidence::default())
                .unwrap();
        assert_eq!(first["catalogCommitId"], changed["catalogCommitId"]);
        assert_ne!(
            first["revision"], changed["revision"],
            "pending changes invalidate cursors too"
        );
    }

    fn full_deletion_fixture() -> (FullDeletionPlan, Vec<DeletionSelection>) {
        let first = Uuid::from_u128(1);
        let selected = Uuid::from_u128(2);
        let plan: FullDeletionPlan = serde_json::from_value(json!({
            "plan_id":Uuid::new_v4(),"operation_id":Uuid::new_v4(),
            "owner":"fixture-native-owner","automatic":false,"requested_count":1,
            "targets":[
                {"deletion":{"app_id":"desktop:dependency","bundle_id":first,"commit_id":Uuid::from_u128(3)},
                    "name":"Dependency","logical_bytes":8},
                {"deletion":{"app_id":"desktop:selected","bundle_id":selected,"commit_id":Uuid::from_u128(4)},
                    "name":"Selected","logical_bytes":9},
            ],
            "packs":{},"metadata":{},
            "target_hashes":{
                "00000000-0000-0000-0000-000000000001":["fixture-manifest","fixture-index"],
                "00000000-0000-0000-0000-000000000002":["fixture-manifest-two","fixture-index-two"]},
            "inventory_hash":"fixture-authenticated-inventory",
        })).unwrap();
        (
            plan,
            vec![DeletionSelection {
                app_id: "desktop:selected".into(),
                bundle_id: selected.to_string(),
            }],
        )
    }

    #[test]
    fn deletion_dependencies_are_exact_not_first_requested_count_targets() {
        let (source, original) = full_deletion_fixture();
        let plan = deletion_projection(&source, Some(&original)).unwrap();
        assert_eq!(
            plan.requested.as_ref().unwrap()[0].app_id,
            "desktop:selected"
        );
        assert_eq!(
            plan.dependencies.as_ref().unwrap()[0].app_id,
            "desktop:dependency"
        );
        let mut ack = DeletionAcknowledgement {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest.clone(),
            affected: plan.targets.clone(),
            dependencies: plan.dependencies.clone().unwrap(),
        };
        validate_deletion_ack(&plan, &ack).unwrap();
        ack.dependencies[0].commit_id = Uuid::new_v4().to_string();
        assert!(validate_deletion_ack(&plan, &ack).is_err());
        ack.dependencies = plan.dependencies.clone().unwrap();
        ack.affected.pop();
        assert!(validate_deletion_ack(&plan, &ack).is_err());
        let unknown = deletion_projection(&source, None).unwrap();
        assert!(unknown.requested.is_none());
        assert!(unknown.dependencies.is_none());
        assert!(validate_deletion_ack(&unknown, &ack).is_err());
    }

    #[test]
    fn automatic_retirement_and_count_only_acknowledgements_are_not_authority() {
        let (mut source, original) = full_deletion_fixture();
        source.automatic = true;
        assert!(deletion_projection(&source, Some(&original)).is_err());
        assert!(serde_json::from_value::<DeletionAcknowledgement>(json!({
            "planId":source.plan_id,"acknowledgeDependencies":true,
        }))
        .is_err());
    }
}
