// SPDX-License-Identifier: GPL-3.0-only
//! Bounded revision-bound catalog/history pagination for native projections.
//!
//! # Parent integration API
//!
//! `CatalogCache::replace(provider_id, projection)` accepts the validated rich
//! document produced by `quicksave_noland::catalog_control::catalog_projection`.
//! `CatalogCache::page(provider_id, CatalogQuery)` returns at most 128 rows.
//! Every cursor binds the actual catalog/content revision, provider and query;
//! replacing the source revision invalidates old cursors instead of offset drift.
//! Call `replace` only after a real source refresh. Cache hits are browse evidence,
//! never execution/restore/deletion authority. No full file inventory crosses IPC.
//!
//! `CatalogView::History` requires an exact app identity. Pending-deletion pages
//! are summaries; `CatalogView::DeletionTargets` pages their exact affected
//! app/bundle/commit identities (and original requested/dependent membership).
//! Foreign/legacy pending summaries retain their real plan ID with dependencies
//! explicitly unknown until the parent authenticates the actual source plan.
//! App rows carry `catalogHead` and mode heads; no page repeats a 4096-ID head
//! array. `headCount` is a count of actual source heads, not a readiness claim.
//! Limits: four providers, 64 MiB aggregate serialized cache, 32 MiB/document,
//! 4096 apps, 100000 history rows, 128 rows and 2 MiB per IPC page. No stale
//! latest/negative cache: the parent must replace after actual source refresh.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub const MAX_CATALOG_PAGE: usize = 128;
pub const MAX_CATALOG_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CATALOG_CACHE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CATALOG_PROVIDERS: usize = 4;
pub const MAX_CATALOG_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogView {
    Apps,
    #[default]
    Bundles,
    History,
    PendingDeletions,
    DeletionTargets,
    Instances,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogMode {
    CompleteApplication,
    PersonalState,
    Custom,
}

impl CatalogMode {
    fn token(self) -> &'static str {
        match self {
            Self::CompleteApplication => "complete_application",
            Self::PersonalState => "personal_state",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogQuery {
    #[serde(default)]
    pub view: CatalogView,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub mode: Option<CatalogMode>,
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cursor {
    version: u32,
    provider_id: String,
    revision: String,
    scope: String,
    last_key: String,
}

struct Snapshot {
    revision: String,
    catalog_commit_id: String,
    created_at: Value,
    freshness: Value,
    head_count: usize,
    apps: Vec<Value>,
    bundles: Vec<Value>,
    instances: Vec<Value>,
    pending: Vec<Value>,
    serialized_bytes: usize,
}

#[derive(Default)]
struct CacheState {
    providers: BTreeMap<String, Arc<Snapshot>>,
    bytes: usize,
}

#[derive(Default)]
pub struct CatalogCache {
    state: Mutex<CacheState>,
}

impl CatalogCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept only the native helper's rich, bounded projection, not the old
    /// flattened `{"bundles":[...]}` or incoming webview JSON. Checks content
    /// revision, not merely a supplied cursor/commit string.
    pub fn replace(&self, provider_id: &str, mut projection: Value) -> Result<String> {
        identifier(provider_id, 128)?;
        let serialized_bytes = json_size(&projection, MAX_CATALOG_DOCUMENT_BYTES)?;
        let object = projection
            .as_object()
            .context("Native catalog projection must be an object")?;
        let allowed = [
            "projectionVersion",
            "providerId",
            "schemaVersion",
            "catalogCommitId",
            "createdAt",
            "heads",
            "apps",
            "bundles",
            "instances",
            "pendingDeletions",
            "pendingDeletionSummaries",
            "revision",
            "freshness",
            "authoritativeForExecution",
        ];
        ensure!(
            object.keys().all(|key| allowed.contains(&key.as_str()))
                && projection["projectionVersion"] == 1
                && projection["schemaVersion"] == 1
                && projection["providerId"] == provider_id
                && projection["authoritativeForExecution"] == false,
            "Native catalog projection schema/provider is invalid"
        );
        let revision = projection["revision"]
            .as_str()
            .context("Native catalog revision is missing")?
            .to_owned();
        digest(&revision)?;
        let catalog_commit_id = canonical_uuid(&projection["catalogCommitId"])?.to_owned();
        timestamp(&projection["createdAt"])?;
        // This exactly matches the native helper's revision content. Freshness
        // timestamps can advance without causing false stale cursors; actual
        // history, pending plans and readiness changes always invalidate them.
        let mut revision_source = projection.clone();
        for field in ["revision", "freshness", "authoritativeForExecution"] {
            revision_source.as_object_mut().unwrap().remove(field);
        }
        ensure!(
            blake3::hash(&serde_json::to_vec(&revision_source)?)
                .to_hex()
                .as_str()
                == revision,
            "Native catalog revision does not match its actual document"
        );
        drop(revision_source);
        validate_freshness(&projection["freshness"])?;
        let apps = take_array(&mut projection, "apps", 4096)?;
        let bundles = take_array(&mut projection, "bundles", 100_000)?;
        let instances = take_array(&mut projection, "instances", 4096)?;
        let mut pending = take_array(&mut projection, "pendingDeletions", 10_000)?;
        let summaries = if projection.get("pendingDeletionSummaries").is_some() {
            take_array(&mut projection, "pendingDeletionSummaries", 10_000)?
        } else {
            Vec::new()
        };
        ensure!(
            pending.len() + summaries.len() <= 10_000,
            "Pending deletion catalog exceeds bound"
        );
        pending.extend(summaries);
        let mut app_ids = BTreeSet::new();
        for app in &apps {
            fields(
                app,
                &[
                    "appId",
                    "catalogHead",
                    "name",
                    "aliases",
                    "desktopEntryId",
                    "steamAppId",
                    "launcher",
                    "canonicalExecutable",
                    "iconPath",
                    "latestBundleId",
                    "headsByMode",
                    "latestCompleteCapturedAt",
                    "latestPersonalStateCapturedAt",
                    "divergentHeads",
                    "bundleCount",
                ],
            )?;
            let app_id = app["appId"]
                .as_str()
                .context("Original catalog app identity is missing")?;
            identifier(app_id, 512)?;
            ensure!(
                app_ids.insert(app_id),
                "Duplicate original catalog app identity"
            );
            text_value(&app["name"], 256)?;
            canonical_uuid(&app["latestBundleId"])?;
            let heads = app["headsByMode"]
                .as_object()
                .context("Catalog mode heads are missing")?;
            ensure!(
                heads.len() == 2
                    && heads.contains_key("completeApplication")
                    && heads.contains_key("personalState"),
                "Catalog mode heads are incomplete"
            );
            for head in heads.values().filter(|value| !value.is_null()) {
                canonical_uuid(head)?;
            }
        }
        let mut bundle_ids = BTreeMap::new();
        for bundle in &bundles {
            fields(
                bundle,
                &[
                    "id",
                    "appId",
                    "name",
                    "providerId",
                    "createdAt",
                    "commitId",
                    "parentBundleId",
                    "sourceInstanceId",
                    "mode",
                    "logicalBytes",
                    "storedIncrementalBytes",
                    "fileCount",
                    "tombstoneCount",
                    "platform",
                    "completeness",
                    "captureScopeLabel",
                    "completeApplication",
                    "subset",
                    "readiness",
                    "currentHead",
                    "currentCompleteHead",
                    "currentPersonalStateHead",
                    "format",
                    "compatibility",
                ],
            )?;
            let id = canonical_uuid(&bundle["id"])?;
            let original_app = bundle["appId"]
                .as_str()
                .context("Catalog bundle app identity missing")?;
            ensure!(
                bundle_ids.insert(id, original_app).is_none(),
                "Duplicate catalog bundle ID"
            );
            canonical_uuid(&bundle["commitId"])?;
            canonical_uuid(&bundle["sourceInstanceId"])?;
            if !bundle["parentBundleId"].is_null() {
                canonical_uuid(&bundle["parentBundleId"])?;
            }
            ensure!(
                bundle["providerId"] == provider_id
                    && bundle["appId"]
                        .as_str()
                        .is_some_and(|id| app_ids.contains(id))
                    && matches!(
                        bundle["mode"].as_str(),
                        Some("complete_application" | "personal_state" | "custom")
                    )
                    && bundle["logicalBytes"].is_u64()
                    && bundle["storedIncrementalBytes"].is_u64(),
                "Catalog bundle lost its original identity/mode/size"
            );
            timestamp(&bundle["createdAt"])?;
            text_value(&bundle["name"], 256)?;
            ensure!(
                matches!(
                    bundle["completeness"].as_str(),
                    Some(
                        "unknown"
                            | "selected_files"
                            | "approved_software"
                            | "personal_state"
                            | "complete_application"
                    )
                ),
                "Catalog completeness evidence is missing"
            );
            ensure!(
                bundle["completeApplication"] != true
                    || bundle["completeness"] == "complete_application"
                        && bundle["mode"] == "complete_application",
                "Partial catalog bundle cannot be advertised as a complete application"
            );
            fields(
                &bundle["readiness"],
                &[
                    "metadataVerified",
                    "filesAvailable",
                    "applicationReady",
                    "requiresNativeRestorePreview",
                ],
            )?;
            ensure!(
                bundle["readiness"]["requiresNativeRestorePreview"] == true
                    && (bundle["readiness"]["applicationReady"] != true
                        || bundle["completeApplication"] == true
                            && bundle["fileCount"].as_u64().is_some_and(|count| count > 0)),
                "Catalog readiness overclaims native application authority"
            );
        }
        for app in &apps {
            let app_id = app["appId"].as_str().unwrap();
            for head in std::iter::once(&app["latestBundleId"])
                .chain(app["headsByMode"].as_object().unwrap().values())
                .filter(|value| !value.is_null())
            {
                ensure!(
                    head.as_str().and_then(|head| bundle_ids.get(head)).copied() == Some(app_id),
                    "Catalog head points outside its original application's history"
                );
            }
        }
        let mut instance_ids = BTreeSet::new();
        for instance in &instances {
            fields(instance, &["instanceId", "imageId", "lastSeal"])?;
            ensure!(
                instance_ids.insert(canonical_uuid(&instance["instanceId"])?),
                "Duplicate catalog source instance"
            );
            text_value(&instance["imageId"], 256)?;
        }
        let mut pending_ids = BTreeSet::new();
        for plan in &pending {
            let id = canonical_uuid(&plan["planId"])?;
            ensure!(
                pending_ids.insert(id),
                "Duplicate actual pending deletion plan ID"
            );
            validate_pending(plan)?;
        }
        let heads = projection["heads"]
            .as_array()
            .context("Native catalog heads are missing")?;
        let mut seen_heads = BTreeSet::new();
        for head in heads {
            let head = head.as_str().context("Invalid native catalog app head")?;
            ensure!(
                app_ids.contains(head) && seen_heads.insert(head),
                "Invalid/duplicate catalog app head"
            );
        }
        for app in &apps {
            ensure!(
                app["catalogHead"].as_bool()
                    == Some(seen_heads.contains(app["appId"].as_str().unwrap())),
                "Catalog app-head membership differs from the actual source heads"
            );
        }
        let head_count = heads.len();
        // Canonical ordering is independent of JSON row offsets.
        let mut apps = apps;
        let mut bundles = bundles;
        let mut instances = instances;
        apps.sort_by(|a, b| a["appId"].as_str().cmp(&b["appId"].as_str()));
        bundles.sort_by(|a, b| {
            b["createdAt"]
                .as_str()
                .cmp(&a["createdAt"].as_str())
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
        instances.sort_by(|a, b| a["instanceId"].as_str().cmp(&b["instanceId"].as_str()));
        pending.sort_by(|a, b| a["planId"].as_str().cmp(&b["planId"].as_str()));
        let snapshot = Arc::new(Snapshot {
            revision: revision.clone(),
            catalog_commit_id,
            created_at: projection["createdAt"].take(),
            freshness: projection["freshness"].take(),
            head_count,
            apps,
            bundles,
            instances,
            pending,
            serialized_bytes,
        });
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Catalog cache lock failed"))?;
        ensure!(
            state.providers.contains_key(provider_id)
                || state.providers.len() < MAX_CATALOG_PROVIDERS,
            "Native catalog provider cache is full; explicitly invalidate an unused provider"
        );
        let old_bytes = state
            .providers
            .get(provider_id)
            .map_or(0, |old| old.serialized_bytes);
        let bytes = state
            .bytes
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(serialized_bytes))
            .context("Catalog cache byte count overflow")?;
        ensure!(
            bytes <= MAX_CATALOG_CACHE_BYTES,
            "Native catalog cache exceeds its 64 MiB budget"
        );
        state.providers.insert(provider_id.to_owned(), snapshot);
        state.bytes = bytes;
        Ok(revision)
    }

    pub fn invalidate(&self, provider_id: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Catalog cache lock failed"))?;
        if let Some(previous) = state.providers.remove(provider_id) {
            state.bytes = state
                .bytes
                .checked_sub(previous.serialized_bytes)
                .context("Catalog cache byte count underflow")?;
        }
        Ok(())
    }

    pub fn page(&self, provider_id: &str, query: CatalogQuery) -> Result<Value> {
        identifier(provider_id, 128)?;
        ensure!(
            query.limit > 0 && query.limit <= MAX_CATALOG_PAGE,
            "Catalog pages contain 1–128 rows"
        );
        if let Some(app) = &query.app_id {
            identifier(app, 512)?;
        }
        ensure!(
            query.view != CatalogView::History || query.app_id.is_some(),
            "History requires an exact original application identity"
        );
        ensure!(
            query.mode.is_none()
                || matches!(query.view, CatalogView::Bundles | CatalogView::History),
            "A mode filter applies only to bundle/history pages"
        );
        if let Some(plan) = &query.plan_id {
            canonical_uuid(&json!(plan))?;
        }
        ensure!(
            query.view != CatalogView::DeletionTargets || query.plan_id.is_some(),
            "Deletion target paging requires the exact source plan ID"
        );
        let snapshot = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Catalog cache lock failed"))?;
            state
                .providers
                .get(provider_id)
                .cloned()
                .context("Refresh the actual native catalog before browsing")?
        };
        let scope = blake3::hash(&serde_json::to_vec(&json!({
            "view":query.view,"appId":query.app_id,"mode":query.mode,"planId":query.plan_id,
        }))?)
        .to_hex()
        .to_string();
        let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
        if let Some(cursor) = &cursor {
            ensure!(
                cursor.version == 1 && cursor.provider_id == provider_id
                    && cursor.revision == snapshot.revision && cursor.scope == scope,
                "Catalog cursor is stale or belongs to another revision/provider/filter; refresh from the first page"
            );
        }
        let owned;
        let rows: &[Value] = match query.view {
            CatalogView::Apps => &snapshot.apps,
            CatalogView::Bundles | CatalogView::History => &snapshot.bundles,
            CatalogView::Instances => &snapshot.instances,
            CatalogView::PendingDeletions => {
                owned = snapshot
                    .pending
                    .iter()
                    .map(pending_summary)
                    .collect::<Result<Vec<_>>>()?;
                &owned
            }
            CatalogView::DeletionTargets => {
                let plan = snapshot
                    .pending
                    .iter()
                    .find(|plan| plan["planId"].as_str() == query.plan_id.as_deref())
                    .context(
                        "Actual pending deletion plan is unavailable in this catalog revision",
                    )?;
                let targets = plan["targets"].as_array()
                    .context("Authenticate/load the actual native deletion plan before paging its affected identities")?;
                let requested = plan["requested"].as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["bundleId"].as_str())
                        .collect::<BTreeSet<_>>()
                });
                let dependencies = plan["dependencies"].as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["bundleId"].as_str())
                        .collect::<BTreeSet<_>>()
                });
                owned = targets
                    .iter()
                    .map(|target| {
                        let id = target["bundleId"].as_str().unwrap();
                        let is_requested = requested.as_ref().map(|items| items.contains(id));
                        let is_dependent = dependencies.as_ref().map(|items| items.contains(id));
                        let mut target = target.clone();
                        target["planId"] = plan["planId"].clone();
                        target["planDigest"] = plan["digest"].clone();
                        target["requested"] = json!(is_requested);
                        target["dependent"] = json!(is_dependent);
                        target
                    })
                    .collect::<Vec<_>>();
                &owned
            }
        };
        let key = |row: &Value| -> Result<String> {
            match query.view {
                CatalogView::Apps => Ok(row["appId"]
                    .as_str()
                    .context("Catalog app key missing")?
                    .to_owned()),
                CatalogView::Bundles | CatalogView::History => Ok(format!(
                    "{}|{}",
                    row["createdAt"]
                        .as_str()
                        .context("Catalog history time missing")?,
                    row["id"].as_str().context("Catalog history key missing")?
                )),
                CatalogView::Instances => Ok(row["instanceId"]
                    .as_str()
                    .context("Catalog instance key missing")?
                    .to_owned()),
                CatalogView::PendingDeletions => Ok(row["planId"]
                    .as_str()
                    .context("Pending source plan key missing")?
                    .to_owned()),
                CatalogView::DeletionTargets => Ok(format!(
                    "{}|{}|{}",
                    row["appId"]
                        .as_str()
                        .context("Deletion target app missing")?,
                    row["bundleId"]
                        .as_str()
                        .context("Deletion target bundle missing")?,
                    row["commitId"]
                        .as_str()
                        .context("Deletion target commit missing")?
                )),
            }
        };
        let matches = |row: &&Value| {
            query.app_id.as_ref().is_none_or(|app| row["appId"] == *app)
                && query.mode.is_none_or(|mode| row["mode"] == mode.token())
        };
        let mut after_cursor = cursor.is_none();
        let mut found_cursor = cursor.is_none();
        let mut selected = Vec::new();
        let mut selected_bytes = 0usize;
        let mut next = false;
        let mut last_key = None;
        for row in rows.iter().filter(matches) {
            let row_key = key(row)?;
            if !after_cursor {
                if cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.last_key == row_key)
                {
                    after_cursor = true;
                    found_cursor = true;
                }
                continue;
            }
            let row_bytes = json_size(row, MAX_CATALOG_PAGE_BYTES / 2)?;
            if selected.len() == query.limit
                || selected_bytes.saturating_add(row_bytes) > MAX_CATALOG_PAGE_BYTES / 2
            {
                next = true;
                break;
            }
            selected_bytes += row_bytes;
            selected.push(row.clone());
            last_key = Some(row_key);
        }
        ensure!(
            found_cursor,
            "Catalog cursor key is absent in its bound revision"
        );
        let field = match query.view {
            CatalogView::Apps => "apps",
            CatalogView::Bundles | CatalogView::History => "bundles",
            CatalogView::PendingDeletions => "pendingDeletions",
            CatalogView::DeletionTargets => "targets",
            CatalogView::Instances => "instances",
        };
        let mut output = json!({
            "providerId":provider_id,"revision":snapshot.revision,
            "catalogCommitId":snapshot.catalog_commit_id, "createdAt":snapshot.created_at,
            "freshness":snapshot.freshness, "headCount":snapshot.head_count,
            "authoritativeForExecution":false,"nextCursor":Value::Null,
        });
        output[field] = json!(selected);
        if next {
            output["nextCursor"] = json!(encode_cursor(&Cursor {
                version: 1,
                provider_id: provider_id.to_owned(),
                revision: snapshot.revision.clone(),
                scope,
                last_key: last_key.context("A catalog row cannot fit the bounded page")?,
            })?);
        }
        json_size(&output, MAX_CATALOG_PAGE_BYTES)?;
        Ok(output)
    }
}

fn pending_summary(plan: &Value) -> Result<Value> {
    canonical_uuid(&plan["planId"])?;
    if plan["detailsAvailable"] == false {
        let names = plan["names"]
            .as_array()
            .context("Pending source names missing")?;
        return Ok(json!({
            "planId":plan["planId"],"detailsAvailable":false,
            "requiresNativePlanLoad":true,"dependenciesKnown":false,
            "nameCount":names.len(),"names":names.iter().take(16).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({
        "planId":plan["planId"],"operationId":plan["operationId"],"digest":plan["digest"],
        "requestedCount":plan["requestedCount"],
        "affectedCount":plan["targets"].as_array().map(Vec::len),
        "dependentCount":plan["dependencies"].as_array().map(Vec::len),
        "dependenciesKnown":plan["dependencies"].is_array(),
        "logicalBytes":plan["logicalBytes"],"physicalBytes":plan["physicalBytes"],
        "packCount":plan["packCount"],"metadataObjectCount":plan["metadataObjectCount"],
        "detailsAvailable":true,"requiresNativePlanLoad":true,
        // Avoid names/target lists growing a single IPC summary without bound.
        "names":plan["names"].as_array().into_iter().flatten().take(16).collect::<Vec<_>>(),
    }))
}

fn validate_pending(plan: &Value) -> Result<()> {
    if plan["detailsAvailable"] == false {
        fields(
            plan,
            &[
                "planId",
                "names",
                "detailsAvailable",
                "requiresNativePlanLoad",
                "dependenciesKnown",
            ],
        )?;
        ensure!(
            plan["requiresNativePlanLoad"] == true && plan["dependenciesKnown"] == false,
            "Foreign pending plan cannot invent dependency identities"
        );
        let names = plan["names"]
            .as_array()
            .context("Pending source names missing")?;
        ensure!(
            names.len() <= 10_000,
            "Pending source names exceed their bound"
        );
        for name in names {
            text_value(name, 1024)?;
        }
        return Ok(());
    }
    fields(
        plan,
        &[
            "planId",
            "operationId",
            "digest",
            "requestedCount",
            "requested",
            "targets",
            "dependencies",
            "names",
            "logicalBytes",
            "physicalBytes",
            "packCount",
            "metadataObjectCount",
        ],
    )?;
    canonical_uuid(&plan["operationId"])?;
    digest(
        plan["digest"]
            .as_str()
            .context("Pending plan digest missing")?,
    )?;
    let targets = plan["targets"]
        .as_array()
        .context("Pending plan target identities missing")?;
    ensure!(
        !targets.is_empty() && targets.len() <= 10_000,
        "Invalid pending source target count"
    );
    let mut ids = BTreeMap::new();
    for target in targets {
        fields(target, &["appId", "bundleId", "commitId"])?;
        identifier(
            target["appId"]
                .as_str()
                .context("Pending target app identity missing")?,
            512,
        )?;
        let id = canonical_uuid(&target["bundleId"])?;
        canonical_uuid(&target["commitId"])?;
        ensure!(
            ids.insert(id, target).is_none(),
            "Duplicate pending source target identity"
        );
    }
    let requested_count = plan["requestedCount"]
        .as_u64()
        .context("Pending request count missing")?;
    ensure!(
        requested_count > 0 && requested_count <= targets.len() as u64,
        "Invalid pending request count"
    );
    match (
        plan["requested"].as_array(),
        plan["dependencies"].as_array(),
    ) {
        (None, None) if plan["requested"].is_null() && plan["dependencies"].is_null() => {}
        (Some(requested), Some(dependencies)) => {
            ensure!(
                requested.len() as u64 == requested_count
                    && requested.len() + dependencies.len() == targets.len(),
                "Pending exact dependency count is inconsistent"
            );
            let mut covered = BTreeSet::new();
            for item in requested.iter().chain(dependencies) {
                let id = canonical_uuid(&item["bundleId"])?;
                ensure!(
                    ids.get(id).is_some_and(|target| *target == item),
                    "Pending dependency is outside the actual frozen source plan"
                );
                ensure!(
                    covered.insert(id),
                    "Pending dependency/request identities overlap or repeat"
                );
            }
        }
        _ => bail!("Pending original selection/dependencies are incomplete"),
    }
    Ok(())
}

fn fields(value: &Value, allowed: &[&str]) -> Result<()> {
    let fields = value
        .as_object()
        .context("Native catalog row must be an object")?;
    ensure!(
        fields.keys().all(|key| allowed.contains(&key.as_str())),
        "Native catalog row contains unsupported/private fields"
    );
    Ok(())
}

fn take_array(value: &mut Value, key: &str, max: usize) -> Result<Vec<Value>> {
    let value = value
        .get_mut(key)
        .context("Rich native catalog field is missing")?
        .take();
    let Value::Array(array) = value else {
        bail!("Rich native catalog field must be an array");
    };
    ensure!(
        array.len() <= max,
        "Rich native catalog field exceeds its native bound"
    );
    Ok(array)
}

fn identifier(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && !value.chars().any(char::is_control)
            && !matches!(value, "." | ".." | "*" | "_all")
            && !value.contains(['/', '\\', '*', '?', '[', ']']),
        "Catalog identity is invalid or oversized"
    );
    Ok(())
}

fn text_value(value: &Value, max: usize) -> Result<()> {
    let value = value.as_str().context("Catalog text is missing")?;
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "Catalog text is invalid or oversized"
    );
    Ok(())
}

fn canonical_uuid(value: &Value) -> Result<&str> {
    let raw = value
        .as_str()
        .context("Catalog source identity is missing")?;
    ensure!(
        Uuid::parse_str(raw)
            .ok()
            .is_some_and(|id| id.to_string() == raw),
        "Catalog source identity is not a canonical UUID"
    );
    Ok(raw)
}

fn timestamp(value: &Value) -> Result<()> {
    let raw = value.as_str().context("Catalog timestamp missing")?;
    ensure!(raw.len() <= 64, "Catalog timestamp is oversized");
    chrono::DateTime::parse_from_rfc3339(raw).context("Catalog timestamp is invalid")?;
    Ok(())
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Native catalog revision/digest is malformed"
    );
    Ok(())
}

fn validate_freshness(freshness: &Value) -> Result<()> {
    fields(
        freshness,
        &["source", "refreshStartedAt", "observedAt", "coalesced"],
    )?;
    let source = freshness["source"]
        .as_str()
        .context("Catalog freshness source missing")?;
    ensure!(
        source.len() <= 128 && !source.chars().any(char::is_control),
        "Invalid catalog freshness source"
    );
    for key in ["refreshStartedAt", "observedAt"] {
        if !freshness[key].is_null() {
            timestamp(&freshness[key])?;
        }
    }
    ensure!(
        freshness["coalesced"].is_boolean(),
        "Invalid source catalog coalescing evidence"
    );
    Ok(())
}

fn encode_cursor(cursor: &Cursor) -> Result<String> {
    let bytes = serde_json::to_vec(cursor)?;
    ensure!(
        bytes.len() <= MAX_CURSOR_BYTES / 2,
        "Catalog cursor exceeds its bound"
    );
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_cursor(raw: &str) -> Result<Cursor> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_CURSOR_BYTES && raw.len() % 2 == 0 && raw.is_ascii(),
        "Catalog cursor is invalid or oversized"
    );
    let bytes = (0..raw.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&raw[index..index + 2], 16)
                .context("Invalid catalog cursor encoding")
        })
        .collect::<Result<Vec<_>>>()?;
    let cursor: Cursor = serde_json::from_slice(&bytes).context("Invalid catalog cursor shape")?;
    digest(&cursor.revision)?;
    digest(&cursor.scope)?;
    ensure!(
        cursor.last_key.len() <= 2048,
        "Catalog cursor key exceeds its bound"
    );
    Ok(cursor)
}

fn json_size(value: &impl Serialize, max: usize) -> Result<usize> {
    struct Count(usize, usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("Catalog JSON size overflow"))?;
            if self.0 > self.1 {
                return Err(std::io::Error::other(
                    "Catalog JSON exceeds its native bound",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0, max);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revise(document: &mut Value) {
        let mut content = document.clone();
        for key in ["revision", "freshness", "authoritativeForExecution"] {
            content.as_object_mut().unwrap().remove(key);
        }
        document["revision"] = json!(blake3::hash(&serde_json::to_vec(&content).unwrap())
            .to_hex()
            .to_string());
    }

    fn fixture() -> Value {
        let bundles=(0..3).map(|index| {
            json!({
                "id":Uuid::from_u128(1+index),"appId":"desktop:original","name":"Original Game",
                "providerId":"fixture-provider","createdAt":format!("2026-11-17T00:00:0{index}Z"),
                "commitId":Uuid::from_u128(101+index),
                "parentBundleId":if index==0 { None } else { Some(Uuid::from_u128(index)) },
                "sourceInstanceId":Uuid::from_u128(501),"mode":
                    match index { 0=>"complete_application",1=>"personal_state",_=>"custom" },
                "logicalBytes":20+index,"storedIncrementalBytes":10+index,
                "fileCount":2,"tombstoneCount":0,"platform":"fixture-platform",
                "completeness":"selected_files","completeApplication":false,"subset":true,
                "readiness":{"metadataVerified":true,"filesAvailable":true,"applicationReady":false,
                    "requiresNativeRestorePreview":true},
                "currentHead":index==2,"currentCompleteHead":index==0,"currentPersonalStateHead":index==1,
                "format":"No Land NLNE/NLZ1/NLPK","compatibility":"requires_native_validation",
            })
        }).collect::<Vec<_>>();
        let mut document = json!({
            "projectionVersion":1,"providerId":"fixture-provider","schemaVersion":1,
            "catalogCommitId":Uuid::from_u128(1001),"createdAt":"2026-11-17T00:00:03Z",
            "heads":["desktop:original"],
            "apps":[{
                "appId":"desktop:original","catalogHead":true,"name":"Original Game","aliases":["Original Alias"],
                "desktopEntryId":"original.desktop","steamAppId":Value::Null,"launcher":"native",
                "canonicalExecutable":"/fixture/Game/game","iconPath":"/fixture/Game/icon.png",
                "latestBundleId":Uuid::from_u128(3),
                "headsByMode":{"completeApplication":Uuid::from_u128(1),"personalState":Uuid::from_u128(2)},
                "latestCompleteCapturedAt":"2026-11-17T00:00:00Z",
                "latestPersonalStateCapturedAt":"2026-11-17T00:00:01Z",
                "divergentHeads":[Uuid::from_u128(3)],"bundleCount":3,
            }],
            "bundles":bundles,
            "instances":[{"instanceId":Uuid::from_u128(501),"imageId":"fixture-image","lastSeal":Value::Null}],
            "pendingDeletions":[],
            "freshness":{"source":"live_remote_validation","refreshStartedAt":"2026-11-17T00:00:03Z",
                "observedAt":"2026-11-17T00:00:04Z","coalesced":false},
            "authoritativeForExecution":false,
        });
        revise(&mut document);
        document
    }

    fn query(view: CatalogView) -> CatalogQuery {
        CatalogQuery {
            view,
            app_id: None,
            mode: None,
            plan_id: None,
            cursor: None,
            limit: 1,
        }
    }

    #[test]
    fn rich_history_pages_keep_lineage_original_identity_and_separate_mode_heads() {
        let cache = CatalogCache::new();
        cache.replace("fixture-provider", fixture()).unwrap();
        let apps = cache
            .page("fixture-provider", query(CatalogView::Apps))
            .unwrap();
        assert_eq!(apps["apps"][0]["appId"], "desktop:original");
        assert_eq!(apps["apps"][0]["aliases"][0], "Original Alias");
        assert_eq!(
            apps["apps"][0]["headsByMode"]["completeApplication"],
            Uuid::from_u128(1).to_string()
        );
        let mut history = query(CatalogView::History);
        history.app_id = Some("desktop:original".into());
        let first = cache.page("fixture-provider", history.clone()).unwrap();
        assert_eq!(first["bundles"][0]["id"], Uuid::from_u128(3).to_string());
        assert_eq!(
            first["bundles"][0]["commitId"],
            Uuid::from_u128(103).to_string()
        );
        assert_eq!(
            first["bundles"][0]["parentBundleId"],
            Uuid::from_u128(2).to_string()
        );
        assert_eq!(
            first["bundles"][0]["sourceInstanceId"],
            Uuid::from_u128(501).to_string()
        );
        assert_eq!(first["bundles"][0]["completeApplication"], false);
        history.cursor = Some(first["nextCursor"].as_str().unwrap().into());
        let second = cache.page("fixture-provider", history).unwrap();
        assert_eq!(second["bundles"][0]["id"], Uuid::from_u128(2).to_string());
        assert_eq!(second["authoritativeForExecution"], false);
    }

    #[test]
    fn actual_revision_change_rejects_old_cursor_instead_of_offset_drift_even_with_same_commit_id()
    {
        let cache = CatalogCache::new();
        let mut document = fixture();
        cache.replace("fixture-provider", document.clone()).unwrap();
        let first = cache
            .page("fixture-provider", query(CatalogView::Bundles))
            .unwrap();
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();
        // A real fresh observation at a later time is not a history revision.
        document["freshness"]["observedAt"] = json!("2026-11-17T00:01:00Z");
        cache.replace("fixture-provider", document.clone()).unwrap();
        let mut next = query(CatalogView::Bundles);
        next.cursor = Some(cursor.clone());
        cache.page("fixture-provider", next.clone()).unwrap();
        // Pending changes can occur before any catalog commit-head change.
        document["pendingDeletionSummaries"] = json!([{
            "planId":Uuid::from_u128(700),"names":["Fixture retained deletion"],
            "detailsAvailable":false,"requiresNativePlanLoad":true,"dependenciesKnown":false,
        }]);
        revise(&mut document);
        cache.replace("fixture-provider", document).unwrap();
        assert!(cache.page("fixture-provider", next).is_err());
        assert_eq!(first["catalogCommitId"], Uuid::from_u128(1001).to_string());
    }

    #[test]
    fn cursor_binds_provider_filter_and_view_and_rejects_legacy_flattening_and_forged_revision() {
        let cache = CatalogCache::new();
        let document = fixture();
        cache.replace("fixture-provider", document.clone()).unwrap();
        let first = cache
            .page("fixture-provider", query(CatalogView::Bundles))
            .unwrap();
        let mut wrong = query(CatalogView::History);
        wrong.app_id = Some("desktop:original".into());
        wrong.cursor = first["nextCursor"].as_str().map(str::to_owned);
        assert!(cache.page("fixture-provider", wrong).is_err());
        assert!(cache
            .page("other-provider", query(CatalogView::Bundles))
            .is_err());
        assert!(cache
            .replace("fixture-provider", json!({"bundles":[]}))
            .is_err());
        let mut forged = document;
        forged["bundles"][0]["logicalBytes"] = json!(999);
        assert!(cache.replace("fixture-provider", forged).is_err());
        let mut too_many = query(CatalogView::Bundles);
        too_many.limit = 129;
        assert!(cache.page("fixture-provider", too_many).is_err());
    }

    #[test]
    fn pending_deletion_summaries_and_paged_exact_dependencies_keep_source_plan_identity() {
        let cache = CatalogCache::new();
        let mut document = fixture();
        let plan = Uuid::from_u128(900);
        let dependent = json!({"appId":"desktop:other","bundleId":Uuid::from_u128(901),"commitId":Uuid::from_u128(911)});
        let requested = json!({"appId":"desktop:original","bundleId":Uuid::from_u128(902),"commitId":Uuid::from_u128(912)});
        document["pendingDeletions"] = json!([{
            "planId":plan,"operationId":plan,"digest":"f".repeat(64),"requestedCount":1,
            "requested":[requested],"targets":[dependent,requested],"dependencies":[dependent],
            "names":["Fixture dependency","Fixture selection"],"logicalBytes":40,"physicalBytes":30,
            "packCount":1,"metadataObjectCount":4,
        }]);
        revise(&mut document);
        cache.replace("fixture-provider", document).unwrap();
        let summary = cache
            .page("fixture-provider", query(CatalogView::PendingDeletions))
            .unwrap();
        assert_eq!(summary["pendingDeletions"][0]["planId"], plan.to_string());
        assert_eq!(summary["pendingDeletions"][0]["dependentCount"], 1);
        assert!(
            summary["pendingDeletions"][0].get("targets").is_none(),
            "IPC summary cannot contain an unbounded target list"
        );
        let mut targets = query(CatalogView::DeletionTargets);
        targets.plan_id = Some(plan.to_string());
        let first = cache.page("fixture-provider", targets.clone()).unwrap();
        assert_eq!(first["targets"][0]["planId"], plan.to_string());
        assert_eq!(first["targets"][0]["dependent"], true);
        assert_eq!(first["targets"][0]["requested"], false);
        targets.cursor = first["nextCursor"].as_str().map(str::to_owned);
        let second = cache.page("fixture-provider", targets).unwrap();
        assert_eq!(
            second["targets"][0]["bundleId"],
            Uuid::from_u128(902).to_string()
        );
        assert_eq!(second["targets"][0]["requested"], true);
        assert_eq!(second["targets"][0]["dependent"], false);
    }

    #[test]
    fn no_catalog_mode_or_ui_flag_can_upgrade_selected_files_to_application_readiness() {
        let cache = CatalogCache::new();
        let mut document = fixture();
        document["bundles"][0]["completeApplication"] = json!(true);
        document["bundles"][0]["readiness"]["applicationReady"] = json!(true);
        revise(&mut document);
        assert!(cache.replace("fixture-provider", document).is_err());
    }
}
