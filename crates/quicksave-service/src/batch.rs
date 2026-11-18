// SPDX-License-Identifier: GPL-3.0-only
//! Actual all/selected-app upload groups over the existing service transfer path.
//!
//! # Parent wiring (required, not optional success fallbacks)
//!
//! Declare `mod native_plans; mod batch;` and attach one `Arc<NativeBatchRuntime>`
//! to the service after construction. Construct with `NativeBatchRuntime::open`
//! using the service, private storage path, native signer, `BatchSourceVerifier`,
//! and `BatchRecovery`. `preview_upload_all`, `approval_scope`, `execute`,
//! `operation`, `cancel`, `retry` are the bounded native gateway entry points.
//!
//! In `WorkspaceService::publication_guard`, if the private plan parameters have
//! `_nativeBatchPlanId`, call the runtime's `check_child_publication(id, plan_id)`
//! BEFORE publication. This installs the durable group cancellation/root guard
//! in the ACTUAL source callback; omission must not be advertised as supported.
//! `NativeBatchRuntime::confirm_core_hooks_installed()` is a native-only
//! constructor handoff, never an incoming JSON flag.
//! Also call `before_child_finalization(source_id, work, success).await` inside
//! run_transfer BEFORE a successful finalize_work. Both hooks are required by
//! `confirm_core_hooks_installed`, not merely a terminal service activity.
//!
//! `BatchSourceVerifier::authenticate` MUST use the actual source's private
//! submission/replay HMAC and real worker owner with the expected exact native
//! roots/capture/mode/provider. No DB JSON, matching ID or service activity alone
//! authenticates a source operation. Missing native support explicitly errors.
//! `reauthenticate_existing` is called ONLY by an admitted explicit group
//! execution/retry, before the coordinator sees retained capture bindings. It is
//! never called by preview, approval, status, cancellation or child monitoring.
//!
//! `BatchRecovery::recover_original_work` may return only the original
//! authenticated work/receipt, with tracker/source reattachment already done.
//! It may not call prepare_upload_scope on today's files. If unavailable,
//! `mark_unknown_dirty` must durably invalidate the exact software baseline; the
//! group reports a reconciliation gap and NEVER resubmits a completed source.
//!
//! Native children use `run_transfer` with fixed source IDs and non-admitted
//! child lifetime guards. One group owns admission/close protection. Source
//! pack/chunk concurrency is untouched; children are not per-file uploads.

use crate::{
    boundary as dto,
    interfaces::{NativeFuture, PublishGuard, SourceGuard},
    native_plans::{
        self, FinalizedNativeChild, FrozenCaptureBinding, FrozenNativePlan, FrozenNativePlanStore,
        NativeHistoryChild, NativeHistoryMetadata, ReconciliationGap, ReconciliationGapKind,
    },
    operations::{
        ChildState, CompletionReceipt, FrozenChildPlan, FrozenPlanSet, NativeChildStatus,
        NativeObservation, NativeOperationBackend, OperationBindings, OperationCoordinator,
        OperationFuture, OperationSummary, ParentState, PublicationGuard, SelectionIntent,
        StoreSigner, MAX_APPS_PER_PLAN, MAX_CHILDREN_PER_JOB,
    },
    Active, Operation, OperationGuard, RetryPlan, WorkspaceService,
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceProofPurpose {
    Observation,
    Cancellation,
}

/// Produced ONLY by the injected native source verifier after the actual source
/// authenticates its submission/committed receipt. This is not an IPC DTO and
/// there is no Deserialize implementation or `"authenticated":true` escape.
#[derive(Clone, Debug)]
pub struct VerifiedSourceOperation {
    pub purpose: SourceProofPurpose,
    pub observation: NativeObservation,
    pub root_authority_revision: String,
    pub capture_digest: Option<String>,
    /// Stable actual source submission/selection/repository binding digest.
    pub binding_digest: Option<String>,
    /// Stable authenticated actual committed result, not a timestamp/status hash.
    pub completion_digest: Option<String>,
}
impl VerifiedSourceOperation {
    fn validate(
        &self,
        plan: &FrozenNativePlan,
        capture: Option<&FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> Result<()> {
        ensure!(
            self.purpose == purpose
                && self.observation.source_id() == plan.source_id
                && self.root_authority_revision == plan.root_authority_revision,
            "Actual source attestation belongs to another frozen root/instance/child"
        );
        if let Some(capture) = capture {
            capture.validate(plan)?;
            ensure!(
                self.capture_digest.as_deref() == Some(capture.digest()?.as_str()),
                "Actual source selection differs from its original frozen capture"
            );
        } else {
            ensure!(
                self.capture_digest.is_none(),
                "A source record cannot add an unapproved captured scope"
            );
        }
        if let NativeObservation::Present { status } = &self.observation {
            if purpose == SourceProofPurpose::Observation {
                ensure!(
                    capture.is_some(),
                    "A source row exists without its original signed capture binding"
                );
                native_plans::checked_digest(
                    self.binding_digest
                        .as_deref()
                        .context("Actual source submission HMAC proof is unavailable")?,
                )?;
                if status.state == ChildState::Completed && !status.worker_running {
                    native_plans::checked_digest(
                        self.completion_digest
                            .as_deref()
                            .context("Actual source committed receipt proof is unavailable")?,
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Parent native adapter requirements:
/// - Absence means an actual same-workspace StateDb + worker-owner lookup.
/// - Present observation authenticates source replay/submission HMAC, canonical
///   app, mode, provider/account binding and native exact root/file selection.
/// - Compare NativeSelection.snapshot_identity with capture.metadata_identity;
///   compare sorted logical file IDs against capture.selection_digest/count.
/// - Expected roots/source identity come from plan.registration_record(), whose
///   device MAC was checked first. Do not trust the row's own roots/digests.
/// - Cancellation verifies a retained exact-ID native capability and real
///   worker owner, even if current provider write/root authority was revoked.
/// Raw SQL/JSON status is never a successful implementation.
pub trait BatchSourceVerifier: Send + Sync + 'static {
    fn require_supported(&self) -> Result<()>;
    fn authenticate<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> NativeFuture<'a, VerifiedSourceOperation>;

    /// Read-only registry/DB ownership of device-MAC-verified fixed IDs. This is
    /// NOT a committed-result proof and cannot mark data Saved. Never request
    /// provider credentials, read retry selections, or perform provider I/O.
    /// Implementations must check the same native workspace, backup kind and
    /// original canonical app ID. Missing support is honestly unknown.
    fn history_owners<'a>(
        &'a self,
        _plan_set_id: Uuid,
        _root_digest: &'a str,
        children: &'a [NativeHistoryChild],
    ) -> NativeFuture<'a, Vec<NativeObservation>> {
        Box::pin(async move {
            Ok(children
                .iter()
                .map(|child| NativeObservation::Unknown {
                    source_id: child.source_id,
                })
                .collect())
        })
    }

    /// Explicit execution/retry only. Authenticate the ORIGINAL retained source
    /// and capture, optionally reacquiring read-only provider access. Never
    /// submit, retry, recapture, or acknowledge a tracker baseline here.
    ///
    /// Polling must use `authenticate`, which cannot acquire provider secrets.
    /// Unsupported implementations fail closed rather than projecting guessed
    /// verified state from matching IDs or serialized source status.
    fn reauthenticate_existing<'a>(
        &'a self,
        _parent: &'a FrozenPlanSet,
        _plan: &'a FrozenNativePlan,
        _capture: &'a FrozenCaptureBinding,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        Box::pin(async {
            bail!("Explicit original-source reauthentication is unavailable; no native source work was resubmitted")
        })
    }
}

/// Optional production optimization: verify one frozen snapshot with one native
/// store/grant frame, transiently pinning roots as needed. No JSON response can
/// implement this capability. Without it the correct (but more expensive)
/// per-instance native pin/verification path is used.
pub trait BatchRootVerifier: Send + Sync + 'static {
    fn verify_roots<'a>(&'a self, provider: &'a str, records: &'a [Value]) -> NativeFuture<'a, ()>;
}

#[derive(Clone, Debug)]
pub struct DirtyBaselineReceipt {
    pub software_id: String,
    pub root_authority_revision: String,
    pub proof_digest: String,
}

pub trait BatchRecovery: Send + Sync + 'static {
    /// Restore ONLY original work/generation/receipt into Tracker/source native
    /// controllers. NEVER obtain a fresh begin_upload/prepare_upload_scope here.
    fn recover_original_work<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: &'a FrozenCaptureBinding,
        source: &'a VerifiedSourceOperation,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value>;
    /// Durably mark CURRENT data dirty/unknown only if the exact frozen software
    /// authority still matches. Preserve the prior authenticated baseline and
    /// physical version history; invalidate current confirmation/reuse instead.
    /// Return actual native persistence evidence.
    fn mark_unknown_dirty<'a>(
        &'a self,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        reason: ReconciliationGapKind,
    ) -> NativeFuture<'a, DirtyBaselineReceipt>;
}

/// Explicit unsupported recovery, never a pretend receipt or dirty-state ack.
pub struct UnavailableBatchRecovery;
impl BatchRecovery for UnavailableBatchRecovery {
    fn recover_original_work<'a>(
        &'a self,
        _: &'a FrozenPlanSet,
        _: &'a FrozenNativePlan,
        _: &'a FrozenCaptureBinding,
        _: &'a VerifiedSourceOperation,
        _: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async {
            bail!("Original native capture/receipt reattachment is not implemented; no source work was resubmitted")
        })
    }
    fn mark_unknown_dirty<'a>(
        &'a self,
        _: &'a FrozenNativePlan,
        _: Option<&'a FrozenCaptureBinding>,
        _: ReconciliationGapKind,
    ) -> NativeFuture<'a, DirtyBaselineReceipt> {
        Box::pin(async {
            bail!("Native tracker dirty/unknown reconciliation is unavailable; keep the workspace open")
        })
    }
}

#[derive(Debug)]
struct BatchGapError {
    baseline_dirty: bool,
}
impl std::fmt::Display for BatchGapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The original native capture needs authenticated reconciliation; it was not recaptured, resubmitted or acknowledged saved")
    }
}
impl std::error::Error for BatchGapError {}

struct ChildAttempt {
    plan_set_id: Uuid,
    native_plan_id: Uuid,
    guard: PublicationGuard,
    running: AtomicBool,
    requires_service_admission: AtomicBool,
    source_completion: Mutex<Option<VerifiedSourceOperation>>,
    tracker_receipt_digest: Mutex<Option<String>>,
    recovered_work: Mutex<Option<Value>>,
}
struct GroupState {
    running: bool,
    cancelled: Arc<AtomicBool>,
    activity: Value,
}

struct ExplicitGroupExecution {
    backend: Arc<WorkingNativeBatchBackend>,
    id: Uuid,
}
impl Drop for ExplicitGroupExecution {
    fn drop(&mut self) {
        if let Ok(mut active) = self.backend.active_group.lock() {
            if *active == Some(self.id) {
                *active = None;
            }
        }
    }
}

pub struct WorkingNativeBatchBackend {
    service: Weak<WorkspaceService>,
    plans: Arc<FrozenNativePlanStore>,
    ledger: Arc<OperationBindings>,
    source: Arc<dyn BatchSourceVerifier>,
    recovery: Arc<dyn BatchRecovery>,
    attempts: Mutex<BTreeMap<Uuid, Arc<ChildAttempt>>>,
    cancellations: Mutex<BTreeMap<Uuid, Arc<AtomicBool>>>,
    active_group: Mutex<Option<Uuid>>,
    hooks_ready: AtomicBool,
    weak: Weak<WorkingNativeBatchBackend>,
}

pub struct NativeBatchRuntime {
    service: Weak<WorkspaceService>,
    pub(crate) plans: Arc<FrozenNativePlanStore>,
    pub(crate) ledger: Arc<OperationBindings>,
    backend: Arc<WorkingNativeBatchBackend>,
    coordinator: Arc<OperationCoordinator>,
    groups: Mutex<BTreeMap<Uuid, GroupState>>,
    root_verifier: Mutex<Option<Arc<dyn BatchRootVerifier>>>,
    history_sources: Mutex<(BTreeSet<Uuid>, BTreeSet<Uuid>)>,
}

impl NativeBatchRuntime {
    pub fn open(
        service: &Arc<WorkspaceService>,
        path: &Path,
        signer: Arc<dyn StoreSigner>,
        source: Arc<dyn BatchSourceVerifier>,
        recovery: Arc<dyn BatchRecovery>,
    ) -> Result<Arc<Self>> {
        quicksave_platform::ensure_private_directory(path)?;
        let root = quicksave_platform::SafeRoot::open(path)?;
        root.create_dir("native-plans")?;
        root.create_dir("operation-bindings")?;
        let plans = Arc::new(FrozenNativePlanStore::open(
            &path.join("native-plans"),
            signer.clone(),
        )?);
        let ledger = Arc::new(OperationBindings::open(
            &path.join("operation-bindings"),
            signer,
        )?);
        plans.attach_history_ledger(&path.join("operation-bindings"))?;
        Self::with_stores(service, plans, ledger, source, recovery)
    }
    pub fn with_stores(
        service: &Arc<WorkspaceService>,
        plans: Arc<FrozenNativePlanStore>,
        ledger: Arc<OperationBindings>,
        source: Arc<dyn BatchSourceVerifier>,
        recovery: Arc<dyn BatchRecovery>,
    ) -> Result<Arc<Self>> {
        let service_weak = Arc::downgrade(service);
        let backend = Arc::new_cyclic(|weak| WorkingNativeBatchBackend {
            service: service_weak.clone(),
            plans: plans.clone(),
            ledger: ledger.clone(),
            source,
            recovery,
            attempts: Mutex::new(BTreeMap::new()),
            cancellations: Mutex::new(BTreeMap::new()),
            active_group: Mutex::new(None),
            hooks_ready: AtomicBool::new(false),
            weak: weak.clone(),
        });
        let coordinator = Arc::new(OperationCoordinator::new(ledger.clone(), backend.clone()));
        let mut groups = BTreeMap::new();
        // IDs are hints until their device MAC is read, never execution authority.
        for id in ledger.list_ids()? {
            groups.insert(
                id,
                GroupState {
                    running: false,
                    cancelled: Arc::new(AtomicBool::new(false)),
                    activity: group_activity(id, Value::Null, None),
                },
            );
        }
        Ok(Arc::new(Self {
            service: service_weak,
            plans,
            ledger,
            backend,
            coordinator,
            groups: Mutex::new(groups),
            root_verifier: Mutex::new(None),
            history_sources: Mutex::new((BTreeSet::new(), BTreeSet::new())),
        }))
    }

    /// Native setup only: parent has installed BOTH documented core hooks.
    /// No frontend parameter can enable these capabilities.
    pub fn confirm_core_hooks_installed(&self) {
        self.backend.hooks_ready.store(true, Ordering::Release);
    }
    pub fn set_root_verifier(&self, verifier: Arc<dyn BatchRootVerifier>) -> Result<()> {
        *self
            .root_verifier
            .lock()
            .map_err(|_| anyhow::anyhow!("Native root verifier lock failed"))? = Some(verifier);
        Ok(())
    }

    pub fn has_batch(&self, id: &str) -> bool {
        let Ok(id) = Uuid::parse_str(id) else {
            return false;
        };
        let hinted = self
            .groups
            .lock()
            .map(|groups| groups.contains_key(&id))
            .unwrap_or(false);
        hinted && self.plans.summary(id).is_ok() && self.ledger.load(id).is_ok()
    }

    pub async fn preview_upload_all(self: &Arc<Self>, params: Value) -> Result<Value> {
        dto::validate_action("preview_upload_all", &params)?;
        self.backend.require_ready()?;
        let service = self.service()?;
        let _active = Active::acquire(&service.lifetime, false)?;
        let provider = dto::id(&params, "providerId")?.to_owned();
        let snapshot = service.snapshot()?;
        let provider_record = dto::provider_record(&snapshot, &provider)?;
        ensure!(
            provider_record["status"] != "disconnected" && provider_record["readOnly"] != true,
            "Choose a connected writable provider before planning an all-app upload"
        );
        let selected = selected_instances(&params)?;
        let mut available = BTreeMap::new();
        for record in snapshot["software"]
            .as_array()
            .context("Native software snapshot missing")?
        {
            if record["tracked"] == true && record["providerId"] == provider {
                let id = dto::id(record, "id")?.to_owned();
                ensure!(
                    available.insert(id, record.clone()).is_none(),
                    "Duplicate native software instance ID"
                );
            }
        }
        let ids = match selected {
            Some(ids) => {
                ensure!(ids.iter().all(|id|available.contains_key(id)),
                    "Every selected software instance must already be tracked for this exact provider");
                ids
            }
            None => available.keys().cloned().collect(),
        };
        ensure!(
            !ids.is_empty() && ids.len() <= MAX_APPS_PER_PLAN,
            "Select 1–4096 genuinely tracked software instances"
        );
        let id = Uuid::new_v4();
        let mut plans = Vec::with_capacity(ids.len());
        let verifier = self
            .root_verifier
            .lock()
            .map_err(|_| anyhow::anyhow!("Native root verifier lock failed"))?
            .clone();
        if let Some(verifier) = &verifier {
            let records = ids
                .iter()
                .map(|id| available[id].clone())
                .collect::<Vec<_>>();
            verifier.verify_roots(&provider, &records).await?;
        }
        for software in &ids {
            let record = &available[software];
            // Real tracker grant/native-handle verification; no content read or
            // directory discovery is performed by this planner.
            if verifier.is_none() {
                let pin = service.pin(record.clone()).await?;
                service.verify_pin(&pin).await?;
            }
            plans.push(FrozenNativePlan::from_record(id, provider_record, record)?);
        }
        let current = service.snapshot()?;
        for plan in &plans {
            plan.verify_snapshot(&current)?;
        }
        let intent = if params.get("softwareIds").is_some() {
            SelectionIntent::SelectedApps
        } else {
            SelectionIntent::AllApprovedApps
        };
        let native_store = self.plans.clone();
        let ledger = self.ledger.clone();
        let provider_for_write = provider.clone();
        tokio::task::spawn_blocking(move || {
            let frozen = native_store.freeze(id, &provider_for_write, intent, &plans)?;
            ledger.freeze(frozen)?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("Native batch plan persistence worker failed"))??;
        self.groups
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch state lock failed"))?
            .insert(
                id,
                GroupState {
                    running: false,
                    cancelled: Arc::new(AtomicBool::new(false)),
                    activity: group_activity(id, json!(provider), None),
                },
            );
        self.public_summary(id)
    }

    pub fn public_summary(&self, id: Uuid) -> Result<Value> {
        let mut summary = self.plans.summary(id)?;
        let count = summary["softwareCount"]
            .as_u64()
            .context("Native batch count missing")?;
        summary["summary"]=json!(format!(
            "Save {count} approved software instance(s) to this provider. The exact software identities and native roots are frozen; each child's file metadata is captured when it starts. Local data and cloud history are kept."
        ));
        dto::bounded(&summary, 32 * 1024)?;
        Ok(summary)
    }

    /// Discover retained groups without JS storage, source reauthentication,
    /// execution/retry/recovery, software enumeration, or provider credentials.
    /// Corrupt native journals are explicit errors, never skipped activities.
    pub async fn recent_activity(&self, limit: usize) -> Result<Vec<Value>> {
        let limit = limit.min(dto::MAX_ACTIVITY);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = self
            .groups
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch state lock failed"))?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        ensure!(
            ids.len() <= crate::operations::MAX_STORED_PLANS,
            "Native batch history exceeds its retained-group bound"
        );
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut activities = Vec::new();
        for id in ids {
            // Retain one group's compact ownership keys at a time, not 64
            // copies of a 4096-child plan or any node/capture inventories.
            let plans = self.plans.clone();
            let ledger = self.ledger.clone();
            let metadata =
                tokio::task::spawn_blocking(move || plans.history_metadata(ledger.as_ref(), id))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("Native batch history metadata worker failed")
                    })??;
            if metadata.admitted_at.is_none() {
                continue;
            }
            {
                let mut known = self
                    .history_sources
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Native history source-membership lock failed"))?;
                if known.0.insert(metadata.plan_set_id) {
                    for child in &metadata.children {
                        known.1.insert(child.source_id);
                    }
                    ensure!(
                        known.0.len() <= crate::operations::MAX_STORED_PLANS
                            && known.1.len()
                                <= crate::operations::MAX_STORED_PLANS * MAX_APPS_PER_PLAN,
                        "Native group source-membership cache exceeds its bound"
                    );
                }
            }
            let live = self
                .groups
                .lock()
                .map_err(|_| anyhow::anyhow!("Batch state lock failed"))?
                .get(&metadata.plan_set_id)
                .filter(|group| group.running)
                .map(|group| group.activity.clone());
            let mut activity = if let Some(live) = live {
                live
            } else {
                self.restored_history_activity(&metadata).await?
            };
            activity["id"] = json!(metadata.plan_set_id);
            activity["operationId"] = json!(metadata.plan_set_id);
            activity["planSetId"] = json!(metadata.plan_set_id);
            activity["providerId"] = json!(metadata.provider_id);
            activity["createdAt"] = json!(metadata.created_at);
            // A timestamp from the signed original header, never "now" at
            // restart or a guessed timestamp from a source row.
            activity["startedAt"] = json!(metadata.created_at);
            activity["admittedAt"] = json!(metadata.admitted_at);
            if !activity["batch"].is_object() {
                activity["batch"] = json!({});
            }
            let apps = metadata
                .children
                .iter()
                .map(|child| child.app_id.as_str())
                .collect::<BTreeSet<_>>();
            activity["batch"]["softwareCount"] = json!(metadata.children.len());
            activity["batch"]["jobCount"] = json!(metadata.job_count);
            activity["batch"]["sourceAppCount"] = json!(apps.len());
            activity["batch"]["sampleSourceAppIds"] =
                json!(apps.into_iter().take(16).collect::<Vec<_>>());
            activity["batch"]["historicalCompleted"] = json!(metadata.completed);
            activity["batch"]["rootDigest"] = json!(metadata.root_digest);
            activity["batch"]["selection"] = json!(metadata.selection);
            activity["batch"]["cancelRequested"] = json!(metadata.cancel_requested);
            activity["batch"]["currentDataStatus"] = json!("not_evaluated");
            dto::bounded(&activity, 32 * 1024)?;
            activities.push(activity);
        }
        activities.sort_by(|left, right| {
            right["startedAt"]
                .as_str()
                .cmp(&left["startedAt"].as_str())
                .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
        });
        activities.truncate(limit);
        dto::bounded(&json!(activities), dto::MAX_OUTPUT_BYTES)?;
        Ok(activities)
    }

    /// Optional native-only footer/deduplication helper. Call recent_activity
    /// first; only device-MAC-verified ADMITTED membership enters this cache.
    /// This is display grouping, never source authentication or write authority.
    pub fn is_group_source(&self, source_id: &str) -> bool {
        let Ok(id) = Uuid::parse_str(source_id) else {
            return false;
        };
        self.history_sources
            .lock()
            .map(|known| known.1.contains(&id))
            .unwrap_or(false)
    }

    async fn restored_history_activity(&self, metadata: &NativeHistoryMetadata) -> Result<Value> {
        let mut unknown = 0usize;
        let mut owner_unknown = 0usize;
        let mut active = 0usize;
        let mut failed = 0usize;
        let mut cancelled = 0usize;
        let mut interrupted = 0usize;
        let mut completed_known_drained = 0usize;
        let mut all_absent = true;
        for page in metadata.children.chunks(MAX_CHILDREN_PER_JOB) {
            let observed = match self
                .backend
                .source
                .history_owners(metadata.plan_set_id, &metadata.root_digest, page)
                .await
            {
                Ok(observed) => observed,
                Err(_) => page
                    .iter()
                    .map(|child| NativeObservation::Unknown {
                        source_id: child.source_id,
                    })
                    .collect(),
            };
            ensure!(
                observed.len() == page.len(),
                "Native history ownership page changed its fixed child count"
            );
            let mut expected = page
                .iter()
                .map(|child| (child.source_id, child))
                .collect::<BTreeMap<_, _>>();
            for observation in observed {
                let child = expected.remove(&observation.source_id())
                    .context("Native history ownership added or duplicated a source outside its signed group")?;
                match observation {
                    NativeObservation::Absent { .. } => {
                        if child.completed {
                            completed_known_drained += 1;
                        }
                        if child.captured && !child.completed {
                            unknown += 1;
                        }
                    }
                    NativeObservation::Unknown { .. } => {
                        all_absent = false;
                        owner_unknown += 1;
                        unknown += 1;
                    }
                    NativeObservation::Present { status } => {
                        all_absent = false;
                        if status.worker_running {
                            active += 1;
                            if status.state == ChildState::Unknown {
                                unknown += 1;
                            }
                        } else if !status.state.terminal() {
                            if status.state == ChildState::Unknown {
                                owner_unknown += 1;
                                unknown += 1;
                            } else {
                                active += 1;
                            }
                        } else {
                            match status.state {
                                ChildState::Completed if child.completed => {
                                    completed_known_drained += 1
                                }
                                ChildState::Completed if !child.completed => unknown += 1,
                                ChildState::Failed => failed += 1,
                                ChildState::Cancelled => cancelled += 1,
                                ChildState::Interrupted => interrupted += 1,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        let total = metadata.children.len();
        let unresolved_capture = metadata.captured > metadata.completed
            && (metadata.reconciliation_gaps == 0
                || metadata.reconciliation_gaps != metadata.settled_reconciliation_gaps);
        let close_blocked = owner_unknown > 0 || active > 0 || unresolved_capture;
        let completed = completed_known_drained == total && metadata.reconciliation_gaps == 0;
        let (state, phase) = if active > 0 {
            ("running", "native_operation")
        } else if metadata.reconciliation_gaps > 0 {
            ("interrupted", "durable_finalization_required")
        } else if completed && owner_unknown == 0 {
            ("completed", "finalized")
        } else {
            ("interrupted", "needs_native_reattachment")
        };
        // The only restart retry advertised without an original-work recovery
        // capability is genuinely never-captured work with authoritative source
        // absence. Its existing explicit retry path prepares inside frozen roots.
        let can_retry = all_absent
            && metadata.captured == 0
            && metadata.reconciliation_gaps == 0
            && !close_blocked
            && self.backend.require_ready().is_ok();
        Ok(json!({
            "id":metadata.plan_set_id,"operationId":metadata.plan_set_id,"planSetId":metadata.plan_set_id,
            "kind":"upload","name":"Save approved software group","providerId":metadata.provider_id,
            "state":state,"phase":phase,"canCancel":close_blocked,"canRetry":can_retry,
            "error":if phase == "needs_native_reattachment" || phase == "durable_finalization_required" {
                json!("This original native upload group needs explicit source reattachment or reconciliation. No source job was started and no current data was acknowledged saved.")
            } else { Value::Null },
            "batch":{
                "softwareCount":total,"jobCount":metadata.job_count,
                "completed":completed_known_drained,"failed":failed,"cancelled":cancelled,
                "interrupted":interrupted,"active":active,
                "notStarted":total-metadata.captured,
                "unknown":unknown,"awaitingFinalization":metadata.awaiting_finalization,
                "reconciliationRequired":metadata.reconciliation_gaps > 0,
                "reconciliationGapCount":metadata.reconciliation_gaps,
                "needsNativeReattachment":phase == "needs_native_reattachment",
                "historical":true,"closeBlocked":close_blocked,
            },
        }))
    }

    /// Called by the native upload_all dialog scope; no file list or private
    /// root/provider reference is exposed as incoming approval authority.
    pub fn approval_scope(&self, id: &str) -> Result<Value> {
        let id = parse_id(id)?;
        let frozen = self.ledger.load(id)?;
        let service = self.service()?;
        let snapshot = service.snapshot()?;
        for child in frozen.children() {
            self.plans.plan(id, child)?.verify_snapshot(&snapshot)?;
        }
        let mut summary = self.public_summary(id)?;
        summary["scopeFingerprint"] = json!(dto::fingerprint(&json!({
            "action":"upload_all","planSetId":id,"rootDigest":frozen.authority_revision,
            "providerScope":frozen.provider_scope,
        }))?);
        Ok(summary)
    }

    pub fn execute(self: &Arc<Self>, id: &str) -> Result<Value> {
        self.start_group(parse_id(id)?, false)
    }
    pub fn retry(self: &Arc<Self>, id: &str) -> Result<Value> {
        self.start_group(parse_id(id)?, true)
    }

    fn start_group(self: &Arc<Self>, id: Uuid, retry: bool) -> Result<Value> {
        self.backend.require_ready()?;
        let service = self.service()?;
        let frozen = self.ledger.load(id)?;
        let snapshot = service.snapshot()?;
        for child in frozen.children() {
            self.plans.plan(id, child)?.verify_snapshot(&snapshot)?;
        }
        let active = Active::acquire(&service.lifetime, true)?;
        if retry {
            ensure!(
                self.plans.admission(id)?.is_some(),
                "A preview is not an executed upload; obtain upload_all confirmation first"
            );
        } else {
            self.plans.admit(&frozen)?;
        }
        let cancellation = {
            let mut groups = self
                .groups
                .lock()
                .map_err(|_| anyhow::anyhow!("Batch state lock failed"))?;
            let group = groups.entry(id).or_insert_with(|| GroupState {
                running: false,
                cancelled: Arc::new(AtomicBool::new(false)),
                activity: group_activity(id, json!(frozen.provider_id), None),
            });
            ensure!(
                !group.running,
                "This native upload group is already running"
            );
            if !retry {
                ensure!(
                    !matches!(group.activity["state"].as_str(), Some("completed")),
                    "This completed group cannot be submitted again; inspect its history"
                );
            }
            group.running = true;
            group.cancelled.store(false, Ordering::Release);
            group.activity = group_activity(id, json!(frozen.provider_id), None);
            group.cancelled.clone()
        };
        self.backend
            .cancellations
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch cancellation lock failed"))?
            .insert(id, cancellation);
        {
            let mut operations = service
                .operations
                .lock()
                .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?;
            if let Some(existing) = operations.get_mut(&id.to_string()) {
                existing.cancelled = false;
                existing.activity = group_activity(id, json!(frozen.provider_id), None);
            } else {
                ensure!(
                    operations.len() < dto::MAX_ACTIVITY,
                    "Active operation history is full"
                );
                operations.insert(
                    id.to_string(),
                    Operation {
                        activity: group_activity(id, json!(frozen.provider_id), None),
                        native_id: None,
                        cancelled: false,
                        retry: None,
                    },
                );
            }
        }
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            let guard = OperationGuard {
                active,
                finalized: false,
            };
            runtime.run_group(id, retry, guard).await;
        });
        if service.remember_task(task).is_err() {
            // The admitted group already owns its fixed source IDs. Returning
            // definitive rejection now could authorize a duplicate submission.
            service
                .lifetime
                .finalization_blocked
                .store(true, Ordering::Release);
        }
        Ok(json!({"operationId":id,"planSetId":id}))
    }

    async fn run_group(self: Arc<Self>, id: Uuid, retry: bool, mut guard: OperationGuard) {
        let result = async {
            let _execution = self.backend.enter_explicit_execution(id)?;
            // This is the only provider-reauthentication entry point. No fresh
            // child has a retained capture, and UI polling never reaches here.
            self.backend.reauthenticate_retained(id).await?;
            if self.backend.cancellation(id)?.load(Ordering::Acquire) {
                let summary = self.coordinator.cancel(id).await?;
                self.update_activity(id, &summary)?;
                return Ok(summary);
            }
            if retry {
                self.coordinator.retry(id).await?;
            }
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let summary = self.coordinator.drive(id).await?;
                self.update_activity(id, &summary)?;
                if !summary.shutdown_blocked {
                    return Ok::<_, anyhow::Error>(summary);
                }
            }
        }
        .await;
        match result {
            Ok(summary) => {
                guard.finalized = !summary.shutdown_blocked;
            }
            Err(error) => {
                // Failed attestation is NOT terminal success/failure of the
                // native worker. Try every exact source cancellation capability
                // before deciding that a reconciled gap may release ownership.
                let drained = self.drain_group(id).await;
                let had_capture = self.backend.has_captures(id).unwrap_or(true);
                let gap_persisted = error
                    .downcast_ref::<BatchGapError>()
                    .is_none_or(|gap| gap.baseline_dirty);
                let safe_gap = drained.is_ok()
                    && gap_persisted
                    && self.backend.settle_error_dirty(id).await.is_ok();
                let activity = json!({
                    "id":id,"kind":"upload","name":"Save approved software group",
                    "state":if safe_gap {if had_capture {"interrupted"} else {"failed"}} else {"running"},
                    "phase":if safe_gap && !had_capture {"failed"} else {"durable_finalization_required"},
                    "canCancel":!safe_gap,"canRetry":safe_gap && !had_capture,
                    "error":if safe_gap && !had_capture {dto::engine_error(&error)}
                        else {"The original native source/capture requires reconciliation. No captured source was recaptured or acknowledged saved."},
                });
                self.store_activity(id, activity);
                guard.finalized = safe_gap;
                if !safe_gap {
                    if let Some(service) = self.service.upgrade() {
                        service
                            .lifetime
                            .finalization_blocked
                            .store(true, Ordering::Release);
                    }
                }
            }
        }
        if let Ok(mut groups) = self.groups.lock() {
            if let Some(group) = groups.get_mut(&id) {
                group.running = false;
            }
        }
    }

    pub async fn cancel(&self, id: &str) -> Result<Value> {
        let id = parse_id(id)?;
        // Do this BEFORE waiting on coordinator.serial / metadata preparation.
        self.ledger.request_cancellation(id)?;
        if let Ok(mut groups) = self.groups.lock() {
            if let Some(group) = groups.get_mut(&id) {
                group.cancelled.store(true, Ordering::Release);
            }
        }
        self.backend.cancel_local_flags(id)?;
        let summary = self.coordinator.cancel(id).await?;
        self.update_activity(id, &summary)?;
        self.operation(&id.to_string()).await
    }

    pub async fn operation(&self, id: &str) -> Result<Value> {
        let id = parse_id(id)?;
        ensure!(
            self.has_batch(&id.to_string()),
            "Unknown native batch group"
        );
        if self.plans.admission(id)?.is_none() {
            let summary = self.public_summary(id)?;
            return Ok(json!({
                "id":id,"operationId":id,"planSetId":id,"kind":"upload","name":"Preview approved software group",
                "providerId":summary["providerId"],"state":"queued","phase":"preparing",
                "canCancel":false,"canRetry":false,"error":Value::Null,
                "batch":{"softwareCount":summary["softwareCount"],"previewOnly":true,"closeBlocked":false},
            }));
        }
        // A live worker owns exact scheduling/finalization. Reading its public
        // activity does not walk software or acquire provider credentials.
        if let Some(activity) = self
            .groups
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch state lock failed"))?
            .get(&id)
            .filter(|group| group.running)
            .map(|group| group.activity.clone())
        {
            return Ok(activity);
        }
        let parent = self.ledger.load(id)?;
        let reconciliation = self.backend.reconciliation_status(&parent).await?;
        let mut activity = match self.coordinator.status(id).await {
            Ok(summary) => group_activity(id, json!(parent.provider_id), Some(&summary)),
            Err(_) if reconciliation.is_some() => {
                let mut activity = group_activity(id, json!(parent.provider_id), None);
                activity["batch"] = json!({
                    "softwareCount":parent.child_count(),"jobCount":parent.jobs.len(),
                    "closeBlocked":true,
                });
                activity
            }
            Err(error) => return Err(error),
        };
        if let Some((count, settled)) = reconciliation {
            activity["state"] = json!(if settled { "interrupted" } else { "running" });
            activity["phase"] = json!("durable_finalization_required");
            activity["canCancel"] = json!(!settled);
            activity["canRetry"] = json!(false);
            activity["error"] = json!("The original native source/capture requires reconciliation. No captured source was recaptured or acknowledged saved.");
            activity["batch"]["reconciliationRequired"] = json!(true);
            activity["batch"]["reconciliationGapCount"] = json!(count);
            activity["batch"]["closeBlocked"] = json!(
                !settled
                    || self
                        .service()?
                        .lifetime
                        .finalization_blocked
                        .load(Ordering::Acquire)
            );
        }
        self.store_activity(id, activity.clone());
        Ok(activity)
    }
    pub async fn batch_status(&self, params: &Value) -> Result<Value> {
        self.operation(dto::id(params, "planSetId")?).await
    }

    pub fn check_child_publication(&self, source_id: &str, native_plan_id: &str) -> Result<()> {
        self.backend
            .check_child_publication(parse_id(source_id)?, parse_id(native_plan_id)?)
    }
    /// Native run_transfer validation for a zero-node full-root snapshot. This
    /// does not accept a JSON approval flag: the live exact child owner and its
    /// device-MAC-authenticated capture must already hold verified native proof.
    pub fn check_empty_child_work(&self, source_id: &str, work: &Value) -> Result<()> {
        let source_id = parse_id(source_id)?;
        let attempt = self
            .backend
            .attempt(source_id)?
            .context("Empty native capture has no original batch child owner")?;
        self.backend
            .check_child_publication(source_id, attempt.native_plan_id)?;
        let parent = self.ledger.load(attempt.plan_set_id)?;
        let child = WorkingNativeBatchBackend::child_for_source(&parent, source_id)?;
        let plan = self.plans.plan(parent.operation_id, child)?;
        let capture = self
            .plans
            .capture(&plan)?
            .context("Original empty capture binding is missing")?;
        ensure!(
            capture.file_count == 0
                && capture.empty_full_scope_proof_digest.is_some()
                && capture.matches_work(&plan, work)?,
            "Zero-node native work lacks its original verified full-snapshot grant"
        );
        Ok(())
    }
    pub async fn before_child_finalization(
        &self,
        source_id: &str,
        work: &Value,
        success: bool,
    ) -> Result<()> {
        self.backend
            .before_child_finalization(parse_id(source_id)?, work, success)
            .await
    }
    fn service(&self) -> Result<Arc<WorkspaceService>> {
        self.service
            .upgrade()
            .context("Native batch workspace is unavailable")
    }
    fn update_activity(&self, id: Uuid, summary: &OperationSummary) -> Result<()> {
        let frozen = self.ledger.load(id)?;
        self.store_activity(
            id,
            group_activity(id, json!(frozen.provider_id), Some(summary)),
        );
        Ok(())
    }
    fn store_activity(&self, id: Uuid, activity: Value) {
        if let Ok(mut groups) = self.groups.lock() {
            if let Some(group) = groups.get_mut(&id) {
                group.activity = activity.clone();
            }
        }
        if let Some(service) = self.service.upgrade() {
            service.patch_operation(&id.to_string(), activity);
        }
    }
    async fn drain_group(&self, id: Uuid) -> Result<()> {
        let parent = self.ledger.load(id)?;
        self.backend.cancel_local_flags(id)?;
        let mut failed = 0usize;
        for child in parent.children() {
            match self.backend.cancel_and_drain(&parent, child).await {
                Ok(NativeObservation::Absent { .. }) => {}
                Ok(NativeObservation::Present { status }) if status.terminal_and_drained() => {}
                _ => failed += 1,
            }
        }
        ensure!(
            failed == 0,
            "Some actual source children are still unknown or draining"
        );
        Ok(())
    }
}

impl WorkingNativeBatchBackend {
    fn enter_explicit_execution(&self, id: Uuid) -> Result<ExplicitGroupExecution> {
        let backend = self
            .weak
            .upgrade()
            .context("Native batch backend owner ended")?;
        let mut active = self
            .active_group
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch execution owner lock failed"))?;
        ensure!(
            active.is_none(),
            "Another native batch group owns execution"
        );
        *active = Some(id);
        Ok(ExplicitGroupExecution { backend, id })
    }

    fn explicitly_executing(&self, id: Uuid) -> Result<bool> {
        Ok(*self
            .active_group
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch execution owner lock failed"))?
            == Some(id))
    }

    async fn reauthenticate_retained(&self, id: Uuid) -> Result<()> {
        self.require_ready()?;
        let parent = self.ledger.load(id)?;
        self.require_admitted(&parent)?;
        ensure!(
            self.explicitly_executing(id)?,
            "Retained source reauthentication requires explicit native group execution"
        );
        for child in parent.children() {
            if self.cancellation(id)?.load(Ordering::Acquire) {
                return Ok(());
            }
            let plan = self.plans.plan(id, child)?;
            let Some(capture) = self.plans.capture(&plan)? else {
                continue;
            };
            let source = match self
                .source
                .reauthenticate_existing(&parent, &plan, &capture)
                .await
            {
                Ok(source)
                    if source
                        .validate(&plan, Some(&capture), SourceProofPurpose::Observation)
                        .is_ok() =>
                {
                    source
                }
                _ => {
                    return Err(self
                        .reconciliation_gap(
                            &plan,
                            Some(&capture),
                            ReconciliationGapKind::SourceAuthentication,
                            false,
                        )
                        .await);
                }
            };
            if self.cancellation(id)?.load(Ordering::Acquire) {
                return Ok(());
            }
            match source.observation {
                NativeObservation::Absent { .. } => {
                    return Err(self
                        .reconciliation_gap(
                            &plan,
                            Some(&capture),
                            ReconciliationGapKind::MissingOriginalWork,
                            true,
                        )
                        .await);
                }
                NativeObservation::Unknown { .. } => {
                    return Err(self
                        .reconciliation_gap(
                            &plan,
                            Some(&capture),
                            ReconciliationGapKind::SourceAuthentication,
                            false,
                        )
                        .await);
                }
                NativeObservation::Present { .. } => {}
            }
        }
        Ok(())
    }

    fn require_ready(&self) -> Result<()> {
        ensure!(
            self.hooks_ready.load(Ordering::Acquire),
            "Native batch publication and pre-finalization hooks are not installed"
        );
        self.source.require_supported()?;
        ensure!(
            self.service()?.engine.native_capture_supported(),
            "Actual native source capture is unavailable for batch uploads"
        );
        Ok(())
    }
    fn require_admitted(&self, parent: &FrozenPlanSet) -> Result<()> {
        let admission = self
            .plans
            .admission(parent.operation_id)?
            .context("A signed preview is not native upload admission")?;
        ensure!(
            admission.root_digest == parent.authority_revision
                && admission.provider_digest == parent.provider_scope,
            "Original native group admission scope changed"
        );
        Ok(())
    }
    fn service(&self) -> Result<Arc<WorkspaceService>> {
        self.service
            .upgrade()
            .context("Native batch workspace is unavailable")
    }
    fn attempt(&self, id: Uuid) -> Result<Option<Arc<ChildAttempt>>> {
        Ok(self
            .attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch child owner lock failed"))?
            .get(&id)
            .cloned())
    }
    fn cancellation(&self, id: Uuid) -> Result<Arc<AtomicBool>> {
        let mut flags = self
            .cancellations
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch cancellation lock failed"))?;
        ensure!(
            flags.contains_key(&id) || flags.len() < 64,
            "Too many retained native batch cancellation scopes"
        );
        Ok(flags
            .entry(id)
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone())
    }
    fn cancel_local_flags(&self, parent: Uuid) -> Result<()> {
        self.cancellation(parent)?.store(true, Ordering::Release);
        let ids = self
            .attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch child owner lock failed"))?
            .iter()
            .filter(|(_, attempt)| {
                attempt.plan_set_id == parent && attempt.running.load(Ordering::Acquire)
            })
            .map(|(id, _)| id.to_string())
            .collect::<Vec<_>>();
        let service = self.service()?;
        let mut operations = service
            .operations
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?;
        for id in ids {
            if let Some(operation) = operations.get_mut(&id) {
                operation.cancelled = true;
            }
        }
        Ok(())
    }
    fn check_child_publication(&self, source: Uuid, plan_id: Uuid) -> Result<()> {
        self.require_ready()?;
        let attempt = self
            .attempt(source)?
            .context("This batch child has no native publication owner")?;
        ensure!(
            attempt.native_plan_id == plan_id && attempt.running.load(Ordering::Acquire),
            "Batch publication belongs to an ended or different child attempt"
        );
        (attempt.guard)()
    }
    async fn authenticated(
        &self,
        parent: &FrozenPlanSet,
        plan: &FrozenNativePlan,
        capture: Option<&FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> Result<VerifiedSourceOperation> {
        self.require_admitted(parent)?;
        self.source.require_supported()?;
        let result = self
            .source
            .authenticate(parent, plan, capture, purpose)
            .await
            .map_err(|_| {
                anyhow::anyhow!("Actual native source binding authentication is unavailable")
            })?;
        result.validate(plan, capture, purpose)?;
        Ok(result)
    }
    fn child_for_source<'a>(parent: &'a FrozenPlanSet, id: Uuid) -> Result<&'a FrozenChildPlan> {
        parent
            .children()
            .find(|child| child.source_id == id)
            .context("Source child is not in this frozen group")
    }

    async fn before_child_finalization(&self, id: Uuid, work: &Value, success: bool) -> Result<()> {
        self.require_ready()?;
        let attempt = self
            .attempt(id)?
            .context("Native batch finalization owner is missing")?;
        let parent = self.ledger.load(attempt.plan_set_id)?;
        let child = Self::child_for_source(&parent, id)?;
        let plan = self.plans.plan(parent.operation_id, child)?;
        let capture = self
            .plans
            .capture(&plan)?
            .context("Native batch capture binding is missing")?;
        ensure!(
            capture.matches_work(&plan, work)?,
            "Tracker finalization changed its original source capture/work/generation"
        );
        if !success {
            return Ok(());
        }
        if attempt.requires_service_admission.load(Ordering::Acquire) {
            let admitted_id = self
                .service()?
                .operations
                .lock()
                .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?
                .get(&id.to_string())
                .and_then(|operation| operation.native_id.clone());
            ensure!(
                admitted_id.as_deref() == Some(id.to_string().as_str()),
                "Actual native admission changed the frozen batch source ID"
            );
        }
        let source = match self
            .authenticated(
                &parent,
                &plan,
                Some(&capture),
                SourceProofPurpose::Observation,
            )
            .await
        {
            Ok(source) => source,
            Err(_) => {
                return Err(self
                    .reconciliation_gap(
                        &plan,
                        Some(&capture),
                        ReconciliationGapKind::SourceAuthentication,
                        false,
                    )
                    .await);
            }
        };
        ensure!(
            matches!(&source.observation,NativeObservation::Present {status}
            if status.state==ChildState::Completed && !status.worker_running),
            "Actual source worker/commit is not authenticated terminal completion"
        );
        // This is the actual Tracker API, whose production implementation
        // verifies the prepared native receipt/grants, not incoming JSON.
        let receipt = self
            .service()?
            .tracking_call("verify_capture_receipt", json!({"workId":capture.work_id}))
            .await?;
        ensure!(
            receipt["verified"] == true
                && receipt["workId"] == capture.work_id
                && receipt["generation"].as_u64() == Some(capture.generation)
                && receipt["sourceExpectedManifestAuthPreserved"] == true,
            "Actual tracker source receipt did not verify the original work"
        );
        let digest = native_plans::fingerprint(&json!({
            "capture":capture.digest()?,"source":source.completion_digest,"receipt":receipt,
        }))?;
        *attempt
            .tracker_receipt_digest
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch receipt lock failed"))? = Some(digest);
        *attempt
            .source_completion
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch source proof lock failed"))? = Some(source);
        Ok(())
    }

    async fn reconciliation_gap(
        &self,
        plan: &FrozenNativePlan,
        capture: Option<&FrozenCaptureBinding>,
        kind: ReconciliationGapKind,
        known_drained: bool,
    ) -> anyhow::Error {
        let dirty = self.recovery.mark_unknown_dirty(plan, capture, kind).await;
        let baseline_dirty = match dirty {
            Ok(receipt) => {
                receipt.software_id == plan.software_id
                    && receipt.root_authority_revision == plan.root_authority_revision
                    && native_plans::checked_digest(&receipt.proof_digest).is_ok()
            }
            Err(_) => false,
        };
        let recorded = self
            .plans
            .record_gap(
                plan,
                &ReconciliationGap {
                    source_id: plan.source_id,
                    native_plan_digest: plan.digest().unwrap_or_default(),
                    kind,
                    baseline_marked_dirty: baseline_dirty,
                    source_known_drained: known_drained,
                },
            )
            .is_ok();
        anyhow::Error::new(BatchGapError {
            baseline_dirty: baseline_dirty && recorded,
        })
    }

    async fn prepare_original_or_fail(
        &self,
        parent: &FrozenPlanSet,
        plan: &FrozenNativePlan,
        capture: &FrozenCaptureBinding,
        source: &VerifiedSourceOperation,
        guard: PublishGuard,
    ) -> Result<Value> {
        match self
            .recovery
            .recover_original_work(parent, plan, capture, source, guard)
            .await
        {
            Ok(work) => {
                ensure!(capture.matches_work(plan,&work)?,
                    "Recovered work is not the original authenticated capture; no recapture is allowed");
                Ok(work)
            }
            Err(_) => {
                let drained = matches!(&source.observation, NativeObservation::Absent { .. })
                    || matches!(&source.observation,
                    NativeObservation::Present {status} if status.terminal_and_drained());
                Err(self
                    .reconciliation_gap(
                        plan,
                        Some(capture),
                        ReconciliationGapKind::MissingOriginalWork,
                        drained,
                    )
                    .await)
            }
        }
    }

    fn install_attempt(
        &self,
        plan: &FrozenNativePlan,
        guard: PublicationGuard,
        recovered: Option<Value>,
    ) -> Result<Arc<ChildAttempt>> {
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch child owner lock failed"))?;
        ensure!(
            attempts
                .get(&plan.source_id)
                .is_none_or(|attempt| !attempt.running.load(Ordering::Acquire)),
            "The same native source child is already owned by a running worker"
        );
        // Terminal attempts contain no inventories and need not accumulate. The
        // signed root/capture/finalization records remain durable on disk.
        attempts.retain(|_, attempt| attempt.running.load(Ordering::Acquire));
        ensure!(
            attempts.len() < MAX_CHILDREN_PER_JOB,
            "Native batch child-owner budget is full"
        );
        let attempt = Arc::new(ChildAttempt {
            plan_set_id: plan.plan_set_id,
            native_plan_id: plan.native_plan_id,
            guard,
            running: AtomicBool::new(false),
            requires_service_admission: AtomicBool::new(false),
            source_completion: Mutex::new(None),
            tracker_receipt_digest: Mutex::new(None),
            recovered_work: Mutex::new(recovered),
        });
        attempts.insert(plan.source_id, attempt.clone());
        Ok(attempt)
    }

    fn launch(
        &self,
        parent: &FrozenPlanSet,
        plan: &FrozenNativePlan,
        work: Value,
        guard: PublicationGuard,
        retry: bool,
    ) -> Result<Uuid> {
        self.require_ready()?;
        (guard)()?;
        let service = self.service()?;
        let capture = self
            .plans
            .capture(plan)?
            .context("Executed capture was not durably bound before admission")?;
        ensure!(
            capture.matches_work(plan, &work)?,
            "Executed capture was not durably bound before admission"
        );
        let attempt = self.install_attempt(plan, guard, None)?;
        let active = Active::acquire(&service.lifetime, false)?; // group owns admission
        let id = plan.source_id.to_string();
        let params = json!({
            "softwareId":plan.software_id,"providerId":plan.provider_id,
            "_nativeBatchPlanId":plan.native_plan_id.to_string(),
        });
        let scope = service.source_scope(&params)?;
        let retry_plan = RetryPlan {
            action: "upload".into(),
            params: params.clone(),
            captured: Some(crate::capture_summary(&work, &params)?),
            scope,
        };
        {
            let operations = service
                .operations
                .lock()
                .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?;
            ensure!(
                operations
                    .get(&id)
                    .is_none_or(|operation| dto::terminal(&operation.activity)),
                "A fixed batch source ID already has a nonterminal service worker"
            );
        }
        service.insert_operation(
            &id,
            Operation {
                activity: json!({
                    "id":id,"kind":"upload","name":plan.name,"providerId":plan.provider_id,
                    "softwareId":plan.software_id,"state":"queued","phase":"preparing",
                    "canCancel":true,"canRetry":false,"startedAt":chrono::Utc::now().to_rfc3339(),
                    "error":Value::Null,
                }),
                native_id: None,
                cancelled: false,
                retry: None,
            },
        )?;
        let backend = self
            .weak
            .upgrade()
            .context("Native batch backend owner ended")?;
        let parent = parent.clone();
        let native = plan.clone();
        let worker_service = service.clone();
        let source_id = plan.source_id;
        attempt
            .requires_service_admission
            .store(true, Ordering::Release);
        attempt.running.store(true, Ordering::Release);
        let task = tokio::spawn(async move {
            let operation_guard = OperationGuard {
                active,
                finalized: false,
            };
            worker_service
                .clone()
                .run_transfer(
                    &id,
                    retry_plan,
                    Some(work),
                    retry.then(|| id.clone()),
                    operation_guard,
                )
                .await;
            // Only now has actual run_transfer returned from durable tracker
            // finalization. A source terminal row by itself was not enough.
            let finished = backend
                .record_worker_finalization(&parent, &native, &attempt)
                .await;
            if finished.is_err() {
                let captured = backend.plans.capture(&native).ok().flatten();
                let known_drained = backend
                    .authenticated(
                        &parent,
                        &native,
                        captured.as_ref(),
                        SourceProofPurpose::Cancellation,
                    )
                    .await
                    .is_ok_and(|source| match source.observation {
                        NativeObservation::Absent { .. } => true,
                        NativeObservation::Present { status } => status.terminal_and_drained(),
                        NativeObservation::Unknown { .. } => false,
                    });
                let capture = backend.plans.capture(&native).ok().flatten();
                let _ = backend
                    .reconciliation_gap(
                        &native,
                        capture.as_ref(),
                        ReconciliationGapKind::TrackerFinalization,
                        known_drained,
                    )
                    .await;
            }
            attempt.running.store(false, Ordering::Release);
        });
        if service.remember_task(task).is_err() {
            // Work was accepted and owns its fixed ID/active guard. Never report
            // definitive rejection after spawning or allocate a replacement ID.
            service
                .lifetime
                .finalization_blocked
                .store(true, Ordering::Release);
        }
        Ok(source_id)
    }

    async fn record_worker_finalization(
        &self,
        _parent: &FrozenPlanSet,
        plan: &FrozenNativePlan,
        attempt: &ChildAttempt,
    ) -> Result<()> {
        let service = self.service()?;
        let activity = service
            .operations
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?
            .get(&plan.source_id.to_string())
            .map(|operation| operation.activity.clone())
            .context("Actual service child finalization activity is missing")?;
        if activity["state"] != "completed" || activity["phase"] != "finalized" {
            // A failed/cancelled child has no successful baseline marker.
            return Ok(());
        }
        ensure!(
            !service
                .lifetime
                .finalization_blocked
                .load(Ordering::Acquire),
            "Actual tracker durable finalization is unresolved"
        );
        let source = attempt
            .source_completion
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch source proof lock failed"))?
            .clone()
            .context("The actual source was not authenticated before tracker finalization")?;
        let receipt = attempt
            .tracker_receipt_digest
            .lock()
            .map_err(|_| anyhow::anyhow!("Batch receipt lock failed"))?
            .clone()
            .context("Actual tracker receipt proof is missing")?;
        let capture = self
            .plans
            .capture(plan)?
            .context("Original source capture binding disappeared")?;
        source.validate(plan, Some(&capture), SourceProofPurpose::Observation)?;
        ensure!(
            matches!(&source.observation,NativeObservation::Present {status}
            if status.state==ChildState::Completed && !status.worker_running),
            "Source finalization was not real joined completion"
        );
        self.plans.finalize(
            plan,
            &FinalizedNativeChild {
                source_id: plan.source_id,
                native_plan_digest: plan.digest()?,
                capture_digest: capture.digest()?,
                source_proof_digest: source
                    .completion_digest
                    .context("Actual source committed result proof missing")?,
                tracker_receipt_digest: receipt,
                generation: capture.generation,
            },
        )
    }
    fn has_captures(&self, id: Uuid) -> Result<bool> {
        let parent = self.ledger.load(id)?;
        for child in parent.children() {
            if self.plans.capture(&self.plans.plan(id, child)?)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn settle_error_dirty(&self, id: Uuid) -> Result<()> {
        let parent = self.ledger.load(id)?;
        for child in parent.children() {
            let plan = self.plans.plan(id, child)?;
            if self.plans.finalization(&plan)?.is_some()
                && self.plans.reconciliation(&plan)?.is_none()
            {
                continue;
            }
            let Some(capture) = self.plans.capture(&plan)? else {
                continue;
            };
            let receipt = self
                .recovery
                .mark_unknown_dirty(
                    &plan,
                    Some(&capture),
                    ReconciliationGapKind::TrackerFinalization,
                )
                .await?;
            ensure!(
                receipt.software_id == plan.software_id
                    && receipt.root_authority_revision == plan.root_authority_revision,
                "Native dirty reconciliation belongs to another software authority"
            );
            native_plans::checked_digest(&receipt.proof_digest)?;
            self.plans.record_gap(
                &plan,
                &ReconciliationGap {
                    source_id: plan.source_id,
                    native_plan_digest: plan.digest()?,
                    kind: ReconciliationGapKind::TrackerFinalization,
                    baseline_marked_dirty: true,
                    source_known_drained: true,
                },
            )?;
        }
        Ok(())
    }

    async fn reconciliation_status(&self, parent: &FrozenPlanSet) -> Result<Option<(usize, bool)>> {
        let mut count = 0usize;
        let mut settled = true;
        for child in parent.children() {
            let plan = self.plans.plan(parent.operation_id, child)?;
            if let Some(gap) = self.plans.reconciliation(&plan)? {
                count += 1;
                settled &= gap.baseline_marked_dirty && gap.source_known_drained;
            }
        }
        if count == 0 {
            return Ok(None);
        }
        if settled {
            // An old signed drained marker does not prove CURRENT native worker
            // ownership. Recheck exact-ID cancellation capabilities, without
            // credentials, provider I/O, reauthentication or tracker mutation.
            for child in parent.children() {
                let plan = self.plans.plan(parent.operation_id, child)?;
                let capture = self.plans.capture(&plan)?;
                let local = self
                    .attempt(child.source_id)?
                    .is_some_and(|attempt| attempt.running.load(Ordering::Acquire));
                let drained = match self
                    .authenticated(
                        parent,
                        &plan,
                        capture.as_ref(),
                        SourceProofPurpose::Cancellation,
                    )
                    .await
                {
                    Ok(source) => match source.observation {
                        NativeObservation::Absent { .. } => true,
                        NativeObservation::Present { status } => status.terminal_and_drained(),
                        NativeObservation::Unknown { .. } => false,
                    },
                    Err(_) => false,
                };
                settled &= drained && !local;
            }
        }
        Ok(Some((count, settled)))
    }
}

impl NativeOperationBackend for WorkingNativeBatchBackend {
    fn publication_guard<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, PublicationGuard> {
        Box::pin(async move {
            self.require_ready()?;
            let native = self.plans.plan(parent.operation_id, child)?;
            let service = self.service()?;
            native.verify_snapshot(&service.snapshot()?)?;
            let pin = service.pin(native.registration_record()).await?;
            service.verify_pin(&pin).await?;
            let cancelled = self.cancellation(parent.operation_id)?;
            let ledger = self.ledger.clone();
            let weak = Arc::downgrade(&service);
            let plan_id = parent.operation_id;
            let guard: PublicationGuard = Arc::new(move || {
                ensure!(
                    !cancelled.load(Ordering::Acquire),
                    "The native upload group was cancelled"
                );
                ledger.ensure_not_cancelled(plan_id)?;
                let service = weak.upgrade().context("Native group service ended")?;
                native.verify_snapshot(&service.snapshot()?)?;
                pin.verify()?;
                ensure!(
                    service.store.provider_writable(&native.provider_id)?,
                    "Native provider write authority was revoked"
                );
                Ok(())
            });
            Ok(guard)
        })
    }
    fn observe<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        children: &'a [FrozenChildPlan],
    ) -> OperationFuture<'a, Vec<NativeObservation>> {
        Box::pin(async move {
            self.require_ready()?;
            ensure!(
                !children.is_empty() && children.len() <= MAX_CHILDREN_PER_JOB,
                "Native batch observation pages contain 1–128 exact children"
            );
            let mut observations = Vec::with_capacity(children.len());
            for child in children {
                let plan = self.plans.plan(parent.operation_id, child)?;
                let capture = self.plans.capture(&plan)?;
                let attempt = self.attempt(child.source_id)?;
                let local_running = attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt.running.load(Ordering::Acquire));
                let source = match self
                    .authenticated(
                        parent,
                        &plan,
                        capture.as_ref(),
                        SourceProofPurpose::Observation,
                    )
                    .await
                {
                    Ok(source) => source,
                    Err(_) => {
                        if self.explicitly_executing(parent.operation_id)?
                            && !local_running
                            && capture.is_some()
                            && self.plans.finalization(&plan)?.is_none()
                        {
                            let known_drained = self
                                .authenticated(
                                    parent,
                                    &plan,
                                    capture.as_ref(),
                                    SourceProofPurpose::Cancellation,
                                )
                                .await
                                .is_ok_and(|source| match source.observation {
                                    NativeObservation::Absent { .. } => true,
                                    NativeObservation::Present { status } => {
                                        status.terminal_and_drained()
                                    }
                                    NativeObservation::Unknown { .. } => false,
                                });
                            return Err(self
                                .reconciliation_gap(
                                    &plan,
                                    capture.as_ref(),
                                    ReconciliationGapKind::SourceAuthentication,
                                    known_drained,
                                )
                                .await);
                        }
                        observations.push(NativeObservation::Unknown {
                            source_id: child.source_id,
                        });
                        continue;
                    }
                };
                let observation = match source.observation {
                    NativeObservation::Absent { .. } if local_running => {
                        // Accepted local preparation/admission handoff, not a
                        // fabricated source DB row and not permission to submit twice.
                        NativeObservation::Unknown {
                            source_id: child.source_id,
                        }
                    }
                    NativeObservation::Absent { .. } if capture.is_some() => {
                        if !self.explicitly_executing(parent.operation_id)? {
                            observations.push(NativeObservation::Unknown {
                                source_id: child.source_id,
                            });
                            continue;
                        }
                        return Err(self
                            .reconciliation_gap(
                                &plan,
                                capture.as_ref(),
                                ReconciliationGapKind::MissingOriginalWork,
                                true,
                            )
                            .await);
                    }
                    NativeObservation::Present { mut status } => {
                        if local_running {
                            status.worker_running = true;
                        }
                        NativeObservation::Present { status }
                    }
                    other => other,
                };
                observations.push(observation);
            }
            Ok(observations)
        })
    }
    fn submit<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, Uuid> {
        Box::pin(async move {
            self.require_ready()?;
            guard()?;
            let plan = self.plans.plan(parent.operation_id, child)?;
            let old = self.plans.capture(&plan)?;
            let source = self
                .authenticated(parent, &plan, old.as_ref(), SourceProofPurpose::Observation)
                .await?;
            ensure!(
                matches!(source.observation, NativeObservation::Absent { .. }),
                "This source child already exists; only exact reattachment/retry is permitted"
            );
            if old.is_some() {
                return Err(self
                    .reconciliation_gap(
                        &plan,
                        old.as_ref(),
                        ReconciliationGapKind::MissingOriginalWork,
                        true,
                    )
                    .await);
            }
            let service = self.service()?;
            plan.verify_snapshot(&service.snapshot()?)?;
            service.engine_call("preflight", None, json!({})).await?;
            // Only first execution may freeze current file metadata, within the
            // exact already-approved whole root set. No file IDs cross IPC.
            let work = service
                .tracking_call(
                    "prepare_upload_scope",
                    json!({
                        "softwareId":plan.software_id,"providerId":plan.provider_id,
                    }),
                )
                .await?;
            let binding = if work["fileIds"].as_array().is_some_and(Vec::is_empty) {
                let tracking = service.tracking.clone();
                let native_plan = plan.clone();
                let native_work = work.clone();
                tokio::task::spawn_blocking(move || {
                    FrozenCaptureBinding::from_native_work(
                        &native_plan,
                        &native_work,
                        tracking.as_ref(),
                    )
                })
                .await
                .map_err(|_| anyhow::anyhow!("Native empty full-snapshot authority worker failed"))
                .and_then(|binding| binding)
            } else {
                FrozenCaptureBinding::from_work(&plan, &work)
            };
            let prepared = (|| -> Result<FrozenCaptureBinding> {
                guard()?;
                plan.verify_snapshot(&service.snapshot()?)?;
                binding
            })();
            let capture = match prepared {
                Ok(capture) => capture,
                Err(error) => {
                    if service.finalize_work(&work, false).await.is_err() {
                        service
                            .lifetime
                            .finalization_blocked
                            .store(true, Ordering::Release);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = self.plans.bind_capture(&plan, &capture) {
                if service.finalize_work(&work, false).await.is_err() {
                    service
                        .lifetime
                        .finalization_blocked
                        .store(true, Ordering::Release);
                }
                return Err(error);
            }
            self.launch(parent, &plan, work, guard, false)
        })
    }
    fn reattach<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, ()> {
        Box::pin(async move {
            self.require_ready()?;
            guard()?;
            let plan = self.plans.plan(parent.operation_id, child)?;
            let capture = self
                .plans
                .capture(&plan)?
                .context("Original native capture is unavailable")?;
            let source = self
                .authenticated(
                    parent,
                    &plan,
                    Some(&capture),
                    SourceProofPurpose::Observation,
                )
                .await?;
            ensure!(
                matches!(&source.observation,NativeObservation::Present {status}
                if !status.worker_running && status.state!=ChildState::Completed),
                "A running/completed source child cannot start a replacement attempt"
            );
            let work = self
                .prepare_original_or_fail(parent, &plan, &capture, &source, guard.clone())
                .await?;
            self.install_attempt(&plan, guard, Some(work))?;
            Ok(())
        })
    }
    fn retry<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, Uuid> {
        Box::pin(async move {
            guard()?;
            let plan = self.plans.plan(parent.operation_id, child)?;
            let capture = self
                .plans
                .capture(&plan)?
                .context("Original native capture is unavailable")?;
            let source = self
                .authenticated(
                    parent,
                    &plan,
                    Some(&capture),
                    SourceProofPurpose::Observation,
                )
                .await?;
            ensure!(
                matches!(&source.observation,NativeObservation::Present {status}
                if status.state.retryable() && !status.worker_running),
                "Retry requires the same authenticated failed/interrupted source child"
            );
            let attempt = self
                .attempt(child.source_id)?
                .context("Original source work was not reattached")?;
            let work = attempt
                .recovered_work
                .lock()
                .map_err(|_| anyhow::anyhow!("Recovered capture lock failed"))?
                .take()
                .context("Original source retry intent was already spent")?;
            ensure!(
                capture.matches_work(&plan, &work)?,
                "Native retry cannot widen captured selection"
            );
            self.launch(parent, &plan, work, guard, true)
        })
    }
    fn cancel_and_drain<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, NativeObservation> {
        Box::pin(async move {
            let plan = self.plans.plan(parent.operation_id, child)?;
            let capture = self.plans.capture(&plan)?;
            let service = self.service()?;
            if let Some(operation) = service
                .operations
                .lock()
                .map_err(|_| anyhow::anyhow!("Operation state lock failed"))?
                .get_mut(&child.source_id.to_string())
            {
                operation.cancelled = true;
            }
            let first = self
                .authenticated(
                    parent,
                    &plan,
                    capture.as_ref(),
                    SourceProofPurpose::Cancellation,
                )
                .await?;
            if matches!(first.observation,NativeObservation::Present {ref status} if status.worker_running)
            {
                // Failed cancellation RPC is not a completion signal; keep
                // observing the actual native owner until it really drains.
                let _ = service
                    .engine_call("cancel", None, json!({"operationId":child.source_id}))
                    .await;
            }
            let mut interval = tokio::time::interval(Duration::from_millis(25));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tokio::time::timeout(Duration::from_secs(120), async {
                loop {
                    interval.tick().await;
                    let source = self
                        .authenticated(
                            parent,
                            &plan,
                            capture.as_ref(),
                            SourceProofPurpose::Cancellation,
                        )
                        .await?;
                    let local = self
                        .attempt(child.source_id)?
                        .is_some_and(|attempt| attempt.running.load(Ordering::Acquire));
                    let drained = match &source.observation {
                        NativeObservation::Absent { .. } => true,
                        NativeObservation::Present { status } => status.terminal_and_drained(),
                        NativeObservation::Unknown { .. } => false,
                    };
                    if drained && !local {
                        return Ok::<_, anyhow::Error>(source.observation);
                    }
                }
            })
            .await
            .context("Actual source cancellation is still draining; retain native ownership")?
        })
    }
    fn finalize_completed<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, CompletionReceipt> {
        Box::pin(async move {
            let plan = self.plans.plan(parent.operation_id, child)?;
            let capture = self
                .plans
                .capture(&plan)?
                .context("Original captured source binding is unavailable")?;
            let source = self
                .authenticated(
                    parent,
                    &plan,
                    Some(&capture),
                    SourceProofPurpose::Observation,
                )
                .await?;
            ensure!(
                matches!(&source.observation,NativeObservation::Present {status}
                if status.state==ChildState::Completed && !status.worker_running),
                "Actual source operation is not authenticated durable joined completion"
            );
            if self.plans.finalization(&plan)?.is_none() {
                // No source resubmission, even if its tracker work was lost.
                // Native recovery must reinstall ONLY the original receipt.
                let guard = self.publication_guard(parent, child).await?;
                let work = self
                    .prepare_original_or_fail(parent, &plan, &capture, &source, guard.clone())
                    .await?;
                let attempt = self.install_attempt(&plan, guard, None)?;
                attempt.running.store(true, Ordering::Release);
                let service = self.service()?;
                let recovered = async {
                    self.before_child_finalization(child.source_id, &work, true)
                        .await?;
                    service.finalize_work(&work, true).await?;
                    let receipt = attempt
                        .tracker_receipt_digest
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Native receipt lock failed"))?
                        .clone()
                        .context("Recovered actual tracker receipt proof missing")?;
                    self.plans.finalize(
                        &plan,
                        &FinalizedNativeChild {
                            source_id: plan.source_id,
                            native_plan_digest: plan.digest()?,
                            capture_digest: capture.digest()?,
                            source_proof_digest: source
                                .completion_digest
                                .clone()
                                .context("Actual committed source proof missing")?,
                            tracker_receipt_digest: receipt,
                            generation: capture.generation,
                        },
                    )
                }
                .await;
                attempt.running.store(false, Ordering::Release);
                if recovered.is_err() {
                    return Err(self
                        .reconciliation_gap(
                            &plan,
                            Some(&capture),
                            ReconciliationGapKind::TrackerFinalization,
                            true,
                        )
                        .await);
                }
            }
            let finalized = self
                .plans
                .finalization(&plan)?
                .context("Actual tracker finalization marker missing")?;
            ensure!(
                finalized.capture_digest == capture.digest()?
                    && finalized.source_proof_digest
                        == source
                            .completion_digest
                            .context("Actual committed source proof missing")?
                    && finalized.generation == capture.generation,
                "Authenticated source result differs from the durable tracker finalization"
            );
            Ok(CompletionReceipt {
                source_id: child.source_id,
                native_plan_digest: child.native_plan_digest.clone(),
                receipt_digest: native_plans::fingerprint(&serde_json::to_value(finalized)?)?,
            })
        })
    }
}

fn selected_instances(params: &Value) -> Result<Option<BTreeSet<String>>> {
    let Some(values) = params.get("softwareIds") else {
        return Ok(None);
    };
    let values = values
        .as_array()
        .context("Selected software instances must be an array")?;
    ensure!(
        !values.is_empty() && values.len() <= MAX_APPS_PER_PLAN,
        "Select 1–4096 exact software instances"
    );
    let mut selected = BTreeSet::new();
    for value in values {
        let id = value
            .as_str()
            .context("Software instance ID must be text")?;
        dto::id(&json!({"id":id}), "id")?;
        ensure!(
            selected.insert(id.to_owned()),
            "Duplicate software instance in native batch selection"
        );
    }
    Ok(Some(selected))
}
fn parse_id(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).context("Invalid native batch/source ID")?;
    ensure!(
        id.to_string() == value,
        "Native batch/source ID is not canonical"
    );
    Ok(id)
}
fn group_activity(id: Uuid, provider: Value, summary: Option<&OperationSummary>) -> Value {
    let state = summary.map_or("queued", |summary| match summary.state {
        ParentState::Queued => "queued",
        ParentState::Running | ParentState::Finalizing | ParentState::Unknown => "running",
        ParentState::Completed => "completed",
        ParentState::Failed => "failed",
        ParentState::Cancelled => "cancelled",
        ParentState::Interrupted => "interrupted",
    });
    let phase = summary.map_or("preparing", |summary| match summary.state {
        ParentState::Unknown => "native_status_unavailable",
        ParentState::Finalizing => "finalizing",
        ParentState::Completed => "finalized",
        ParentState::Failed => "failed",
        ParentState::Cancelled => "cancelled",
        ParentState::Interrupted => "interrupted",
        _ => "native_operation",
    });
    json!({
        "id":id,"operationId":id,"planSetId":id,"kind":"upload","name":"Save approved software group",
        "providerId":provider,"state":state,"phase":phase,
        "canCancel":summary.is_none_or(|summary|summary.shutdown_blocked),
        "canRetry":summary.is_some_and(|summary|summary.can_retry),
        "error":Value::Null,
        "batch":summary.map(|summary|json!({
            "softwareCount":summary.child_count,"jobCount":summary.job_count,
            "completed":summary.completed,"failed":summary.failed,"cancelled":summary.cancelled,
            "interrupted":summary.interrupted,"active":summary.active,"notStarted":summary.not_started,
            "unknown":summary.unknown,"awaitingFinalization":summary.awaiting_finalization,
            "progress":summary.progress,"closeBlocked":summary.shutdown_blocked,
        })),
    })
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
