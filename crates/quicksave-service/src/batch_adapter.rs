// SPDX-License-Identifier: GPL-3.0-only
//! Private production batch/source and restart reconciliation adapters.
//!
//! Parent wiring:
//! - Declare this module alongside `batch` and `native_plans`.
//! - Construct one `Arc<NativeBatchAdapters>` with the actual WorkspaceStore,
//!   shared Arc<NativeEngine>, and actual ServiceTracking implementation. Use it
//!   for BOTH injected batch traits.
//! - `reauthenticate_existing` is an explicit execution/retry hook, not a status
//!   hook. Ordinary `authenticate` NEVER opens the vault or reads a provider.
//! - Tracking's `mark_unknown_dirty` must perform real Tracker persistence. Its
//!   return shape is documented at the call below. The previous authenticated
//!   baseline/history is retained; only CURRENT confirmation/reuse is invalidated.
//!   No default acknowledges persistence.
//!
//! A source terminal row is not a completion receipt. Restart uses ONLY a real
//! original frozen-work frame, original device-authenticated receipt sidecar,
//! source expected-manifest AEAD and immutable prepared source proof/packs.
//! Missing original artifacts remain unknown/dirty; today's files never replace
//! the original work or cause a completed source child to run again.

use crate::{
    batch::{
        BatchRecovery, BatchSourceVerifier, DirtyBaselineReceipt, SourceProofPurpose,
        VerifiedSourceOperation,
    },
    boundary as dto,
    interfaces::{NativeFuture, PublishGuard, ServiceTracking},
    native_plans::{
        self, FrozenCaptureBinding, FrozenNativePlan, NativeHistoryChild, ReconciliationGapKind,
    },
    operations::{
        ChildState, FrozenPlanSet, NativeChildStatus, NativeObservation, NativeProgress,
        OperationKind,
    },
};
use anyhow::{bail, ensure, Context, Result};
#[cfg(unix)]
use quicksave_noland::capture_control::NativeCaptureController;
use quicksave_noland::NativeEngine;
use quicksave_state::WorkspaceStore;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct NativeBatchAdapters {
    store: WorkspaceStore,
    engine: Arc<NativeEngine>,
    tracking: Arc<dyn ServiceTracking>,
}

impl NativeBatchAdapters {
    pub fn new(
        store: WorkspaceStore,
        engine: Arc<NativeEngine>,
        tracking: Arc<dyn ServiceTracking>,
    ) -> Self {
        Self {
            store,
            engine,
            tracking,
        }
    }

    /// Call only for an already admitted explicit native execution/retry. This
    /// does not submit/retry a source job or restore a tracker baseline. It only
    /// authenticates the original existing source ID/selection/repository.
    ///
    /// The runtime should invoke this before driving a restarted group. Merely
    /// displaying a retained group must use BatchSourceVerifier::authenticate.
    pub fn reauthenticate_existing<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: &'a FrozenCaptureBinding,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        Box::pin(async move {
            self.require_supported()?;
            let binding = source_binding(parent, plan, Some(capture))?;
            #[cfg(unix)]
            {
                // Retained in-process ownership or authenticated completion
                // caches need no second vault lookup. Authoritative absence
                // needs no credentials either.
                if let Ok(raw) = self
                    .engine
                    .verify_batch_source(None, binding.clone(), "observation")
                    .await
                {
                    return verified_projection(
                        &raw,
                        plan,
                        Some(capture),
                        SourceProofPurpose::Observation,
                    );
                }
                let store = self.store.clone();
                let plan_for_access = plan.clone();
                let access = tokio::task::spawn_blocking(move || {
                    let snapshot = serde_json::to_value(store.document()?)?;
                    plan_for_access.verify_snapshot(&snapshot)?;
                    let mut access = store.provider_access(
                        &plan_for_access.provider_id,
                        &plan_for_access.source_id.to_string(),
                    )?;
                    // Verification is read-only even if the original profile
                    // owns a write grant. No new write grant is requested.
                    access.read_only = true;
                    Ok::<_, anyhow::Error>(access)
                })
                .await
                .map_err(|_| anyhow::anyhow!("Explicit native source access worker failed"))??;
                let raw = self
                    .engine
                    .verify_batch_source(Some(access), binding, "observation")
                    .await?;
                verified_projection(&raw, plan, Some(capture), SourceProofPurpose::Observation)
            }
            #[cfg(not(unix))]
            {
                let _ = binding;
                bail!("Actual batch source attestation is not implemented for this platform")
            }
        })
    }
}

impl BatchSourceVerifier for NativeBatchAdapters {
    fn history_owners<'a>(
        &'a self,
        plan_set_id: uuid::Uuid,
        root_digest: &'a str,
        children: &'a [NativeHistoryChild],
    ) -> NativeFuture<'a, Vec<NativeObservation>> {
        Box::pin(async move {
            self.require_supported()?;
            native_plans::checked_digest(root_digest)?;
            ensure!(
                !children.is_empty() && children.len() <= 128,
                "Native history ownership pages contain 1–128 exact children"
            );
            #[cfg(unix)]
            {
                let keys = json!(children
                    .iter()
                    .map(|child| json!({
                        "sourceId":child.source_id,"canonicalAppId":child.app_id,
                    }))
                    .collect::<Vec<_>>());
                let raw = self
                    .engine
                    .batch_history_owners(&plan_set_id.to_string(), root_digest, keys)
                    .await?;
                dto::bounded(&raw, 128 * 1024)?;
                ensure!(
                    raw["planSetId"] == plan_set_id.to_string() && raw["rootDigest"] == root_digest,
                    "Native history ownership projection changed its authenticated set"
                );
                let items = raw["items"]
                    .as_array()
                    .context("Native history ownership projection is unavailable")?;
                ensure!(
                    items.len() == children.len(),
                    "Native history ownership page is incomplete"
                );
                items
                    .iter()
                    .zip(children)
                    .map(|(item, child)| {
                        ensure!(
                            item["sourceId"] == child.source_id.to_string(),
                            "Native history ownership returned another exact source ID"
                        );
                        match dto::text(item, "presence", 16)? {
                            "absent" => {
                                ensure!(
                                    item["workerRunning"] == false,
                                    "Native history absence contradicts its actual worker owner"
                                );
                                Ok(NativeObservation::Absent {
                                    source_id: child.source_id,
                                })
                            }
                            "unknown" => Ok(NativeObservation::Unknown {
                                source_id: child.source_id,
                            }),
                            "present" => {
                                let state = match dto::text(item, "state", 32)? {
                                    "queued" => ChildState::Queued,
                                    "running" => ChildState::Running,
                                    "completed" => ChildState::Completed,
                                    "failed" => ChildState::Failed,
                                    "cancelled" => ChildState::Cancelled,
                                    "interrupted" => ChildState::Interrupted,
                                    "unknown" => ChildState::Unknown,
                                    _ => bail!("Native history source state is unsupported"),
                                };
                                let worker_running = item["workerRunning"]
                                    .as_bool()
                                    .context("Native history worker ownership is unavailable")?;
                                let progress =
                                    match item.get("progress").filter(|value| !value.is_null()) {
                                        Some(progress) => {
                                            Some(NativeProgress {
                                                phase: dto::text(progress, "phase", 128)?.into(),
                                                unit: {
                                                    let unit = dto::text(progress, "unit", 32)?;
                                                    ensure!(matches!(unit,"bytes"|"files"|"items"),
                                            "Native history progress unit is unsupported");
                                                    unit.into()
                                                },
                                                completed: progress["completed"].as_u64().context(
                                                    "Native history progress count is unavailable",
                                                )?,
                                                total: match progress
                                                    .get("total")
                                                    .filter(|value| !value.is_null())
                                                {
                                                    Some(total) => Some(total.as_u64().context(
                                                        "Native history progress total is invalid",
                                                    )?),
                                                    None => None,
                                                },
                                            })
                                        }
                                        None => None,
                                    };
                                // Ownership only. In particular COMPLETED here
                                // creates NO VerifiedSourceOperation/receipt/hash.
                                Ok(NativeObservation::Present {
                                    status: NativeChildStatus {
                                        source_id: child.source_id,
                                        state,
                                        worker_running,
                                        progress,
                                    },
                                })
                            }
                            _ => bail!("Native history source presence is unsupported"),
                        }
                    })
                    .collect()
            }
            #[cfg(not(unix))]
            {
                let _ = (plan_set_id, root_digest, children);
                bail!("Native history source ownership is unsupported on this platform")
            }
        })
    }

    fn reauthenticate_existing<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: &'a FrozenCaptureBinding,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        NativeBatchAdapters::reauthenticate_existing(self, parent, plan, capture)
    }
    fn require_supported(&self) -> Result<()> {
        #[cfg(unix)]
        {
            self.engine.batch_source_verification_supported()
        }
        #[cfg(not(unix))]
        {
            bail!("Actual batch source attestation is not implemented for this platform")
        }
    }

    fn authenticate<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        purpose: SourceProofPurpose,
    ) -> NativeFuture<'a, VerifiedSourceOperation> {
        Box::pin(async move {
            self.require_supported()?;
            let binding = source_binding(parent, plan, capture)?;
            #[cfg(unix)]
            {
                let purpose_name = match purpose {
                    SourceProofPurpose::Observation => "observation",
                    SourceProofPurpose::Cancellation => "cancellation",
                };
                // No provider_access, vault lookup, discovery, registration,
                // preflight or remote read is allowed in this polling method.
                let raw = self
                    .engine
                    .verify_batch_source(None, binding, purpose_name)
                    .await?;
                verified_projection(&raw, plan, capture, purpose)
            }
            #[cfg(not(unix))]
            {
                let _ = (binding, purpose);
                bail!("Actual batch source attestation is not implemented for this platform")
            }
        })
    }
}

impl BatchRecovery for NativeBatchAdapters {
    fn recover_original_work<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        plan: &'a FrozenNativePlan,
        capture: &'a FrozenCaptureBinding,
        source: &'a VerifiedSourceOperation,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            let binding = source_binding(parent, plan, Some(capture))?;
            (guard)()?;
            ensure!(
                source.observation.source_id() == plan.source_id
                    && source.root_authority_revision == plan.root_authority_revision
                    && source.capture_digest.as_deref() == Some(capture.digest()?.as_str()),
                "Original source recovery belongs to another native capture"
            );
            let completed = match &source.observation {
                NativeObservation::Present { status } if !status.worker_running => {
                    ensure!(
                        status.state == ChildState::Completed || status.state.retryable(),
                        "Original source recovery is not a drained terminal operation"
                    );
                    status.state == ChildState::Completed
                }
                _ => bail!("Original source worker is absent, unknown, or still running/draining"),
            };
            #[cfg(unix)]
            {
                let tracking = self.tracking.clone();
                let record = plan.registration_record();
                let work_id = capture.work_id.clone();
                let generation = capture.generation;
                // This is a typed original native owner, not a JSON restored
                // flag, new scan, new begin_upload or recapture of today's files.
                let original: Arc<quicksave_tracking::NativeFrozenWork> =
                    tokio::task::spawn_blocking(move || {
                        tracking.original_work(&record, &work_id, generation)
                    })
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("Original frozen work recovery worker failed")
                    })??;
                original.revalidate()?;
                let work = original.work()?;
                let header = original.header()?;
                dto::bounded(&work, dto::MAX_WORK_BYTES)?;
                ensure!(
                    FrozenCaptureBinding::from_work(plan, &work)? == *capture,
                    "Recovered Tracker work is not the original signed batch capture"
                );
                let receipt_seal = original
                    .accepted_receipt()?
                    .context("Original post-capture device receipt was not retained")?;
                ensure!(
                    receipt_seal["scope"]["workId"] == capture.work_id
                        && receipt_seal["scope"]["generation"] == capture.generation
                        && receipt_seal["scope"]["metadataIdentity"] == capture.metadata_identity
                        && receipt_seal["scope"]["immutablePreparedCapture"] == true,
                    "Original post-capture device receipt is unavailable"
                );
                let controller = Arc::new(OriginalRecoveryController::new(
                    self.tracking.clone(),
                    self.engine.clone(),
                    Arc::new(binding.clone()),
                    original,
                    &work,
                    receipt_seal.clone(),
                )?);
                let store = self.store.clone();
                let access_plan = plan.clone();
                let access = tokio::task::spawn_blocking(move || {
                    access_plan.verify_snapshot(&serde_json::to_value(store.document()?)?)?;
                    let mut access = store.provider_access(
                        &access_plan.provider_id,
                        &access_plan.source_id.to_string(),
                    )?;
                    if completed {
                        access.read_only = true;
                    }
                    Ok::<_, anyhow::Error>(access)
                })
                .await
                .map_err(|_| anyhow::anyhow!("Original capture private access worker failed"))??;
                (guard)()?;
                let result = self
                    .engine
                    .recover_original_capture(
                        access,
                        json!({
                            "binding":binding,"work":work,
                            "frozenWork":header["frameReference"],
                            "captureReceipt":receipt_seal,
                        }),
                        guard.clone(),
                        controller,
                    )
                    .await?;
                ensure!(
                    result["sourceOperationId"] == plan.source_id.to_string()
                        && result["workId"] == capture.work_id
                        && result["sourceAlreadyCompleted"] == completed
                        && result["originalReceiptReattached"] == true,
                    "Actual source did not reattach the original native receipt"
                );
                (guard)()?;
                // Same original request, including work ID/generation, exact
                // IDs, roots/metadata scope and original full-scope grants.
                Ok(work)
            }
            #[cfg(not(unix))]
            {
                let _ = (binding, completed);
                bail!("Original native source capture recovery is unsupported on this platform")
            }
        })
    }

    fn mark_unknown_dirty<'a>(
        &'a self,
        plan: &'a FrozenNativePlan,
        capture: Option<&'a FrozenCaptureBinding>,
        reason: ReconciliationGapKind,
    ) -> NativeFuture<'a, DirtyBaselineReceipt> {
        Box::pin(async move {
            plan.validate()?;
            if let Some(capture) = capture {
                capture.validate(plan)?;
            }
            let store = self.store.clone();
            let tracking = self.tracking.clone();
            let plan = plan.clone();
            let capture = capture.cloned();
            tokio::task::spawn_blocking(move || {
                // This authority check deliberately does not require a
                // connected provider, fresh write grant, or provider secrets.
                // Revocation must not prevent exact-baseline invalidation.
                let before = serde_json::to_value(store.document()?)?;
                let previous = check_exact_software_authority(&before, &plan)?;
                let receipt = tracking.call(
                    "mark_unknown_dirty",
                    &json!({
                        "record":plan.registration_record(),
                        "softwareId":plan.software_id,"appId":plan.tracker_app_id,
                        "providerId":plan.provider_id,
                        "rootAuthorityRevision":plan.root_authority_revision,
                        "sourceId":plan.source_id,
                        "workId":capture.as_ref().map(|capture|capture.work_id.as_str()),
                        "generation":capture.as_ref().map(|capture|capture.generation),
                        "reason":reason,
                    }),
                )?;
                // Actual Tracker::mark_unknown_dirty returns only AFTER its
                // TrackingStore commit:
                // {softwareId, dirty, dirtyGeneration, unknownGeneration,
                //  lastConfirmedUploadedGeneration, reconciliationRequired,
                //  status, authorityUnchanged, keepsVersionHistory, ...}.
                // The historical baseline is NOT current confirmation. Keeping
                // it preserves additive deletion IDs and snapshot provenance.
                // An unavailable method or "dirty":true alone is no ack.
                dto::bounded(&receipt, 16 * 1024)?;
                if let Some(revision) = receipt.get("rootAuthorityRevision") {
                    ensure!(
                        revision.as_str() == Some(plan.root_authority_revision.as_str()),
                        "Tracker dirty acknowledgement changed its exact root authority"
                    );
                }
                if receipt.get("persisted").is_some() {
                    ensure!(
                        receipt["persisted"] == true,
                        "Tracker reported unresolved dirty-state persistence"
                    );
                }
                if receipt.get("proofDigest").is_some() {
                    // A parent service may additionally MAC its own readback.
                    // This never replaces validation of the actual transition.
                    native_plans::checked_digest(dto::text(&receipt, "proofDigest", 64)?)?;
                }
                // Read the actual WorkspaceStore, not a mock UI status or the
                // acknowledgement's own copy of nativeState. Losing or ignoring
                // the store commit is a hard reconciliation failure.
                let after = serde_json::to_value(store.document()?)?;
                let record = check_exact_software_authority(&after, &plan)?;
                validate_unknown_transition(
                    previous,
                    record,
                    &receipt,
                    &plan.software_id,
                    capture.as_ref().map(|capture| capture.generation),
                )?;
                // Bind the genuine persisted transition to the original exact
                // plan/source/capture with EXISTING device authority. This MAC
                // is an unknown-current reconciliation receipt, never a saved
                // baseline or a fabricated native source/capture receipt.
                let proof_scope = json!({
                    "domain":"QuickSave/native-batch-unknown-current/v1",
                    "sourceId":plan.source_id,"nativePlanDigest":plan.digest()?,
                    "rootAuthorityRevision":plan.root_authority_revision,
                    "captureDigest":capture.as_ref().map(FrozenCaptureBinding::digest).transpose()?,
                    "reason":reason,
                    "persistedRecordDigest":native_plans::fingerprint(record)?,
                    "trackerTransition":receipt,
                });
                dto::bounded(&proof_scope, 32 * 1024)?;
                let proof = store
                    .operation_mac_existing(&serde_json::to_vec(&proof_scope)?)?
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                Ok(DirtyBaselineReceipt {
                    software_id: plan.software_id,
                    root_authority_revision: plan.root_authority_revision,
                    proof_digest: proof,
                })
            })
            .await
            .map_err(|_| anyhow::anyhow!("Native dirty reconciliation worker failed"))?
        })
    }
}

#[cfg(unix)]
struct RecoveredTrackerReceipt {
    source: Arc<quicksave_noland::capture_control::PreparedCaptureReceipt>,
    engine: Arc<NativeEngine>,
    binding: Arc<Value>,
}
#[cfg(unix)]
impl quicksave_tracking::NativeCaptureReceipt for RecoveredTrackerReceipt {
    fn evidence(&self) -> Result<Value> {
        self.source.evidence()
    }
    fn revalidate(&self) -> Result<()> {
        self.source.revalidate()
    }
    fn immutable_prepared_capture(&self) -> bool {
        true
    }
    fn verify_committed(&self) -> Result<()> {
        // Tracker already revalidated this source receipt and its original
        // device grants. PREPARED evidence is never substituted for COMMITTED.
        self.engine.verify_cached_batch_commit(&self.binding)
    }
}

#[cfg(unix)]
struct OriginalRecoveryController {
    // Retain the actual authenticated Tracker owner through receipt admission;
    // a work ID or JSON locator cannot replace this native capability.
    original: Arc<quicksave_tracking::NativeFrozenWork>,
    tracking: Arc<dyn ServiceTracking>,
    engine: Arc<NativeEngine>,
    binding: Arc<Value>,
    work_id: String,
    app_id: String,
    metadata_identity: String,
    full_scope: Option<Arc<OriginalFrozenFullScope>>,
    receipt_seal: Value,
}
#[cfg(unix)]
struct OriginalFrozenFullScope {
    original: Arc<quicksave_tracking::NativeFrozenWork>,
    evidence: Value,
}
#[cfg(unix)]
impl quicksave_noland::capture_control::NativeFullScopeAuthority for OriginalFrozenFullScope {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        self.original.revalidate()
    }
}
#[cfg(unix)]
impl OriginalRecoveryController {
    fn new(
        tracking: Arc<dyn ServiceTracking>,
        engine: Arc<NativeEngine>,
        binding: Arc<Value>,
        original: Arc<quicksave_tracking::NativeFrozenWork>,
        work: &Value,
        receipt_seal: Value,
    ) -> Result<Self> {
        original.revalidate()?;
        let full_scope = if work["captureSource"]["selectionKind"] == "full_scope" {
            Some(Arc::new(OriginalFrozenFullScope {
                evidence: original.full_scope_evidence()?,
                original: original.clone(),
            }))
        } else {
            None
        };
        Ok(Self {
            tracking,
            engine,
            binding,
            original,
            full_scope,
            receipt_seal,
            work_id: dto::id(work, "workId")?.into(),
            app_id: work
                .pointer("/sourceIdentity/app_id")
                .and_then(Value::as_str)
                .unwrap_or(dto::id(work, "appId")?)
                .into(),
            metadata_identity: dto::text(
                &work["captureSource"]["metadataSelection"],
                "metadataIdentity",
                512,
            )?
            .into(),
        })
    }
}
#[cfg(unix)]
impl quicksave_noland::capture_control::NativeCaptureController for OriginalRecoveryController {
    fn node_page(
        &self,
        scope: &quicksave_noland::capture_control::CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<quicksave_noland::capture_control::FrozenCaptureNode>> {
        ensure!(
            scope.work_id == self.work_id && scope.metadata_identity == self.metadata_identity,
            "Original frozen node page requested another native scope"
        );
        let page = self.original.node_page(offset, limit)?;
        ensure!(
            page["workId"] == self.work_id && page["metadataIdentity"] == self.metadata_identity,
            "Original native frozen page changed identity"
        );
        let nodes = page["nodes"]
            .as_array()
            .context("Original frozen native nodes are unavailable")?;
        ensure!(
            nodes.len() <= limit,
            "Original frozen native page exceeds its bound"
        );
        nodes
            .iter()
            .map(|node| {
                let root = dto::id(node, "rootId")?;
                Ok(quicksave_noland::capture_control::FrozenCaptureNode {
                    id: dto::id(node, "id")?.into(),
                    root_id: root.into(),
                    logical_root: quicksave_noland::native_capture_root_token(&self.app_id, root)?,
                    path: dto::text(node, "path", 32768)?.into(),
                    kind: dto::text(node, "kind", 32)?.into(),
                    size: node["size"]
                        .as_u64()
                        .context("Original node size is missing")?,
                    stamp: serde_json::from_value(node["stamp"].clone())?,
                    link_target_hash: node
                        .get("linkTargetHash")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
            })
            .collect()
    }
    fn reuse_epoch(
        &self,
        _: &quicksave_noland::capture_control::CaptureScope,
    ) -> Result<Option<String>> {
        Ok(None)
    }
    fn full_scope_authority(
        &self,
        scope: &quicksave_noland::capture_control::CaptureScope,
    ) -> Result<Option<Arc<dyn quicksave_noland::capture_control::NativeFullScopeAuthority>>> {
        ensure!(
            scope.work_id == self.work_id && scope.metadata_identity == self.metadata_identity,
            "Original full-scope owner requested another native work"
        );
        Ok(self.full_scope.clone().map(|owner| {
            owner as Arc<dyn quicksave_noland::capture_control::NativeFullScopeAuthority>
        }))
    }
    fn accept(
        &self,
        receipt: Arc<quicksave_noland::capture_control::PreparedCaptureReceipt>,
    ) -> Result<()> {
        receipt.revalidate()?;
        // A typed native receipt, not an incoming JSON "authenticated" field.
        // The actual Tracker implementation verifies its ORIGINAL receipt and
        // sidecar grants and MUST NOT mint a replacement capture receipt here.
        // Pass the retained owner directly; never look it up again by work ID.
        let attached = self.tracking.resume_pending(
            self.original.clone(),
            Arc::new(RecoveredTrackerReceipt {
                source: receipt,
                engine: self.engine.clone(),
                binding: self.binding.clone(),
            }),
        )?;
        dto::bounded(&attached, dto::MAX_WORK_BYTES)?;
        let seal = attached
            .get("captureReceipt")
            .unwrap_or(&attached["captureSource"]["captureReceipt"]);
        ensure!(
            attached["workId"] == self.work_id && *seal == self.receipt_seal,
            "Tracker reattachment changed the original device capture/sidecar grant"
        );
        Ok(())
    }
    fn verify_publication(&self) -> Result<()> {
        self.original.revalidate()?;
        let receipt = self
            .tracking
            .call("verify_capture_receipt", &json!({"workId":self.work_id}))?;
        ensure!(
            receipt["verified"] == true && receipt["workId"] == self.work_id,
            "Original reattached Tracker receipt did not verify for publication"
        );
        Ok(())
    }
}

/// The actual batch runtime verified the device MAC before passing these native
/// structures. This function additionally prevents cross-parent/provider mixing;
/// it does not accept a caller's `"authenticated":true` or row-shaped JSON.
fn source_binding(
    parent: &FrozenPlanSet,
    plan: &FrozenNativePlan,
    capture: Option<&FrozenCaptureBinding>,
) -> Result<Value> {
    plan.validate()?;
    ensure!(
        parent.kind == OperationKind::Upload
            && parent.operation_id == plan.plan_set_id
            && parent.provider_id == plan.provider_id
            && parent.provider_scope == plan.provider_digest,
        "Actual source proof belongs to another frozen native parent/provider"
    );
    let child = parent
        .children()
        .find(|child| child.source_id == plan.source_id)
        .context("Actual source is not a member of this frozen native group")?;
    ensure!(
        *child == plan.child()?,
        "Actual source proof changed its signed exact child/root identity"
    );
    if let Some(capture) = capture {
        capture.validate(plan)?;
    }
    let binding = json!({
        "version":1,"sourceId":plan.source_id,
        "planSetId":plan.plan_set_id,"rootDigest":parent.authority_revision,
        "nativePlanId":plan.native_plan_id,
        "nativePlanDigest":plan.digest()?,
        "softwareId":plan.software_id,"canonicalAppId":plan.canonical_app_id,
        "trackerAppId":plan.tracker_app_id,"providerId":plan.provider_id,
        "providerDigest":plan.provider_digest,
        "rootAuthorityRevision":plan.root_authority_revision,
        "registration":plan.registration_record(),
        "capture":capture,
        "captureDigest":capture.map(FrozenCaptureBinding::digest).transpose()?,
    });
    dto::bounded(&binding, native_plans::MAX_NATIVE_PLAN_BYTES)?;
    Ok(binding)
}

fn verified_projection(
    raw: &Value,
    plan: &FrozenNativePlan,
    capture: Option<&FrozenCaptureBinding>,
    purpose: SourceProofPurpose,
) -> Result<VerifiedSourceOperation> {
    dto::bounded(raw, 16 * 1024)?;
    let purpose_name = match purpose {
        SourceProofPurpose::Observation => "observation",
        SourceProofPurpose::Cancellation => "cancellation",
    };
    let capture_digest = capture.map(FrozenCaptureBinding::digest).transpose()?;
    ensure!(
        raw["version"] == 1
            && raw["sourceId"] == plan.source_id.to_string()
            && raw["purpose"] == purpose_name
            && raw["rootAuthorityRevision"] == plan.root_authority_revision
            && raw.get("captureDigest").and_then(Value::as_str) == capture_digest.as_deref(),
        "Native source attestation changed its frozen child/root/capture identity"
    );
    let binding_digest = optional_digest(raw, "bindingDigest")?;
    let completion_digest = optional_digest(raw, "completionDigest")?;
    let observation = match dto::text(raw, "presence", 16)? {
        "absent" => {
            ensure!(
                raw["workerRunning"] == false
                    && binding_digest.is_none()
                    && completion_digest.is_none(),
                "Actual source absence contradicts its native worker owner/proof"
            );
            NativeObservation::Absent {
                source_id: plan.source_id,
            }
        }
        "unknown" => NativeObservation::Unknown {
            source_id: plan.source_id,
        },
        "present" => {
            let worker_running = raw["workerRunning"]
                .as_bool()
                .context("Actual source worker ownership is unavailable")?;
            let state = match dto::text(raw, "state", 32)? {
                "queued" => ChildState::Queued,
                "running" => ChildState::Running,
                "completed" => ChildState::Completed,
                "failed" => ChildState::Failed,
                "cancelled" => ChildState::Cancelled,
                "interrupted" => ChildState::Interrupted,
                "unknown" => ChildState::Unknown,
                _ => bail!("Actual source returned an unsupported native state"),
            };
            if purpose == SourceProofPurpose::Observation {
                ensure!(
                    capture.is_some() && binding_digest.is_some(),
                    "Actual source submission/replay authentication is unavailable"
                );
                if state == ChildState::Completed && !worker_running {
                    ensure!(
                        completion_digest.is_some(),
                        "A COMPLETED row is not an actual authenticated committed source receipt"
                    );
                }
            } else {
                ensure!(
                    binding_digest.is_none() && completion_digest.is_none(),
                    "A cancellation capability cannot impersonate source completion proof"
                );
            }
            NativeObservation::Present {
                status: NativeChildStatus {
                    source_id: plan.source_id,
                    state,
                    worker_running,
                    progress: match raw.get("progress").filter(|value| !value.is_null()) {
                        Some(progress) => Some(NativeProgress {
                            phase: dto::text(progress, "phase", 128)?.to_owned(),
                            unit: {
                                let unit = dto::text(progress, "unit", 32)?;
                                ensure!(
                                    matches!(unit, "bytes" | "files" | "items"),
                                    "Unsupported actual source progress unit"
                                );
                                unit.to_owned()
                            },
                            completed: progress["completed"]
                                .as_u64()
                                .context("Actual source progress count is missing")?,
                            total: match progress.get("total").filter(|value| !value.is_null()) {
                                Some(total) => Some(
                                    total
                                        .as_u64()
                                        .context("Actual source progress total is invalid")?,
                                ),
                                None => None,
                            },
                        }),
                        None => None,
                    },
                },
            }
        }
        _ => bail!("Actual source presence is not verified"),
    };
    // Deliberately construct the native type, never Deserialize a proof object
    // from row JSON, provider output, operation history or incoming IPC.
    Ok(VerifiedSourceOperation {
        purpose,
        observation,
        root_authority_revision: plan.root_authority_revision.clone(),
        capture_digest,
        binding_digest,
        completion_digest,
    })
}

fn optional_digest(value: &Value, field: &str) -> Result<Option<String>> {
    value
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            let digest = value
                .as_str()
                .context("Native source proof digest is malformed")?;
            native_plans::checked_digest(digest)?;
            Ok(digest.to_owned())
        })
        .transpose()
}

fn check_exact_software_authority<'a>(
    snapshot: &'a Value,
    plan: &FrozenNativePlan,
) -> Result<&'a Value> {
    let record = dto::software_record(snapshot, &plan.software_id)?;
    ensure!(
        native_plans::root_authority_revision(record)? == plan.root_authority_revision,
        "The frozen software/root/grant authority changed; no other baseline was invalidated"
    );
    Ok(record)
}

/// Unknown-current is an advancing native gap partition, not deletion of an old
/// authenticated baseline. The original Tracker receipt can remain evidence of
/// an older immutable version, but its older unknownGeneration cannot confirm
/// the current local generation. No filesystem/provider read is needed here.
fn validate_unknown_transition(
    previous: &Value,
    persisted: &Value,
    receipt: &Value,
    software_id: &str,
    captured_generation: Option<u64>,
) -> Result<()> {
    let dirty = receipt["dirtyGeneration"]
        .as_u64()
        .context("Tracker dirty acknowledgement lacks its real dirty generation")?;
    let unknown = receipt["unknownGeneration"]
        .as_u64()
        .context("Tracker dirty acknowledgement lacks its real gap generation")?;
    let previous_dirty = previous["dirtyGeneration"]
        .as_u64()
        .context("Persisted original dirty generation is unavailable")?;
    let previous_unknown = match previous.get("unknownGeneration") {
        None | Some(Value::Null) => 0, // Legacy persisted records predate this partition.
        Some(value) => value
            .as_u64()
            .context("Invalid original native gap generation")?,
    };
    let confirmed = previous["lastConfirmedUploadedGeneration"]
        .as_u64()
        .context("Historical confirmed generation is unavailable")?;
    ensure!(
        receipt["softwareId"] == software_id
            && receipt["dirty"] == true
            && receipt["reconciliationRequired"] == true
            && receipt["authorityUnchanged"] == true
            && receipt["keepsVersionHistory"] == true
            && receipt["lastConfirmedUploadedGeneration"].as_u64() == Some(confirmed)
            && dirty > previous_dirty
            && dirty > confirmed
            && unknown > previous_unknown,
        "Actual Tracker did not acknowledge an advancing unknown-current transition"
    );
    let receipt_status = dto::text(receipt, "status", 64)?;
    ensure!(
        receipt_status != "saved"
            && persisted["dirty"] == true
            && persisted["reconciliationRequired"] == true
            && persisted["dirtyGeneration"].as_u64() == Some(dirty)
            && persisted["unknownGeneration"].as_u64() == Some(unknown)
            && persisted["lastConfirmedUploadedGeneration"].as_u64() == Some(confirmed)
            && dto::text(persisted, "status", 64)? != "saved"
            // Explicit current confirmation is unknown, not the historical
            // lastConfirmedUploadedGeneration and not a missing-field default.
            && persisted.get("confirmedGeneration") == Some(&Value::Null),
        "The exact current generation is not durably unknown/dirty in WorkspaceStore"
    );
    if let Some(generation) = captured_generation {
        ensure!(
            dirty > generation,
            "Durable reconciliation did not invalidate the original captured generation"
        );
    }
    if let Some(sealed) = persisted
        .get("captureReceipt")
        .filter(|value| !value.is_null())
    {
        let scope = sealed["scope"]
            .as_object()
            .context("Historical native capture receipt has no original scope")?;
        let receipt_unknown = match scope.get("unknownGeneration") {
            None | Some(Value::Null) => 0, // An older receipt cannot cross the new gap.
            Some(value) => value
                .as_u64()
                .context("Invalid historical receipt gap generation")?,
        };
        ensure!(
            receipt_unknown < unknown,
            "A retained native receipt still claims the current unknown gap partition"
        );
    }
    for field in [
        "baseline",
        "baselineFullScope",
        "previousBundleManifest",
        "lastSavedAt",
        "lastConfirmedVersion",
    ] {
        ensure!(
            persisted.get(field) == previous.get(field),
            "Unknown-current reconciliation changed authenticated historical version provenance"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::SelectionIntent;
    use uuid::Uuid;

    fn fixture() -> (FrozenNativePlan, FrozenPlanSet, FrozenCaptureBinding) {
        // Pure native-plan/parser fixtures. No vault, source state, provider or
        // filesystem is consulted and none is installed as a production default.
        let provider = json!({
            "id":"isolated-provider","kind":"s3","origin":"manual",
            "readOnly":false,"status":"connected",
            "credentialRef":"fixture-reference","repositoryKeyRef":"fixture-key-reference",
        });
        let record = json!({
            "id":"synthetic-installation","appId":"steam:480@installation-one",
            "sourceIdentity":{"app_id":"steam:480","display_name":"Synthetic application"},
            "name":"Synthetic application","providerId":"isolated-provider","tracked":true,
            "roots":[{
                "id":"save-root","path":"/isolated-fixture/application","role":"save",
                "identity":{"device":1,"fileId":[2,0]},"allowedFiles":null,
            }],
            "trackingGrant":{"fixtureOnly":"not-a-production-grant"},
        });
        let plan = FrozenNativePlan::from_record(Uuid::new_v4(), &provider, &record).unwrap();
        let parent = FrozenPlanSet::from_children(
            plan.plan_set_id,
            OperationKind::Upload,
            SelectionIntent::AllApprovedApps,
            plan.provider_id.clone(),
            plan.provider_digest.clone(),
            "a".repeat(64),
            vec![plan.child().unwrap()],
        )
        .unwrap();
        let work_id = Uuid::new_v4().to_string();
        let work = json!({
            "workId":work_id,"softwareId":plan.software_id,"providerId":plan.provider_id,
            "appId":plan.tracker_app_id,"sourceIdentity":plan.source_identity,
            "roots":plan.roots,"generation":7,
            "fileIds":["file-fixture-one"],
            "captureSource":{
                "stage":"awaiting_native_capture_receipt","selectionKind":"full_scope",
                "snapshotIdentity":format!("blake3:{}","b".repeat(64)),
                "metadataSelection":{
                    "workId":work_id,"metadataIdentity":format!("blake3:{}","b".repeat(64)),
                    "nodeCount":1,"source":"tracker_native_index",
                },
                "expectedFullScope":{
                    "scope":{"workId":work_id,"softwareId":plan.software_id,"generation":7},
                    "grant":{"fixtureOnly":"not-a-production-grant"},
                },
            },
        });
        let capture = FrozenCaptureBinding::from_work(&plan, &work).unwrap();
        (plan, parent, capture)
    }

    fn projection(plan: &FrozenNativePlan, capture: &FrozenCaptureBinding, purpose: &str) -> Value {
        json!({
            "version":1,"sourceId":plan.source_id,"purpose":purpose,
            "rootAuthorityRevision":plan.root_authority_revision,
            "captureDigest":capture.digest().unwrap(),
            "presence":"present","state":"completed","workerRunning":false,
            "progress":null,"bindingDigest":null,"completionDigest":null,
        })
    }

    #[test]
    fn completed_json_or_boolean_authentication_never_constructs_a_verified_completion() {
        let (plan, _, capture) = fixture();
        let mut raw = projection(&plan, &capture, "observation");
        raw["authenticated"] = json!(true);
        assert!(
            verified_projection(&raw, &plan, Some(&capture), SourceProofPurpose::Observation)
                .is_err()
        );
        raw["bindingDigest"] = json!("a".repeat(64));
        assert!(
            verified_projection(&raw, &plan, Some(&capture), SourceProofPurpose::Observation)
                .is_err()
        );
        raw["completionDigest"] = json!("b".repeat(64));
        let source =
            verified_projection(&raw, &plan, Some(&capture), SourceProofPurpose::Observation)
                .unwrap();
        assert!(
            matches!(source.observation,NativeObservation::Present {status}
            if status.state==ChildState::Completed && !status.worker_running)
        );
    }

    #[test]
    fn cancellation_and_absence_require_no_provider_or_completion_digest() {
        let (plan, _, capture) = fixture();
        let mut raw = projection(&plan, &capture, "cancellation");
        raw["state"] = json!("running");
        raw["workerRunning"] = json!(true);
        let source = verified_projection(
            &raw,
            &plan,
            Some(&capture),
            SourceProofPurpose::Cancellation,
        )
        .unwrap();
        assert!(
            matches!(source.observation,NativeObservation::Present {status} if status.worker_running)
        );
        raw["presence"] = json!("absent");
        assert!(verified_projection(
            &raw,
            &plan,
            Some(&capture),
            SourceProofPurpose::Cancellation
        )
        .is_err());
        raw["workerRunning"] = json!(false);
        assert!(matches!(
            verified_projection(
                &raw,
                &plan,
                Some(&capture),
                SourceProofPurpose::Cancellation
            )
            .unwrap()
            .observation,
            NativeObservation::Absent { .. }
        ));
    }

    #[test]
    fn original_instance_capture_and_parent_are_not_replaceable_by_canonical_app_id() {
        let (plan, parent, capture) = fixture();
        assert!(source_binding(&parent, &plan, Some(&capture)).is_ok());
        let mut different = plan.clone();
        different.source_id = Uuid::new_v4();
        assert!(source_binding(&parent, &different, None).is_err());
        let mut raw = projection(&plan, &capture, "cancellation");
        raw["captureDigest"] = json!("f".repeat(64));
        assert!(verified_projection(
            &raw,
            &plan,
            Some(&capture),
            SourceProofPurpose::Cancellation
        )
        .is_err());
        let mut record = plan.registration_record();
        record["appId"] = json!("steam:480@installation-two");
        let snapshot = json!({"software":[record]});
        assert!(check_exact_software_authority(&snapshot, &plan).is_err());
    }

    fn unknown_transition_fixture() -> (Value, Value, Value) {
        // Parser-only fixture representing a previously authenticated version.
        // It neither issues a real grant nor installs a mock native capability.
        let previous = json!({
            "id":"software-one","dirty":false,"reconciliationRequired":false,
            "dirtyGeneration":7,"unknownGeneration":2,
            "confirmedGeneration":7,"lastConfirmedUploadedGeneration":7,"status":"saved",
            "baseline":{"name":"older-authenticated-snapshot","hash":"fixture-history-hash",
                "grant":{"fixtureOnly":"historical-baseline-authentication"}},
            "baselineFullScope":true,
            "previousBundleManifest":{"bundleId":"older-immutable-version"},
            "lastSavedAt":"2026-11-17T00:00:00Z",
            "lastConfirmedVersion":"older-immutable-version",
            "captureReceipt":{"scope":{"workId":"older-frozen-work","generation":7,
                "unknownGeneration":2},"grant":{"fixtureOnly":"older-receipt"}},
        });
        let mut persisted = previous.clone();
        persisted["dirty"] = json!(true);
        persisted["reconciliationRequired"] = json!(true);
        persisted["dirtyGeneration"] = json!(8);
        persisted["unknownGeneration"] = json!(3);
        persisted["confirmedGeneration"] = Value::Null;
        persisted["status"] = json!("checking");
        let receipt = json!({
            "softwareId":"software-one","dirty":true,"reconciliationRequired":true,
            "dirtyGeneration":8,"unknownGeneration":3,"lastConfirmedUploadedGeneration":7,
            "status":"checking","authorityUnchanged":true,"keepsVersionHistory":true,
        });
        (previous, persisted, receipt)
    }

    #[test]
    fn unknown_current_keeps_historical_baseline_full_scope_and_receipt_provenance() {
        let (previous, persisted, receipt) = unknown_transition_fixture();
        validate_unknown_transition(&previous, &persisted, &receipt, "software-one", Some(7))
            .unwrap();
        assert!(persisted["baseline"].is_object());
        assert_eq!(persisted["baselineFullScope"], true);
        assert!(persisted["captureReceipt"].is_object());
        assert_eq!(persisted["lastConfirmedUploadedGeneration"], 7);
        assert!(persisted["confirmedGeneration"].is_null());
    }

    #[test]
    fn dirty_flags_alone_do_not_invalidate_current_confirmation_or_native_receipt() {
        let (previous, persisted, receipt) = unknown_transition_fixture();
        for (field, invalid) in [
            ("status", json!("saved")),
            ("confirmedGeneration", json!(7)),
            ("unknownGeneration", json!(2)),
            ("dirtyGeneration", json!(7)),
        ] {
            let mut changed = persisted.clone();
            changed[field] = invalid;
            assert!(validate_unknown_transition(
                &previous,
                &changed,
                &receipt,
                "software-one",
                Some(7)
            )
            .is_err());
        }
        let mut current_receipt = persisted.clone();
        current_receipt["captureReceipt"]["scope"]["unknownGeneration"] = json!(3);
        assert!(validate_unknown_transition(
            &previous,
            &current_receipt,
            &receipt,
            "software-one",
            Some(7)
        )
        .is_err());
        let mut lost_history = persisted.clone();
        lost_history["baseline"] = Value::Null;
        assert!(validate_unknown_transition(
            &previous,
            &lost_history,
            &receipt,
            "software-one",
            Some(7)
        )
        .is_err());
        assert!(validate_unknown_transition(
            &previous,
            &persisted,
            &json!({"softwareId":"software-one","dirty":true}),
            "software-one",
            Some(7)
        )
        .is_err());
    }
}
