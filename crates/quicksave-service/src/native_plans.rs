// SPDX-License-Identifier: GPL-3.0-only
//! Native-only signed whole-root batch plans; no keys, sessions or JS authority.
//!
//! # Parent integration API
//!
//! - `WorkspaceOperationSigner::new(WorkspaceStore)` adapts the actual native
//!   device-key MAC, without one vault entry per row. Reads use only
//!   `operation_mac_existing`; validating retained plans never creates a key.
//! - `FrozenNativePlanStore::open(private_path, signer)` stores immutable,
//!   MAC-authenticated root plans and execution/finalization sidecars.
//! - A `FrozenNativePlan` separates `software_id` / `tracker_app_id` from
//!   `canonical_app_id` / `source_identity`; two installations may share the last.
//! - `FrozenCaptureBinding` is written after actual tracker preparation and before
//!   admission. It contains only work/generation/digests, NEVER file inventories.
//!   Its existence prohibits silent recapture after restart.
//!
//! Roots/app instances/provider routing/grants are frozen during preview. File
//! metadata is frozen by the real tracker at each child's first execution inside
//! those exact roots. All large node lists stay in native tracker/source handles.
//! Tests inject MACs and use private temporary directories only.

use crate::{
    boundary as dto,
    interfaces::ServiceTracking,
    operations::{
        CompletionReceipt, FrozenChildPlan, FrozenJobPlan, FrozenPlanSet, FrozenRootBinding,
        OperationBindings, OperationKind, SelectionIntent, StoreSigner, MAX_APPS_PER_PLAN,
        MAX_CONTROL_RECORDS, MAX_JOBS_PER_PLAN, MAX_RETRY_ADMISSIONS, MAX_STORED_PLANS,
    },
};
use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::{ensure_private_directory, verify_private_file, RootIdentity, SafeRoot};
use quicksave_state::WorkspaceStore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

pub const MAX_NATIVE_PLAN_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_NATIVE_SET_BYTES: usize = 32 * 1024 * 1024;
const MAX_SET_HEADER_BYTES: usize = 1024 * 1024;
const MAX_EXECUTION_BYTES: usize = 32 * 1024;
const DOMAIN: &str = "QuickSave/native-batch-sidecars/v1";
const HISTORY_CACHE_BYTES: usize = 16 * 1024 * 1024;
const HISTORY_RECORD_LIMIT: usize =
    MAX_APPS_PER_PLAN * 7 + MAX_RETRY_ADMISSIONS + MAX_CONTROL_RECORDS + MAX_JOBS_PER_PLAN + 16;

/// Actual workspace-bound, purpose-separated device-key MAC. This object never
/// serializes or exposes the device key, provider keys or session credentials.
pub struct WorkspaceOperationSigner {
    store: WorkspaceStore,
}
impl WorkspaceOperationSigner {
    pub fn new(store: WorkspaceStore) -> Self {
        Self { store }
    }
}
impl StoreSigner for WorkspaceOperationSigner {
    fn seal(&self, scope: &Value) -> Result<Value> {
        let mac = self
            .store
            .operation_mac(&canonical(scope, MAX_NATIVE_PLAN_BYTES)?)?;
        Ok(json!({"version":1,"algorithm":"hmac-sha256","mac":hex(&mac)}))
    }
    fn verify(&self, scope: &Value, signature: &Value) -> Result<bool> {
        if signature["version"] != 1 || signature["algorithm"] != "hmac-sha256" {
            return Ok(false);
        }
        let Some(mac) = signature["mac"].as_str().and_then(decode_mac) else {
            return Ok(false);
        };
        let expected = self
            .store
            .operation_mac_existing(&canonical(scope, MAX_NATIVE_PLAN_BYTES)?)?;
        // Fixed-length comparison: no early exit on a matching MAC prefix.
        let mut different = 0u8;
        for (left, right) in expected.iter().zip(mac) {
            different |= *left ^ right;
        }
        Ok(different == 0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenNativePlan {
    pub version: u32,
    pub plan_set_id: Uuid,
    pub native_plan_id: Uuid,
    pub source_id: Uuid,
    pub software_id: String,
    /// Exact installation/tracker identity, never substituted with canonical ID.
    pub tracker_app_id: String,
    pub canonical_app_id: String,
    pub source_identity: Option<Value>,
    pub name: String,
    pub provider_id: String,
    pub provider_scope: Value,
    pub provider_digest: String,
    pub roots: Value,
    pub tracking_grant: Value,
    pub auto_enrollment: Option<Value>,
    pub root_authority_revision: String,
    pub roots_fingerprint: String,
}

impl FrozenNativePlan {
    /// `record` is native state already verified/pinned by the tracker, not a
    /// webview request. This method is structural; the caller MUST verify roots.
    pub fn from_record(plan_set_id: Uuid, provider: &Value, record: &Value) -> Result<Self> {
        let provider_scope = provider_scope(provider)?;
        let provider_id = dto::id(provider, "id")?.to_owned();
        ensure!(
            record["tracked"] == true && record["providerId"] == provider_id,
            "Only tracked software bound to this provider can enter an upload group"
        );
        let software_id = dto::id(record, "id")?.to_owned();
        let tracker_app_id = dto::id(record, "appId")?.to_owned();
        let source_identity = record
            .get("sourceIdentity")
            .filter(|value| !value.is_null())
            .map(source_identity)
            .transpose()?;
        let canonical_app_id = match &source_identity {
            Some(identity) => dto::id(identity, "app_id")?.to_owned(),
            None => tracker_app_id.clone(),
        };
        let roots = authority_roots(record)?;
        let tracking_grant = record
            .get("trackingGrant")
            .filter(|grant| grant.is_object())
            .context("Software has no native authenticated tracking grant")?
            .clone();
        dto::bounded(&tracking_grant, 4096)?;
        non_secret(&tracking_grant)?;
        let auto_enrollment = record
            .get("autoEnrollment")
            .filter(|value| !value.is_null())
            .cloned();
        if let Some(value) = &auto_enrollment {
            non_secret(value)?;
            dto::bounded(value, 128 * 1024)?;
        }
        let root_authority_revision = root_authority_revision(record)?;
        let result = Self {
            version: 1,
            plan_set_id,
            native_plan_id: Uuid::new_v4(),
            source_id: Uuid::new_v4(),
            software_id,
            tracker_app_id,
            canonical_app_id,
            source_identity,
            name: dto::text(record, "name", 512)?.to_owned(),
            provider_digest: fingerprint(&provider_scope)?,
            provider_scope,
            provider_id,
            roots_fingerprint: fingerprint(&roots)?,
            roots,
            tracking_grant,
            auto_enrollment,
            root_authority_revision,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported native batch plan version");
        for (name, value) in [
            ("softwareId", &self.software_id),
            ("appId", &self.tracker_app_id),
            ("sourceAppId", &self.canonical_app_id),
            ("providerId", &self.provider_id),
        ] {
            checked_id(name, value)?;
        }
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 512
                && !self.name.chars().any(char::is_control),
            "Invalid native batch software name"
        );
        if let Some(identity) = &self.source_identity {
            ensure!(
                source_identity(identity)? == *identity
                    && identity["app_id"] == self.canonical_app_id,
                "Original source identity changed"
            );
        } else {
            ensure!(
                self.canonical_app_id == self.tracker_app_id,
                "A missing original identity cannot create another canonical application"
            );
        }
        ensure!(
            self.provider_scope["id"] == self.provider_id
                && fingerprint(&self.provider_scope)? == self.provider_digest,
            "Native batch provider routing binding changed"
        );
        non_secret(&self.provider_scope)?;
        checked_digest(&self.root_authority_revision)?;
        checked_digest(&self.roots_fingerprint)?;
        ensure!(
            self.tracking_grant.is_object(),
            "Native batch tracking grant is missing"
        );
        dto::bounded(&self.tracking_grant, 4096)?;
        non_secret(&self.tracking_grant)?;
        let record = self.registration_record();
        ensure!(
            authority_roots(&record)? == self.roots
                && fingerprint(&self.roots)? == self.roots_fingerprint
                && root_authority_revision(&record)? == self.root_authority_revision,
            "Native batch root/identity/grant binding changed"
        );
        dto::bounded(&serde_json::to_value(self)?, MAX_NATIVE_PLAN_BYTES - 8192)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        fingerprint(&serde_json::to_value(self)?)
    }

    pub fn registration_record(&self) -> Value {
        let mut record = json!({
            "id":self.software_id,"appId":self.tracker_app_id,"name":self.name,
            "providerId":self.provider_id,"tracked":true,"roots":self.roots,
            "trackingGrant":self.tracking_grant,
        });
        if let Some(identity) = &self.source_identity {
            record["sourceIdentity"] = identity.clone();
        }
        if let Some(enrollment) = &self.auto_enrollment {
            record["autoEnrollment"] = enrollment.clone();
        }
        record
    }

    pub fn child(&self) -> Result<FrozenChildPlan> {
        self.validate()?;
        let roots = self
            .roots
            .as_array()
            .context("Frozen native roots missing")?
            .iter()
            .map(|root| {
                Ok(FrozenRootBinding {
                    root_id: dto::id(root, "id")?.to_owned(),
                    identity_digest: fingerprint(&json!({
                        "identity":root["identity"],"role":root["role"],"path":root["path"],
                        "allowedFiles":root["allowedFiles"],"directory":root.get("directory"),
                    }))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FrozenChildPlan {
            source_id: self.source_id,
            native_plan_id: self.native_plan_id,
            native_plan_digest: self.digest()?,
            app_id: self.canonical_app_id.clone(),
            software_id: Some(self.software_id.clone()),
            source_revision: self.root_authority_revision.clone(),
            roots_fingerprint: self.roots_fingerprint.clone(),
            roots,
            mode: Some("complete_application".into()),
            bundle_id: None,
        })
    }

    /// Does not discover apps, recapture files or change today's approved set.
    pub fn verify_snapshot(&self, snapshot: &Value) -> Result<()> {
        self.validate()?;
        let provider = dto::provider_record(snapshot, &self.provider_id)?;
        ensure!(
            fingerprint(&provider_scope(provider)?)? == self.provider_digest
                && provider["status"] != "disconnected",
            "Frozen batch provider configuration changed or was disconnected"
        );
        let record = dto::software_record(snapshot, &self.software_id)?;
        ensure!(
            record["tracked"] == true
                && record["providerId"] == self.provider_id
                && root_authority_revision(record)? == self.root_authority_revision,
            "Frozen batch software instance/root/grant/source identity changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenCaptureBinding {
    pub version: u32,
    pub source_id: Uuid,
    pub native_plan_digest: String,
    pub work_id: String,
    pub generation: u64,
    pub snapshot_identity: String,
    pub metadata_identity: String,
    pub selection_digest: String,
    /// Count of exact frozen native node IDs, not a UI regular-file count.
    pub file_count: usize,
    pub roots_fingerprint: String,
    /// Present only after the ORIGINAL native Tracker owner verifies an empty
    /// full-root snapshot grant. Legacy zero-node sidecars without this digest
    /// remain invalid; a JSON full-scope flag cannot create this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_full_scope_proof_digest: Option<String>,
}
impl FrozenCaptureBinding {
    pub fn from_work(plan: &FrozenNativePlan, work: &Value) -> Result<Self> {
        Self::from_work_inner(plan, work, None)
    }

    /// Native-only constructor. Empty capture is accepted only after the real
    /// tracking port revalidates its original full-scope/baseline grants and
    /// native roots. Never authenticate edited JSON by simply sealing it.
    pub fn from_native_work(
        plan: &FrozenNativePlan,
        work: &Value,
        tracking: &dyn ServiceTracking,
    ) -> Result<Self> {
        if !work["fileIds"].as_array().is_some_and(Vec::is_empty) {
            return Self::from_work(plan, work);
        }
        tracking.pin_scope(&plan.registration_record())?.verify()?;
        let evidence = tracking.call(
            "full_scope_evidence",
            &json!({"workId":dto::id(work,"workId")?}),
        )?;
        dto::bounded(&evidence, dto::MAX_WORK_BYTES)?;
        let proof = &evidence["expectedFullScope"];
        let scope = &proof["scope"];
        ensure!(
            evidence["version"] == 1
                && evidence["fullScope"] == true
                && evidence["completeFileList"] == true
                && evidence["keepsVersionHistory"] == true
                && evidence["coverageScope"] == "approved_evidenced_roots_only"
                && evidence["softwareId"] == plan.software_id
                && evidence["providerId"] == plan.provider_id
                && evidence["workId"] == work["workId"]
                && evidence["generation"] == work["generation"]
                && evidence["metadataIdentity"] == work["captureSource"]["snapshotIdentity"]
                && authority_roots(&evidence)? == plan.roots
                && proof == &work["captureSource"]["expectedFullScope"]
                && proof["grant"].is_object()
                && scope["version"] == 1
                && scope["workId"] == work["workId"]
                && scope["softwareId"] == plan.software_id
                && scope["providerId"] == plan.provider_id
                && scope["generation"] == work["generation"]
                && scope["metadataIdentity"] == evidence["metadataIdentity"]
                && scope["expectedNodeIdsHash"] == fingerprint(&json!([]))?
                && scope["snapshotMode"] == "additive_full_scope"
                && scope["keepsHistory"] == true,
            "Original native empty full-scope grant does not bind this frozen root capture"
        );
        Self::from_work_inner(plan, work, Some(fingerprint(proof)?))
    }

    /// Compare only with an already device-MAC-authenticated capture binding.
    /// Publication still requires the actual native Tracker/source owners.
    pub fn matches_work(&self, plan: &FrozenNativePlan, work: &Value) -> Result<bool> {
        self.validate(plan)?;
        Ok(Self::from_work_inner(plan, work, self.empty_full_scope_proof_digest.clone())? == *self)
    }

    fn from_work_inner(
        plan: &FrozenNativePlan,
        work: &Value,
        empty_proof: Option<String>,
    ) -> Result<Self> {
        dto::bounded(work, dto::MAX_WORK_BYTES)?;
        ensure!(
            work["softwareId"] == plan.software_id
                && work["providerId"] == plan.provider_id
                && work["appId"] == plan.tracker_app_id
                && authority_roots(work)? == plan.roots,
            "Actual tracker work widened or changed its frozen batch roots/instance"
        );
        ensure!(
            work.get("sourceIdentity")
                .filter(|identity| !identity.is_null())
                == plan.source_identity.as_ref(),
            "Actual tracker canonical source identity changed"
        );
        ensure!(
            work["captureSource"]["stage"] == "awaiting_native_capture_receipt"
                && work["captureSource"]["selectionKind"] == "full_scope",
            "Batch uploads require the actual whole-approved-scope native capture/receipt pipeline"
        );
        let ids = work["fileIds"]
            .as_array()
            .context("Actual tracker file selection missing")?;
        ensure!(
            ids.len() <= 250_000 && (!ids.is_empty() || empty_proof.is_some()),
            "Empty native capture requires original verified full-scope authority"
        );
        if let Some(proof) = &empty_proof {
            ensure!(
                ids.is_empty()
                    && work["captureSource"]["expectedFullScope"]["grant"].is_object()
                    && fingerprint(&work["captureSource"]["expectedFullScope"])? == *proof,
                "An empty native capture changed its authenticated full-scope proof"
            );
        }
        let mut previous: Option<&str> = None;
        for value in ids {
            let id = value
                .as_str()
                .context("Native capture node ID is not text")?;
            ensure!(
                !id.is_empty()
                    && id.len() <= 512
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-@".contains(&byte))
                    && previous.is_none_or(|previous| previous < id),
                "Native capture requires sorted, unique exact logical node IDs"
            );
            previous = Some(id);
        }
        let result = Self {
            version: 1,
            source_id: plan.source_id,
            native_plan_digest: plan.digest()?,
            work_id: dto::id(work, "workId")?.to_owned(),
            generation: work["generation"]
                .as_u64()
                .context("Actual capture generation missing")?,
            snapshot_identity: dto::text(&work["captureSource"], "snapshotIdentity", 512)?
                .to_owned(),
            metadata_identity: dto::text(
                &work["captureSource"]["metadataSelection"],
                "metadataIdentity",
                512,
            )?
            .to_owned(),
            selection_digest: fingerprint(&work["fileIds"])?,
            file_count: ids.len(),
            roots_fingerprint: plan.roots_fingerprint.clone(),
            empty_full_scope_proof_digest: empty_proof,
        };
        result.validate(plan)?;
        Ok(result)
    }
    pub fn validate(&self, plan: &FrozenNativePlan) -> Result<()> {
        ensure!(
            self.version == 1
                && self.source_id == plan.source_id
                && self.native_plan_digest == plan.digest()?
                && self.roots_fingerprint == plan.roots_fingerprint
                && (self.file_count > 0 || self.empty_full_scope_proof_digest.is_some())
                && self.file_count <= 250_000,
            "Frozen capture belongs to another native batch child"
        );
        checked_id("workId", &self.work_id)?;
        for value in [&self.snapshot_identity, &self.metadata_identity] {
            ensure!(
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
                "Invalid frozen native capture identity"
            );
        }
        checked_digest(&self.selection_digest)?;
        if let Some(proof) = &self.empty_full_scope_proof_digest {
            checked_digest(proof)?;
            ensure!(
                self.file_count == 0 && self.selection_digest == fingerprint(&json!([]))?,
                "Native empty full-scope proof changed its exact empty selection"
            );
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        fingerprint(&serde_json::to_value(self)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedNativeChild {
    pub source_id: Uuid,
    pub native_plan_digest: String,
    pub capture_digest: String,
    pub source_proof_digest: String,
    pub tracker_receipt_digest: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSetAdmission {
    pub plan_set_id: Uuid,
    pub root_digest: String,
    pub provider_digest: String,
    pub started_at: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationGapKind {
    MissingOriginalWork,
    SourceAuthentication,
    TrackerFinalization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciliationGap {
    pub source_id: Uuid,
    pub native_plan_digest: String,
    pub kind: ReconciliationGapKind,
    pub baseline_marked_dirty: bool,
    pub source_known_drained: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeReference {
    id: Uuid,
    source_id: Uuid,
    digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeRootSummary {
    count: usize,
    roles: BTreeMap<String, usize>,
    canonical_app_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeSetHeader {
    version: u32,
    plan_set_id: Uuid,
    provider_id: String,
    authority_digest: String,
    created_at: String,
    intent: SelectionIntent,
    plans: Vec<NativeReference>,
    sample_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_summary: Option<NativeRootSummary>,
}

struct CachedSetHeader {
    header: NativeSetHeader,
    stamp: quicksave_platform::FileStamp,
    references: BTreeMap<Uuid, NativeReference>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    scope: Value,
    signature: Value,
}

/// Native-only ownership keys derived from the authenticated frozen ledger.
/// They authorize no upload/retry and are not deserializable from a UI request.
#[derive(Clone, Debug)]
pub struct NativeHistoryChild {
    pub source_id: Uuid,
    pub app_id: String,
    pub software_id: Option<String>,
    pub native_plan_id: Uuid,
    pub native_plan_digest: String,
    pub roots_fingerprint: String,
    pub frozen_child_digest: String,
    pub completed: bool,
    pub captured: bool,
}

#[derive(Clone, Debug)]
pub struct NativeHistoryMetadata {
    pub plan_set_id: Uuid,
    pub provider_id: String,
    pub root_digest: String,
    pub created_at: String,
    pub admitted_at: Option<String>,
    pub job_count: usize,
    pub selection: SelectionIntent,
    pub children: Vec<NativeHistoryChild>,
    pub completed: usize,
    pub captured: usize,
    pub awaiting_finalization: usize,
    pub reconciliation_gaps: usize,
    pub settled_reconciliation_gaps: usize,
    pub cancel_requested: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct HistoryFrame {
    native_root: quicksave_platform::FileStamp,
    ledger_root: quicksave_platform::FileStamp,
    native: BTreeMap<String, quicksave_platform::FileStamp>,
    ledger: BTreeMap<String, quicksave_platform::FileStamp>,
}
struct CachedHistory {
    frame: HistoryFrame,
    metadata: NativeHistoryMetadata,
    captures: BTreeMap<Uuid, (String, u64)>,
    finalizations: BTreeMap<Uuid, FinalizedNativeChild>,
    completions: BTreeMap<Uuid, CompletionReceipt>,
    gaps: BTreeSet<Uuid>,
    settled_gaps: BTreeSet<Uuid>,
    controls: BTreeMap<usize, HistoryControl>,
    provider_digest: String,
    job_references: Value,
    retry_admissions: Vec<(usize, Uuid)>,
}
struct HistoryReader {
    ledger_path: PathBuf,
    ledger_root: SafeRoot,
    cache: BTreeMap<Uuid, CachedHistory>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryControl {
    sequence: usize,
    previous_digest: String,
    desired: String,
    retry_source_ids: Vec<Uuid>,
}

pub struct FrozenNativePlanStore {
    path: PathBuf,
    root: SafeRoot,
    signer: Arc<dyn StoreSigner>,
    gate: Mutex<()>,
    failed: AtomicBool,
    roots: Mutex<BTreeMap<Uuid, RootIdentity>>,
    headers: Mutex<BTreeMap<Uuid, Arc<CachedSetHeader>>>,
    history: Mutex<Option<HistoryReader>>,
    #[cfg(unix)]
    lock: File,
    #[cfg(unix)]
    lock_stamp: quicksave_platform::FileStamp,
    #[cfg(windows)]
    lock: quicksave_platform::PrivateLock,
}

impl FrozenNativePlanStore {
    pub fn open(path: &Path, signer: Arc<dyn StoreSigner>) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "Private batch plan directory must be absolute"
        );
        ensure_private_directory(path)?;
        let root = SafeRoot::open(path)?;
        flush_root(path, &root)?;
        #[cfg(unix)]
        let (lock, lock_stamp) = {
            match root.read_file("native-plans.lock") {
                Ok((file, _)) => verify_private_file(&file)?,
                Err(error) if missing(&error) => root.write_new("native-plans.lock", |_| Ok(()))?,
                Err(error) => return Err(error),
            }
            let (file, stamp) = root.read_file("native-plans.lock")?;
            verify_private_file(&file)?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
            root.verify_file("native-plans.lock", &stamp)?;
            (file, stamp)
        };
        #[cfg(windows)]
        let lock = quicksave_platform::PrivateDirectory::open(path)?.lock("native-plans.lock")?;
        #[cfg(not(any(unix, windows)))]
        bail!("Private native batch plans are unsupported on this platform");
        Ok(Self {
            path: path.to_owned(),
            root,
            signer,
            gate: Mutex::new(()),
            failed: AtomicBool::new(false),
            roots: Mutex::new(BTreeMap::new()),
            headers: Mutex::new(BTreeMap::new()),
            history: Mutex::new(None),
            #[cfg(any(unix, windows))]
            lock,
            #[cfg(unix)]
            lock_stamp,
        })
    }

    /// Bind the actual operation-store directory explicitly. Never guess a
    /// sibling path or accept a root digest from a webview as a verified frame.
    /// Construction performs no MAC/vault lookup, including for an empty store.
    pub fn attach_history_ledger(&self, path: &Path) -> Result<()> {
        ensure_private_directory(path)?;
        let root = SafeRoot::open(path)?;
        let mut history = self
            .history
            .lock()
            .map_err(|_| anyhow::anyhow!("Native history metadata lock failed"))?;
        if let Some(existing) = history.as_ref() {
            ensure!(
                existing.ledger_root.same_root(&root)?,
                "Native history cannot replace its original operation-store root"
            );
        } else {
            *history = Some(HistoryReader {
                ledger_path: path.to_owned(),
                ledger_root: root,
                cache: BTreeMap::new(),
            });
        }
        Ok(())
    }

    /// Incremental, read-only private-journal metadata. Existing files are
    /// immutable: changed/deleted stamps are errors, never permission to keep a
    /// stale successful projection. New records alone require another MAC read.
    /// No software roots, file inventories, source DB rows or providers are read.
    pub fn history_metadata(
        &self,
        ledger: &OperationBindings,
        id: Uuid,
    ) -> Result<NativeHistoryMetadata> {
        let mut history = self
            .history
            .lock()
            .map_err(|_| anyhow::anyhow!("Native history metadata lock failed"))?;
        let reader = history
            .as_mut()
            .context("The actual native history ledger root is not installed")?;
        let native = self.set_root(id)?;
        let ledger_handle = reader
            .ledger_root
            .open_directory(&format!("operation-{id}"))?;
        let operation = SafeRoot::open(&reader.ledger_path.join(format!("operation-{id}")))?;
        let anchored = history_file_stamp(&ledger_handle)?;
        let actual = history_root_stamp(&operation)?;
        ensure!(
            anchored.device == actual.device && anchored.file_id == actual.file_id,
            "Native history frame opened a different operation directory"
        );
        reader.ledger_root.identity()?;
        let frame = history_frame(&native, &operation)?;
        let previous = reader.cache.remove(&id);
        let mut cached = if let Some(cached) = previous {
            ensure!(
                cached.frame.native_root.device == frame.native_root.device
                    && cached.frame.native_root.file_id == frame.native_root.file_id
                    && cached.frame.ledger_root.device == frame.ledger_root.device
                    && cached.frame.ledger_root.file_id == frame.ledger_root.file_id,
                "Native history frame directory identity changed"
            );
            history_unchanged(&cached.frame.native, &frame.native)?;
            history_unchanged(&cached.frame.ledger, &frame.ledger)?;
            if cached.frame == frame {
                let metadata = cached.metadata.clone();
                reader.cache.insert(id, cached);
                return Ok(metadata);
            }
            cached
        } else {
            let parent = ledger.load(id)?;
            let header = self.header(&native, id)?;
            let expected_authority = fingerprint(&json!({
                "provider":parent.provider_scope,
                "children":parent.children().map(|child|json!({
                    "sourceId":child.source_id,"nativePlanId":child.native_plan_id,
                    "digest":child.native_plan_digest,
                })).collect::<Vec<_>>(),
            }))?;
            ensure!(
                parent.kind == OperationKind::Upload
                    && parent.operation_id == id
                    && header.header.provider_id == parent.provider_id
                    && header.header.created_at == parent.created_at
                    && header.header.intent == parent.intent
                    && header.header.authority_digest == parent.authority_revision
                    && expected_authority == parent.authority_revision
                    && header.references.len() == parent.child_count()
                    && parent.children().all(|child| header
                        .references
                        .get(&child.native_plan_id)
                        .is_some_and(|reference| reference.source_id == child.source_id
                            && reference.digest == child.native_plan_digest)),
                "Native history frame is not bound to the original signed ledger/root digest"
            );
            chrono::DateTime::parse_from_rfc3339(&parent.created_at)?;
            for child in parent.children() {
                self.plan(id, child)?;
            }
            let children = parent
                .children()
                .map(|child| {
                    Ok(NativeHistoryChild {
                        source_id: child.source_id,
                        app_id: child.app_id.clone(),
                        software_id: child.software_id.clone(),
                        native_plan_id: child.native_plan_id,
                        native_plan_digest: child.native_plan_digest.clone(),
                        roots_fingerprint: child.roots_fingerprint.clone(),
                        frozen_child_digest: fingerprint(&serde_json::to_value(child)?)?,
                        completed: false,
                        captured: false,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let job_references = parent
                .jobs
                .iter()
                .map(|job| {
                    Ok(json!({
                        "jobId":job.job_id,
                        "digest":blake3::hash(&serde_json::to_vec(job)?).to_hex().to_string(),
                        "children":job.children.len(),
                    }))
                })
                .collect::<Result<Vec<Value>>>()?;
            CachedHistory {
                frame: HistoryFrame {
                    native_root: frame.native_root.clone(),
                    ledger_root: frame.ledger_root.clone(),
                    native: BTreeMap::new(),
                    ledger: BTreeMap::new(),
                },
                metadata: NativeHistoryMetadata {
                    plan_set_id: id,
                    provider_id: parent.provider_id.clone(),
                    root_digest: parent.authority_revision.clone(),
                    created_at: parent.created_at.clone(),
                    admitted_at: None,
                    job_count: parent.jobs.len(),
                    selection: parent.intent,
                    children,
                    completed: 0,
                    captured: 0,
                    awaiting_finalization: 0,
                    reconciliation_gaps: 0,
                    settled_reconciliation_gaps: 0,
                    cancel_requested: false,
                },
                captures: BTreeMap::new(),
                finalizations: BTreeMap::new(),
                completions: BTreeMap::new(),
                gaps: BTreeSet::new(),
                settled_gaps: BTreeSet::new(),
                controls: BTreeMap::new(),
                provider_digest: parent.provider_scope.clone(),
                retry_admissions: Vec::new(),
                job_references: Value::Array(job_references),
            }
        };
        let new_native = frame
            .native
            .keys()
            .filter(|name| !cached.frame.native.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();
        let new_ledger = frame
            .ledger
            .keys()
            .filter(|name| !cached.frame.ledger.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();
        for name in &new_native {
            self.history_native_record(&native, id, name, &mut cached)?;
        }
        for name in &new_ledger {
            let (kind, payload) = self.history_ledger_record(&operation, id, name)?;
            history_ledger_payload(name, &kind, payload, &mut cached)?;
        }
        history_finish(&mut cached)?;
        ensure!(
            history_frame(&native, &operation)? == frame,
            "Native history metadata changed during verification; retry the read-only query"
        );
        cached.frame = frame;
        let metadata = cached.metadata.clone();
        let bytes = history_cache_size(&cached);
        while !reader.cache.is_empty()
            && reader
                .cache
                .values()
                .map(history_cache_size)
                .sum::<usize>()
                .saturating_add(bytes)
                > HISTORY_CACHE_BYTES
        {
            let old = *reader.cache.keys().next().unwrap();
            reader.cache.remove(&old);
        }
        if bytes <= HISTORY_CACHE_BYTES {
            reader.cache.insert(id, cached);
        }
        Ok(metadata)
    }

    fn history_native_record(
        &self,
        root: &SafeRoot,
        id: Uuid,
        name: &str,
        cached: &mut CachedHistory,
    ) -> Result<()> {
        let kind = if name == "set.json" {
            "set"
        } else if name == "admitted.json" {
            "admission"
        } else if name.starts_with("plan-") {
            "plan"
        } else if name.starts_with("capture-") {
            "capture"
        } else if name.starts_with("finalized-") {
            "finalized"
        } else if name.starts_with("gap-") {
            "gap"
        } else {
            bail!("Unknown record in the native batch history journal");
        };
        let payload: Value = self
            .read(root, name, id, kind, MAX_NATIVE_PLAN_BYTES)?
            .context("A native history journal record disappeared")?;
        match kind {
            "set" => {}
            "admission" => {
                let admission: NativeSetAdmission = serde_json::from_value(payload)?;
                ensure!(
                    admission.plan_set_id == id
                        && admission.root_digest == cached.metadata.root_digest
                        && admission.provider_digest == cached.provider_digest,
                    "Native history admission changed its original ledger/root/provider scope"
                );
                chrono::DateTime::parse_from_rfc3339(&admission.started_at)?;
                cached.metadata.admitted_at = Some(admission.started_at);
            }
            "plan" => {
                let plan: FrozenNativePlan = serde_json::from_value(payload)?;
                let child = cached
                    .metadata
                    .children
                    .iter()
                    .find(|child| child.source_id == plan.source_id)
                    .context("Native history plan added an unapproved source child")?;
                ensure!(
                    name == format!("plan-{}.json", child.native_plan_id)
                        && plan.plan_set_id == id
                        && plan.native_plan_id == child.native_plan_id
                        && plan.digest()? == child.native_plan_digest,
                    "Native history plan differs from its original signed child"
                );
            }
            "capture" => {
                let capture: FrozenCaptureBinding = serde_json::from_value(payload)?;
                let child = cached
                    .metadata
                    .children
                    .iter()
                    .find(|child| child.source_id == capture.source_id)
                    .context("Native history capture added an unapproved source child")?;
                ensure!(
                    capture.version == 1
                        && name == format!("capture-{}.json", child.source_id)
                        && capture.native_plan_digest == child.native_plan_digest
                        && capture.roots_fingerprint == child.roots_fingerprint
                        && capture.file_count <= 250_000
                        && (capture.file_count > 0
                            || capture.empty_full_scope_proof_digest.is_some()),
                    "Native history capture changed its original child/root binding"
                );
                checked_digest(&capture.selection_digest)?;
                if let Some(proof) = &capture.empty_full_scope_proof_digest {
                    checked_digest(proof)?;
                    ensure!(
                        capture.file_count == 0
                            && capture.selection_digest == fingerprint(&json!([]))?,
                        "Native history empty snapshot lost its original native proof"
                    );
                }
                cached
                    .captures
                    .insert(child.source_id, (capture.digest()?, capture.generation));
            }
            "finalized" => {
                let proof: FinalizedNativeChild = serde_json::from_value(payload)?;
                let child = cached
                    .metadata
                    .children
                    .iter()
                    .find(|child| child.source_id == proof.source_id)
                    .context("Native history finalization added an unapproved child")?;
                ensure!(
                    name == format!("finalized-{}.json", child.source_id)
                        && proof.native_plan_digest == child.native_plan_digest,
                    "Native history finalization changed its original source/plan"
                );
                for digest in [
                    &proof.capture_digest,
                    &proof.source_proof_digest,
                    &proof.tracker_receipt_digest,
                ] {
                    checked_digest(digest)?;
                }
                cached.finalizations.insert(child.source_id, proof);
            }
            "gap" => {
                let gap: ReconciliationGap = serde_json::from_value(payload)?;
                let child = cached
                    .metadata
                    .children
                    .iter()
                    .find(|child| child.source_id == gap.source_id)
                    .context("Native history gap added an unapproved child")?;
                ensure!(
                    gap.native_plan_digest == child.native_plan_digest
                        && (name == format!("gap-{}-{:?}.json", child.source_id, gap.kind)
                            || name == format!("gap-settled-{}.json", child.source_id)
                                && gap.baseline_marked_dirty
                                && gap.source_known_drained),
                    "Native history gap changed its original source/plan"
                );
                cached.gaps.insert(child.source_id);
                if gap.baseline_marked_dirty && gap.source_known_drained {
                    cached.settled_gaps.insert(child.source_id);
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn history_ledger_record(
        &self,
        root: &SafeRoot,
        id: Uuid,
        name: &str,
    ) -> Result<(String, Value)> {
        // Read the ACTUAL operations.rs SignedRecord/signing_scope wire format,
        // with that store's existing device-MAC verifier, never a JSON flag.
        const LEDGER_DOMAIN: &str = "quicksave-private-operation-bindings-v1";
        let (mut file, stamp) = root.read_file(name)?;
        verify_private_file(&file)?;
        ensure!(
            stamp.size <= MAX_NATIVE_PLAN_BYTES as u64,
            "Native history ledger record exceeds its bound"
        );
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_NATIVE_PLAN_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_NATIVE_PLAN_BYTES,
            "Native history ledger record exceeds its bound"
        );
        root.verify_file(name, &stamp)?;
        let record: Envelope = serde_json::from_slice(&bytes)
            .context("Native operation history journal is corrupt")?;
        dto::bounded(&record.scope, MAX_NATIVE_PLAN_BYTES)?;
        let scope = &record.scope;
        ensure!(
            scope["domain"] == LEDGER_DOMAIN
                && scope["operationId"] == id.to_string()
                && scope["recordName"] == name
                && scope.as_object().is_some_and(|scope| scope.len() == 5),
            "Native operation history journal changed its original domain/identity"
        );
        signature_envelope(&record.signature)?;
        let signing = json!({
            "domain":LEDGER_DOMAIN,"operationId":scope["operationId"],
            "recordType":scope["recordType"],"recordName":scope["recordName"],
            "contentDigest":blake3::hash(&serde_json::to_vec(scope)?).to_hex().to_string(),
        });
        ensure!(
            self.signer.verify(&signing, &record.signature)?,
            "Native operation history journal authentication failed"
        );
        let kind = dto::text(scope, "recordType", 32)?.to_owned();
        Ok((kind, scope["payload"].clone()))
    }

    pub fn freeze(
        &self,
        id: Uuid,
        provider_id: &str,
        intent: SelectionIntent,
        plans: &[FrozenNativePlan],
    ) -> Result<FrozenPlanSet> {
        ensure!(
            !plans.is_empty() && plans.len() <= MAX_APPS_PER_PLAN,
            "Select 1–4096 native software instances"
        );
        checked_id("providerId", provider_id)?;
        let children = plans
            .iter()
            .map(FrozenNativePlan::child)
            .collect::<Result<Vec<_>>>()?;
        let provider_digest = plans[0].provider_digest.clone();
        let mut instances = BTreeSet::new();
        let mut native_ids = BTreeSet::new();
        let mut bytes = 0usize;
        let mut root_count = 0usize;
        let mut root_roles = BTreeMap::<String, usize>::new();
        let mut canonical_apps = BTreeSet::new();
        for plan in plans {
            plan.validate()?;
            ensure!(
                plan.plan_set_id == id
                    && plan.provider_id == provider_id
                    && plan.provider_digest == provider_digest
                    && instances.insert(&plan.software_id)
                    && native_ids.insert(plan.native_plan_id),
                "Duplicate or cross-provider native batch scope"
            );
            bytes = bytes
                .checked_add(canonical(&serde_json::to_value(plan)?, MAX_NATIVE_PLAN_BYTES)?.len())
                .context("Native plan-set size overflow")?;
            ensure!(
                bytes <= MAX_NATIVE_SET_BYTES,
                "Native batch root plans exceed their 32 MiB bound"
            );
            canonical_apps.insert(&plan.canonical_app_id);
            for root in plan
                .roots
                .as_array()
                .context("Native root summary is unavailable")?
            {
                let role = match root["role"].as_str() {
                    Some(role @ ("installation" | "save" | "config" | "runtime")) => role,
                    None => "unclassified",
                    _ => "other",
                };
                root_count += 1;
                *root_roles.entry(role.to_owned()).or_default() += 1;
            }
        }
        let authority_digest = fingerprint(&json!({
            "provider":provider_digest,
            "children":children.iter().map(|child| json!({
                "sourceId":child.source_id,"nativePlanId":child.native_plan_id,
                "digest":child.native_plan_digest,
            })).collect::<Vec<_>>(),
        }))?;
        let ledger = FrozenPlanSet::from_children(
            id,
            OperationKind::Upload,
            intent,
            provider_id.to_owned(),
            provider_digest,
            authority_digest.clone(),
            children,
        )?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        self.check()?;
        ensure!(
            self.ids_locked()?.len() < MAX_STORED_PLANS,
            "The 64-plan native batch store is full; no history was deleted"
        );
        self.root.create_dir(&format!("set-{id}"))?;
        let root = self.set_root(id)?;
        ensure!(
            self.read::<NativeSetHeader>(&root, "set.json", id, "set", MAX_SET_HEADER_BYTES)?
                .is_none(),
            "This native batch plan-set ID is already frozen"
        );
        for plan in plans {
            self.write(
                &root,
                &format!("plan-{}.json", plan.native_plan_id),
                id,
                "plan",
                plan,
                MAX_NATIVE_PLAN_BYTES,
            )?;
        }
        let header = NativeSetHeader {
            version: 1,
            plan_set_id: id,
            provider_id: provider_id.to_owned(),
            authority_digest,
            created_at: ledger.created_at.clone(),
            intent,
            plans: plans
                .iter()
                .map(|plan| {
                    Ok(NativeReference {
                        id: plan.native_plan_id,
                        source_id: plan.source_id,
                        digest: plan.digest()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            sample_names: plans
                .iter()
                .take(16)
                .map(|plan| plan.name.clone())
                .collect(),
            root_summary: Some(NativeRootSummary {
                count: root_count,
                roles: root_roles,
                canonical_app_count: canonical_apps.len(),
            }),
        };
        self.write(&root, "set.json", id, "set", &header, MAX_SET_HEADER_BYTES)?;
        Ok(ledger)
    }

    pub fn plan(&self, set: Uuid, child: &FrozenChildPlan) -> Result<FrozenNativePlan> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(set)?;
        let header = self.header(&root, set)?;
        ensure!(
            header
                .references
                .get(&child.native_plan_id)
                .is_some_and(|reference| reference.source_id == child.source_id
                    && reference.digest == child.native_plan_digest),
            "Native child is not in the approved exact plan set"
        );
        let plan: FrozenNativePlan = self
            .read(
                &root,
                &format!("plan-{}.json", child.native_plan_id),
                set,
                "plan",
                MAX_NATIVE_PLAN_BYTES,
            )?
            .context("Native frozen root plan is missing")?;
        plan.validate()?;
        ensure!(
            plan.plan_set_id == set && plan.child()? == *child,
            "Native child differs from its signed root plan"
        );
        Ok(plan)
    }

    pub fn summary(&self, id: Uuid) -> Result<Value> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(id)?;
        let cached = self.header(&root, id)?;
        let header = &cached.header;
        ensure!(
            header.version == 1
                && header.plan_set_id == id
                && !header.plans.is_empty()
                && header.plans.len() <= MAX_APPS_PER_PLAN
                && header.sample_names.len() <= 16,
            "Native batch summary is corrupt"
        );
        Ok(json!({
            "planSetId":id,"providerId":header.provider_id,"softwareCount":header.plans.len(),
            "appCount":header.plans.len(),
            "canonicalAppCount":header.root_summary.as_ref().map(|summary|summary.canonical_app_count),
            "rootCount":header.root_summary.as_ref().map(|summary|summary.count),
            "rootRoles":header.root_summary.as_ref().map(|summary|&summary.roles),
            "jobCount":header.plans.len().div_ceil(128),"rootDigest":header.authority_digest,
            "createdAt":header.created_at,"selection":header.intent,"sampleNames":header.sample_names,
            "fileCount":Value::Null,"logicalBytes":Value::Null,"keepsLocalData":true,
            "fileCapture":"at_each_child_first_execution",
            "selectionFrozen":"software_instances_source_identities_and_exact_approved_roots",
        }))
    }

    pub fn admission(&self, id: Uuid) -> Result<Option<NativeSetAdmission>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(id)?;
        let result: Option<NativeSetAdmission> =
            self.read(&root, "admitted.json", id, "admission", MAX_EXECUTION_BYTES)?;
        if let Some(result) = &result {
            let header = self.header(&root, id)?;
            ensure!(
                result.plan_set_id == id && result.root_digest == header.header.authority_digest,
                "Native group admission changed its approved root scope"
            );
            checked_digest(&result.provider_digest)?;
            chrono::DateTime::parse_from_rfc3339(&result.started_at)?;
        }
        Ok(result)
    }
    /// Native gateway calls this only AFTER exact upload_all consent. A preview
    /// and its signed root plans are not by themselves cloud-write admission.
    pub fn admit(&self, parent: &FrozenPlanSet) -> Result<()> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let id = parent.operation_id;
        let root = self.set_root(id)?;
        let header = self.header(&root, id)?;
        ensure!(
            header.header.authority_digest == parent.authority_revision,
            "Approved native group root digest differs from its ledger"
        );
        if let Some(existing) = self.read::<NativeSetAdmission>(
            &root,
            "admitted.json",
            id,
            "admission",
            MAX_EXECUTION_BYTES,
        )? {
            ensure!(
                existing.root_digest == parent.authority_revision
                    && existing.provider_digest == parent.provider_scope,
                "Native group cannot replace its original admission"
            );
            return Ok(());
        }
        self.write(
            &root,
            "admitted.json",
            id,
            "admission",
            &NativeSetAdmission {
                plan_set_id: id,
                root_digest: parent.authority_revision.clone(),
                provider_digest: parent.provider_scope.clone(),
                started_at: chrono::Utc::now().to_rfc3339(),
            },
            MAX_EXECUTION_BYTES,
        )
    }

    pub fn capture(&self, plan: &FrozenNativePlan) -> Result<Option<FrozenCaptureBinding>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        let result: Option<FrozenCaptureBinding> = self.read(
            &root,
            &format!("capture-{}.json", plan.source_id),
            plan.plan_set_id,
            "capture",
            MAX_EXECUTION_BYTES,
        )?;
        if let Some(capture) = &result {
            capture.validate(plan)?;
        }
        Ok(result)
    }
    pub fn bind_capture(
        &self,
        plan: &FrozenNativePlan,
        capture: &FrozenCaptureBinding,
    ) -> Result<()> {
        capture.validate(plan)?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        let name = format!("capture-{}.json", plan.source_id);
        if let Some(existing) = self.read::<FrozenCaptureBinding>(
            &root,
            &name,
            plan.plan_set_id,
            "capture",
            MAX_EXECUTION_BYTES,
        )? {
            ensure!(
                &existing == capture,
                "An executed source child cannot be recaptured or widened"
            );
            return Ok(());
        }
        self.write(
            &root,
            &name,
            plan.plan_set_id,
            "capture",
            capture,
            MAX_EXECUTION_BYTES,
        )
    }
    pub fn finalization(&self, plan: &FrozenNativePlan) -> Result<Option<FinalizedNativeChild>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        let result: Option<FinalizedNativeChild> = self.read(
            &root,
            &format!("finalized-{}.json", plan.source_id),
            plan.plan_set_id,
            "finalized",
            MAX_EXECUTION_BYTES,
        )?;
        if let Some(result) = &result {
            ensure!(
                result.source_id == plan.source_id && result.native_plan_digest == plan.digest()?,
                "Tracker finalization belongs to another native source child"
            );
            for digest in [
                &result.capture_digest,
                &result.source_proof_digest,
                &result.tracker_receipt_digest,
            ] {
                checked_digest(digest)?;
            }
        }
        Ok(result)
    }
    pub fn finalize(&self, plan: &FrozenNativePlan, proof: &FinalizedNativeChild) -> Result<()> {
        ensure!(
            proof.source_id == plan.source_id && proof.native_plan_digest == plan.digest()?,
            "Native tracker finalization scope changed"
        );
        for digest in [
            &proof.capture_digest,
            &proof.source_proof_digest,
            &proof.tracker_receipt_digest,
        ] {
            checked_digest(digest)?;
        }
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        let name = format!("finalized-{}.json", plan.source_id);
        if let Some(existing) = self.read::<FinalizedNativeChild>(
            &root,
            &name,
            plan.plan_set_id,
            "finalized",
            MAX_EXECUTION_BYTES,
        )? {
            ensure!(&existing == proof, "Native finalization receipt changed");
            return Ok(());
        }
        self.write(
            &root,
            &name,
            plan.plan_set_id,
            "finalized",
            proof,
            MAX_EXECUTION_BYTES,
        )
    }
    pub fn record_gap(&self, plan: &FrozenNativePlan, gap: &ReconciliationGap) -> Result<()> {
        ensure!(
            gap.source_id == plan.source_id && gap.native_plan_digest == plan.digest()?,
            "Native reconciliation gap belongs to another source child"
        );
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        // A later real dirty-state acknowledgement plus exact source draining
        // is an ADDITIVE record, never an overwrite of an unresolved gap.
        let name = if gap.baseline_marked_dirty && gap.source_known_drained {
            format!("gap-settled-{}.json", plan.source_id)
        } else {
            format!("gap-{}-{:?}.json", plan.source_id, gap.kind)
        };
        if let Some(existing) = self.read::<ReconciliationGap>(
            &root,
            &name,
            plan.plan_set_id,
            "gap",
            MAX_EXECUTION_BYTES,
        )? {
            ensure!(
                existing.source_id == gap.source_id
                    && existing.native_plan_digest == gap.native_plan_digest
                    && (!(gap.baseline_marked_dirty && gap.source_known_drained)
                        || existing.baseline_marked_dirty && existing.source_known_drained),
                "Native reconciliation gap identity changed"
            );
            return Ok(());
        }
        self.write(
            &root,
            &name,
            plan.plan_set_id,
            "gap",
            gap,
            MAX_EXECUTION_BYTES,
        )
    }

    /// Read-only, fixed-size recovery reporting. No tracker call, provider
    /// access or replacement work is necessary to display an original-work gap.
    pub fn reconciliation(&self, plan: &FrozenNativePlan) -> Result<Option<ReconciliationGap>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan store lock failed"))?;
        let root = self.set_root(plan.plan_set_id)?;
        let names = [
            format!("gap-settled-{}.json", plan.source_id),
            format!(
                "gap-{}-{:?}.json",
                plan.source_id,
                ReconciliationGapKind::MissingOriginalWork
            ),
            format!(
                "gap-{}-{:?}.json",
                plan.source_id,
                ReconciliationGapKind::SourceAuthentication
            ),
            format!(
                "gap-{}-{:?}.json",
                plan.source_id,
                ReconciliationGapKind::TrackerFinalization
            ),
        ];
        for (index, name) in names.iter().enumerate() {
            if let Some(gap) = self.read::<ReconciliationGap>(
                &root,
                name,
                plan.plan_set_id,
                "gap",
                MAX_EXECUTION_BYTES,
            )? {
                ensure!(
                    gap.source_id == plan.source_id
                        && gap.native_plan_digest == plan.digest()?
                        && (index != 0 || gap.baseline_marked_dirty && gap.source_known_drained),
                    "Native reconciliation record changed its original child identity"
                );
                return Ok(Some(gap));
            }
        }
        Ok(None)
    }

    fn ids_locked(&self) -> Result<Vec<Uuid>> {
        let mut result = BTreeSet::new();
        for entry in self.root.entries()? {
            if entry.is_directory && !entry.relative_path.contains('/') {
                let raw = entry
                    .relative_path
                    .strip_prefix("set-")
                    .context("Unknown native batch plan directory")?;
                let id = Uuid::parse_str(raw)?;
                ensure!(id.to_string() == raw, "Noncanonical native plan set ID");
                result.insert(id);
            }
        }
        ensure!(
            result.len() <= MAX_STORED_PLANS,
            "Native plan history exceeds its bound"
        );
        Ok(result.into_iter().collect())
    }
    fn header(&self, root: &SafeRoot, id: Uuid) -> Result<Arc<CachedSetHeader>> {
        let mut headers = self
            .headers
            .lock()
            .map_err(|_| anyhow::anyhow!("Native header cache lock failed"))?;
        if let Some(cached) = headers.get(&id) {
            // Immutable authenticated metadata only. A 4096-child header is
            // never reparsed for every individual child's status poll.
            root.verify_file("set.json", &cached.stamp)?;
            return Ok(cached.clone());
        }
        let (file, stamp) = root.read_file("set.json")?;
        verify_private_file(&file)?;
        let header: NativeSetHeader = self
            .read(root, "set.json", id, "set", MAX_SET_HEADER_BYTES)?
            .context("Native plan set has no committed authenticated header")?;
        root.verify_file("set.json", &stamp)?;
        ensure!(
            header.version == 1
                && header.plan_set_id == id
                && !header.plans.is_empty()
                && header.plans.len() <= MAX_APPS_PER_PLAN,
            "Native batch header bounds changed"
        );
        if let Some(summary) = &header.root_summary {
            let mut total = 0usize;
            for (role, count) in &summary.roles {
                ensure!(
                    [
                        "installation",
                        "save",
                        "config",
                        "runtime",
                        "unclassified",
                        "other"
                    ]
                    .contains(&role.as_str())
                        && *count > 0,
                    "Native root-role summary is invalid"
                );
                total = total
                    .checked_add(*count)
                    .context("Native root-role count overflow")?;
            }
            ensure!(
                summary.count >= header.plans.len()
                    && summary.count <= header.plans.len() * 128
                    && total == summary.count
                    && summary.canonical_app_count > 0
                    && summary.canonical_app_count <= header.plans.len(),
                "Native batch root/app summary changed its bounds"
            );
        }
        let mut references = BTreeMap::new();
        let mut source_ids = BTreeSet::new();
        for reference in &header.plans {
            checked_digest(&reference.digest)?;
            ensure!(
                references.insert(reference.id, reference.clone()).is_none()
                    && source_ids.insert(reference.source_id),
                "Native batch header has duplicate child IDs"
            );
        }
        if headers.len() >= 4 {
            if let Some(old) = headers.keys().next().copied() {
                headers.remove(&old);
            }
        }
        let cached = Arc::new(CachedSetHeader {
            header,
            stamp,
            references,
        });
        headers.insert(id, cached.clone());
        Ok(cached)
    }
    fn check(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "Native batch plan durability requires recovery"
        );
        self.root.identity()?;
        #[cfg(unix)]
        {
            verify_private_file(&self.lock)?;
            self.root
                .verify_file("native-plans.lock", &self.lock_stamp)?;
        }
        #[cfg(windows)]
        self.lock.check()?;
        Ok(())
    }
    fn set_root(&self, id: Uuid) -> Result<SafeRoot> {
        self.check()?;
        let path = self.path.join(format!("set-{id}"));
        let root = SafeRoot::open(&path)?; // unknown reads must never create directories
        ensure_private_directory(&path)?;
        let identity = root.identity()?;
        let mut roots = self
            .roots
            .lock()
            .map_err(|_| anyhow::anyhow!("Native plan root lock failed"))?;
        if let Some(previous) = roots.get(&id) {
            ensure!(
                previous == &identity,
                "Native plan directory identity changed"
            );
        } else {
            ensure!(roots.len() < MAX_STORED_PLANS, "Too many native plan roots");
            if let Err(error) = flush_root(&path, &root) {
                self.failed.store(true, Ordering::Release);
                return Err(error);
            }
            roots.insert(id, identity);
        }
        self.check()?;
        Ok(root)
    }
    fn write<T: Serialize>(
        &self,
        root: &SafeRoot,
        name: &str,
        set: Uuid,
        kind: &str,
        payload: &T,
        max: usize,
    ) -> Result<()> {
        self.check()?;
        let scope = json!({"domain":DOMAIN,"setId":set,"name":name,"kind":kind,"payload":payload});
        let signing = signature_scope(&scope, max)?;
        let signature = self.signer.seal(&signing)?;
        signature_envelope(&signature)?;
        ensure!(
            self.signer.verify(&signing, &signature)?,
            "Native device MAC could not verify a batch record"
        );
        let bytes = canonical(&serde_json::to_value(Envelope { scope, signature })?, max)?;
        let result = root.write_new(name, |file| {
            file.write_all(&bytes)?;
            Ok(())
        });
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    fn read<T: DeserializeOwned>(
        &self,
        root: &SafeRoot,
        name: &str,
        set: Uuid,
        kind: &str,
        max: usize,
    ) -> Result<Option<T>> {
        self.check()?;
        let (mut file, stamp) = match root.read_file(name) {
            Ok(file) => file,
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        verify_private_file(&file)?;
        ensure!(
            stamp.size <= max as u64,
            "Native batch sidecar exceeds its bound"
        );
        let mut bytes = Vec::new();
        (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= max, "Native batch sidecar exceeds its bound");
        verify_private_file(&file)?;
        root.verify_file(name, &stamp)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).context("Native batch sidecar is corrupt")?;
        ensure!(
            envelope.scope["domain"] == DOMAIN
                && envelope.scope["setId"] == set.to_string()
                && envelope.scope["name"] == name
                && envelope.scope["kind"] == kind
                && envelope
                    .scope
                    .as_object()
                    .is_some_and(|object| object.len() == 5),
            "Native batch sidecar domain/identity changed"
        );
        signature_envelope(&envelope.signature)?;
        ensure!(
            self.signer
                .verify(&signature_scope(&envelope.scope, max)?, &envelope.signature)?,
            "Native batch sidecar authentication failed"
        );
        Ok(Some(serde_json::from_value(
            envelope.scope["payload"].clone(),
        )?))
    }
}

fn history_file_stamp(file: &File) -> Result<quicksave_platform::FileStamp> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            (0..1_000_000_000).contains(&metadata.mtime_nsec())
                && (0..1_000_000_000).contains(&metadata.ctime_nsec()),
            "Native history metadata timestamp is invalid"
        );
        Ok(quicksave_platform::FileStamp {
            device: metadata.dev(),
            file_id: [metadata.ino(), 0],
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec() as u32,
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec() as u32,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        bail!("Native history metadata-frame validation is unsupported on this platform")
    }
}
fn history_root_stamp(root: &SafeRoot) -> Result<quicksave_platform::FileStamp> {
    history_file_stamp(&root.clone_root_directory_handle()?)
}
fn history_files(root: &SafeRoot) -> Result<BTreeMap<String, quicksave_platform::FileStamp>> {
    let entries = root.entries()?;
    ensure!(
        entries.len() <= HISTORY_RECORD_LIMIT,
        "Native history journal exceeds its record bound"
    );
    let mut files = BTreeMap::new();
    for entry in entries {
        ensure!(
            !entry.is_directory
                && !entry.relative_path.contains('/')
                && entry.relative_path.len() <= 160,
            "Native history contains an unexpected nested/oversized record"
        );
        let (file, stamp) = root.read_file(&entry.relative_path)?;
        verify_private_file(&file)?;
        files.insert(entry.relative_path, stamp);
    }
    Ok(files)
}
fn history_frame(native: &SafeRoot, ledger: &SafeRoot) -> Result<HistoryFrame> {
    let native_root = history_root_stamp(native)?;
    let ledger_root = history_root_stamp(ledger)?;
    let native_files = history_files(native)?;
    let ledger_files = history_files(ledger)?;
    ensure!(
        history_root_stamp(native)? == native_root && history_root_stamp(ledger)? == ledger_root,
        "Native history changed during metadata-frame inspection; retry the query"
    );
    Ok(HistoryFrame {
        native_root,
        ledger_root,
        native: native_files,
        ledger: ledger_files,
    })
}
fn history_unchanged(
    previous: &BTreeMap<String, quicksave_platform::FileStamp>,
    current: &BTreeMap<String, quicksave_platform::FileStamp>,
) -> Result<()> {
    ensure!(
        previous
            .iter()
            .all(|(name, stamp)| current.get(name) == Some(stamp)),
        "An immutable native history journal record changed or disappeared"
    );
    Ok(())
}
fn history_ledger_payload(
    name: &str,
    kind: &str,
    payload: Value,
    cached: &mut CachedHistory,
) -> Result<()> {
    match kind {
        "binding" => {
            ensure!(
                name == "binding.json"
                    && payload["operationId"] == cached.metadata.plan_set_id.to_string()
                    && payload["kind"] == "upload"
                    && payload["intent"] == serde_json::to_value(cached.metadata.selection)?
                    && payload["providerId"] == cached.metadata.provider_id
                    && payload["providerScope"] == cached.provider_digest
                    && payload["authorityRevision"] == cached.metadata.root_digest
                    && payload["createdAt"] == cached.metadata.created_at
                    && payload["jobs"] == cached.job_references,
                "Native history metadata frame belongs to another signed ledger/root digest"
            );
        }
        "job" => {
            let job: FrozenJobPlan = serde_json::from_value(payload)?;
            let reference = cached
                .job_references
                .as_array()
                .unwrap()
                .iter()
                .find(|reference| reference["jobId"] == job.job_id.to_string())
                .context("Native history journal added an unapproved job")?;
            ensure!(
                name == format!("job-{}.json", job.job_id)
                    && reference["children"].as_u64() == Some(job.children.len() as u64)
                    && reference["digest"]
                        == blake3::hash(&serde_json::to_vec(&job)?)
                            .to_hex()
                            .to_string(),
                "Native history job differs from its original signed binding"
            );
            for child in &job.children {
                let expected = cached
                    .metadata
                    .children
                    .iter()
                    .find(|known| known.source_id == child.source_id)
                    .context("Native history job added an unapproved source")?;
                ensure!(
                    fingerprint(&serde_json::to_value(child)?)? == expected.frozen_child_digest,
                    "Native history job changed a frozen child/root/provider identity"
                );
            }
        }
        "control" => {
            let control: HistoryControl = serde_json::from_value(payload)?;
            ensure!(
                control.sequence > 0
                    && control.sequence <= MAX_CONTROL_RECORDS
                    && name == format!("control-{:04}.json", control.sequence)
                    && matches!(control.desired.as_str(), "run" | "cancel")
                    && control.retry_source_ids.len() <= MAX_APPS_PER_PLAN
                    && (control.desired != "cancel" || control.retry_source_ids.is_empty())
                    && control
                        .retry_source_ids
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        == control.retry_source_ids.len()
                    && control.retry_source_ids.iter().all(|id| cached
                        .metadata
                        .children
                        .iter()
                        .any(|child| child.source_id == *id)),
                "Native history control journal changed its exact child/sequence scope"
            );
            cached.controls.insert(control.sequence, control);
        }
        "completion" => {
            let receipt: CompletionReceipt = serde_json::from_value(payload)?;
            let child = cached
                .metadata
                .children
                .iter()
                .find(|child| child.source_id == receipt.source_id)
                .context("Native history completion added an unapproved child")?;
            ensure!(
                name == format!("completed-{}.json", child.source_id)
                    && receipt.native_plan_digest == child.native_plan_digest,
                "Native history completion changed its original source/plan"
            );
            checked_digest(&receipt.receipt_digest)?;
            cached.completions.insert(child.source_id, receipt);
        }
        "retry_admission" => {
            let sequence = payload["sequence"]
                .as_u64()
                .context("Native history retry sequence is missing")?;
            let source = Uuid::parse_str(dto::id(&payload, "sourceId")?)?;
            ensure!(
                sequence > 0
                    && sequence <= MAX_CONTROL_RECORDS as u64
                    && payload
                        .as_object()
                        .is_some_and(|payload| payload.len() == 2)
                    && name == format!("retry-{sequence:04}-{source}.json")
                    && cached
                        .metadata
                        .children
                        .iter()
                        .any(|child| child.source_id == source),
                "Native history retry admission changed its original fixed source"
            );
            cached.retry_admissions.push((sequence as usize, source));
        }
        _ => bail!("Unsupported record in the actual native operation history journal"),
    }
    Ok(())
}
fn history_finish(cached: &mut CachedHistory) -> Result<()> {
    let mut previous = String::new();
    for (offset, control) in cached.controls.values().enumerate() {
        ensure!(
            control.sequence == offset + 1 && control.previous_digest == previous,
            "Native history control journal has a missing or invalid signed predecessor"
        );
        previous = blake3::hash(&serde_json::to_vec(control)?)
            .to_hex()
            .to_string();
    }
    for (sequence, source) in &cached.retry_admissions {
        let control = cached
            .controls
            .get(sequence)
            .context("Native history retry admission lost its original signed control")?;
        ensure!(
            control.desired == "run"
                && control.retry_source_ids.contains(source)
                && cached.captures.contains_key(source),
            "Native history retry lost its original capture/explicit retry scope"
        );
    }
    for (id, proof) in &cached.finalizations {
        let (digest, generation) = cached
            .captures
            .get(id)
            .context("Native history finalization lost its original capture binding")?;
        ensure!(
            proof.capture_digest == *digest && proof.generation == *generation,
            "Native history finalization changed its original capture/generation"
        );
    }
    for (id, receipt) in &cached.completions {
        let proof = cached
            .finalizations
            .get(id)
            .context("Native history completion lost its actual tracker/source finalization")?;
        ensure!(
            receipt.receipt_digest == fingerprint(&serde_json::to_value(proof)?)?,
            "Native history completion does not match the actual finalized source receipt"
        );
    }
    ensure!(
        cached.metadata.admitted_at.is_some()
            || cached.captures.is_empty()
                && cached.finalizations.is_empty()
                && cached.completions.is_empty()
                && cached.controls.is_empty()
                && cached.gaps.is_empty(),
        "Native work journal exists without its original signed group admission"
    );
    cached.metadata.completed = cached.completions.len();
    cached.metadata.captured = cached.captures.len();
    cached.metadata.awaiting_finalization = cached.finalizations.len() - cached.completions.len();
    cached.metadata.reconciliation_gaps = cached.gaps.len();
    cached.metadata.settled_reconciliation_gaps = cached.settled_gaps.len();
    for child in &mut cached.metadata.children {
        child.completed = cached.completions.contains_key(&child.source_id);
        child.captured = cached.captures.contains_key(&child.source_id);
    }
    cached.metadata.cancel_requested = cached
        .controls
        .values()
        .next_back()
        .is_some_and(|control| control.desired == "cancel");
    Ok(())
}
fn history_cache_size(cached: &CachedHistory) -> usize {
    let stamps = cached
        .frame
        .native
        .iter()
        .chain(cached.frame.ledger.iter())
        .map(|(name, _)| name.len() + std::mem::size_of::<quicksave_platform::FileStamp>() + 128)
        .sum::<usize>();
    let children = cached
        .metadata
        .children
        .iter()
        .map(|child| {
            child.app_id.len()
                + child.software_id.as_ref().map_or(0, String::len)
                + child.native_plan_digest.len()
                + child.roots_fingerprint.len()
                + child.frozen_child_digest.len()
                + 384
        })
        .sum::<usize>();
    stamps
        .saturating_add(children)
        .saturating_add(cached.captures.len() * 256)
        .saturating_add(cached.finalizations.len() * 768)
        .saturating_add(cached.completions.len() * 512)
        .saturating_add(cached.gaps.len() * 128)
        .saturating_add(cached.retry_admissions.len() * 64)
        .saturating_add(
            cached
                .controls
                .values()
                .map(|control| control.retry_source_ids.len() * 32 + 512)
                .sum::<usize>(),
        )
}

pub fn provider_scope(provider: &Value) -> Result<Value> {
    dto::id(provider, "id")?;
    let value = dto::copy_fields(
        provider,
        &[
            "id",
            "kind",
            "origin",
            "readOnly",
            "bucket",
            "prefix",
            "credentialRef",
            "repositoryKeyRef",
            "sourceProfileId",
            "authorityGeneration",
            "authorityRevision",
            "profileFingerprint",
            "publicScope",
        ],
    );
    dto::bounded(&value, 128 * 1024)?;
    non_secret(&value)?;
    Ok(value)
}
pub fn root_authority_revision(record: &Value) -> Result<String> {
    let mut scope = json!({
        "softwareId":dto::id(record,"id")?,"appId":dto::id(record,"appId")?,
        "providerId":dto::id(record,"providerId")?,"roots":authority_roots(record)?,
        "trackingGrant":record.get("trackingGrant").context("Tracking grant missing")?,
    });
    if let Some(identity) = record
        .get("sourceIdentity")
        .filter(|value| !value.is_null())
    {
        scope["sourceIdentity"] = source_identity(identity)?;
    }
    if let Some(enrollment) = record
        .get("autoEnrollment")
        .filter(|value| !value.is_null())
    {
        non_secret(enrollment)?;
        scope["autoEnrollment"] = enrollment.clone();
    }
    fingerprint(&scope)
}
pub fn authority_roots(record: &Value) -> Result<Value> {
    let roots = record["roots"]
        .as_array()
        .context("Exact approved native roots are missing")?;
    ensure!(
        !roots.is_empty() && roots.len() <= 128,
        "Approve 1–128 exact native roots per batch instance"
    );
    let mut ids = BTreeSet::new();
    let mut result = Vec::with_capacity(roots.len());
    for root in roots {
        let id = dto::id(root, "id")?;
        ensure!(ids.insert(id), "Duplicate approved native root ID");
        let path = dto::text(root, "path", quicksave_platform::MAX_PATH_BYTES)?;
        let native = Path::new(path);
        ensure!(
            native.is_absolute()
                && !native.components().any(|part| matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )),
            "Invalid native approved root path"
        );
        let _: RootIdentity = serde_json::from_value(root["identity"].clone())
            .context("Approved root has no real native identity")?;
        if let Some(leaves) = root.get("allowedFiles").filter(|value| !value.is_null()) {
            let leaves = leaves
                .as_array()
                .context("Native root allowlist is malformed")?;
            ensure!(
                !leaves.is_empty() && leaves.len() <= 4096,
                "Native manual root allowlist exceeds its bound"
            );
            let mut seen = BTreeSet::new();
            for leaf in leaves {
                let leaf = leaf.as_str().context("Native manual leaf is not text")?;
                ensure!(
                    !leaf.is_empty()
                        && leaf.len() <= 255
                        && !matches!(leaf, "." | "..")
                        && !leaf.contains(['/', '\\', ':', '\0'])
                        && !leaf.chars().any(char::is_control)
                        && seen.insert(leaf),
                    "Invalid native manual leaf authority"
                );
            }
        }
        let mut value = json!({
            "id":id,"path":path,"role":root.get("role").unwrap_or(&Value::Null),
            "identity":root["identity"],"allowedFiles":root.get("allowedFiles").unwrap_or(&Value::Null),
        });
        if root["directory"] == false {
            value["directory"] = json!(false);
        }
        result.push(value);
    }
    Ok(json!(result))
}
fn source_identity(identity: &Value) -> Result<Value> {
    let object = identity
        .as_object()
        .context("Original source identity is malformed")?;
    let allowed = [
        "app_id",
        "display_name",
        "canonical_executable",
        "desktop_entry_id",
        "steam_app_id",
        "launcher",
        "aliases",
        "identity_confidence",
        "icon_path",
    ];
    ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "Original source identity has unsupported/private fields"
    );
    dto::id(identity, "app_id")?;
    dto::bounded(identity, 16 * 1024)?;
    non_secret(identity)?;
    Ok(identity.clone())
}
pub fn fingerprint(value: &Value) -> Result<String> {
    Ok(blake3::hash(&canonical(value, MAX_NATIVE_SET_BYTES)?)
        .to_hex()
        .to_string())
}
pub fn checked_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid native batch authority digest"
    );
    Ok(())
}
fn checked_id(name: &str, value: &str) -> Result<()> {
    dto::id(&json!({name:value}), name).map(|_| ())
}
fn non_secret(value: &Value) -> Result<()> {
    dto::bounded(value, MAX_NATIVE_PLAN_BYTES)?;
    fn visit(value: &Value) -> Result<()> {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let name = key.to_ascii_lowercase().replace(['_', '-'], "");
                    ensure!(
                        ![
                            "token",
                            "accesstoken",
                            "refreshtoken",
                            "password",
                            "secret",
                            "clientsecret",
                            "credentials",
                            "session",
                            "configini",
                            "masterkey",
                            "masterkeyhex",
                            "repositorykey",
                            "privatekey",
                            "approved",
                        ]
                        .contains(&name.as_str()),
                        "Secret/boolean authority is forbidden in native batch plans"
                    );
                    visit(value)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(value)
}
fn signature_scope(value: &Value, max: usize) -> Result<Value> {
    let bytes = canonical(value, max)?;
    Ok(
        json!({"domain":DOMAIN,"setId":value["setId"],"name":value["name"],"kind":value["kind"],
        "digest":blake3::hash(&bytes).to_hex().to_string()}),
    )
}
fn signature_envelope(value: &Value) -> Result<()> {
    dto::bounded(value, 4096)?;
    let object = value
        .as_object()
        .context("Native batch MAC envelope is missing")?;
    ensure!(
        object.keys().all(|key| [
            "version",
            "algorithm",
            "mac",
            "kind",
            "nonce",
            "authorityRef",
        ]
        .contains(&key.as_str()))
            && value["version"] == 1
            && matches!(
                value["algorithm"].as_str(),
                Some("hmac-sha256" | "keyed-blake3")
            ),
        "Unsupported or secret-bearing native batch MAC envelope"
    );
    checked_digest(
        value["mac"]
            .as_str()
            .context("Native batch MAC is missing")?,
    )?;
    if let Some(nonce) = value.get("nonce") {
        checked_digest(
            nonce
                .as_str()
                .context("Native batch MAC nonce is invalid")?,
        )?;
    }
    for (key, max) in [("kind", 64), ("authorityRef", 256)] {
        if value.get(key).is_some() {
            dto::text(value, key, max)?;
        }
    }
    Ok(())
}
fn canonical(value: &Value, max: usize) -> Result<Vec<u8>> {
    dto::bounded(value, max)?;
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut result: serde_json::Map<String, Value> = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect();
                result.sort_keys();
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    Ok(serde_json::to_vec(&sorted(value))?)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_mac(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}
fn missing(error: &anyhow::Error) -> bool {
    error.chain().any(|error| {
        error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}
fn flush_root(path: &Path, root: &SafeRoot) -> Result<()> {
    let expected = root.identity()?;
    ensure_private_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file = File::from(rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.dev() == expected.device
                && [metadata.ino(), 0] == expected.file_id,
            "Native batch flush handle changed identity"
        );
        file.sync_all()?;
    }
    #[cfg(windows)]
    quicksave_platform::PrivateDirectory::open(path)?.flush()?;
    #[cfg(not(any(unix, windows)))]
    bail!("Private native directory flushing is unsupported");
    ensure!(
        root.identity()? == expected,
        "Native batch directory changed during flush"
    );
    Ok(())
}
