// SPDX-License-Identifier: GPL-3.0-only
//! Durable exact-selection orchestration (native-only; never an IPC dispatcher).
//!
//! # Parent integration API
//!
//! - `OperationBindings::open(private_directory, Arc<dyn StoreSigner>)` opens
//!   pinned, private storage; signer callbacks must use native authenticated
//!   authority (the parent can adapt `WorkspaceStore::grant_seal/grant_verify`).
//! - `OperationBindings::freeze(FrozenPlanSet)` atomically publishes signed
//!   fixed IDs in chunks of at most 128 children, up to 4096 selected apps.
//! - `OperationCoordinator::new(Arc<OperationBindings>, Arc<dyn
//!   NativeOperationBackend>)`, then `drive`, `cancel`, `retry`, `status`.
//! - `NativeOperationBackend` MUST supply fresh publication guards, exact source
//!   status/reattachment/admission/retry/cancel-and-drain callbacks. No callback
//!   defaults to success. Credentials and large native selections never enter
//!   these records. Parent adapters must consume their private native plan IDs.
//!
//! Wire this module from the parent only. No raw `StartBackupAll`/`*` RPC, no
//! implicit enrollment, local deletion, provider access, baseline acknowledgement,
//! or automatic retirement is performed here. Source optimizations inside each
//! real child (parallel/adaptive packs and publication) are left intact.
//!
//! Storage is an authenticated immutable journal, not an unsigned JSON retry
//! database. `SafeRoot::write_new` stages, fsyncs, publishes without replacement
//! and fsyncs the parent. All chunks precede the final binding's atomic publish.
//! Partial uncommitted directories are never admitted. Controls are hash-chained
//! and create-new; ambiguous source retry admission is NOT automatically repeated.
//! Limits: 128 children/job, 32 jobs/plan, 4096 apps, 64 explicit controls/plan,
//! 2 MiB/chunk, 128 KiB/header, 4 KiB/signature, 64 stored plans, no file lists.
//! At most 8192 retry admissions per plan; limits fail closed, never retire work.
//! A full store fails explicitly; no history or cloud generation is retired.
//!
//! Parent hooks: freeze real native selections before approval; include native
//! root identity/capture/provider-scope digests; retain their private native plan
//! handles durably. Reacquire provider secrets natively in submit/reattach/retry.
//! `finalize_completed` must verify the real source commit/restore receipt and
//! durably finalize the exact tracker generation, idempotently. On restart call
//! `drive` for retained IDs; never rescan today's software into an old plan.
//! A completed source ID is only finalized, never resubmitted/retried.
//! Custom/subset captures finalize only their selected nodes/epochs, never an
//! app-wide "saved" baseline. The native receipt/coverage determines that scope.
//! Store open/freeze/recovery are native filesystem work, not GUI-thread work.
//! Signer adapters should retain a bounded native MAC capability for the store;
//! do not perform one credential-vault lookup/registry insertion per journal row.

use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::{ensure_private_directory, verify_private_file, SafeRoot};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub const MAX_CHILDREN_PER_JOB: usize = 128;
pub const MAX_APPS_PER_PLAN: usize = 4096;
pub const MAX_JOBS_PER_PLAN: usize = MAX_APPS_PER_PLAN / MAX_CHILDREN_PER_JOB;
pub const MAX_CONTROL_RECORDS: usize = 64;
pub const MAX_STORED_PLANS: usize = 64;
pub const MAX_RETRY_ADMISSIONS: usize = 8192;
const MAX_CHUNK_BYTES: usize = 2 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 128 * 1024;
const MAX_SMALL_BYTES: usize = 256 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;
const JOURNAL_DOMAIN: &str = "quicksave-private-operation-bindings-v1";

pub type OperationFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type PublicationGuard = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Mandatory native MAC callbacks. Verification must authenticate the payload,
/// not merely hash JSON, compare a UI flag, or trust a signature's presence.
/// Do not persist keys/tokens in the returned non-secret signature.
pub trait StoreSigner: Send + Sync + 'static {
    /// Scope is a small domain/identity/content-digest document, never a 250k
    /// native file inventory. The supported signature envelope is
    /// `{version:1,algorithm:"hmac-sha256"|"keyed-blake3",mac:<64 hex>}` with
    /// optional native grant kind/nonce/authorityRef, not arbitrary secret JSON.
    fn seal(&self, scope: &Value) -> Result<Value>;
    fn verify(&self, scope: &Value, signature: &Value) -> Result<bool>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Upload,
    Restore,
    CloudDeletion,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionIntent {
    AllApprovedApps,
    SelectedApps,
    SelectedFiles,
    ExplicitDeletion,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenRootBinding {
    pub root_id: String,
    pub identity_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenChildPlan {
    /// Exactly the actual source client_operation_id, never a UI child ID.
    pub source_id: Uuid,
    pub native_plan_id: Uuid,
    pub native_plan_digest: String,
    pub app_id: String,
    pub software_id: Option<String>,
    pub source_revision: String,
    pub roots_fingerprint: String,
    pub roots: Vec<FrozenRootBinding>,
    pub mode: Option<String>,
    pub bundle_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenJobPlan {
    pub job_id: Uuid,
    pub children: Vec<FrozenChildPlan>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenPlanSet {
    pub operation_id: Uuid,
    pub kind: OperationKind,
    pub intent: SelectionIntent,
    pub provider_id: String,
    pub provider_scope: String,
    pub authority_revision: String,
    pub created_at: String,
    pub jobs: Vec<FrozenJobPlan>,
}

impl FrozenPlanSet {
    /// Input must already be materialized and natively approved. This labels
    /// "all" without storing a wildcard or reevaluating discovery on retry.
    #[allow(clippy::too_many_arguments)]
    pub fn from_children(
        operation_id: Uuid,
        kind: OperationKind,
        intent: SelectionIntent,
        provider_id: String,
        provider_scope: String,
        authority_revision: String,
        children: Vec<FrozenChildPlan>,
    ) -> Result<Self> {
        ensure!(
            !children.is_empty() && children.len() <= MAX_APPS_PER_PLAN,
            "Select 1–4096 exact native children"
        );
        let plan = Self {
            operation_id,
            kind,
            intent,
            provider_id,
            provider_scope,
            authority_revision,
            created_at: chrono::Utc::now().to_rfc3339(),
            jobs: children
                .chunks(MAX_CHILDREN_PER_JOB)
                .map(|children| FrozenJobPlan {
                    job_id: Uuid::new_v4(),
                    children: children.to_vec(),
                })
                .collect(),
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn child_count(&self) -> usize {
        self.jobs.iter().map(|job| job.children.len()).sum()
    }

    pub fn children(&self) -> impl Iterator<Item = &FrozenChildPlan> {
        self.jobs.iter().flat_map(|job| job.children.iter())
    }

    pub fn validate(&self) -> Result<()> {
        text(&self.provider_id, 128)?;
        ensure!(
            !self.provider_id.contains(['/', '\\']),
            "Invalid native provider identity"
        );
        digest(&self.provider_scope)?;
        digest(&self.authority_revision)?;
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .context("Invalid frozen operation time")?;
        ensure!(
            !self.jobs.is_empty()
                && self.jobs.len() <= MAX_JOBS_PER_PLAN
                && self.child_count() <= MAX_APPS_PER_PLAN,
            "Frozen native plan exceeds its bounded job/app limit"
        );
        ensure!(
            self.kind != OperationKind::CloudDeletion
                || self.intent == SelectionIntent::ExplicitDeletion,
            "Cloud deletion requires an explicit separately approved plan"
        );
        let mut jobs = BTreeSet::new();
        let mut source_ids = BTreeSet::from([self.operation_id]);
        let mut native_plans = BTreeSet::new();
        let mut apps = BTreeSet::new();
        let mut app_root_scopes = BTreeSet::new();
        for job in &self.jobs {
            ensure!(
                job.job_id != self.operation_id
                    && jobs.insert(job.job_id)
                    && !job.children.is_empty()
                    && job.children.len() <= MAX_CHILDREN_PER_JOB,
                "Frozen job IDs are duplicate or exceed the 128-child bound"
            );
            for child in &job.children {
                text(&child.app_id, 512)?;
                ensure!(
                    !matches!(child.app_id.as_str(), "." | ".." | "*" | "_all")
                        && !child.app_id.contains(['/', '\\', '*', '?', '[', ']']),
                    "Frozen application ID is not an exact safe source identity"
                );
                if let Some(id) = &child.software_id {
                    text(id, 128)?;
                }
                ensure!(
                    source_ids.insert(child.source_id) && native_plans.insert(child.native_plan_id),
                    "Frozen source/native plan ID occurs more than once"
                );
                ensure!(
                    self.kind != OperationKind::Upload
                        || apps.insert(match child.software_id.as_deref() {
                            Some(instance) => (true, instance),
                            None => (false, child.app_id.as_str()),
                        }) && app_root_scopes.insert((&child.app_id, &child.roots_fingerprint)),
                    "A software instance/root scope must have exactly one frozen upload child"
                );
                ensure!(
                    !jobs.contains(&child.source_id),
                    "Source child cannot alias a grouping job ID"
                );
                text(&child.source_revision, 512)?;
                digest(&child.native_plan_digest)?;
                digest(&child.roots_fingerprint)?;
                ensure!(
                    child.roots.len() <= 128
                        && (self.kind == OperationKind::CloudDeletion || !child.roots.is_empty()),
                    "Frozen child requires bounded exact native root bindings"
                );
                let mut roots = BTreeSet::new();
                for root in &child.roots {
                    text(&root.root_id, 128)?;
                    digest(&root.identity_digest)?;
                    ensure!(
                        roots.insert(&root.root_id),
                        "Duplicate root in frozen source child"
                    );
                }
                ensure!(
                    self.kind != OperationKind::Restore || child.bundle_id.is_some(),
                    "Frozen restore child lacks its bundle identity"
                );
                ensure!(
                    self.kind == OperationKind::CloudDeletion && child.mode.is_none()
                        || self.kind != OperationKind::CloudDeletion
                            && matches!(
                                child.mode.as_deref(),
                                Some("complete_application" | "personal_state" | "custom")
                            ),
                    "Frozen native source mode is missing or invalid"
                );
            }
        }
        ensure!(
            jobs.is_disjoint(&source_ids),
            "Source child IDs cannot alias grouping IDs"
        );
        // Every field is typed and small; never persist captured file lists,
        // session JSON, a repository key or arbitrary retry parameters.
        for job in &self.jobs {
            bounded_json(job, MAX_CHUNK_BYTES / 2)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobReference {
    job_id: Uuid,
    digest: String,
    children: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanHeader {
    operation_id: Uuid,
    kind: OperationKind,
    intent: SelectionIntent,
    provider_id: String,
    provider_scope: String,
    authority_revision: String,
    created_at: String,
    jobs: Vec<JobReference>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRecord {
    scope: Value,
    signature: Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DesiredState {
    Run,
    Cancel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlRecord {
    sequence: usize,
    previous_digest: String,
    desired: DesiredState,
    retry_source_ids: Vec<Uuid>,
}

#[derive(Clone, Debug)]
struct Control {
    sequence: usize,
    digest: String,
    desired: DesiredState,
    retry_source_ids: BTreeSet<Uuid>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            sequence: 0,
            digest: String::new(),
            desired: DesiredState::Run,
            retry_source_ids: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionReceipt {
    pub source_id: Uuid,
    pub native_plan_digest: String,
    pub receipt_digest: String,
}

pub struct OperationBindings {
    path: PathBuf,
    root: SafeRoot,
    signer: Arc<dyn StoreSigner>,
    gate: Mutex<()>,
    durability_failed: AtomicBool,
    recovered_roots: Mutex<BTreeMap<Uuid, quicksave_platform::RootIdentity>>,
    #[cfg(unix)]
    _lock: File,
    #[cfg(unix)]
    lock_stamp: quicksave_platform::FileStamp,
    #[cfg(windows)]
    _lock: quicksave_platform::PrivateLock,
}

impl OperationBindings {
    /// This is QuickSave's own dedicated directory, not a No Land state path.
    /// Native private ACL checks never repair existing paths/permissions.
    pub fn open(path: &Path, signer: Arc<dyn StoreSigner>) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "Operation binding directory must be absolute"
        );
        ensure_private_directory(path)?;
        let root = SafeRoot::open(path)?;
        sync_private_root(path, &root)?;
        #[cfg(unix)]
        let (lock, lock_stamp) = {
            match root.read_file("bindings.lock") {
                Ok((file, _)) => verify_private_file(&file)?,
                Err(error) if not_found(&error) => root.write_new("bindings.lock", |_| Ok(()))?,
                Err(error) => return Err(error),
            }
            let (file, stamp) = root.read_file("bindings.lock")?;
            verify_private_file(&file)?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .context("Another native operation-binding store owns this directory")?;
            root.verify_file("bindings.lock", &stamp)?;
            (file, stamp)
        };
        #[cfg(windows)]
        let lock = quicksave_platform::PrivateDirectory::open(path)?.lock("bindings.lock")?;
        #[cfg(not(any(unix, windows)))]
        bail!("Private atomic operation-binding storage is unsupported on this platform");
        Ok(Self {
            path: path.to_path_buf(),
            root,
            signer,
            gate: Mutex::new(()),
            durability_failed: AtomicBool::new(false),
            recovered_roots: Mutex::new(BTreeMap::new()),
            #[cfg(any(unix, windows))]
            _lock: lock,
            #[cfg(unix)]
            lock_stamp,
        })
    }

    pub fn freeze(&self, plan: FrozenPlanSet) -> Result<Uuid> {
        plan.validate()?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        self.require_durable()?;
        ensure!(
            self.list_ids_locked()?.len() < MAX_STORED_PLANS,
            "The bounded durable operation history is full; no history was deleted"
        );
        let directory = format!("operation-{}", plan.operation_id);
        self.root.create_dir(&directory)?;
        let root = self.operation_root(plan.operation_id)?;
        match root.read_file("binding.json") {
            Ok(_) => bail!("This durable parent ID is already frozen; reattach the original plan"),
            Err(error) if not_found(&error) => {}
            Err(error) => return Err(error),
        }
        let mut references = Vec::with_capacity(plan.jobs.len());
        for job in &plan.jobs {
            let bytes = bounded_json(job, MAX_CHUNK_BYTES / 2)?;
            references.push(JobReference {
                job_id: job.job_id,
                digest: blake3::hash(&bytes).to_hex().to_string(),
                children: job.children.len(),
            });
            self.write_signed(
                &root,
                &format!("job-{}.json", job.job_id),
                plan.operation_id,
                "job",
                job,
                MAX_CHUNK_BYTES,
            )?;
        }
        let header = PlanHeader {
            operation_id: plan.operation_id,
            kind: plan.kind,
            intent: plan.intent,
            provider_id: plan.provider_id,
            provider_scope: plan.provider_scope,
            authority_revision: plan.authority_revision,
            created_at: plan.created_at,
            jobs: references,
        };
        // The only admission commit point. A chunk without this signed final
        // manifest is an incomplete plan and can never start source work.
        self.write_signed(
            &root,
            "binding.json",
            plan.operation_id,
            "binding",
            &header,
            MAX_HEADER_BYTES,
        )?;
        Ok(plan.operation_id)
    }

    pub fn load(&self, id: Uuid) -> Result<FrozenPlanSet> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        self.load_locked(id)
    }

    fn load_locked(&self, id: Uuid) -> Result<FrozenPlanSet> {
        self.require_durable()?;
        let root = self.operation_root(id)?;
        let header: PlanHeader = self
            .read_signed(&root, "binding.json", id, "binding", MAX_HEADER_BYTES)?
            .context("Durable operation plan has no committed signed binding")?;
        ensure!(
            header.operation_id == id
                && !header.jobs.is_empty()
                && header.jobs.len() <= MAX_JOBS_PER_PLAN,
            "Durable operation header has an invalid identity or job bound"
        );
        let mut jobs = Vec::with_capacity(header.jobs.len());
        for reference in &header.jobs {
            ensure!(
                reference.children > 0 && reference.children <= MAX_CHILDREN_PER_JOB,
                "Durable job child count is invalid"
            );
            digest(&reference.digest)?;
            let job: FrozenJobPlan = self
                .read_signed(
                    &root,
                    &format!("job-{}.json", reference.job_id),
                    id,
                    "job",
                    MAX_CHUNK_BYTES,
                )?
                .context("Durable frozen job is missing")?;
            ensure!(
                job.job_id == reference.job_id
                    && job.children.len() == reference.children
                    && blake3::hash(&bounded_json(&job, MAX_CHUNK_BYTES / 2)?)
                        .to_hex()
                        .as_str()
                        == reference.digest,
                "Durable child plan differs from the committed parent binding"
            );
            jobs.push(job);
        }
        let plan = FrozenPlanSet {
            operation_id: id,
            kind: header.kind,
            intent: header.intent,
            provider_id: header.provider_id,
            provider_scope: header.provider_scope,
            authority_revision: header.authority_revision,
            created_at: header.created_at,
            jobs,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Native-only fixed plan chunks; never return root proofs to JS as authority.
    pub fn plan_page(&self, id: Uuid, job_index: usize) -> Result<FrozenJobPlan> {
        self.load(id)?
            .jobs
            .get(job_index)
            .cloned()
            .context("Frozen plan chunk is out of range")
    }

    pub fn list_ids(&self) -> Result<Vec<Uuid>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        self.list_ids_locked()
    }

    fn list_ids_locked(&self) -> Result<Vec<Uuid>> {
        let mut ids = BTreeSet::new();
        // SafeRoot's walk itself has hard entry/path/depth bounds. This runs on
        // recovery/history listing, never on every publication/status callback.
        for entry in self.root.entries()? {
            if entry.is_directory && !entry.relative_path.contains('/') {
                let raw = entry
                    .relative_path
                    .strip_prefix("operation-")
                    .context("Unknown entry in the private operation binding store")?;
                let id = Uuid::parse_str(raw).context("Invalid private operation directory ID")?;
                ensure!(
                    id.to_string() == raw,
                    "Noncanonical private operation directory"
                );
                ids.insert(id);
            }
        }
        ensure!(
            ids.len() <= MAX_STORED_PLANS,
            "Durable operation history exceeds its bound"
        );
        Ok(ids.into_iter().collect())
    }

    fn operation_root(&self, id: Uuid) -> Result<SafeRoot> {
        self.require_durable()?;
        self.root.identity()?;
        let path = self.path.join(format!("operation-{id}"));
        // A read of an unknown ID must not materialize an empty directory.
        let root = SafeRoot::open(&path)?;
        ensure_private_directory(&path)?;
        let identity = root.identity()?;
        let mut recovered = self
            .recovered_roots
            .lock()
            .map_err(|_| anyhow::anyhow!("Private operation recovery lock failed"))?;
        if let Some(previous) = recovered.get(&id) {
            ensure!(
                previous == &identity,
                "Private operation directory identity changed"
            );
        } else {
            ensure!(
                recovered.len() < MAX_STORED_PLANS,
                "Too many pinned private operation roots"
            );
            // A prior create-new may have published its fully fsynced file but
            // failed the directory flush. On restart, flush this actual pinned
            // directory before any record can be treated as durable. This does
            // not rescan software or hash file content.
            if let Err(error) = sync_private_root(&path, &root) {
                self.durability_failed.store(true, Ordering::Release);
                return Err(error);
            }
            recovered.insert(id, identity);
        }
        self.root.identity()?;
        Ok(root)
    }

    fn require_durable(&self) -> Result<()> {
        ensure!(
            !self.durability_failed.load(Ordering::Acquire),
            "Private operation durability is unresolved; retain native ownership and recover the store"
        );
        #[cfg(unix)]
        {
            verify_private_file(&self._lock)?;
            self.root.verify_file("bindings.lock", &self.lock_stamp)?;
        }
        #[cfg(windows)]
        self._lock.check()?;
        Ok(())
    }

    fn write_signed<T: Serialize>(
        &self,
        root: &SafeRoot,
        filename: &str,
        id: Uuid,
        kind: &str,
        payload: &T,
        max: usize,
    ) -> Result<()> {
        self.require_durable()?;
        let scope = json!({
            "domain":JOURNAL_DOMAIN, "operationId":id, "recordType":kind,
            "recordName":filename, "payload":payload,
        });
        bounded_json(&scope, max.saturating_sub(MAX_SIGNATURE_BYTES + 128))?;
        let signing_scope = signing_scope(&scope)?;
        let signature = self.signer.seal(&signing_scope)?;
        validate_signature(&signature)?;
        ensure!(
            self.signer.verify(&signing_scope, &signature)?,
            "Native operation-binding signer did not authenticate its record"
        );
        let bytes = bounded_json(&SignedRecord { scope, signature }, max)?;
        let result = root.write_new(filename, |file| {
            file.write_all(&bytes)?;
            Ok(())
        });
        if result.is_err() {
            // Never turn a failed fsync after publication into success merely
            // because a subsequent read sees the record's bytes.
            self.durability_failed.store(true, Ordering::Release);
        }
        result
    }

    fn read_signed<T: DeserializeOwned>(
        &self,
        root: &SafeRoot,
        filename: &str,
        id: Uuid,
        kind: &str,
        max: usize,
    ) -> Result<Option<T>> {
        let (mut file, before) = match root.read_file(filename) {
            Ok(file) => file,
            Err(error) if not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        verify_private_file(&file)?;
        ensure!(
            before.size <= max as u64,
            "Private operation record exceeds its bound"
        );
        let mut bytes = Vec::new();
        (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= max,
            "Private operation record exceeds its bound"
        );
        verify_private_file(&file)?;
        root.verify_file(filename, &before)?;
        let record: SignedRecord = serde_json::from_slice(&bytes)
            .context("Private operation record is corrupt; no source work was authorized")?;
        ensure!(
            record.scope["domain"] == JOURNAL_DOMAIN
                && record.scope["operationId"] == id.to_string()
                && record.scope["recordType"] == kind
                && record.scope["recordName"] == filename
                && record
                    .scope
                    .as_object()
                    .is_some_and(|scope| scope.len() == 5),
            "Private operation record has a different domain/identity"
        );
        validate_signature(&record.signature)?;
        ensure!(
            self.signer
                .verify(&signing_scope(&record.scope)?, &record.signature)?,
            "Private operation record authentication failed; no source work was authorized"
        );
        Ok(Some(serde_json::from_value(
            record.scope["payload"].clone(),
        )?))
    }

    fn control_locked(&self, id: Uuid) -> Result<Control> {
        let root = self.operation_root(id)?;
        let mut result = Control::default();
        for sequence in 1..=MAX_CONTROL_RECORDS + 1 {
            let filename = format!("control-{sequence:04}.json");
            let Some(record): Option<ControlRecord> =
                self.read_signed(&root, &filename, id, "control", MAX_SMALL_BYTES)?
            else {
                // Missing a middle record must not make a later cancellation
                // disappear or reactivate earlier retry authority.
                for later in sequence + 1..=MAX_CONTROL_RECORDS + 1 {
                    let later_name = format!("control-{later:04}.json");
                    ensure!(
                        self.read_signed::<ControlRecord>(
                            &root,
                            &later_name,
                            id,
                            "control",
                            MAX_SMALL_BYTES,
                        )?
                        .is_none(),
                        "Private operation control chain has a missing signed predecessor"
                    );
                }
                return Ok(result);
            };
            ensure!(
                sequence <= MAX_CONTROL_RECORDS
                    && record.sequence == sequence
                    && record.previous_digest == result.digest
                    && record.retry_source_ids.len() <= MAX_APPS_PER_PLAN
                    && (record.desired != DesiredState::Cancel
                        || record.retry_source_ids.is_empty()),
                "Private operation control chain is invalid"
            );
            let retry_source_ids = record
                .retry_source_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            ensure!(
                retry_source_ids.len() == record.retry_source_ids.len(),
                "Duplicate retry child in the signed operation control"
            );
            result = Control {
                sequence,
                digest: blake3::hash(&bounded_json(&record, MAX_SMALL_BYTES)?)
                    .to_hex()
                    .to_string(),
                desired: record.desired,
                retry_source_ids,
            };
        }
        bail!("Private operation control chain exceeds its bound")
    }

    fn record_control(&self, id: Uuid, desired: DesiredState, retry: Vec<Uuid>) -> Result<()> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        let plan = self.load_locked(id)?;
        let known = plan
            .children()
            .map(|child| child.source_id)
            .collect::<BTreeSet<_>>();
        ensure!(
            retry.len() <= MAX_APPS_PER_PLAN && retry.iter().all(|id| known.contains(id)),
            "A retry cannot add children to the approved frozen plan"
        );
        let previous = self.control_locked(id)?;
        ensure!(
            previous.sequence < MAX_CONTROL_RECORDS,
            "The explicit retry/cancellation journal is full; no source work was started"
        );
        let record = ControlRecord {
            sequence: previous.sequence + 1,
            previous_digest: previous.digest,
            desired,
            retry_source_ids: retry,
        };
        let root = self.operation_root(id)?;
        self.write_signed(
            &root,
            &format!("control-{:04}.json", record.sequence),
            id,
            "control",
            &record,
            MAX_SMALL_BYTES,
        )
    }

    pub fn ensure_not_cancelled(&self, id: Uuid) -> Result<()> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        ensure!(
            self.control_locked(id)?.desired == DesiredState::Run,
            "The durable native parent was cancelled"
        );
        Ok(())
    }

    /// Persist cancellation before waiting for a scheduling tick that may be
    /// preparing metadata. Native publication guards see this intent immediately;
    /// callers must still cancel/drain the real source IDs with the coordinator.
    pub fn request_cancellation(&self, id: Uuid) -> Result<()> {
        if self.control(id)?.desired != DesiredState::Cancel {
            self.record_control(id, DesiredState::Cancel, Vec::new())?;
        }
        Ok(())
    }

    fn control(&self, id: Uuid) -> Result<Control> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        self.control_locked(id)
    }

    fn retry_spent(&self, parent: Uuid, sequence: usize, child: Uuid, spend: bool) -> Result<bool> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        let root = self.operation_root(parent)?;
        let filename = format!("retry-{sequence:04}-{child}.json");
        let expected = json!({"sequence":sequence,"sourceId":child});
        if let Some(record) =
            self.read_signed::<Value>(&root, &filename, parent, "retry_admission", MAX_SMALL_BYTES)?
        {
            ensure!(
                record == expected,
                "Signed retry admission has a different child identity"
            );
            return Ok(true);
        }
        if spend {
            let admissions = root
                .entries()?
                .iter()
                .filter(|entry| !entry.is_directory && entry.relative_path.starts_with("retry-"))
                .count();
            ensure!(
                admissions < MAX_RETRY_ADMISSIONS,
                "Durable native retry admission history is full; no source attempt was started"
            );
            self.write_signed(
                &root,
                &filename,
                parent,
                "retry_admission",
                &expected,
                MAX_SMALL_BYTES,
            )?;
        }
        Ok(false)
    }

    fn completion(
        &self,
        parent: Uuid,
        child: &FrozenChildPlan,
    ) -> Result<Option<CompletionReceipt>> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        let root = self.operation_root(parent)?;
        let receipt: Option<CompletionReceipt> = self.read_signed(
            &root,
            &format!("completed-{}.json", child.source_id),
            parent,
            "completion",
            MAX_SMALL_BYTES,
        )?;
        if let Some(receipt) = &receipt {
            ensure!(
                receipt.source_id == child.source_id
                    && receipt.native_plan_digest == child.native_plan_digest,
                "Durable completion belongs to another frozen child"
            );
            digest(&receipt.receipt_digest)?;
        }
        Ok(receipt)
    }

    fn record_completion(
        &self,
        parent: Uuid,
        child: &FrozenChildPlan,
        receipt: CompletionReceipt,
    ) -> Result<()> {
        ensure!(
            receipt.source_id == child.source_id
                && receipt.native_plan_digest == child.native_plan_digest,
            "Native completion receipt differs from the approved frozen child"
        );
        digest(&receipt.receipt_digest)?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Binding lock failed"))?;
        let root = self.operation_root(parent)?;
        let filename = format!("completed-{}.json", child.source_id);
        if let Some(existing) = self.read_signed::<CompletionReceipt>(
            &root,
            &filename,
            parent,
            "completion",
            MAX_SMALL_BYTES,
        )? {
            ensure!(
                existing == receipt,
                "Concurrent native completion receipts differ"
            );
            return Ok(());
        }
        self.write_signed(
            &root,
            &filename,
            parent,
            "completion",
            &receipt,
            MAX_SMALL_BYTES,
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
    Unknown,
}

impl ChildState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }
    pub fn retryable(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Interrupted)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProgress {
    pub phase: String,
    pub unit: String,
    pub completed: u64,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeChildStatus {
    pub source_id: Uuid,
    pub state: ChildState,
    /// Source terminal DB writes precede joined worker teardown.
    pub worker_running: bool,
    pub progress: Option<NativeProgress>,
}

impl NativeChildStatus {
    pub fn terminal_and_drained(&self) -> bool {
        self.state.terminal() && !self.worker_running
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "presence", rename_all = "snake_case")]
pub enum NativeObservation {
    /// Only an authoritative same-native-StateDb lookup may return Absent.
    /// Timeouts, permissions, failed authentication and unknown states may not.
    Absent {
        source_id: Uuid,
    },
    Present {
        status: NativeChildStatus,
    },
    Unknown {
        source_id: Uuid,
    },
}

impl NativeObservation {
    pub fn source_id(&self) -> Uuid {
        match self {
            Self::Absent { source_id } | Self::Unknown { source_id } => *source_id,
            Self::Present { status } => status.source_id,
        }
    }
}

/// Required hooks to the ACTUAL NativeEngine. No synthetic backend is installed
/// in production. Each submission/replay/retry must pass the exact original
/// `source_id`, authenticated NativeSelection/FullDeletionPlan and this fresh
/// operation-bound publication guard. Returning another source ID is an error.
///
/// `reattach` MUST NOT queue work. Source StartBackup replay validates its real
/// repository/key/selection HMAC and returns the original record without spawn.
/// `retry` may retry only that same source child. `submit` must be idempotent by
/// that ID even if an admission response is lost. Ambiguous acceptance is read
/// back by `observe`; never allocate a replacement ID.
pub trait NativeOperationBackend: Send + Sync + 'static {
    fn publication_guard<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, PublicationGuard>;
    fn observe<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        children: &'a [FrozenChildPlan],
    ) -> OperationFuture<'a, Vec<NativeObservation>>;
    fn reattach<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, ()>;
    fn submit<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, Uuid>;
    fn retry<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
        guard: PublicationGuard,
    ) -> OperationFuture<'a, Uuid>;
    /// Must drain the actual source worker/finalizers, including on cancellation
    /// during commit. Unknown/unreachable is not cancelled or terminal.
    /// Use retained authenticated exact-ID cancellation authority, NOT a fresh
    /// provider write grant: revocation must not prevent draining owned work.
    fn cancel_and_drain<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, NativeObservation>;
    fn finalize_completed<'a>(
        &'a self,
        parent: &'a FrozenPlanSet,
        child: &'a FrozenChildPlan,
    ) -> OperationFuture<'a, CompletionReceipt>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParentState {
    Queued,
    Running,
    Finalizing,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressSum {
    pub phase: String,
    pub unit: String,
    pub completed: u64,
    /// None if ANY contributing actual source sample lacks a total.
    pub total: Option<u64>,
    pub reporting_children: usize,
}

/// Deliberately no percentage: queued apps and different source phases do not
/// have a common denominator. Counts and per-phase/unit sums are real evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationSummary {
    pub operation_id: Uuid,
    pub kind: OperationKind,
    pub state: ParentState,
    pub job_count: usize,
    pub child_count: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub interrupted: usize,
    pub active: usize,
    pub not_started: usize,
    pub unknown: usize,
    pub awaiting_finalization: usize,
    pub cancel_requested: bool,
    pub can_retry: bool,
    pub shutdown_blocked: bool,
    pub progress: Vec<ProgressSum>,
}

pub struct OperationCoordinator {
    bindings: Arc<OperationBindings>,
    backend: Arc<dyn NativeOperationBackend>,
    serial: tokio::sync::Mutex<()>,
}

impl OperationCoordinator {
    pub fn new(bindings: Arc<OperationBindings>, backend: Arc<dyn NativeOperationBackend>) -> Self {
        Self {
            bindings,
            backend,
            serial: tokio::sync::Mutex::new(()),
        }
    }

    /// One bounded scheduling tick. The source has a managed transfer lane; this
    /// starts at most ONE actual child per call and leaves all intra-child
    /// packing/hash/network concurrency to the source. Call again after native
    /// progress/state changes; no full content scans or new plans are made here.
    pub async fn drive(&self, id: Uuid) -> Result<OperationSummary> {
        let _serial = self.serial.lock().await;
        self.drive_locked(id).await
    }

    async fn drive_locked(&self, id: Uuid) -> Result<OperationSummary> {
        let plan = self.bindings.load(id)?;
        let control = self.bindings.control(id)?;
        if control.desired == DesiredState::Cancel {
            self.drain(&plan).await?;
        }
        let mut observations = self.observe_all(&plan).await?;
        self.finalize(&plan, &observations).await?;
        if control.desired == DesiredState::Run {
            // Never add new work while even one source worker or unknown
            // lifecycle is outstanding. Terminal-but-running is still active.
            let busy = observations.values().any(|observation| match observation {
                NativeObservation::Unknown { .. } => true,
                NativeObservation::Present { status } => !status.terminal_and_drained(),
                NativeObservation::Absent { .. } => false,
            });
            if !busy {
                for child in plan.children() {
                    let observation = observations
                        .get(&child.source_id)
                        .context("Actual source observation omitted a frozen child")?;
                    // An authenticated completed child is finalization-only.
                    // A durable receipt also prohibits replay after source DB
                    // rollback/corruption/removal; do not duplicate its work.
                    if self.bindings.completion(id, child)?.is_some() {
                        ensure!(
                            matches!(observation, NativeObservation::Present { status }
                                if status.state==ChildState::Completed && !status.worker_running),
                            "A finalized child disappeared or regressed in the actual source DB"
                        );
                        continue;
                    }
                    match observation {
                        NativeObservation::Absent { .. } => {
                            let guard = self.guard(&plan, child).await?;
                            let returned = self.backend.submit(&plan, child, guard).await?;
                            ensure!(
                                returned == child.source_id,
                                "Source admission changed a frozen child ID"
                            );
                            break;
                        }
                        NativeObservation::Present { status }
                            if status.state.retryable()
                                && control.retry_source_ids.contains(&child.source_id) =>
                        {
                            if self.bindings.retry_spent(
                                id,
                                control.sequence,
                                child.source_id,
                                false,
                            )? {
                                // A consumed retry followed by FAILED may be a
                                // failed new attempt OR an interrupted handoff.
                                // Neither permits another automatic retry.
                                continue;
                            }
                            let guard = self.guard(&plan, child).await?;
                            self.backend
                                .reattach(&plan, child, Arc::clone(&guard))
                                .await?;
                            // Before side effects: a crash can lose this attempt,
                            // not duplicate it. A fresh explicit native retry
                            // may spend a new control record, same source ID.
                            if self.bindings.retry_spent(
                                id,
                                control.sequence,
                                child.source_id,
                                true,
                            )? {
                                // Another coordinator claimed this exact intent
                                // while provider reattachment was in progress.
                                continue;
                            }
                            let returned = self.backend.retry(&plan, child, guard).await?;
                            ensure!(
                                returned == child.source_id,
                                "Source retry changed a frozen child ID"
                            );
                            break;
                        }
                        _ => {}
                    }
                }
                observations = self.observe_all(&plan).await?;
                self.finalize(&plan, &observations).await?;
            } else {
                // Reattach only non-running persisted children. Never replace a
                // live source publication guard or silently start a retry.
                for child in plan.children() {
                    if matches!(observations.get(&child.source_id),
                        Some(NativeObservation::Present { status })
                        if !status.worker_running && !status.state.terminal()
                            && status.state != ChildState::Unknown)
                    {
                        let guard = self.guard(&plan, child).await?;
                        self.backend.reattach(&plan, child, guard).await?;
                    }
                }
            }
        }
        self.summarize(&plan, &control, &observations)
    }

    /// Read-only status uses native source observations, not a private cached
    /// activity's guessed terminal state. Unknown stays non-terminal.
    pub async fn status(&self, id: Uuid) -> Result<OperationSummary> {
        let _serial = self.serial.lock().await;
        let plan = self.bindings.load(id)?;
        let control = self.bindings.control(id)?;
        let observations = self.observe_all(&plan).await?;
        self.summarize(&plan, &control, &observations)
    }

    pub async fn cancel(&self, id: Uuid) -> Result<OperationSummary> {
        let _serial = self.serial.lock().await;
        let plan = self.bindings.load(id)?;
        if self.bindings.control(id)?.desired != DesiredState::Cancel {
            self.bindings
                .record_control(id, DesiredState::Cancel, Vec::new())?;
        }
        self.drain(&plan).await?;
        let observations = self.observe_all(&plan).await?;
        self.finalize(&plan, &observations).await?;
        self.summarize(&plan, &self.bindings.control(id)?, &observations)
    }

    /// Call only after new exact native approval of the retained plan. There is
    /// deliberately no API for replacement roots/apps/provider/child IDs.
    pub async fn retry(&self, id: Uuid) -> Result<OperationSummary> {
        let _serial = self.serial.lock().await;
        let plan = self.bindings.load(id)?;
        let observations = self.observe_all(&plan).await?;
        let mut retry = Vec::new();
        for child in plan.children() {
            let observation = &observations[&child.source_id];
            match observation {
                NativeObservation::Unknown { .. } => {
                    bail!("Unknown source status cannot authorize retry")
                }
                NativeObservation::Present { status } => {
                    ensure!(
                        status.terminal_and_drained(),
                        "Drain the real source operation before retry"
                    );
                    if status.state.retryable() {
                        ensure!(
                            self.bindings.completion(id, child)?.is_none(),
                            "A finalized native child can never be retried"
                        );
                        retry.push(child.source_id);
                    }
                }
                NativeObservation::Absent { .. } => {
                    ensure!(
                        self.bindings.completion(id, child)?.is_none(),
                        "A finalized child is missing from its original source DB"
                    );
                }
            }
        }
        if retry.is_empty()
            && observations.values().all(|observation| {
                matches!(observation,
                NativeObservation::Present { status } if status.state==ChildState::Completed)
            })
        {
            self.finalize(&plan, &observations).await?;
            return self.summarize(&plan, &self.bindings.control(id)?, &observations);
        }
        self.bindings.record_control(id, DesiredState::Run, retry)?;
        self.drive_locked(id).await
    }

    async fn guard(
        &self,
        plan: &FrozenPlanSet,
        child: &FrozenChildPlan,
    ) -> Result<PublicationGuard> {
        self.bindings.ensure_not_cancelled(plan.operation_id)?;
        let native = self.backend.publication_guard(plan, child).await?;
        native()?; // Mandatory before admission AND retained for publication.
        let bindings = Arc::clone(&self.bindings);
        let parent = plan.operation_id;
        Ok(Arc::new(move || {
            bindings.ensure_not_cancelled(parent)?;
            native()
        }))
    }

    async fn observe_all(&self, plan: &FrozenPlanSet) -> Result<BTreeMap<Uuid, NativeObservation>> {
        let mut output = BTreeMap::new();
        for job in &plan.jobs {
            let observations = self.backend.observe(plan, &job.children).await?;
            ensure!(
                observations.len() == job.children.len(),
                "Source observation page has the wrong fixed child count"
            );
            let expected = job
                .children
                .iter()
                .map(|child| child.source_id)
                .collect::<BTreeSet<_>>();
            for observation in observations {
                let id = observation.source_id();
                ensure!(
                    expected.contains(&id) && !output.contains_key(&id),
                    "Source observation added or duplicated a child outside the approved plan"
                );
                if let NativeObservation::Present { status } = &observation {
                    if let Some(progress) = &status.progress {
                        text(&progress.phase, 128)?;
                        text(&progress.unit, 64)?;
                    }
                }
                output.insert(id, observation);
            }
        }
        Ok(output)
    }

    async fn finalize(
        &self,
        plan: &FrozenPlanSet,
        observed: &BTreeMap<Uuid, NativeObservation>,
    ) -> Result<()> {
        for child in plan.children() {
            if matches!(observed.get(&child.source_id),
                Some(NativeObservation::Present { status })
                if status.state==ChildState::Completed && !status.worker_running)
                && self
                    .bindings
                    .completion(plan.operation_id, child)?
                    .is_none()
            {
                let receipt = self.backend.finalize_completed(plan, child).await?;
                self.bindings
                    .record_completion(plan.operation_id, child, receipt)?;
            }
        }
        Ok(())
    }

    async fn drain(&self, plan: &FrozenPlanSet) -> Result<()> {
        let mut failures = 0usize;
        // Drain all fixed source IDs even when one callback errors. An early
        // return here could leave a different real source child publishing.
        for child in plan.children() {
            match self.backend.cancel_and_drain(plan, child).await {
                Ok(observation) if observation.source_id() == child.source_id => {
                    match observation {
                        NativeObservation::Absent { .. } => {}
                        NativeObservation::Present { status } if status.terminal_and_drained() => {}
                        _ => failures += 1,
                    }
                }
                _ => failures += 1,
            }
        }
        ensure!(
            failures == 0,
            "Cancellation remains pending for {failures} real source children; retain native handles"
        );
        Ok(())
    }

    fn summarize(
        &self,
        plan: &FrozenPlanSet,
        control: &Control,
        observed: &BTreeMap<Uuid, NativeObservation>,
    ) -> Result<OperationSummary> {
        let mut output = OperationSummary {
            operation_id: plan.operation_id,
            kind: plan.kind,
            state: ParentState::Queued,
            job_count: plan.jobs.len(),
            child_count: plan.child_count(),
            completed: 0,
            failed: 0,
            cancelled: 0,
            interrupted: 0,
            active: 0,
            not_started: 0,
            unknown: 0,
            awaiting_finalization: 0,
            cancel_requested: control.desired == DesiredState::Cancel,
            can_retry: false,
            shutdown_blocked: true,
            progress: Vec::new(),
        };
        let mut sums = BTreeMap::<(String, String), ProgressSum>::new();
        for child in plan.children() {
            let receipt = self.bindings.completion(plan.operation_id, child)?;
            match observed
                .get(&child.source_id)
                .context("Missing actual source child observation")?
            {
                NativeObservation::Absent { .. } => {
                    ensure!(
                        receipt.is_none(),
                        "A finalized child is absent from its actual source DB"
                    );
                    output.not_started += 1;
                }
                NativeObservation::Unknown { .. } => output.unknown += 1,
                NativeObservation::Present { status } => {
                    if receipt.is_some() {
                        ensure!(
                            status.state == ChildState::Completed && !status.worker_running,
                            "A finalized child regressed in its actual source DB"
                        );
                    }
                    if status.worker_running || !status.state.terminal() {
                        if status.state == ChildState::Unknown {
                            output.unknown += 1;
                        } else {
                            output.active += 1;
                        }
                    } else {
                        match status.state {
                            ChildState::Completed => {
                                if receipt.is_some() {
                                    output.completed += 1;
                                } else {
                                    output.awaiting_finalization += 1;
                                }
                            }
                            ChildState::Failed => output.failed += 1,
                            ChildState::Cancelled => output.cancelled += 1,
                            ChildState::Interrupted => output.interrupted += 1,
                            _ => output.unknown += 1,
                        }
                    }
                    if let Some(progress) = &status.progress {
                        let sum = sums
                            .entry((progress.phase.clone(), progress.unit.clone()))
                            .or_insert_with(|| ProgressSum {
                                phase: progress.phase.clone(),
                                unit: progress.unit.clone(),
                                completed: 0,
                                total: Some(0),
                                reporting_children: 0,
                            });
                        sum.completed = sum
                            .completed
                            .checked_add(progress.completed)
                            .context("Actual source progress sum overflow")?;
                        sum.total = match (sum.total, progress.total) {
                            (Some(left), Some(right)) => Some(
                                left.checked_add(right)
                                    .context("Actual source progress total overflow")?,
                            ),
                            _ => None,
                        };
                        sum.reporting_children += 1;
                    }
                }
            }
        }
        output.progress = sums.into_values().collect();
        output.state = if output.unknown > 0 {
            ParentState::Unknown
        } else if output.active > 0 {
            ParentState::Running
        } else if output.awaiting_finalization > 0 {
            ParentState::Finalizing
        } else if output.completed == output.child_count {
            ParentState::Completed
        } else if output.cancel_requested {
            ParentState::Cancelled
        } else if output.not_started > 0 {
            ParentState::Queued
        } else if output.failed > 0 {
            ParentState::Failed
        } else if output.interrupted > 0 {
            ParentState::Interrupted
        } else if output.cancelled > 0 {
            ParentState::Cancelled
        } else {
            ParentState::Unknown
        };
        output.shutdown_blocked = matches!(
            output.state,
            ParentState::Unknown | ParentState::Running | ParentState::Finalizing
        ) || output.not_started > 0 && !output.cancel_requested;
        output.can_retry = !output.shutdown_blocked
            && (output.failed + output.cancelled + output.interrupted > 0
                || output.cancel_requested && output.not_started > 0);
        Ok(output)
    }
}

fn not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|error| {
        error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn sync_private_root(path: &Path, root: &SafeRoot) -> Result<()> {
    let expected = root.identity()?;
    ensure_private_directory(path)?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        let file = File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.dev() == expected.device
                && [metadata.ino(), 0] == expected.file_id,
            "Private operation flush handle differs from its pinned native directory"
        );
        file.sync_all()
            .context("Flush actual private operation directory")?;
    }
    #[cfg(windows)]
    quicksave_platform::PrivateDirectory::open(path)?.flush()?;
    #[cfg(not(any(unix, windows)))]
    bail!("Native private-directory durability is unsupported on this platform");
    ensure!(
        root.identity()? == expected,
        "Private operation directory changed during durable flush"
    );
    Ok(())
}

fn text(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "Frozen native identity is empty, invalid or oversized"
    );
    Ok(())
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid frozen native scope/plan digest"
    );
    Ok(())
}

fn signing_scope(record: &Value) -> Result<Value> {
    // Native authority registries often bound scopes to 128 KiB. Authenticate
    // the entire canonical record via a digest without handing the vault a
    // megabyte-sized inventory or doing one vault lookup per file/chunk.
    let bytes = bounded_json(record, MAX_CHUNK_BYTES)?;
    Ok(json!({
        "domain":JOURNAL_DOMAIN,
        "operationId":record["operationId"],
        "recordType":record["recordType"],
        "recordName":record["recordName"],
        "contentDigest":blake3::hash(&bytes).to_hex().to_string(),
    }))
}

fn validate_signature(signature: &Value) -> Result<()> {
    bounded_json(signature, MAX_SIGNATURE_BYTES)?;
    let fields = signature
        .as_object()
        .context("Native binding MAC envelope is missing")?;
    ensure!(
        fields.keys().all(|key| [
            "version",
            "algorithm",
            "mac",
            "kind",
            "nonce",
            "authorityRef",
        ]
        .contains(&key.as_str()))
            && signature["version"] == 1
            && matches!(
                signature["algorithm"].as_str(),
                Some("hmac-sha256" | "keyed-blake3")
            ),
        "Native binding signature has unsupported/private fields or algorithm"
    );
    digest(
        signature["mac"]
            .as_str()
            .context("Native binding MAC is missing")?,
    )?;
    if let Some(kind) = signature.get("kind") {
        text(kind.as_str().context("Invalid native MAC grant kind")?, 64)?;
    }
    if let Some(nonce) = signature.get("nonce") {
        digest(nonce.as_str().context("Invalid native MAC grant nonce")?)?;
    }
    if let Some(reference) = signature.get("authorityRef") {
        text(
            reference
                .as_str()
                .context("Invalid native MAC grant reference")?,
            256,
        )?;
    }
    Ok(())
}

fn bounded_json(value: &impl Serialize, max: usize) -> Result<Vec<u8>> {
    struct Count {
        size: usize,
        max: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.size = self
                .size
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("Operation record size overflow"))?;
            if self.size > self.max {
                return Err(std::io::Error::other(
                    "Operation record exceeds its private bound",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Count { size: 0, max }, value)?;
    Ok(serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FixtureSigner([u8; 32]);
    impl StoreSigner for FixtureSigner {
        fn seal(&self, scope: &Value) -> Result<Value> {
            Ok(json!({"version":1,"algorithm":"keyed-blake3",
                "mac":blake3::keyed_hash(&self.0,&serde_json::to_vec(scope)?).to_hex().to_string()}))
        }
        fn verify(&self, scope: &Value, signature: &Value) -> Result<bool> {
            Ok(self.seal(scope)? == *signature)
        }
    }

    #[derive(Default)]
    struct FixtureBackend {
        states: Mutex<BTreeMap<Uuid, NativeChildStatus>>,
        unknown: Mutex<BTreeSet<Uuid>>,
        events: Mutex<Vec<(&'static str, Uuid)>>,
        guards: Mutex<BTreeMap<Uuid, PublicationGuard>>,
        allowed: Arc<AtomicBool>,
        complete_immediately: AtomicBool,
        fail_cancellation: Mutex<BTreeSet<Uuid>>,
    }

    impl FixtureBackend {
        fn new() -> Self {
            Self {
                allowed: Arc::new(AtomicBool::new(true)),
                ..Self::default()
            }
        }
        fn set(&self, id: Uuid, state: ChildState, running: bool) {
            self.states.lock().unwrap().insert(
                id,
                NativeChildStatus {
                    source_id: id,
                    state,
                    worker_running: running,
                    progress: None,
                },
            );
        }
        fn observation(&self, id: Uuid) -> NativeObservation {
            if self.unknown.lock().unwrap().contains(&id) {
                return NativeObservation::Unknown { source_id: id };
            }
            match self.states.lock().unwrap().get(&id).cloned() {
                Some(status) => NativeObservation::Present { status },
                None => NativeObservation::Absent { source_id: id },
            }
        }
        fn admissions(&self, kind: &str) -> Vec<Uuid> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|(event, _)| *event == kind)
                .map(|(_, id)| *id)
                .collect()
        }
        fn admit(
            &self,
            child: &FrozenChildPlan,
            guard: PublicationGuard,
            kind: &'static str,
        ) -> Result<Uuid> {
            guard()?;
            self.events.lock().unwrap().push((kind, child.source_id));
            self.guards.lock().unwrap().insert(child.source_id, guard);
            let complete = self.complete_immediately.load(Ordering::SeqCst);
            self.set(
                child.source_id,
                if complete {
                    ChildState::Completed
                } else {
                    ChildState::Running
                },
                !complete,
            );
            Ok(child.source_id)
        }
    }

    impl NativeOperationBackend for FixtureBackend {
        fn publication_guard<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            _: &'a FrozenChildPlan,
        ) -> OperationFuture<'a, PublicationGuard> {
            Box::pin(async move {
                let allowed = Arc::clone(&self.allowed);
                let guard: PublicationGuard = Arc::new(move || {
                    ensure!(
                        allowed.load(Ordering::SeqCst),
                        "Fixture native publication authority was revoked"
                    );
                    Ok(())
                });
                Ok(guard)
            })
        }
        fn observe<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            children: &'a [FrozenChildPlan],
        ) -> OperationFuture<'a, Vec<NativeObservation>> {
            Box::pin(async move {
                ensure!(
                    children.len() <= MAX_CHILDREN_PER_JOB,
                    "Fixture source page exceeded bound"
                );
                Ok(children
                    .iter()
                    .map(|child| self.observation(child.source_id))
                    .collect())
            })
        }
        fn reattach<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            child: &'a FrozenChildPlan,
            guard: PublicationGuard,
        ) -> OperationFuture<'a, ()> {
            Box::pin(async move {
                guard()?;
                self.events
                    .lock()
                    .unwrap()
                    .push(("reattach", child.source_id));
                ensure!(
                    self.states.lock().unwrap().contains_key(&child.source_id),
                    "Fixture original source row missing"
                );
                Ok(())
            })
        }
        fn submit<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            child: &'a FrozenChildPlan,
            guard: PublicationGuard,
        ) -> OperationFuture<'a, Uuid> {
            Box::pin(async move {
                if self.states.lock().unwrap().contains_key(&child.source_id) {
                    return Ok(child.source_id); // fixture source idempotent replay, no new worker
                }
                self.admit(child, guard, "submit")
            })
        }
        fn retry<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            child: &'a FrozenChildPlan,
            guard: PublicationGuard,
        ) -> OperationFuture<'a, Uuid> {
            Box::pin(async move {
                let old = self
                    .states
                    .lock()
                    .unwrap()
                    .get(&child.source_id)
                    .cloned()
                    .context("Fixture source retry row missing")?;
                ensure!(
                    old.terminal_and_drained() && old.state.retryable(),
                    "Fixture completed/active source retry rejected"
                );
                self.admit(child, guard, "retry")
            })
        }
        fn cancel_and_drain<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            child: &'a FrozenChildPlan,
        ) -> OperationFuture<'a, NativeObservation> {
            Box::pin(async move {
                self.events
                    .lock()
                    .unwrap()
                    .push(("cancel_and_drain", child.source_id));
                ensure!(
                    !self
                        .fail_cancellation
                        .lock()
                        .unwrap()
                        .contains(&child.source_id),
                    "Fixture real child could not drain"
                );
                if let Some(status) = self.states.lock().unwrap().get_mut(&child.source_id) {
                    if !status.state.terminal() {
                        status.state = ChildState::Cancelled;
                    }
                    status.worker_running = false;
                }
                self.guards.lock().unwrap().remove(&child.source_id);
                Ok(self.observation(child.source_id))
            })
        }
        fn finalize_completed<'a>(
            &'a self,
            _: &'a FrozenPlanSet,
            child: &'a FrozenChildPlan,
        ) -> OperationFuture<'a, CompletionReceipt> {
            Box::pin(async move {
                let status = self
                    .states
                    .lock()
                    .unwrap()
                    .get(&child.source_id)
                    .cloned()
                    .context("Fixture source receipt missing")?;
                ensure!(
                    status.state == ChildState::Completed && !status.worker_running,
                    "Fixture source worker/receipt is not durably complete"
                );
                self.events
                    .lock()
                    .unwrap()
                    .push(("finalize", child.source_id));
                self.guards.lock().unwrap().remove(&child.source_id);
                Ok(CompletionReceipt {
                    source_id: child.source_id,
                    native_plan_digest: child.native_plan_digest.clone(),
                    receipt_digest: blake3::hash(child.source_id.as_bytes())
                        .to_hex()
                        .to_string(),
                })
            })
        }
    }

    fn child(index: usize) -> FrozenChildPlan {
        FrozenChildPlan {
            source_id: Uuid::new_v4(),
            native_plan_id: Uuid::new_v4(),
            native_plan_digest: "a".repeat(64),
            app_id: format!("desktop:fixture-{index}"),
            software_id: Some(format!("fixture-{index}")),
            source_revision: format!("fixture-revision-{index}"),
            roots_fingerprint: "b".repeat(64),
            roots: vec![FrozenRootBinding {
                root_id: "fixture-root".into(),
                identity_digest: "c".repeat(64),
            }],
            mode: Some("complete_application".into()),
            bundle_id: None,
        }
    }
    fn plan(count: usize) -> FrozenPlanSet {
        FrozenPlanSet::from_children(
            Uuid::new_v4(),
            OperationKind::Upload,
            SelectionIntent::AllApprovedApps,
            "fixture-provider".into(),
            "d".repeat(64),
            "e".repeat(64),
            (0..count).map(child).collect(),
        )
        .unwrap()
    }
    fn storage() -> (tempfile::TempDir, PathBuf, Arc<OperationBindings>) {
        let temp = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(temp.path()).unwrap().join("bindings");
        let bindings =
            Arc::new(OperationBindings::open(&path, Arc::new(FixtureSigner([7; 32]))).unwrap());
        (temp, path, bindings)
    }

    #[test]
    fn real_private_storage_reopens_fixed_signed_plan_chunks_and_rejects_changed_mac() {
        let (_temp, path, bindings) = storage();
        let frozen = plan(129);
        let id = bindings.freeze(frozen.clone()).unwrap();
        assert_eq!(bindings.plan_page(id, 0).unwrap().children.len(), 128);
        assert_eq!(bindings.plan_page(id, 1).unwrap().children.len(), 1);
        drop(bindings);
        let reopened = OperationBindings::open(&path, Arc::new(FixtureSigner([7; 32]))).unwrap();
        assert_eq!(reopened.load(id).unwrap(), frozen);
        drop(reopened);
        let wrong_key = OperationBindings::open(&path, Arc::new(FixtureSigner([8; 32]))).unwrap();
        assert!(wrong_key.load(id).is_err());
    }

    #[test]
    fn corrupt_unsigned_and_wrong_provider_records_never_authorize_source_work() {
        let (_temp, path, bindings) = storage();
        let frozen = plan(1);
        let id = bindings.freeze(frozen).unwrap();
        let file = path.join(format!("operation-{id}/binding.json"));
        let mut document: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        document["scope"]["payload"]["providerId"] = json!("different-provider");
        std::fs::write(&file, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(bindings.load(id).is_err());
        std::fs::write(
            &file,
            br#"{"providerId":"fixture-provider","approved":true}"#,
        )
        .unwrap();
        assert!(bindings.load(id).is_err());
        let unknown = Uuid::new_v4();
        assert!(bindings.load(unknown).is_err());
        assert!(
            !path.join(format!("operation-{unknown}")).exists(),
            "unknown reads cannot create state"
        );
        assert!(validate_signature(&json!({
            "version":1,"algorithm":"keyed-blake3","mac":"a".repeat(64),"repositoryKey":"never-store-keys",
        })).is_err());
    }

    #[test]
    fn frozen_limits_reject_duplicate_apps_ids_roots_and_raw_all() {
        let mut frozen = plan(2);
        frozen.jobs[0].children[1].app_id = "*".into();
        assert!(frozen.validate().is_err());
        frozen = plan(2);
        frozen.jobs[0].children[1].source_id = frozen.jobs[0].children[0].source_id;
        assert!(frozen.validate().is_err());
        frozen = plan(2);
        frozen.jobs[0].children[1].app_id = frozen.jobs[0].children[0].app_id.clone();
        assert!(frozen.validate().is_err());
        let max = plan(MAX_APPS_PER_PLAN);
        assert_eq!(max.jobs.len(), 32);
        assert_eq!(max.child_count(), 4096);
        assert!(FrozenPlanSet::from_children(
            Uuid::new_v4(),
            OperationKind::Upload,
            SelectionIntent::AllApprovedApps,
            "fixture".into(),
            "d".repeat(64),
            "e".repeat(64),
            (0..4097).map(child).collect()
        )
        .is_err());
    }

    #[tokio::test]
    async fn restart_finalizes_but_never_reruns_completed_children_or_adds_late_apps() {
        let (_temp, path, bindings) = storage();
        let frozen = plan(2);
        let ids = frozen
            .children()
            .map(|child| child.source_id)
            .collect::<Vec<_>>();
        let id = bindings.freeze(frozen.clone()).unwrap();
        let backend = Arc::new(FixtureBackend::new());
        backend.complete_immediately.store(true, Ordering::SeqCst);
        let coordinator = OperationCoordinator::new(bindings.clone(), backend.clone());
        coordinator.drive(id).await.unwrap();
        let late = child(99);
        backend.set(late.source_id, ChildState::Interrupted, false);
        drop(coordinator);
        drop(bindings);
        let reopened =
            Arc::new(OperationBindings::open(&path, Arc::new(FixtureSigner([7; 32]))).unwrap());
        let coordinator = OperationCoordinator::new(reopened, backend.clone());
        let final_state = coordinator.drive(id).await.unwrap();
        assert_eq!(final_state.state, ParentState::Completed);
        assert_eq!(final_state.completed, 2);
        assert_eq!(backend.admissions("submit"), ids);
        assert!(!backend.admissions("submit").contains(&late.source_id));
        coordinator.drive(id).await.unwrap();
        assert_eq!(backend.admissions("submit").len(), 2);
        assert_eq!(backend.admissions("finalize").len(), 2);
        assert!(backend.admissions("retry").is_empty());
    }

    #[tokio::test]
    async fn unknown_and_terminal_but_running_children_do_not_finish_or_admit_more_work() {
        let (_temp, _path, bindings) = storage();
        let frozen = plan(2);
        let first = frozen.jobs[0].children[0].source_id;
        let id = bindings.freeze(frozen).unwrap();
        let backend = Arc::new(FixtureBackend::new());
        backend.set(first, ChildState::Completed, true);
        let coordinator = OperationCoordinator::new(bindings, backend.clone());
        let status = coordinator.drive(id).await.unwrap();
        assert!(status.shutdown_blocked);
        assert_eq!(status.active, 1);
        assert!(backend.admissions("submit").is_empty());
        assert!(backend.admissions("finalize").is_empty());
        backend.set(first, ChildState::Unknown, false);
        let status = coordinator.drive(id).await.unwrap();
        assert_eq!(status.state, ParentState::Unknown);
        assert!(status.shutdown_blocked);
        assert!(coordinator.retry(id).await.is_err());
    }

    #[tokio::test]
    async fn cancellation_is_durable_drains_every_real_id_and_revokes_retained_guard() {
        let (_temp, _path, bindings) = storage();
        let frozen = plan(3);
        let ids = frozen
            .children()
            .map(|child| child.source_id)
            .collect::<Vec<_>>();
        let id = bindings.freeze(frozen).unwrap();
        let backend = Arc::new(FixtureBackend::new());
        let coordinator = OperationCoordinator::new(bindings.clone(), backend.clone());
        coordinator.drive(id).await.unwrap();
        let retained = backend
            .guards
            .lock()
            .unwrap()
            .get(&ids[0])
            .cloned()
            .unwrap();
        retained().unwrap();
        backend.fail_cancellation.lock().unwrap().insert(ids[1]);
        assert!(coordinator.cancel(id).await.is_err());
        assert_eq!(backend.admissions("cancel_and_drain"), ids);
        assert!(bindings.ensure_not_cancelled(id).is_err());
        assert!(
            retained().is_err(),
            "late source publication must not use the old callback"
        );
        backend.fail_cancellation.lock().unwrap().clear();
        let status = coordinator.drive(id).await.unwrap();
        assert_eq!(status.state, ParentState::Cancelled);
        assert!(!status.shutdown_blocked);
        assert_eq!(backend.admissions("submit"), vec![ids[0]]);
    }

    #[tokio::test]
    async fn explicit_retry_only_reattaches_same_failed_child_once_and_preserves_completed_child() {
        let (_temp, _path, bindings) = storage();
        let frozen = plan(2);
        let ids = frozen
            .children()
            .map(|child| child.source_id)
            .collect::<Vec<_>>();
        let id = bindings.freeze(frozen).unwrap();
        let backend = Arc::new(FixtureBackend::new());
        backend.set(ids[0], ChildState::Completed, false);
        backend.set(ids[1], ChildState::Interrupted, false);
        let coordinator = OperationCoordinator::new(bindings, backend.clone());
        assert_eq!(
            coordinator.drive(id).await.unwrap().state,
            ParentState::Interrupted
        );
        coordinator.retry(id).await.unwrap();
        assert_eq!(backend.admissions("retry"), vec![ids[1]]);
        assert_eq!(backend.admissions("reattach"), vec![ids[1]]);
        backend.set(ids[1], ChildState::Failed, false);
        coordinator.drive(id).await.unwrap();
        assert_eq!(
            backend.admissions("retry"),
            vec![ids[1]],
            "spent admission cannot automatically repeat"
        );
        coordinator.retry(id).await.unwrap();
        assert_eq!(backend.admissions("retry"), vec![ids[1], ids[1]]);
        assert!(backend.admissions("submit").is_empty());
        assert_eq!(backend.admissions("finalize"), vec![ids[0]]);
    }

    #[tokio::test]
    async fn native_guard_failure_is_not_default_success_and_real_progress_is_summed_by_phase_unit()
    {
        let (_temp, _path, bindings) = storage();
        let frozen = plan(2);
        let ids = frozen
            .children()
            .map(|child| child.source_id)
            .collect::<Vec<_>>();
        let id = bindings.freeze(frozen).unwrap();
        let backend = Arc::new(FixtureBackend::new());
        backend.allowed.store(false, Ordering::SeqCst);
        let coordinator = OperationCoordinator::new(bindings, backend.clone());
        assert!(coordinator.drive(id).await.is_err());
        assert!(backend.admissions("submit").is_empty());
        for (index, id) in ids.iter().enumerate() {
            backend.states.lock().unwrap().insert(
                *id,
                NativeChildStatus {
                    source_id: *id,
                    state: ChildState::Running,
                    worker_running: true,
                    progress: Some(NativeProgress {
                        phase: "uploading".into(),
                        unit: "bytes".into(),
                        completed: 7 + index as u64,
                        total: if index == 0 { Some(20) } else { None },
                    }),
                },
            );
        }
        let status = coordinator.status(id).await.unwrap();
        assert_eq!(status.progress[0].completed, 15);
        assert_eq!(status.progress[0].total, None);
        assert_eq!(status.progress[0].reporting_children, 2);
        assert!(!serde_json::to_string(&status).unwrap().contains("percent"));
    }

    #[cfg(unix)]
    #[test]
    fn private_storage_rejects_symlinked_root_without_touching_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let outside = root.join("outside-fixture");
        ensure_private_directory(&outside).unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        assert!(
            OperationBindings::open(&root.join("linked"), Arc::new(FixtureSigner([7; 32])))
                .is_err()
        );
        assert!(std::fs::read_dir(outside).unwrap().next().is_none());
    }
}
