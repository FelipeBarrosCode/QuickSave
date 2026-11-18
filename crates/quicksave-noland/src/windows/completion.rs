// SPDX-License-Identifier: GPL-3.0-only
//! One-time native Saved barrier. Prepared files and unsigned DB state are not
//! publication authority. Uses this Windows adapter's actual QSWREC1 + No Land
//! metadata envelopes, never the Unix source agent's private envelope schema.
use super::*;
use noland_state_core::{bundle_dir, BundleManifest};
use noland_storage::{RemoteKey, SharedStorageProvider};
use serde::{Deserialize, Serialize};
#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;

const MAX_BINDING: usize = 128 * 1024;
const MAX_RETAINED: usize = 128;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const POST_COMMIT: &str = "capture-committed.enc";
const DRAINED: &str = "capture-drained.enc";

#[derive(Default)]
pub(super) struct CompletionState {
    store: Option<WorkspaceStore>,
    accepted: BTreeMap<Uuid, Accepted>,
    pending: BTreeMap<Uuid, DrainReceipt>,
    retained: BTreeMap<Uuid, Retained>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    operation: Uuid,
    plan_hash: String,
    source_auth: Value,
    capture_receipt: Value,
}

struct Retained {
    access: Arc<PrivateAccess>,
    created: Instant,
    bytes: usize,
    verified: Option<(String, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitReceipt {
    version: u32,
    operation: Uuid,
    instance: Uuid,
    repository_binding: String,
    accepted: Accepted,
    marker: String,
    manifest: BundleManifest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainReceipt {
    version: u32,
    operation: Uuid,
    instance: Uuid,
    plan_hash: String,
    repository_binding: String,
    committed_receipt_hash: String,
    source_auth_hash: String,
    capture_receipt_hash: String,
    bundle: Uuid,
    commit: Uuid,
}

pub(super) fn bind_workspace(inner: &Inner, store: WorkspaceStore) -> Result<()> {
    let mut state = inner.completion.lock().map_err(poison)?;
    ensure!(
        state.store.is_none(),
        "native completion workspace is already installed"
    );
    state.store = Some(store);
    Ok(())
}

fn workspace(inner: &Inner) -> Result<WorkspaceStore> {
    inner
        .completion
        .lock()
        .map_err(poison)?
        .store
        .clone()
        .context("native completion workspace is unavailable")
}

fn plan_hash(plan: &FrozenPlan) -> Result<String> {
    full_scope::metadata_digest(plan)
}

fn repository_binding(access: &PrivateAccess) -> Result<String> {
    ensure!(
        access.authority_revision.is_some(),
        "original native provider authority revision is unavailable"
    );
    let mut hash = blake3::Hasher::new_keyed(&access.master.0);
    hash.update(b"QuickSave/windows-original-capture-repository/v1\0");
    hash.update(&serde_json::to_vec(&(
        &access.provider,
        access.session.storage_identity(),
        access.read_only,
        access.authority_revision,
    ))?);
    Ok(hash.finalize().to_hex().to_string())
}

fn upload_context(
    plan: &FrozenPlan,
) -> Result<(&str, &str, &AppId, &CaptureScope, &CaptureOrigin)> {
    let Work::Upload {
        software,
        software_instance_id,
        app,
        capture_scope: Some(scope),
        capture_origin: Some(origin),
        ..
    } = &plan.work
    else {
        bail!("original actual native capture scope/generation is unavailable; explicit reconciliation is required")
    };
    Ok((software, software_instance_id, app, scope, origin))
}

pub(super) fn expected_files_hash(manifest: &BundleManifest) -> Result<String> {
    let mut files = BTreeMap::new();
    ensure!(
        manifest.files.len() <= MAX_FILES,
        "native captured-file receipt bound exceeded"
    );
    for file in &manifest.files {
        let id = file_id(&file.logical_root, &file.relative_path);
        let value = match file.file_type.as_str() {
            "file" => {
                let raw = file
                    .file_hash
                    .strip_prefix("blake3:")
                    .filter(|hash| full_scope::raw_hash(hash))
                    .context("actual native captured file lacks its canonical content hash")?;
                json!({"id":id,"fileHash":raw,"size":file.size})
            }
            "directory" => json!({"id":id,"kind":"directory","size":0}),
            "symlink" => json!({"id":id,"kind":"symlink","size":0,
                "linkTargetHash":blake3::hash(file.symlink_target.as_deref()
                    .context("actual native captured link has no target")?.as_bytes()).to_hex().to_string()}),
            _ => bail!("unknown actual native captured file kind"),
        };
        ensure!(
            files.insert(id, value).is_none(),
            "actual captured native IDs are duplicated"
        );
    }
    full_scope::metadata_digest(&files.into_values().collect::<Vec<_>>())
}

fn full_proof_hash(plan: &FrozenPlan) -> Result<String> {
    let Work::Upload { full_snapshot, .. } = &plan.work else {
        bail!("not a native capture")
    };
    full_scope::metadata_digest(
        &full_snapshot
            .as_ref()
            .map(|full| &full.evidence["expectedFullScope"])
            .unwrap_or(&Value::Null),
    )
}

fn current_tracking(record: &Value) -> Result<Value> {
    let roots = record["roots"]
        .as_array()
        .context("current native tracking roots are missing")?;
    ensure!(
        !roots.is_empty() && roots.len() <= 128,
        "current native root bound is invalid"
    );
    let roots = roots.iter().map(|root| {
        let mut value = json!({"id":root["id"],"path":root["path"],"role":root["role"],
            "identity":root["identity"],"allowedFiles":root.get("allowedFiles").unwrap_or(&Value::Null)});
        if root["directory"] == false { value["directory"] = json!(false); }
        value
    }).collect::<Vec<_>>();
    let mut scope =
        json!({"version":1,"softwareId":record["id"],"appId":record["appId"],"roots":roots});
    if let Some(identity) = record
        .get("sourceIdentity")
        .filter(|value| !value.is_null())
    {
        scope["sourceIdentity"] = identity.clone();
    }
    if let Some(auto) = record
        .get("autoEnrollment")
        .filter(|value| !value.is_null())
    {
        scope["autoEnrollment"] = json!({
            "policyHash":full_scope::metadata_digest(&auto["policyScope"])?,
            "discoveryHash":full_scope::metadata_digest(&auto["discoveryScope"])?,
            "appEvidenceHash":auto["appEvidenceHash"],"candidateHash":auto["candidateHash"],
            "coverageHash":full_scope::metadata_digest(&json!({
                "rootsComplete":auto["rootsComplete"],"unresolvedRoots":auto["unresolvedRoots"],
                "unresolvedReasons":auto["unresolvedReasons"],
            }))?,
        });
    }
    bounded(&scope, MAX_BINDING)?;
    Ok(scope)
}

fn verify_scope(
    plan: &FrozenPlan,
    source_auth: &Value,
    receipt: &Value,
    files_hash: &str,
) -> Result<()> {
    let (software, _, _, capture, origin) = upload_context(plan)?;
    let scope = &receipt["scope"];
    let Work::Upload { bundle, .. } = &plan.work else {
        bail!("not native capture")
    };
    ensure!(
        scope["version"] == 1
            && scope["softwareId"] == software
            && scope["providerId"] == plan.provider
            && scope["workId"] == capture.work_id
            && scope["generation"].as_u64() == Some(origin.generation)
            && scope["metadataIdentity"] == capture.metadata_identity
            && scope["sourceSnapshotId"] == bundle.to_string()
            && scope["immutablePreparedCapture"] == true
            && receipt["grant"].is_object()
            && scope["sourceExpectedManifestAuthHash"] == full_scope::metadata_digest(source_auth)?
            && scope["expectedFilesHash"] == files_hash
            && scope["fullScopeProofHash"] == full_proof_hash(plan)?
            && scope["trackingScopeHash"]
                == full_scope::metadata_digest(&origin.authorization["trackingScope"])?,
        "native tracking receipt does not bind the actual original captured hashes/scope"
    );
    for field in [
        "capturedSnapshotIdentity",
        "expectedFilesHash",
        "sourceExpectedManifestAuthHash",
        "fullScopeProofHash",
        "trackingScopeHash",
    ] {
        ensure!(
            scope[field].as_str().is_some_and(full_scope::raw_hash),
            "native tracking receipt has an invalid metadata digest"
        );
    }
    Ok(())
}

type CheckGrant<'a> = dyn Fn(&str, &Value, &Value) -> Result<bool> + 'a;

/// Current settings only, not current file contents. A newer dirty generation
/// remains dirty: this barrier never writes state or substitutes its generation.
fn check_current(
    store: &WorkspaceStore,
    plan: &FrozenPlan,
    access: &PrivateAccess,
    receipt: &Value,
    grant: &CheckGrant<'_>,
) -> Result<Value> {
    let (software, instance, app, _, origin) = upload_context(plan)?;
    let record = store.software_record(software)?;
    let document = store.document()?;
    let provider = document
        .providers
        .iter()
        .find(|provider| provider.id == plan.provider)
        .context("original native provider is unavailable")?;
    let tracking = current_tracking(&record)?;
    ensure!(
        record["id"] == software
            && record["appId"] == instance
            && record["sourceIdentity"]["app_id"] == app.as_str()
            && record["providerId"] == plan.provider
            && record["tracked"] == true
            && provider.status == "connected"
            && !provider.read_only
            && !access.read_only
            && access.authority_revision == Some(provider.authority_revision)
            && tracking == origin.authorization["trackingScope"]
            && record["trackingGrant"] == origin.authorization["trackingGrant"]
            && record["captureReceipt"]["scope"] == receipt["scope"]
            && record["captureReceipt"]["grant"] == receipt["grant"]
            && record["dirtyGeneration"]
                .as_u64()
                .is_some_and(|generation| generation >= origin.generation),
        "current native provider/instance/root/receipt authority differs from the original capture"
    );
    ensure!(
        grant("tracking", &tracking, &record["trackingGrant"])?
            && grant(
                "tracking_capture_receipt",
                &receipt["scope"],
                &receipt["grant"]
            )?,
        "original native tracking/capture receipt MAC is unavailable or revoked"
    );
    let reference = &record["captureReceipt"]["reference"];
    let name = reference["name"]
        .as_str()
        .context("original capture sidecar reference is missing")?;
    validate_relative(name)?;
    ensure!(
        !name.contains('/')
            && reference["hash"].as_str().is_some_and(full_scope::raw_hash)
            && reference["scope"]["captureScope"] == receipt["scope"]
            && reference["scope"]["tracking"] == tracking
            && reference["scope"]["name"] == reference["name"]
            && reference["scope"]["hash"] == reference["hash"]
            && grant(
                "tracking_capture_receipt_sidecar",
                &reference["scope"],
                &reference["grant"]
            )?,
        "original native capture sidecar binding is unavailable or revoked"
    );
    if origin.automatic || record["autosave"] == true {
        let autosave = json!({"version":1,"tracking":tracking,"providerId":plan.provider});
        ensure!(
            record["autosave"] == true && grant("autosave", &autosave, &record["autosaveGrant"])?,
            "original automatic capture authorization is unavailable or revoked"
        );
        if origin.automatic {
            ensure!(
                origin.authorization["autosaveScope"] == autosave
                    && origin.authorization["autosaveGrant"] == record["autosaveGrant"],
                "automatic capture differs from its original frozen native grant"
            );
        }
    }
    if let Work::Upload {
        full_snapshot: Some(full),
        ..
    } = &plan.work
    {
        let proof = &full.evidence["expectedFullScope"];
        ensure!(
            grant("tracking_full_capture", &proof["scope"], &proof["grant"])?,
            "original full-scope capture MAC is unavailable or revoked"
        );
        let baseline = &full.evidence["baseline"];
        if baseline["kind"] != "none" {
            ensure!(
                grant(
                    "tracking_baseline",
                    &baseline["scope"],
                    &baseline["reference"]["grant"]
                )?,
                "original full-scope baseline MAC is unavailable or revoked"
            );
        }
    }
    if let Some(auto) = record
        .get("autoEnrollment")
        .filter(|value| !value.is_null())
    {
        ensure!(
            grant(
                "app_tracking_policy",
                &auto["policyScope"],
                &auto["policyGrant"]
            )? && grant(
                "bundle_discovery",
                &auto["discoveryScope"],
                &auto["discoveryGrant"]
            )?,
            "native discovery/policy authority changed after actual capture"
        );
    }
    Ok(record)
}

/// Fresh WorkspaceStore MAC/nonce verification is permitted here, once, inside
/// actual capture acceptance, BEFORE visibility publication and finalization.
pub(super) fn accepted(
    inner: &Inner,
    job: &Job,
    manifest: &BundleManifest,
    source_auth: &Value,
) -> Result<()> {
    let store = workspace(inner)?;
    let (software, _, _, _, _) = upload_context(&job.plan)?;
    let record = store.software_record(software)?;
    let receipt = json!({"scope":record["captureReceipt"]["scope"],"grant":record["captureReceipt"]["grant"]});
    verify_scope(
        &job.plan,
        source_auth,
        &receipt,
        &expected_files_hash(manifest)?,
    )?;
    let checked = check_current(
        &store,
        &job.plan,
        &job.access,
        &receipt,
        &|kind, scope, grant| store.verify_grant(kind, scope, grant),
    )?;
    ensure!(
        checked["captureReceipt"]["scope"] == receipt["scope"],
        "native receipt changed during source acceptance"
    );
    let accepted = Accepted {
        operation: job.plan.operation,
        plan_hash: plan_hash(&job.plan)?,
        source_auth: source_auth.clone(),
        capture_receipt: receipt,
    };
    bounded(&accepted, MAX_BINDING)?;
    let mut state = inner.completion.lock().map_err(poison)?;
    ensure!(
        state.accepted.len() < MAX_RETAINED || state.accepted.contains_key(&job.plan.operation),
        "native completion acceptance cache is full"
    );
    state.accepted.insert(job.plan.operation, accepted);
    Ok(())
}

fn directory(inner: &Inner, operation: Uuid) -> Result<pipeline::ReceiptDirectory> {
    // No create-missing fallback at completion/recovery.
    pipeline::ReceiptDirectory::open(
        inner,
        &inner.paths.packs.join(format!("native-upload-{operation}")),
    )
}

/// Real post-COMMITTED readback, on the owned worker. Marker is the source's
/// canonical UUID text; manifest decoding is the shared No Land NLNE/NLZ1 AEAD
/// decoder. A prepared envelope or DB commit row is not used as readback.
pub(super) async fn record_committed(
    inner: &Inner,
    job: &Job,
    provider: &dyn SharedStorageProvider,
    prepared: &BundleManifest,
) -> Result<()> {
    if job.controller.is_none() {
        return Ok(());
    }
    let accepted = inner
        .completion
        .lock()
        .map_err(poison)?
        .accepted
        .get(&job.plan.operation)
        .cloned()
        .context("original accepted native capture proof is missing")?;
    let marker_key = RemoteKey::new(format!(
        "{}/COMMITTED",
        bundle_dir(&prepared.app.app_id, prepared.bundle_id)
    ));
    let marker = provider
        .read_small(&marker_key, 64)
        .await
        .map_err(source_error)?;
    let marker = std::str::from_utf8(&marker)
        .context("source COMMITTED marker is not canonical UUID text")?;
    ensure!(
        marker == prepared.commit_id.to_string(),
        "actual source COMMITTED marker belongs to another publication"
    );
    let actual = read_committed_manifest(
        provider,
        &job.access.master,
        &prepared.app.app_id,
        prepared.bundle_id,
    )
    .await
    .map_err(source_error)?;
    ensure!(
        full_scope::metadata_digest(&actual)? == full_scope::metadata_digest(prepared)?,
        "actual authenticated COMMITTED manifest differs from immutable prepared capture"
    );
    pipeline::validate_captured_manifest(&actual, &job.plan)?;
    verify_scope(
        &job.plan,
        &accepted.source_auth,
        &accepted.capture_receipt,
        &expected_files_hash(&actual)?,
    )?;
    catalog::remember_manifest(inner, &job.access, &actual)?;
    let repository = repository_binding(&job.access)?;
    let bundle = actual.bundle_id;
    let commit = actual.commit_id;
    let document = CommitReceipt {
        version: 1,
        operation: job.plan.operation,
        instance: inner.instance,
        repository_binding: repository.clone(),
        accepted,
        marker: marker.into(),
        manifest: actual,
    };
    let hash = full_scope::metadata_digest(&document)?;
    let directory = directory(inner, job.plan.operation)?;
    match pipeline::read_document::<CommitReceipt>(
        &directory,
        POST_COMMIT,
        &job.access.master,
        job.plan.operation,
    )? {
        Some(existing) => ensure!(
            full_scope::metadata_digest(&existing)? == hash,
            "original native post-COMMITTED receipt changed on retry"
        ),
        None => pipeline::write_document(
            &directory,
            POST_COMMIT,
            &job.access.master,
            job.plan.operation,
            &document,
        )?,
    }
    let pending = DrainReceipt {
        version: 1,
        operation: job.plan.operation,
        instance: inner.instance,
        plan_hash: document.accepted.plan_hash.clone(),
        repository_binding: repository,
        committed_receipt_hash: hash,
        source_auth_hash: full_scope::metadata_digest(&document.accepted.source_auth)?,
        capture_receipt_hash: full_scope::metadata_digest(&document.accepted.capture_receipt)?,
        bundle,
        commit,
    };
    inner
        .completion
        .lock()
        .map_err(poison)?
        .pending
        .insert(job.plan.operation, pending);
    Ok(())
}

/// Called only after execute has joined real transfers and finished its actual
/// session, and operation-bound registrations have been invalidated successfully.
pub(super) fn finalize(inner: &Inner, job: &Job) -> Result<()> {
    if !matches!(
        &job.plan.work,
        Work::Upload {
            capture_scope: Some(_),
            ..
        }
    ) {
        return Ok(());
    }
    ensure!(
        !inner.finalization_failed.load(Ordering::Acquire),
        "actual native execution/session finalization is unverified"
    );
    let receipt = inner
        .completion
        .lock()
        .map_err(poison)?
        .pending
        .get(&job.plan.operation)
        .cloned()
        .context(
            "actual post-COMMITTED native receipt is missing; explicit reconciliation is required",
        )?;
    ensure!(
        receipt.plan_hash == plan_hash(&job.plan)?
            && receipt.repository_binding == repository_binding(&job.access)?,
        "native drained completion differs from original operation/repository"
    );
    let directory = directory(inner, job.plan.operation)?;
    match pipeline::read_document::<DrainReceipt>(
        &directory,
        DRAINED,
        &job.access.master,
        job.plan.operation,
    )? {
        Some(existing) => ensure!(
            full_scope::metadata_digest(&existing)? == full_scope::metadata_digest(&receipt)?,
            "original native drained completion receipt changed"
        ),
        None => pipeline::write_document(
            &directory,
            DRAINED,
            &job.access.master,
            job.plan.operation,
            &receipt,
        )?,
    }
    Ok(())
}

pub(super) fn retain(inner: &Inner, job: &Job) -> Result<()> {
    if !matches!(
        &job.plan.work,
        Work::Upload {
            capture_scope: Some(_),
            ..
        }
    ) {
        return Ok(());
    }
    // Account already bounded original strings without allocating another
    // plaintext credential/config serialization merely to measure retention.
    let session = &job.access.session;
    let bytes = [
        &session.operation_id,
        &session.provider,
        &session.backend_type,
        &session.remote_name,
        &session.root,
        &session.config_ini,
    ]
    .iter()
    .map(|value| value.len())
    .sum::<usize>();
    ensure!(
        bytes <= MAX_SESSION,
        "original native completion session exceeds its bound"
    );
    let mut state = inner.completion.lock().map_err(poison)?;
    state.accepted.remove(&job.plan.operation);
    state.pending.remove(&job.plan.operation);
    while state.retained.len() >= MAX_RETAINED
        || state
            .retained
            .values()
            .map(|entry| entry.bytes)
            .sum::<usize>()
            .saturating_add(bytes)
            > MAX_RETAINED_BYTES
    {
        let oldest = state
            .retained
            .iter()
            .min_by_key(|(_, entry)| entry.created)
            .map(|(id, _)| *id)
            .context("native completion retention budget is exhausted")?;
        state.retained.remove(&oldest);
    }
    state.retained.insert(
        job.plan.operation,
        Retained {
            access: Arc::clone(&job.access),
            created: Instant::now(),
            bytes,
            verified: None,
        },
    );
    Ok(())
}

pub(super) fn discard_pending(inner: &Inner, operation: Uuid) -> Result<()> {
    let mut state = inner.completion.lock().map_err(poison)?;
    state.accepted.remove(&operation);
    state.pending.remove(&operation);
    Ok(())
}

pub(super) fn clear(inner: &Inner) -> Result<()> {
    let mut state = inner.completion.lock().map_err(poison)?;
    state.retained.clear();
    state.accepted.clear();
    state.pending.clear();
    Ok(())
}

/// Historical UI hint only, never incoming Saved/execution authority.
pub(super) fn verified_hint(inner: &Inner, operation: Uuid) -> Result<bool> {
    Ok(inner
        .completion
        .lock()
        .map_err(poison)?
        .retained
        .get(&operation)
        .is_some_and(|entry| entry.verified.is_some()))
}

impl NativeEngine {
    /// Native-only barrier immediately before Saved, never a status-poll helper.
    /// No runtime discovery, provider/session command, provider credential/key
    /// fetch, live-file scan or JSON completed/saved flag can satisfy this method.
    /// The user-authorized one-time barrier freshly verifies native grant nonces;
    /// status/polling never calls it.
    pub async fn verify_capture_completion(
        &self,
        original_id: &str,
        binding: Value,
    ) -> Result<Value> {
        bounded(&binding, MAX_BINDING)?;
        let operation =
            Uuid::parse_str(original_id).context("invalid original native capture ID")?;
        let _submission = self.inner.submission.lock().await;
        ensure!(
            !self.inner.stopping.load(Ordering::Acquire)
                && !self.inner.finalization_failed.load(Ordering::Acquire)
                && !self
                    .inner
                    .active
                    .lock()
                    .map_err(poison)?
                    .contains_key(&operation),
            "actual native worker/session has not drained"
        );
        let access = self.inner.completion.lock().map_err(poison)?.retained.get(&operation)
            .map(|entry|Arc::clone(&entry.access)).context(
                "original operation-bound native crypto access is unavailable; explicit reconciliation is required")?;
        let store = workspace(&self.inner)?;
        let plan = self.inner.read_plan(operation, &access.master)?;
        check_access(&plan, &access, self.inner.instance)?;
        let (software, instance, app, capture, origin) = upload_context(&plan)?;
        ensure!(
            binding["softwareId"] == software
                && binding["appId"] == app.as_str()
                && binding["softwareInstanceId"] == instance
                && binding["providerId"] == plan.provider
                && binding["workId"] == capture.work_id
                && binding["generation"].as_u64() == Some(origin.generation)
                && binding["metadataIdentity"] == capture.metadata_identity
                && access.session.operation_id == operation.to_string()
                && !access.read_only,
            "native completion binding belongs to another original capture/provider/instance"
        );
        let receipt = &binding["captureReceipt"];
        let source_auth = &binding["sourceExpectedManifestAuth"];
        let current = check_current(&store, &plan, &access, receipt, &|kind, scope, grant| {
            store.verify_grant(kind, scope, grant)
        })?;
        let binding_hash = full_scope::metadata_digest(&binding)?;
        let cached = self
            .inner
            .completion
            .lock()
            .map_err(poison)?
            .retained
            .get(&operation)
            .and_then(|entry| entry.verified.as_ref())
            .filter(|(expected, _)| expected == &binding_hash)
            .map(|(_, proof)| proof.clone());
        let monitoring = self
            .inner
            .db
            .projected_operation(operation, false)
            .map_err(source_error)?
            .context("actual native completion row is missing")?;
        ensure!(
            monitoring.kind == "backup"
                && monitoring.app_id.as_ref() == Some(app)
                && monitoring.state == "COMPLETED",
            "actual native capture is not a stopped completed operation"
        );
        let proof = match cached {
            Some(proof) => proof,
            None => {
                let directory = directory(&self.inner, operation)?;
                let committed = pipeline::read_document::<CommitReceipt>(&directory,POST_COMMIT,&access.master,operation)?
                    .context("actual post-COMMITTED native manifest receipt is missing; explicit reconciliation is required")?;
                let drained = pipeline::read_document::<DrainReceipt>(&directory,DRAINED,&access.master,operation)?
                    .context("actual joined native completion receipt is missing; explicit reconciliation is required")?;
                validate_receipts(&plan, &access, source_auth, receipt, &committed, &drained)?;
                let authority = self
                    .inner
                    .operation_authority
                    .lock()
                    .map_err(poison)?
                    .clone()
                    .context("existing device completion authority is unavailable")?;
                let message = serde_json::to_vec(&json!({
                    "domain":"QuickSave/windows-actual-capture-completion/v1",
                    "operation":operation,"bindingHash":binding_hash,
                    "drained":full_scope::metadata_digest(&drained)?,
                }))?;
                let mac = authority(&message)?;
                let proof = blake3::hash(&mac).to_hex().to_string();
                let mut state = self.inner.completion.lock().map_err(poison)?;
                state
                    .retained
                    .get_mut(&operation)
                    .context("original completion access was evicted")?
                    .verified = Some((binding_hash, proof.clone()));
                proof
            }
        };
        ensure!(
            !self
                .inner
                .active
                .lock()
                .map_err(poison)?
                .contains_key(&operation)
                && store.software_record(software)? == current,
            "native completion authority changed during verification"
        );
        // Fresh nonce revocation check at this explicit barrier, never a status
        // poll. No substitution of newer data/counters and no mark_saved here.
        check_current(&store, &plan, &access, receipt, &|kind, scope, grant| {
            store.verify_grant(kind, scope, grant)
        })?;
        Ok(
            json!({"verified":true,"operationId":operation,"workId":capture.work_id,
            "generation":origin.generation,"committedManifestAuth":proof}),
        )
    }
}

fn validate_receipts(
    plan: &FrozenPlan,
    access: &PrivateAccess,
    source_auth: &Value,
    tracker_receipt: &Value,
    committed: &CommitReceipt,
    drained: &DrainReceipt,
) -> Result<()> {
    ensure!(
        committed.version == 1
            && drained.version == 1
            && committed.operation == plan.operation
            && drained.operation == plan.operation
            && committed.instance == plan.instance
            && drained.instance == plan.instance
            && committed.repository_binding == repository_binding(access)?
            && drained.repository_binding == committed.repository_binding
            && committed.accepted.operation == plan.operation
            && committed.accepted.plan_hash == plan_hash(plan)?
            && drained.plan_hash == committed.accepted.plan_hash
            && committed.accepted.source_auth == *source_auth
            && committed.accepted.capture_receipt == *tracker_receipt
            && drained.source_auth_hash == full_scope::metadata_digest(source_auth)?
            && drained.capture_receipt_hash == full_scope::metadata_digest(tracker_receipt)?
            && drained.committed_receipt_hash == full_scope::metadata_digest(committed)?
            && committed.marker == committed.manifest.commit_id.to_string()
            && drained.bundle == committed.manifest.bundle_id
            && drained.commit == committed.manifest.commit_id,
        "authenticated post-COMMITTED/drained capture proof belongs to another original operation"
    );
    pipeline::validate_captured_manifest(&committed.manifest, plan)?;
    capture::verify_source_auth(source_auth, &access.master, plan, &committed.manifest)?;
    verify_scope(
        plan,
        source_auth,
        tracker_receipt,
        &expected_files_hash(&committed.manifest)?,
    )
}

fn bounded(value: &impl Serialize, limit: usize) -> Result<()> {
    struct Bound {
        bytes: usize,
        limit: usize,
    }
    impl Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= self.limit)
                .ok_or_else(|| {
                    std::io::Error::other("native completion binding exceeds its bound")
                })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound { bytes: 0, limit }, value)?;
    Ok(())
}
