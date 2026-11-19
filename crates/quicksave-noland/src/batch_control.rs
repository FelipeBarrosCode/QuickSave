// SPDX-License-Identifier: GPL-3.0-only
// Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! Read-only, actual-source batch attestation. This is a child of `native.rs`.
//!
//! Parent wiring: `NativeEngine` owns `batch: Mutex<EngineBatchState>`, initially
//! `Default`. No public RPC, discovery, rclone preflight or credential lookup is
//! used for absence, cancellation, or cached monitoring. The caller supplies
//! device-MAC-verified native plans, never incoming webview JSON.
//!
//! The submission authenticator and repository-identity rules below deliberately
//! match the active fork's rpc_handler/submission.rs and storage_scope.rs. A
//! read-only implementation avoids StartBackup's check/create race: even a lost
//! row can NEVER turn verification into a new worker.

use super::{public_source_error, NativeEngine, PrivateAccess};
use anyhow::{bail, ensure, Context, Result};
use noland_crypto::MasterKey;
use noland_rclone_adapter::{EphemeralRcloneSession, ProviderRootIdentity};
use noland_state_agent::native_capture::{
    self, resume::NativeOriginalCaptureAuthority, NativeCaptureReceipt, NativeCaptureScope,
    NativeCaptureSink,
};
use noland_state_agent::native_host::{
    native_file_id, native_root_token, validate_native_relative, NativeCoverage, NativeSelection,
};
#[cfg(test)]
use noland_state_core::BackupMode;
use noland_state_core::{AppId, BundleManifest, ConsistencyKind, OperationRecord};
use quicksave_platform::{FileStamp, SafeRoot};
use quicksave_state::ProviderAccess;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};
use uuid::Uuid;

const MAX_BINDINGS: usize = 8192;
const MAX_BINDING_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 250_000;
const MAX_SOURCE_DOCUMENT: usize = noland_storage::MAX_METADATA_BYTES as usize;

#[derive(Default)]
pub(crate) struct EngineBatchState {
    authenticated: BTreeMap<Uuid, Arc<AuthenticatedSource>>,
    resumed: BTreeMap<Uuid, ResumedSource>,
    verified_captures: BTreeMap<Uuid, (String, String)>,
}

struct ResumedSource {
    native_selection_digest: String,
    manifest_hash: String,
    checkpoint: Option<FileStamp>,
    controller: Weak<dyn crate::capture_control::NativeCaptureController>,
    authority: Weak<DeviceOriginalCaptureAuthority>,
}

struct AuthenticatedSource {
    expected_digest: String,
    native_selection_digest: String,
    submission_binding: String,
    repository_binding: String,
    binding_digest: String,
    app: AppId,
    instance: String,
    native_roots_fingerprint: String,
    scope_digest: String,
    completion: Mutex<CompletionMemo>,
}

#[derive(Default)]
struct CompletionMemo {
    digest: Option<String>,
    failed: bool,
    manifest_hash: Option<String>,
    bundle: Option<Uuid>,
    commit: Option<Uuid>,
    original_capture: Option<Arc<OriginalCommitBinding>>,
}

/// Retained only after the ORIGINAL device-authenticated sidecar was opened.
/// Neither a status row nor a caller-provided "committed" flag can create this.
struct OriginalCommitBinding {
    receipt: Value,
    expected_manifest_auth: Value,
}

struct ExpectedBinding<'a> {
    id: Uuid,
    app: AppId,
    instance: &'a str,
    provider: &'a str,
    mode: &'a str,
    root_authority: &'a str,
    registration: &'a Value,
    roots: &'a [Value],
    native_roots_fingerprint: String,
    capture: Option<&'a Value>,
    capture_digest: Option<&'a str>,
    digest: String,
}

impl NativeEngine {
    /// Synchronous finalization barrier for a recovered native receipt. The
    /// private caller retains the original device-MAC-verified source binding.
    /// Only authenticate_batch_completion can mint the required in-memory proof;
    /// this method never reads a manifest, retry selection or node inventory.
    ///
    /// Tracker verifies the original frame/receipt grants and the source receipt
    /// immediately BEFORE this callback. Do not reenter Tracker or request vault
    /// credentials here. These fresh document/root/DB checks supplement, rather
    /// than replace, that mandatory grant/publication revalidation.
    pub fn verify_cached_batch_commit(&self, binding: &Value) -> Result<()> {
        self.batch_source_verification_supported()?;
        let expected = ExpectedBinding::parse(binding)?;
        let _submission = self
            .submission
            .try_lock()
            .context("Native source submission is busy; retry original completion verification")?;
        let authenticated = self
            .batch
            .lock()
            .map_err(|_| anyhow::anyhow!("Native cached commit ownership lock failed"))?
            .authenticated
            .get(&expected.id)
            .cloned()
            .context("Actual authenticated source completion is not cached")?;
        ensure!(
            authenticated.expected_digest == expected.digest
                && authenticated.app == expected.app
                && authenticated.instance == expected.instance
                && authenticated.native_roots_fingerprint == expected.native_roots_fingerprint,
            "Cached source completion belongs to another frozen operation/capture/root"
        );
        let (proof, manifest_hash, bundle, commit, original) = {
            let memo = authenticated
                .completion
                .lock()
                .map_err(|_| anyhow::anyhow!("Native cached commit receipt lock failed"))?;
            ensure!(!memo.failed, "Actual source completion proof failed");
            (
                memo.digest
                    .clone()
                    .context("Actual COMMITTED proof is not cached")?,
                memo.manifest_hash
                    .clone()
                    .context("Actual committed manifest identity is missing")?,
                memo.bundle
                    .context("Actual committed bundle identity is missing")?,
                memo.commit
                    .context("Actual committed commit identity is missing")?,
                memo.original_capture
                    .clone()
                    .context("Original device capture binding is missing")?,
            )
        };
        valid_digest(&proof)?;
        let raw_manifest_hash = manifest_hash
            .strip_prefix("blake3:")
            .context("Actual committed manifest digest has no source domain")?;
        valid_digest(raw_manifest_hash)?;
        ensure!(
            equal_digest(
                &proof,
                &digest(
                    &json!({
                        "domain":"QuickSave/actual-source-completion/v1",
                        "sourceId":expected.id,"bindingDigest":authenticated.binding_digest,
                        "bundleId":bundle,"commitId":commit,"manifestDigest":raw_manifest_hash,
                    }),
                    MAX_BINDING_BYTES,
                )?
            ),
            "Cached actual source completion binding changed"
        );
        let private = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("Native cached completion private ownership lock failed"))?
            .get(&expected.id)
            .cloned()
            .context("Original source private operation owner is unavailable")?;
        ensure!(
            private.provider_id == expected.provider
                && private.session.operation_id == expected.id.to_string()
                && repository_cache_digest(
                    &bound_session_identity(&private.session, &private.master)?,
                    &private.master,
                )? == authenticated.repository_binding,
            "Cached completion private repository/key/operation binding changed"
        );
        let envelope = source_expected_envelope(
            &private.master,
            expected.id,
            &original.expected_manifest_auth,
        )?;
        let capture = expected
            .capture
            .context("Original frozen capture is missing")?;
        let scope = &original.receipt["scope"];
        ensure!(
            envelope.app == expected.app
                && envelope.operation == expected.id
                && envelope.source_snapshot_id == bundle
                && envelope.manifest_hash == manifest_hash
                && envelope.roots_fingerprint == expected.native_roots_fingerprint
                && authenticated.scope_digest
                    == hash_serialized(&envelope.scope, MAX_BINDING_BYTES)?
                && scope["workId"] == capture["workId"]
                && scope["generation"] == capture["generation"]
                && scope["metadataIdentity"] == capture["metadataIdentity"]
                && scope["sourceSnapshotId"] == bundle.to_string()
                && scope["immutablePreparedCapture"] == true
                && scope["sourceExpectedManifestAuthHash"]
                    == hash_serialized(&original.expected_manifest_auth, MAX_BINDING_BYTES)?,
            "Cached COMMITTED manifest differs from the original device-authenticated capture"
        );
        let store = self
            .workspace
            .as_ref()
            .context("Native completion workspace is missing")?;
        let document = store.document()?;
        let software = text(binding, "softwareId", 512)?;
        let record = serde_json::to_value(
            document
                .software
                .iter()
                .find(|record| record.id == software)
                .context("Original native software is missing")?,
        )?;
        let provider = document
            .providers
            .iter()
            .find(|provider| provider.id == expected.provider)
            .context("Original native provider is missing")?;
        let tracking = current_tracking_scope(&record)?;
        ensure!(
            record["tracked"] == true
                && record["id"] == expected.registration["id"]
                && record["providerId"] == expected.provider
                && record["trackingGrant"] == expected.registration["trackingGrant"]
                && record["autoEnrollment"] == expected.registration["autoEnrollment"]
                && tracking == current_tracking_scope(expected.registration)?
                && record["captureReceipt"] == original.receipt
                && scope["softwareId"] == software
                && scope["providerId"] == expected.provider
                && scope["trackingScopeHash"] == hash_serialized(&tracking, MAX_BINDING_BYTES)?
                && provider.status == "connected"
                && !provider.read_only
                && batch_provider_digest(&serde_json::to_value(provider)?)?
                    == text(binding, "providerDigest", 64)?,
            "Original native completion software/provider/root/policy authority changed"
        );
        if let Some(enrollment) = record
            .get("autoEnrollment")
            .filter(|value| !value.is_null())
        {
            let settings = serde_json::to_value(&document.settings)?;
            ensure!(
                settings["appTracking"]["policyScope"] == enrollment["policyScope"]
                    && settings["appTracking"]["policyGrant"] == enrollment["policyGrant"],
                "Original native application tracking policy was replaced or disabled"
            );
        }
        let pins = current_root_pins(expected.roots)?;
        ensure!(
            self.agent
                .native_binding_fingerprint(&expected.app)
                .map_err(public_source_error)?
                == expected.native_roots_fingerprint,
            "Actual native source root/instance map changed"
        );
        // The actual DB's monitoring lock revalidates its protected native file
        // and ancestor pins. It returns NO detail/retry/result JSON. The state
        // below is a drain condition only; the proof above is independently
        // minted from the authenticated actual COMMITTED manifest.
        let check_drained = || -> Result<()> {
            let snapshot = self
                .agent
                .db
                .operation_monitoring_snapshot(expected.id)
                .map_err(public_source_error)?
                .context("Original source completion row is missing")?;
            ensure!(
                snapshot.operation.operation_id == expected.id
                    && snapshot.operation.kind == "backup"
                    && snapshot.operation.app_id.as_ref() == Some(&expected.app)
                    && snapshot.operation.state == "COMPLETED"
                    && !self.agent.operations.is_running(expected.id),
                "Actual source completion is not the same drained native backup"
            );
            Ok(())
        };
        check_drained()?;
        quicksave_platform::verify_private_file(&self._lock)?;
        check_current_root_pins(&pins)?;
        ensure!(
            store.document()? == document,
            "Native authority document changed during cached completion verification"
        );
        self._data.identity()?;
        check_drained()?;
        Ok(())
    }

    /// Cheap ownership-only history for already device-MAC-verified child IDs.
    /// This is NOT source authentication, a capture receipt, or commit proof.
    /// No registration, retry JSON, file keys, credential/vault/tool/provider
    /// access, or full frozen plan is read by this method.
    pub async fn batch_history_owners(
        &self,
        plan_set_id: &str,
        root_digest: &str,
        children: Value,
    ) -> Result<Value> {
        self.batch_source_verification_supported()?;
        let set = Uuid::parse_str(plan_set_id).context("Invalid native history plan-set ID")?;
        ensure!(
            set.to_string() == plan_set_id,
            "Noncanonical native history plan-set ID"
        );
        valid_digest(root_digest)?;
        bounded(&children, 128 * 1024)?;
        let children = children
            .as_array()
            .context("Native history ownership keys are missing")?;
        ensure!(
            !children.is_empty() && children.len() <= 128,
            "Native history ownership pages contain 1–128 children"
        );
        let mut seen = BTreeSet::new();
        let mut items = Vec::with_capacity(children.len());
        for child in children {
            let id = uuid_field(child, "sourceId")?;
            let app = text(child, "canonicalAppId", 512)?;
            ensure!(
                seen.insert(id) && !matches!(app, "*" | "_all"),
                "Native history ownership requires unique exact source/app IDs"
            );
            let observed = self.agent.db.operation_monitoring_snapshot(id);
            let running = self.agent.operations.is_running(id);
            let item = match observed {
                Ok(None) if !running => {
                    json!({"sourceId":id,"presence":"absent","workerRunning":false})
                }
                Ok(Some(snapshot))
                    if snapshot.operation.kind == "backup"
                        && snapshot.operation.operation_id == id
                        && snapshot
                            .operation
                            .app_id
                            .as_ref()
                            .is_some_and(|source| source.as_str() == app) =>
                {
                    json!({
                        "sourceId":id,"presence":"present","state":batch_state(&snapshot.operation.state),
                        "workerRunning":running,
                        "progress":snapshot.progress.as_ref().map(|progress|json!({
                            "phase":super::safe_phase(&progress.phase),
                            "unit":match progress.unit.as_deref() {
                                Some("bytes")=>"bytes",Some("files")=>"files",_=>"items",
                            },
                            "completed":progress.completed_units,"total":progress.total_units,
                        })),
                    })
                }
                // A missing row with a live owner, wrong kind/app, unreadable
                // database, or unavailable status is never authoritative drain.
                _ => json!({"sourceId":id,"presence":"unknown","workerRunning":running}),
            };
            items.push(item);
        }
        Ok(json!({"planSetId":set,"rootDigest":root_digest,"items":items}))
    }

    /// Mandatory one-time barrier before EVERY successful native upload
    /// finalization, including non-batch/manual/autosave. No RPC status flag,
    /// prepared receipt alone, incoming boolean or DB result is a commit proof.
    ///
    /// Compact native-only binding (<=128 KiB) comes from the actual original
    /// Tracker receipt owner. Provider access MUST already be retained by this
    /// exact operation. This function never unlocks provider credentials,
    /// preflights tools, lists accounts, contacts a provider or recaptures files.
    pub async fn verify_capture_completion(
        &self,
        original_id: &str,
        binding: Value,
    ) -> Result<Value> {
        self.batch_source_verification_supported()?;
        bounded(&binding, 128 * 1024)?;
        let operation =
            Uuid::parse_str(original_id).context("Invalid original capture operation ID")?;
        let software = text(&binding, "softwareId", 512)?;
        let provider = text(&binding, "providerId", 128)?;
        let work = text(&binding, "workId", 128)?;
        let generation = binding["generation"]
            .as_u64()
            .context("Original capture generation is missing")?;
        let metadata = text(&binding, "metadataIdentity", 512)?;
        let store = self
            .workspace
            .as_ref()
            .context("Native completion workspace is unavailable")?;
        let record = store.software_record(software)?;
        let provider_record = store
            .document()?
            .providers
            .into_iter()
            .find(|record| record.id == provider)
            .context("Native completion provider is missing")?;
        ensure!(
            record["id"] == software
                && record["providerId"] == provider
                && record["tracked"] == true
                && provider_record.status == "connected"
                && !provider_record.read_only
                && store.verify_tracking_grant(software)?,
            "Current native software/root/policy authority is invalid or revoked"
        );
        let tracking = current_tracking_scope(&record)?;
        let scope = &binding["captureReceipt"]["scope"];
        let receipt_grant = &binding["captureReceipt"]["grant"];
        ensure!(
            scope["version"] == 1 && scope["softwareId"] == software
                && scope["providerId"] == provider && scope["workId"] == work
                && scope["generation"] == generation && scope["metadataIdentity"] == metadata
                && scope["immutablePreparedCapture"] == true
                && scope["trackingScopeHash"] == hash_serialized(&tracking,MAX_BINDING_BYTES)?
                && store.verify_grant("tracking_capture_receipt",scope,receipt_grant)?,
            "Original native source receipt is not device-authenticated for this work/root/provider"
        );
        for field in [
            "capturedSnapshotIdentity",
            "expectedFilesHash",
            "sourceExpectedManifestAuthHash",
            "fullScopeProofHash",
            "trackingScopeHash",
        ] {
            valid_digest(text(scope, field, 64)?)?;
        }
        // The actual stored receipt/sidecar supplies the independently native
        // reference even when the compact handoff intentionally omits nodes.
        let stored_receipt = &record["captureReceipt"];
        ensure!(
            stored_receipt["scope"] == *scope && stored_receipt["grant"] == *receipt_grant,
            "Current native receipt owner no longer retains this original capture"
        );
        let reference = &stored_receipt["reference"];
        ensure!(
            reference["scope"]["captureScope"] == *scope
                && reference["scope"]["tracking"] == tracking
                && reference["scope"]["name"] == reference["name"]
                && reference["scope"]["hash"] == reference["hash"]
                && store.verify_grant(
                    "tracking_capture_receipt_sidecar",
                    &reference["scope"],
                    &reference["grant"]
                )?,
            "Original native capture sidecar authority is unavailable or revoked"
        );
        valid_digest(text(reference, "hash", 64)?)?;
        if binding["automatic"] == true || record["autosave"] == true {
            ensure!(
                record["autosave"] == true
                    && store.verify_grant(
                        "autosave",
                        &json!({
                            "version":1,"tracking":tracking,"providerId":provider,
                        }),
                        &record["autosaveGrant"]
                    )?,
                "Current native automatic capture authority is invalid or revoked"
            );
        }
        let generation_now = record["dirtyGeneration"]
            .as_u64()
            .context("Current native dirty generation is unavailable")?;
        ensure!(
            generation <= generation_now,
            "Original captured generation is not a native current/past generation"
        );
        let roots = tracking["roots"]
            .as_array()
            .context("Native completion roots are missing")?;
        let app = AppId(
            record
                .pointer("/sourceIdentity/app_id")
                .and_then(Value::as_str)
                .unwrap_or(text(&record, "appId", 512)?)
                .into(),
        );
        let instance = text(&record, "appId", 512)?;
        let roots_fingerprint = frozen_native_roots_fingerprint(&app, roots)?;
        let pins = current_root_pins(roots)?;
        let _submission = self.submission.lock().await;
        let private = self.access.lock()
            .map_err(|_|anyhow::anyhow!("Native completion private access lock failed"))?
            .get(&operation).cloned().context(
                "Original operation-bound private source access is unavailable; explicit reconciliation is required"
            )?;
        ensure!(
            private.provider_id == provider
                && private.session.operation_id == operation.to_string(),
            "Native completion access belongs to another provider/operation"
        );
        let expected_auth = &binding["sourceExpectedManifestAuth"];
        ensure!(
            hash_serialized(expected_auth, 128 * 1024)?
                == text(scope, "sourceExpectedManifestAuthHash", 64)?,
            "Actual original source expected-manifest authentication changed"
        );
        let envelope = source_expected_envelope(&private.master, operation, expected_auth)?;
        ensure!(
            envelope.app == app && envelope.operation == operation
                && envelope.scope.work_id == work && envelope.scope.metadata_identity == metadata
                && envelope.roots_fingerprint == roots_fingerprint
                && scope["sourceSnapshotId"] == envelope.source_snapshot_id.to_string(),
            "Actual source expected-manifest envelope belongs to another original scope/instance/root"
        );
        let repository = bound_session_identity(&private.session, &private.master)?;
        let repository_binding = repository_cache_digest(&repository, &private.master)?;
        let device_binding = digest(
            &json!({
                "operation":operation,"receipt":binding["captureReceipt"],
                "sourceExpectedManifestAuth":expected_auth,"tracking":tracking,
                "provider":provider,"instance":instance,"repository":repository_binding,
            }),
            MAX_BINDING_BYTES,
        )?;
        let monitoring = self
            .agent
            .db
            .operation_monitoring_snapshot(operation)
            .map_err(public_source_error)?
            .context("Actual source completion record is missing")?;
        ensure!(
            monitoring.operation.kind == "backup"
                && monitoring.operation.app_id.as_ref() == Some(&app)
                && monitoring.operation.state == "COMPLETED"
                && !self.agent.operations.is_running(operation),
            "Actual source worker is not joined terminal completion"
        );
        let ready = {
            let state = self
                .batch
                .lock()
                .map_err(|_| anyhow::anyhow!("Native completion cache lock failed"))?;
            state
                .verified_captures
                .get(&operation)
                .filter(|(binding, _)| binding == &device_binding)
                .map(|(_, digest)| digest.clone())
        };
        if let Some(proof) = ready {
            check_current_root_pins(&pins)?;
            recheck_completion_authority(
                store,
                software,
                &record,
                &tracking,
                scope,
                receipt_grant,
            )?;
            return Ok(
                json!({"verified":true,"operationId":operation,"workId":work,
                "generation":generation,"committedManifestAuth":proof}),
            );
        }
        // A prior actual batch commit may be reused ONLY for this exact
        // device-bound original manifest/scope/repository and native instance.
        let batch_proof = self
            .batch
            .lock()
            .map_err(|_| anyhow::anyhow!("Native completion cache lock failed"))?
            .authenticated
            .get(&operation)
            .cloned();
        if let Some(batch) = batch_proof {
            let memo = batch
                .completion
                .lock()
                .map_err(|_| anyhow::anyhow!("Native batch completion receipt lock failed"))?;
            if memo.digest.is_some()
                && memo.manifest_hash.as_deref() == Some(&envelope.manifest_hash)
                && memo.bundle == Some(envelope.source_snapshot_id)
                && batch.app == app
                && batch.instance == instance
                && batch.native_roots_fingerprint == roots_fingerprint
                && batch.scope_digest == hash_serialized(&envelope.scope, MAX_BINDING_BYTES)?
                && batch.repository_binding == repository_binding
            {
                let proof = digest(
                    &json!({
                        "domain":"QuickSave/actual-source-capture-completion/v1","deviceBinding":device_binding,
                        "manifestHash":envelope.manifest_hash,"batchProof":memo.digest,
                    }),
                    MAX_BINDING_BYTES,
                )?;
                drop(memo);
                check_current_root_pins(&pins)?;
                recheck_completion_authority(
                    store,
                    software,
                    &record,
                    &tracking,
                    scope,
                    receipt_grant,
                )?;
                remember_capture_completion(self, operation, &device_binding, &proof)?;
                return Ok(
                    json!({"verified":true,"operationId":operation,"workId":work,
                    "generation":generation,"committedManifestAuth":proof}),
                );
            }
        }
        let operation_record = self
            .agent
            .db
            .get_operation(operation)
            .map_err(public_source_error)?
            .context("Original actual source completion record disappeared")?;
        let selection = verify_native_submission(
            operation,
            &app,
            instance,
            &roots_fingerprint,
            &envelope.scope,
            &private,
            &operation_record,
        )?;
        let bundle = uuid_field(&operation_record.detail_json, "bundle_id")?;
        let commit = uuid_field(&operation_record.detail_json, "commit_id")?;
        ensure!(
            bundle == envelope.source_snapshot_id,
            "Actual source completion points to another captured bundle"
        );
        let manifest = read_cached_manifest(
            &self.agent.config.paths.cache,&app,bundle,&repository_binding,&private.master,
        )?.context("Authenticated post-COMMITTED source manifest is missing locally; explicit reconciliation is required")?;
        ensure!(
            manifest.app.app_id == app && manifest.bundle_id == bundle && manifest.commit_id == commit
                && manifest.source.instance_id == self.agent.config.instance_id
                && manifest.mode.as_str() == operation_record.detail_json["mode"].as_str().unwrap_or("")
                && manifest.consistency != ConsistencyKind::BestEffort
                && format!("blake3:{}",hash_serialized(&manifest,MAX_SOURCE_DOCUMENT)?) == envelope.manifest_hash
                && manifest.environment["quicksave_native"]["selection"] == serde_json::to_value(&selection)?
                && manifest.environment["quicksave_native"]["software_instance_id"] == instance
                && format!("blake3:{}",hash_serialized(
                    &manifest.environment["quicksave_native_root_layouts"],MAX_BINDING_BYTES)?) == envelope.root_layouts_hash,
            "Actual authenticated committed manifest does not match the original device-bound capture"
        );
        ensure!(
            !self.agent.operations.is_running(operation),
            "Actual source worker restarted before completion verification"
        );
        check_current_root_pins(&pins)?;
        recheck_completion_authority(store, software, &record, &tracking, scope, receipt_grant)?;
        let proof = digest(
            &json!({
                "domain":"QuickSave/actual-source-capture-completion/v1",
                "deviceBinding":device_binding,"manifestHash":envelope.manifest_hash,
                "bundleId":bundle,"commitId":commit,
            }),
            MAX_BINDING_BYTES,
        )?;
        remember_capture_completion(self, operation, &device_binding, &proof)?;
        Ok(
            json!({"verified":true,"operationId":operation,"workId":work,
            "generation":generation,"committedManifestAuth":proof}),
        )
    }

    /// Reattach ONLY original signed native work and source capture. This never
    /// submits/retries a worker. Completed children need no prepared pack files
    /// and are finalized from the authenticated actual committed manifest.
    pub async fn recover_original_capture(
        &self,
        access: ProviderAccess,
        signed_frozen_work: Value,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        controller: Arc<dyn crate::capture_control::NativeCaptureController>,
    ) -> Result<Value> {
        self.batch_source_verification_supported()?;
        bounded(&signed_frozen_work, MAX_SOURCE_DOCUMENT)?;
        let binding = &signed_frozen_work["binding"];
        let expected = ExpectedBinding::parse(binding)?;
        let work = &signed_frozen_work["work"];
        verify_original_work(&expected, work)?;
        ensure!(
            access.provider_id == expected.provider,
            "Original capture provider changed"
        );
        guard()?;
        // Registration reopens ONLY exact signed native roots. It performs no
        // inventory, content read, metadata recapture, or source discovery.
        self.register(&binding["registration"]).await?;
        let _submission = self.submission.lock().await;
        ensure!(
            !self.agent.operations.is_running(expected.id),
            "Original source worker must be drained before capture reattachment"
        );
        let record = self
            .agent
            .db
            .get_operation(expected.id)
            .map_err(public_source_error)?
            .context("Original source operation is missing")?;
        let private = Arc::new(self.private_access(&access, Some(expected.id))?);
        let current = Arc::new(authenticate_record(&expected, &record, &private)?);
        let authenticated = {
            let mut state = self
                .batch
                .lock()
                .map_err(|_| anyhow::anyhow!("Original source binding cache lock failed"))?;
            match state.authenticated.get(&expected.id) {
                Some(original) => {
                    ensure!(
                        original.expected_digest == current.expected_digest
                            && original.binding_digest == current.binding_digest,
                        "Original source recovery changed its authenticated source/capture binding"
                    );
                    original.clone()
                }
                None => {
                    ensure!(
                        state.authenticated.len() < MAX_BINDINGS,
                        "Original source binding cache is full"
                    );
                    state.authenticated.insert(expected.id, current.clone());
                    current
                }
            }
        };
        let native = NativeSelection::parse(&record.detail_json["native_selection"])
            .map_err(public_source_error)?;
        let completed = record.state == "COMPLETED";
        ensure!(
            completed
                || matches!(
                    record.state.as_str(),
                    "FAILED" | "CANCELLED" | "INTERRUPTED"
                ),
            "Original capture recovery requires a terminal/drained source operation"
        );
        ensure!(
            completed || !private.read_only,
            "Retrying original captured bytes requires the current exact provider write grant"
        );
        let data_path = self
            .agent
            .config
            .paths
            .state_root
            .parent()
            .and_then(Path::parent)
            .context("Original native QuickSave workspace location is unavailable")?;
        let data = SafeRoot::open(data_path)?;
        ensure!(
            data.identity()? == self._data.identity()?,
            "Original native workspace identity changed"
        );
        let authority = Arc::new(DeviceOriginalCaptureAuthority::open(
            self.workspace
                .clone()
                .context("Original native device authority is unavailable")?,
            data,
            &expected,
            work,
            &signed_frozen_work["frozenWork"],
            &signed_frozen_work["captureReceipt"],
        )?);
        authority.revalidate_native()?;
        let original_commit = Arc::new(OriginalCommitBinding {
            receipt: signed_frozen_work["captureReceipt"].clone(),
            expected_manifest_auth: authority.expected_manifest_auth.clone(),
        });
        {
            let mut memo = authenticated
                .completion
                .lock()
                .map_err(|_| anyhow::anyhow!("Original capture commit binding lock failed"))?;
            if let Some(original) = &memo.original_capture {
                ensure!(
                    original.receipt == original_commit.receipt
                        && original.expected_manifest_auth
                            == original_commit.expected_manifest_auth,
                    "Original device-authenticated capture commit binding changed"
                );
            } else {
                memo.original_capture = Some(original_commit);
            }
        }
        let (manifest, checkpoint) = if completed {
            // Actual completion proof, not COMPLETED JSON. Verification is
            // explicit here, so a missing local cache may use the source's
            // immutable COMMITTED + repository-key AEAD reader.
            self.authenticate_batch_completion(&expected, &authenticated, Some(&private), true)
                .await?;
            let bundle = uuid_field(&record.detail_json, "bundle_id")?;
            let manifest = match read_cached_manifest(
                &self.agent.config.paths.cache,
                &expected.app,
                bundle,
                &authenticated.repository_binding,
                &private.master,
            )? {
                Some(manifest) => manifest,
                None => {
                    self.manifest(
                        &private,
                        &json!({
                            "appId":expected.app.as_str(),"bundleId":bundle,
                        }),
                    )
                    .await?
                }
            };
            (manifest, None)
        } else {
            let (manifest, stamp) = original_prepared_manifest(
                &self.agent.config.paths.packs,
                expected.id,
                &expected.app,
                expected.mode,
                &private.session,
                &private.master,
            )?;
            (manifest, Some(stamp))
        };
        ensure!(
            manifest.app.app_id == expected.app
                && manifest.mode.as_str() == expected.mode
                && manifest.source.instance_id == self.agent.config.instance_id,
            "Original prepared/committed capture belongs to another source workspace/app/mode"
        );
        let sink: Arc<dyn NativeCaptureSink> = Arc::new(OriginalSink {
            controller: controller.clone(),
            authority: authority.clone(),
        });
        guard()?;
        let receipt = native_capture::resume::reattach_original_capture(
            &self.agent,
            expected.id,
            &native,
            &private.master,
            &manifest,
            sink,
            authority.clone(),
        )
        .map_err(public_source_error)?;
        receipt.revalidate().map_err(public_source_error)?;
        authority.revalidate_native()?;
        let manifest_hash = hash_serialized(&manifest, MAX_SOURCE_DOCUMENT)?;
        self.reserve_private(expected.id, private.clone())?;
        if !completed {
            let lifecycle = private.lifecycle.clone();
            let weak_controller = Arc::downgrade(&controller);
            let weak_authority = Arc::downgrade(&authority);
            let publication = guard.clone();
            self.agent
                .native_set_publication_guard(
                    expected.id,
                    Arc::new(move || {
                        if let Some(lifecycle) = &lifecycle {
                            lifecycle.checkpoint().map_err(|_| {
                                noland_state_core::StateError::Conflict(
                                    "Original-capture native credential finalization failed".into(),
                                )
                            })?;
                        }
                        let authority = weak_authority.upgrade().ok_or_else(|| {
                            noland_state_core::StateError::Conflict(
                                "Original device capture owner ended".into(),
                            )
                        })?;
                        authority.revalidate()?;
                        weak_controller
                            .upgrade()
                            .ok_or_else(|| {
                                noland_state_core::StateError::Conflict(
                                    "Original Tracker capture owner ended".into(),
                                )
                            })?
                            .verify_publication()
                            .map_err(|_| {
                                noland_state_core::StateError::Conflict(
                                    "Original Tracker capture receipt/grants changed".into(),
                                )
                            })?;
                        publication().map_err(|_| {
                            noland_state_core::StateError::Conflict(
                                "Original native capture publication authority was revoked".into(),
                            )
                        })
                    }),
                )
                .map_err(public_source_error)?;
            let mut state = self
                .batch
                .lock()
                .map_err(|_| anyhow::anyhow!("Native original capture owner lock failed"))?;
            state
                .resumed
                .retain(|_, owner| owner.authority.strong_count() != 0);
            ensure!(
                state.resumed.len() < MAX_BINDINGS,
                "Original capture owner budget is full"
            );
            state.resumed.insert(
                expected.id,
                ResumedSource {
                    native_selection_digest: authenticated.native_selection_digest.clone(),
                    manifest_hash: manifest_hash.clone(),
                    checkpoint,
                    controller: Arc::downgrade(&controller),
                    authority: Arc::downgrade(&authority),
                },
            );
        } else {
            // The reconstructed native receipt is now owned by original Tracker
            // Pending. A completed source must never retain retry authority.
            native_capture::remove(&self.agent, expected.id).map_err(public_source_error)?;
        }
        guard()?;
        Ok(json!({
            "workId":work["workId"],"sourceOperationId":expected.id,
            "originalReceiptReattached":true,"sourceAlreadyCompleted":completed,
            "manifestDigest":manifest_hash,
        }))
    }

    /// Parent retry_guarded dispatch calls this for capture_scope operations.
    /// It spends no new capture/ID and the source reuses its authenticated
    /// PreparedBackup, fixed packs, journal and actual source retry pipeline.
    pub async fn retry_original_capture_guarded(
        &self,
        id: &str,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        let operation = Uuid::parse_str(id).context("Invalid original capture operation ID")?;
        let before = self
            .agent
            .db
            .operation_monitoring_snapshot(operation)
            .map_err(public_source_error)?
            .context("Original source retry operation is missing")?;
        ensure!(
            before.operation.kind == "backup"
                && matches!(
                    before.operation.state.as_str(),
                    "FAILED" | "CANCELLED" | "INTERRUPTED"
                )
                && !self.agent.operations.is_running(operation),
            "A completed or running source child can never start another captured retry"
        );
        if let Some(proof) = self
            .batch
            .lock()
            .map_err(|_| anyhow::anyhow!("Native completed-source proof lock failed"))?
            .authenticated
            .get(&operation)
            .cloned()
        {
            ensure!(
                proof
                    .completion
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Native completed-source receipt lock failed"))?
                    .digest
                    .is_none(),
                "An authenticated completed source child can never be rerun"
            );
        }
        self.preflight().await?; // Transfer execution only, never a status query.
        let _submission = self.submission.lock().await;
        guard()?;
        ensure!(
            !self.agent.operations.is_running(operation),
            "Original source worker is still running/draining"
        );
        let (selection_digest, manifest_hash, stamp, controller, authority) = {
            let state = self
                .batch
                .lock()
                .map_err(|_| anyhow::anyhow!("Native original capture owner lock failed"))?;
            let owner = state
                .resumed
                .get(&operation)
                .context("The original native capture has not been reattached")?;
            (
                owner.native_selection_digest.clone(),
                owner.manifest_hash.clone(),
                owner.checkpoint.clone(),
                owner.controller.upgrade(),
                owner.authority.upgrade(),
            )
        };
        let controller = controller.context("The original Tracker capture owner ended")?;
        let authority = authority.context("The original device capture owner ended")?;
        ensure!(
            native_capture::is_installed(&self.agent, operation),
            "The original source capture capability must be reattached before retry"
        );
        let record = self
            .agent
            .db
            .get_operation(operation)
            .map_err(public_source_error)?
            .context("The original source retry record is missing")?;
        ensure!(
            matches!(
                record.state.as_str(),
                "FAILED" | "CANCELLED" | "INTERRUPTED"
            ) && record.kind == "backup",
            "A completed or non-retryable source child can never be rerun"
        );
        let native = NativeSelection::parse(&record.detail_json["native_selection"])
            .map_err(public_source_error)?;
        ensure!(
            native.capture_scope.is_some()
                && digest(&serde_json::to_value(&native)?, MAX_SOURCE_DOCUMENT)?
                    == selection_digest,
            "Original captured retry selection changed"
        );
        let private = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("Native private source access lock failed"))?
            .get(&operation)
            .cloned()
            .context("Original captured retry requires private provider access")?;
        ensure!(
            !private.read_only,
            "Original captured retry has no provider write grant"
        );
        let packs = SafeRoot::open(&self.agent.config.paths.packs)?;
        packs.verify_file(
            &format!("resume/{operation}.enc"),
            stamp
                .as_ref()
                .context("A completed source has no retry checkpoint authority")?,
        )?;
        let (manifest, _) = original_prepared_manifest(
            &self.agent.config.paths.packs,
            operation,
            record
                .app_id
                .as_ref()
                .context("Original retry app is missing")?,
            text(&record.detail_json, "mode", 32)?,
            &private.session,
            &private.master,
        )?;
        ensure!(
            hash_serialized(&manifest, MAX_SOURCE_DOCUMENT)? == manifest_hash,
            "Original prepared manifest changed before retry"
        );
        authority.revalidate_native()?;
        controller.verify_publication()?;
        let lifecycle = private.lifecycle.clone();
        let weak_authority = Arc::downgrade(&authority);
        let weak_controller = Arc::downgrade(&controller);
        self.agent
            .native_set_publication_guard(
                operation,
                Arc::new(move || {
                    if let Some(lifecycle) = &lifecycle {
                        lifecycle.checkpoint().map_err(|_| {
                            noland_state_core::StateError::Conflict(
                                "Original retry credential finalization failed".into(),
                            )
                        })?;
                    }
                    weak_authority
                        .upgrade()
                        .ok_or_else(|| {
                            noland_state_core::StateError::Conflict(
                                "Original device capture owner ended".into(),
                            )
                        })?
                        .revalidate()?;
                    weak_controller
                        .upgrade()
                        .ok_or_else(|| {
                            noland_state_core::StateError::Conflict(
                                "Original Tracker capture owner ended".into(),
                            )
                        })?
                        .verify_publication()
                        .map_err(|_| {
                            noland_state_core::StateError::Conflict(
                                "Original Tracker receipt no longer authorizes publication".into(),
                            )
                        })?;
                    guard().map_err(|_| {
                        noland_state_core::StateError::Conflict(
                            "Original captured retry authority was revoked".into(),
                        )
                    })
                }),
            )
            .map_err(public_source_error)?;
        self.rpc_private(
            "RetryOperation",
            &private,
            json!({"operation_id":operation}),
        )
        .await?;
        Ok(json!({"operationId":operation}))
    }

    /// A capability check, not tool/provider health or a successful placeholder.
    pub fn batch_source_verification_supported(&self) -> Result<()> {
        ensure!(
            self.agent.config.native_host && self.workspace.is_some(),
            "Batch source verification requires this QuickSave native workspace"
        );
        self._data.identity()?;
        Ok(())
    }

    /// Native-private result only: compact identities/digests and real monitoring
    /// progress. There are no keys, sessions, filesystem paths or SQL row details.
    ///
    /// `access` is optional and may be supplied ONLY during explicit native
    /// execution/reattachment. Ordinary status uses the existing private access
    /// and immutable authenticated cache; it cannot unlock a vault or do network
    /// I/O. Cancellation needs only the retained signed exact-ID capability,
    /// independent of subsequently revoked provider/write/root grants.
    pub async fn verify_batch_source(
        &self,
        access: Option<ProviderAccess>,
        binding: Value,
        purpose: &str,
    ) -> Result<Value> {
        self.batch_source_verification_supported()?;
        ensure!(
            matches!(purpose, "observation" | "cancellation"),
            "Unsupported actual-source proof purpose"
        );
        let expected = ExpectedBinding::parse(&binding)?;
        ensure!(
            purpose != "cancellation" || access.is_none(),
            "Cancellation must not acquire provider credentials"
        );
        // The same native bridge gate protects StartBackup's creation. No
        // database lookup/replay can race this method into spawning work.
        let _submission = self.submission.lock().await;
        let monitoring = self
            .agent
            .db
            .operation_monitoring_snapshot(expected.id)
            .map_err(public_source_error)?;
        let running = self.agent.operations.is_running(expected.id);
        let Some(monitoring) = monitoring else {
            return Ok(expected.projection(
                purpose,
                if running { "unknown" } else { "absent" },
                None,
                running,
                None,
                None,
                None,
            ));
        };
        let operation = &monitoring.operation;
        ensure!(
            operation.operation_id == expected.id
                && operation.kind == "backup"
                && operation.app_id.as_ref() == Some(&expected.app),
            "The actual source ID belongs to another kind or canonical application"
        );
        let state = batch_state(&operation.state);
        let progress = monitoring.progress.as_ref().map(|progress| {
            json!({
                "phase":super::safe_phase(&progress.phase),
                "unit":match progress.unit.as_deref() {
                    Some("bytes") => "bytes",
                    Some("files") => "files",
                    _ => "items",
                },
                "completed":progress.completed_units,
                "total":progress.total_units,
            })
        });
        if purpose == "cancellation" {
            // Monitoring is not cancellation AUTHORITY. The device-authenticated
            // frozen plan supplied by the service is the exact-ID capability;
            // this lookup only projects the matching real same-agent owner.
            return Ok(expected.projection(
                purpose,
                "present",
                Some(state),
                running,
                progress,
                None,
                None,
            ));
        }
        ensure!(
            expected.capture.is_some(),
            "An existing actual source needs its original signed frozen capture"
        );
        let explicit_access = access.is_some();
        let retained = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("Native private source ownership lock failed"))?
            .get(&expected.id)
            .cloned();
        let private = match access {
            Some(access) => {
                ensure!(
                    access.provider_id == expected.provider,
                    "Explicit source reattachment changed the frozen provider"
                );
                Some(Arc::new(self.private_access(&access, Some(expected.id))?))
            }
            None => retained,
        };
        if let Some(private) = &private {
            ensure!(
                private.provider_id == expected.provider
                    && private.session.operation_id == expected.id.to_string(),
                "Retained source credentials belong to another native operation"
            );
        }
        let cached = self
            .batch
            .lock()
            .map_err(|_| anyhow::anyhow!("Native batch binding cache lock failed"))?
            .authenticated
            .get(&expected.id)
            .cloned();
        let authenticated = match cached {
            Some(cached) => {
                ensure!(
                    cached.expected_digest == expected.digest,
                    "The frozen native source/capture binding changed"
                );
                if explicit_access {
                    let record = self
                        .agent
                        .db
                        .get_operation(expected.id)
                        .map_err(public_source_error)?
                        .context("The original source row disappeared during reattachment")?;
                    let current = authenticate_record(
                        &expected,
                        &record,
                        private
                            .as_deref()
                            .context("Private source access is unavailable")?,
                    )?;
                    ensure!(
                        current.submission_binding == cached.submission_binding
                            && current.native_selection_digest == cached.native_selection_digest
                            && current.repository_binding == cached.repository_binding,
                        "Actual source reattachment changed its authenticated submission"
                    );
                    cached
                        .completion
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Native completion proof lock failed"))?
                        .failed = false;
                }
                cached
            }
            None => {
                let private = private
                    .as_deref()
                    .context("Explicit private source reattachment is required after restart")?;
                let record = self
                    .agent
                    .db
                    .get_operation(expected.id)
                    .map_err(public_source_error)?
                    .context("The original source row disappeared during authentication")?;
                let authenticated = Arc::new(authenticate_record(&expected, &record, private)?);
                let mut cache = self
                    .batch
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Native batch binding cache lock failed"))?;
                ensure!(
                    cache.authenticated.len() < MAX_BINDINGS,
                    "The bounded native source attestation cache is full"
                );
                cache
                    .authenticated
                    .insert(expected.id, authenticated.clone());
                authenticated
            }
        };
        if explicit_access {
            self.reserve_private(
                expected.id,
                private
                    .clone()
                    .context("Explicit native source access is unavailable")?,
            )?;
        }
        let mut completion = authenticated
            .completion
            .lock()
            .map_err(|_| anyhow::anyhow!("Native completion proof lock failed"))?
            .digest
            .clone();
        if state == "completed" && !running && completion.is_none() {
            ensure!(
                !authenticated
                    .completion
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Native completion proof lock failed"))?
                    .failed,
                "Actual committed source proof failed; explicit reconciliation is required"
            );
            let result = self
                .authenticate_batch_completion(
                    &expected,
                    &authenticated,
                    private.as_deref(),
                    explicit_access,
                )
                .await;
            let mut memo = authenticated
                .completion
                .lock()
                .map_err(|_| anyhow::anyhow!("Native completion proof lock failed"))?;
            match result {
                Ok(digest) => {
                    completion = Some(digest.clone());
                    memo.digest = Some(digest);
                }
                Err(error) => {
                    // Neither a 4-Hz source poll nor a UI refresh should reload a
                    // huge manifest or retry provider I/O after failed proof.
                    memo.failed = true;
                    return Err(error);
                }
            }
        }
        Ok(expected.projection(
            purpose,
            "present",
            Some(state),
            running,
            progress,
            Some(&authenticated.binding_digest),
            completion.as_deref(),
        ))
    }

    async fn authenticate_batch_completion(
        &self,
        expected: &ExpectedBinding<'_>,
        authenticated: &AuthenticatedSource,
        private: Option<&PrivateAccess>,
        allow_remote: bool,
    ) -> Result<String> {
        let private =
            private.context("Original private source completion access is unavailable")?;
        let record = self
            .agent
            .db
            .get_operation(expected.id)
            .map_err(public_source_error)?
            .context("Actual completed source row is missing")?;
        ensure!(
            record.state == "COMPLETED" && !self.agent.operations.is_running(expected.id),
            "The actual source is not terminal and joined"
        );
        // Authenticate the full row once more at the terminal transition. Normal
        // polls between admission and this barrier read no retry/file-key JSON.
        let current = authenticate_record(expected, &record, private)?;
        ensure!(
            current.binding_digest == authenticated.binding_digest,
            "Actual source submission changed before durable completion"
        );
        let bundle = uuid_field(&record.detail_json, "bundle_id")?;
        let commit = uuid_field(&record.detail_json, "commit_id")?;
        let manifest = match read_cached_manifest(
            &self.agent.config.paths.cache,
            &expected.app,
            bundle,
            &authenticated.repository_binding,
            &private.master,
        )? {
            Some(manifest) => manifest,
            None => {
                ensure!(
                    allow_remote,
                    "Authenticated source metadata is not retained locally; explicit native completion reconciliation is required"
                );
                // Only explicit reattachment/finalization can take this path.
                // The actual source reader checks immutable COMMITTED plus the
                // repository-key AEAD manifest; raw COMPLETED JSON is no proof.
                self.preflight().await?;
                self.manifest(
                    private,
                    &json!({"appId":expected.app.as_str(),"bundleId":bundle}),
                )
                .await?
            }
        };
        ensure!(
            manifest.bundle_id == bundle
                && manifest.commit_id == commit
                && manifest.app.app_id == expected.app
                && manifest.source.instance_id == self.agent.config.instance_id
                && manifest.mode.as_str() == expected.mode
                && manifest.consistency != ConsistencyKind::BestEffort
                && manifest.environment["quicksave_native"]["coverage"]
                    == if expected.mode == "complete_application" {
                        "full_approved_scope"
                    } else {
                        "selected_nodes"
                    }
                && manifest.environment["quicksave_native"]["software_instance_id"]
                    == expected.instance
                && manifest.environment["quicksave_native"]["consistency"]
                    == "validated_stable_files",
            "Authenticated committed manifest differs from the exact native batch child"
        );
        let selection =
            NativeSelection::parse(&manifest.environment["quicksave_native"]["selection"])
                .map_err(public_source_error)?;
        verify_selection(expected, &selection)?;
        ensure!(
            digest(&serde_json::to_value(&selection)?, MAX_SOURCE_DOCUMENT)?
                == authenticated.native_selection_digest,
            "Committed source manifest changed its original authenticated selection"
        );
        let mut ids = BTreeSet::new();
        for file in &manifest.files {
            validate_native_relative(&file.relative_path).map_err(public_source_error)?;
            ensure!(
                ids.insert(native_file_id(&file.logical_root, &file.relative_path)),
                "Committed source manifest has duplicate logical file IDs"
            );
        }
        verify_ids(expected, &ids)?;
        // Verify full bytes/metadata, not just status, bundle ID, or timestamps.
        let manifest_hash = hash_serialized(&manifest, MAX_SOURCE_DOCUMENT)?;
        let original = authenticated
            .completion
            .lock()
            .map_err(|_| anyhow::anyhow!("Original manifest commit binding lock failed"))?
            .original_capture
            .clone();
        if let Some(original) = original {
            let envelope = source_expected_envelope(
                &private.master,
                expected.id,
                &original.expected_manifest_auth,
            )?;
            ensure!(
                envelope.app == expected.app
                    && envelope.operation == expected.id
                    && envelope.source_snapshot_id == bundle
                    && envelope.manifest_hash == format!("blake3:{manifest_hash}")
                    && envelope.roots_fingerprint == expected.native_roots_fingerprint
                    && authenticated.scope_digest
                        == hash_serialized(&envelope.scope, MAX_BINDING_BYTES)?,
                "Actual COMMITTED bytes differ from the original device-authenticated manifest"
            );
        }
        let result = digest(
            &json!({
                "domain":"QuickSave/actual-source-completion/v1",
                "sourceId":expected.id,
                "bindingDigest":authenticated.binding_digest,
                "bundleId":bundle,"commitId":commit,
                "manifestDigest":manifest_hash,
            }),
            MAX_BINDING_BYTES,
        )?;
        let mut memo = authenticated
            .completion
            .lock()
            .map_err(|_| anyhow::anyhow!("Native source manifest completion cache lock failed"))?;
        memo.manifest_hash = Some(format!("blake3:{manifest_hash}"));
        memo.bundle = Some(bundle);
        memo.commit = Some(commit);
        // Publish the entire authenticated result atomically here, including
        // direct completed-source recovery callers, not just status's wrapper.
        memo.digest = Some(result.clone());
        memo.failed = false;
        Ok(result)
    }
}

#[derive(Deserialize)]
struct SourceExpectedManifest {
    version: u32,
    operation: Uuid,
    app: AppId,
    scope: NativeCaptureScope,
    roots_fingerprint: String,
    source_snapshot_id: Uuid,
    manifest_hash: String,
    captured_files_hash: String,
    capture_proof_hash: String,
    root_layouts_hash: String,
}

fn source_expected_envelope(
    master: &MasterKey,
    operation: Uuid,
    auth: &Value,
) -> Result<SourceExpectedManifest> {
    ensure!(
        auth["version"] == 1
            && auth["operationId"] == operation.to_string()
            && auth["aad"] == "quicksave-native-expected-manifest-v1"
            && auth["algorithm"] == "source-xchacha20poly1305-metadata",
        "Actual original source expected-manifest envelope is unavailable"
    );
    let encoded = text(auth, "envelopeHex", 128 * 1024)?;
    ensure!(
        encoded.len() % 2 == 0 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Actual source expected-manifest envelope encoding is invalid"
    );
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair =
                std::str::from_utf8(pair).context("Invalid native source envelope encoding")?;
            u8::from_str_radix(pair, 16).context("Invalid native source envelope byte")
        })
        .collect::<Result<Vec<_>>>()?;
    let binding: SourceExpectedManifest = noland_storage::open_metadata_with_limit(
        &noland_crypto::derive_keys(master).manifest,
        b"quicksave-native-expected-manifest-v1",
        bytes,
        64 * 1024,
    )
    .map_err(public_source_error)?;
    binding.scope.validate().map_err(public_source_error)?;
    ensure!(
        binding.version == 1
            && binding.operation == operation
            && auth["manifestHash"] == binding.manifest_hash
            && auth["capturedFilesHash"] == binding.captured_files_hash
            && auth["capturedProofHash"] == binding.capture_proof_hash
            && auth["rootLayoutsHash"] == binding.root_layouts_hash,
        "Actual source envelope fields do not match their original authenticated bytes"
    );
    for hash in [
        &binding.manifest_hash,
        &binding.captured_files_hash,
        &binding.capture_proof_hash,
        &binding.root_layouts_hash,
    ] {
        valid_digest(
            hash.strip_prefix("blake3:")
                .context("Native source wire digest lacks its exact domain prefix")?,
        )?;
    }
    Ok(binding)
}

fn repository_cache_digest(
    repository: &ProviderRootIdentity,
    master: &MasterKey,
) -> Result<String> {
    let mut hash = blake3::Hasher::new_keyed(&master.0);
    hash.update(b"noland-repository-cache-v2\0");
    hash.update(&serde_json::to_vec(repository)?);
    Ok(hash.finalize().to_hex().to_string())
}

/// Exact non-secret provider projection used by native_plans::provider_scope.
/// No credentials are read: references/revision/routing must still be unchanged.
fn batch_provider_digest(provider: &Value) -> Result<String> {
    let mut scope = serde_json::Map::new();
    for key in [
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
    ] {
        if let Some(value) = provider.get(key) {
            scope.insert(key.into(), value.clone());
        }
    }
    digest(&Value::Object(scope), 128 * 1024)
}

fn verify_native_submission(
    operation: Uuid,
    app: &AppId,
    instance: &str,
    roots: &str,
    scope: &NativeCaptureScope,
    private: &PrivateAccess,
    record: &OperationRecord,
) -> Result<NativeSelection> {
    bounded(&record.detail_json["native_selection"], MAX_SOURCE_DOCUMENT)?;
    let selection = NativeSelection::parse(&record.detail_json["native_selection"])
        .map_err(public_source_error)?;
    let mode = text(&record.detail_json, "mode", 32)?;
    let performance = text(&record.detail_json, "performance_mode", 32)?;
    ensure!(
        record.operation_id == operation
            && record.kind == "backup"
            && record.app_id.as_ref() == Some(app)
            && record.detail_json["app_id"] == app.as_str()
            && record.detail_json["client_operation_id"] == operation.to_string()
            && matches!(performance, "automatic" | "fast" | "balanced" | "full")
            && record.detail_json["regenerable_caches"] == "include"
            && selection.destination.is_none()
            && selection.destination_identity.is_none()
            && selection.expected_files.is_none()
            && selection.capture_scope.as_ref() == Some(scope)
            && selection.snapshot_identity.as_deref() == Some(scope.metadata_identity.as_str())
            && selection.software_instance_id.as_deref() == Some(instance)
            && selection.roots_fingerprint == roots
            && (mode == "complete_application"
                && selection.coverage == NativeCoverage::FullApprovedScope
                || mode == "custom" && selection.coverage == NativeCoverage::SelectedNodes),
        "Actual source original native submission differs from its device-bound capture"
    );
    let repository = bound_session_identity(&private.session, &private.master)?;
    let expected = blake3::keyed_hash(
        &private.master.0,
        &serde_json::to_vec(&json!({
            "domain":"noland-operation-submission-v1","kind":"backup","repository":repository,
            "selection":{"app_id":app.as_str(),"mode":mode,"performance_mode":performance,
                "regenerable_caches":"include","native_selection":selection},
        }))?,
    )
    .to_hex()
    .to_string();
    ensure!(
        equal_digest(
            text(&record.detail_json, "submission_binding", 64)?,
            &expected
        ),
        "Actual source submission/repository replay HMAC did not authenticate"
    );
    Ok(selection)
}

fn current_tracking_scope(record: &Value) -> Result<Value> {
    let roots = record["roots"]
        .as_array()
        .context("Current approved native roots are missing")?;
    ensure!(
        !roots.is_empty() && roots.len() <= 128,
        "Current native root count is invalid"
    );
    let roots = roots.iter().map(|root| {
        let mut authority = json!({
            "id":root["id"],"path":root["path"],"role":root["role"],
            "identity":root["identity"],"allowedFiles":root.get("allowedFiles").unwrap_or(&Value::Null),
        });
        if root["directory"] == false { authority["directory"] = json!(false); }
        authority
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
            "policyHash":hash_serialized(&auto["policyScope"],MAX_BINDING_BYTES)?,
            "discoveryHash":hash_serialized(&auto["discoveryScope"],MAX_BINDING_BYTES)?,
            "appEvidenceHash":auto["appEvidenceHash"],"candidateHash":auto["candidateHash"],
            "coverageHash":hash_serialized(&json!({
                "rootsComplete":auto["rootsComplete"],"unresolvedRoots":auto["unresolvedRoots"],
                "unresolvedReasons":auto["unresolvedReasons"],
            }),MAX_BINDING_BYTES)?,
        });
    }
    bounded(&scope, MAX_BINDING_BYTES)?;
    Ok(scope)
}

struct CurrentRootPin {
    path: PathBuf,
    file: std::fs::File,
    identity: (u64, u64),
    directory: bool,
}
fn current_root_pins(roots: &[Value]) -> Result<Vec<CurrentRootPin>> {
    use std::os::unix::fs::MetadataExt;
    let mut pins = Vec::with_capacity(roots.len());
    for root in roots {
        let path = PathBuf::from(text(root, "path", 32768)?);
        let source = noland_snapshot::SourcePath::new(&path).map_err(public_source_error)?;
        let identity: quicksave_platform::RootIdentity =
            serde_json::from_value(root["identity"].clone())?;
        let directory = root["directory"] != false;
        let file = if directory {
            source.open_directory()
        } else {
            source.open_regular()
        }
        .map_err(public_source_error)?;
        let metadata = file.metadata()?;
        ensure!(
            identity.file_id[1] == 0
                && metadata.dev() == identity.device
                && metadata.ino() == identity.file_id[0]
                && metadata.is_dir() == directory
                && (metadata.is_file() || metadata.is_dir()),
            "Current completion root is not its originally approved native identity/kind"
        );
        pins.push(CurrentRootPin {
            path,
            file,
            identity: (identity.device, identity.file_id[0]),
            directory,
        });
    }
    check_current_root_pins(&pins)?;
    Ok(pins)
}
fn check_current_root_pins(pins: &[CurrentRootPin]) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for pin in pins {
        let held = pin.file.metadata()?;
        let actual = noland_snapshot::SourcePath::new(&pin.path)
            .and_then(|source| source.metadata())
            .map_err(public_source_error)?;
        ensure!(
            !actual.is_symlink()
                && actual.is_dir() == pin.directory
                && (actual.dev(), actual.ino()) == pin.identity
                && (held.dev(), held.ino()) == pin.identity,
            "Current native completion root identity changed"
        );
    }
    Ok(())
}

fn recheck_completion_authority(
    store: &quicksave_state::WorkspaceStore,
    software: &str,
    original: &Value,
    tracking: &Value,
    scope: &Value,
    grant: &Value,
) -> Result<()> {
    let current = store.software_record(software)?;
    ensure!(
        current["providerId"] == original["providerId"]
            && current["trackingGrant"] == original["trackingGrant"]
            && current["autosave"] == original["autosave"]
            && current["autosaveGrant"] == original["autosaveGrant"]
            && current_tracking_scope(&current)? == *tracking
            && current["captureReceipt"]["scope"] == *scope
            && current["captureReceipt"]["grant"] == *grant
            && store.verify_tracking_grant(software)?
            && store.verify_grant("tracking_capture_receipt", scope, grant)?,
        "Original native source completion authority changed before finalization"
    );
    let provider = text(&current, "providerId", 128)?;
    ensure!(
        store
            .document()?
            .providers
            .iter()
            .any(|record| record.id == provider
                && record.status == "connected"
                && !record.read_only),
        "Original provider authority was disconnected/revoked before native finalization"
    );
    Ok(())
}

fn remember_capture_completion(
    engine: &NativeEngine,
    operation: Uuid,
    binding: &str,
    proof: &str,
) -> Result<()> {
    let mut state = engine
        .batch
        .lock()
        .map_err(|_| anyhow::anyhow!("Native commit proof cache lock failed"))?;
    ensure!(
        state.verified_captures.len() < MAX_BINDINGS
            || state.verified_captures.contains_key(&operation),
        "Native committed capture proof cache is full"
    );
    if let Some((original, existing)) = state.verified_captures.get(&operation) {
        ensure!(
            original == binding && existing == proof,
            "Original native committed capture proof changed"
        );
    } else {
        state
            .verified_captures
            .insert(operation, (binding.into(), proof.into()));
    }
    Ok(())
}

struct OriginalSink {
    controller: Arc<dyn crate::capture_control::NativeCaptureController>,
    // The actual resumed source Session owns this compact native authority.
    // Publication callbacks use Weak so old terminal attempts retain no frame.
    authority: Arc<DeviceOriginalCaptureAuthority>,
}

struct OriginalFullScope {
    owner: Arc<dyn crate::capture_control::NativeFullScopeAuthority>,
}
impl native_capture::NativeFullScopeAuthority for OriginalFullScope {
    fn evidence(&self) -> noland_state_core::Result<Value> {
        self.owner
            .evidence()
            .map_err(|_| resume_error("Original full-scope evidence is unavailable"))
    }
    fn revalidate(&self) -> noland_state_core::Result<()> {
        self.owner
            .revalidate()
            .map_err(|_| resume_error("Original full-scope grants/policy changed"))
    }
}
impl NativeCaptureSink for OriginalSink {
    fn node_page(
        &self,
        scope: &NativeCaptureScope,
        offset: usize,
        limit: usize,
    ) -> noland_state_core::Result<Vec<native_capture::NativeCaptureNode>> {
        self.controller
            .node_page(scope, offset, limit)
            .map_err(|_| resume_error("Original signed Tracker metadata page is unavailable"))
    }
    fn reuse_epoch(&self, _: &NativeCaptureScope) -> noland_state_core::Result<Option<String>> {
        Ok(None) // Restart is a gap, never a new unchanged-content capability.
    }
    fn full_scope_authority(
        &self,
        scope: &NativeCaptureScope,
    ) -> noland_state_core::Result<Option<Arc<dyn native_capture::NativeFullScopeAuthority>>> {
        self.controller
            .full_scope_authority(scope)
            .map(|owner| {
                owner.map(|owner| {
                    Arc::new(OriginalFullScope { owner })
                        as Arc<dyn native_capture::NativeFullScopeAuthority>
                })
            })
            .map_err(|_| resume_error("Original full-scope native owner is unavailable"))
    }
    fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> noland_state_core::Result<()> {
        self.authority.revalidate()?;
        self.controller
            .accept(Arc::new(
                crate::capture_control::PreparedCaptureReceipt::from_source_receipt(receipt),
            ))
            .map_err(|_| resume_error("Tracker refused original native receipt reattachment"))
    }
}

struct DeviceOriginalCaptureAuthority {
    store: quicksave_state::WorkspaceStore,
    root: SafeRoot,
    artifacts: Vec<(String, FileStamp)>,
    grants: Vec<(&'static str, Value, Value)>,
    original_evidence: Mutex<Option<Arc<Value>>>,
    evidence_digest: String,
    expected_manifest_auth: Value,
}
impl DeviceOriginalCaptureAuthority {
    fn open(
        store: quicksave_state::WorkspaceStore,
        root: SafeRoot,
        expected: &ExpectedBinding<'_>,
        work: &Value,
        frozen: &Value,
        receipt: &Value,
    ) -> Result<Self> {
        let frozen_scope = &frozen["scope"];
        let receipt_scope = &receipt["scope"];
        let authorization = &work["authorization"];
        let tracking = &authorization["trackingScope"];
        let tracking_hash = hash_serialized(tracking, MAX_BINDING_BYTES)?;
        let capture = expected
            .capture
            .context("Original frozen batch capture is missing")?;
        for (scope, field) in [
            (frozen_scope, "frameHash"),
            (frozen_scope, "authorizationHash"),
            (frozen_scope, "selectedIdsHash"),
            (frozen_scope, "deletedIdsHash"),
            (frozen_scope, "captureReceiptHash"),
            (frozen_scope, "originalReferenceHash"),
            (receipt_scope, "capturedSnapshotIdentity"),
            (receipt_scope, "expectedFilesHash"),
            (receipt_scope, "sourceExpectedManifestAuthHash"),
            (receipt_scope, "fullScopeProofHash"),
        ] {
            valid_digest(text(scope, field, 64)?)?;
        }
        ensure!(
            frozen_scope["version"] == 1
                && frozen_scope["workId"] == work["workId"]
                && frozen_scope["softwareId"] == work["softwareId"]
                && frozen_scope["providerId"] == work["providerId"]
                && frozen_scope["generation"] == work["generation"]
                && frozen_scope["unknownGeneration"].as_u64().is_some()
                && frozen_scope["metadataIdentity"] == capture["metadataIdentity"]
                && frozen_scope["trackingScopeHash"] == tracking_hash
                && frozen_scope["trackingGrantHash"] == hash_serialized(&authorization["trackingGrant"],MAX_BINDING_BYTES)?
                && frozen_scope["authorizationHash"] == hash_serialized(authorization,MAX_BINDING_BYTES)?
                && frozen_scope["selectedIdsHash"] == hash_serialized(&work["fileIds"],MAX_SOURCE_DOCUMENT)?
                && frozen_scope["deletedIdsHash"] == hash_serialized(&work["deletedFileIds"],MAX_SOURCE_DOCUMENT)?
                && frozen_scope["captureReceiptHash"] == hash_serialized(receipt,MAX_BINDING_BYTES)?
                && frozen_scope["stage"] == "source_receipt_accepted"
                && receipt_scope["version"] == 1
                && receipt_scope["workId"] == work["workId"]
                && receipt_scope["softwareId"] == work["softwareId"]
                && receipt_scope["providerId"] == work["providerId"]
                && receipt_scope["generation"] == work["generation"]
                && receipt_scope["metadataIdentity"] == capture["metadataIdentity"]
                && receipt_scope["unknownGeneration"] == frozen_scope["unknownGeneration"]
                && receipt_scope["trackingScopeHash"] == tracking_hash
                && receipt_scope["immutablePreparedCapture"] == true
                && receipt_scope["fullScopeProofHash"]
                    == hash_serialized(&work["captureSource"]["expectedFullScope"],MAX_BINDING_BYTES)?,
            "Original frozen frame and post-capture receipt do not bind this exact native source work"
        );
        if let Some(source) = frozen_scope.get("sourceOperationId") {
            ensure!(
                source.as_str() == Some(expected.id.to_string().as_str()),
                "Original signed frame is bound to another source operation"
            );
        }
        let frame_reference = frozen;
        let receipt_reference = &receipt["reference"];
        let mut grants = vec![
            (
                "tracking",
                tracking.clone(),
                authorization["trackingGrant"].clone(),
            ),
            (
                "tracking_frozen_work",
                frozen_scope.clone(),
                frozen["grant"].clone(),
            ),
            (
                "tracking_capture_receipt",
                receipt_scope.clone(),
                receipt["grant"].clone(),
            ),
            (
                "tracking_capture_receipt_sidecar",
                receipt_reference["scope"].clone(),
                receipt_reference["grant"].clone(),
            ),
        ];
        let full = &work["captureSource"]["expectedFullScope"];
        if expected.mode == "complete_application" {
            ensure!(
                full["scope"]["workId"] == work["workId"]
                    && full["scope"]["softwareId"] == work["softwareId"]
                    && full["scope"]["providerId"] == work["providerId"]
                    && full["scope"]["generation"] == work["generation"]
                    && full["scope"]["metadataIdentity"] == capture["metadataIdentity"]
                    && full["scope"]["trackingScopeHash"] == tracking_hash
                    && full["scope"]["expectedNodeIdsHash"]
                        == hash_serialized(&work["fileIds"], MAX_SOURCE_DOCUMENT)?
                    && full["scope"]["deletedNodeIdsHash"]
                        == hash_serialized(&work["deletedFileIds"], MAX_SOURCE_DOCUMENT)?,
                "Original full-scope/omission grant differs from the frozen work frame"
            );
            grants.push((
                "tracking_full_capture",
                full["scope"].clone(),
                full["grant"].clone(),
            ));
        } else {
            ensure!(
                full.is_null(),
                "Selected original work cannot add full-scope omission authority"
            );
        }
        if work["automatic"] == true {
            grants.push((
                "autosave",
                authorization["autosaveScope"].clone(),
                authorization["autosaveGrant"].clone(),
            ));
        }
        for (kind, scope, grant) in &grants {
            ensure!(
                store.verify_grant(kind, scope, grant)?,
                "An original native work/receipt grant is invalid or revoked"
            );
        }
        ensure!(
            receipt_reference["scope"]["tracking"] == *tracking
                && receipt_reference["scope"]["captureScope"] == *receipt_scope
                && frozen_scope["frameHash"] == frame_reference["hash"],
            "Original native frame/receipt sidecar references changed their signed scope"
        );
        let (frame, frame_name, frame_stamp) =
            read_original_artifact(&root, frame_reference, "work-")?;
        let metadata_count = frame["metadata"]["nodes"]
            .as_object()
            .map(|nodes| nodes.len());
        let selected_count = capture["fileCount"].as_u64().unwrap_or(u64::MAX);
        ensure!(
            frame["version"] == 1
                && frame["request"] == *work
                && frame["originToken"] == frozen_scope["originToken"]
                && frame["unknownGeneration"] == frozen_scope["unknownGeneration"]
                && frame["acceptedReceipt"] == *receipt
                && metadata_count.is_some_and(|count| count <= MAX_NODES
                    && if expected.mode == "complete_application" {
                        count as u64 == selected_count
                    } else {
                        count as u64 >= selected_count
                    }),
            "Original native frame lacks its complete unchanged frozen metadata snapshot"
        );
        // The accepted frame's fresh device MAC authenticates the ORIGINAL
        // pre-execution frame reference as well. Its old per-purpose registry
        // nonce may have rotated when the accepted frame was persisted; do not
        // reissue it or silently substitute today's metadata.
        let original_reference = &frame["originalReference"];
        ensure!(
            original_reference.is_object()
                && frozen_scope["originalReferenceHash"]
                    == hash_serialized(original_reference, MAX_BINDING_BYTES)?
                && original_reference["scope"]["stage"] == "metadata_frozen"
                && original_reference["scope"]["originToken"] == frozen_scope["originToken"]
                && original_reference["scope"]["workId"] == work["workId"]
                && original_reference["scope"]["generation"] == work["generation"]
                && original_reference["scope"]["metadataIdentity"] == capture["metadataIdentity"],
            "Original pre-execution native frame provenance is unavailable"
        );
        let (initial, initial_name, initial_stamp) =
            read_original_artifact(&root, original_reference, "work-")?;
        ensure!(
            initial["version"] == 1
                && initial["request"] == *work
                && initial["originToken"] == frame["originToken"]
                && initial["metadata"] == frame["metadata"]
                && initial["acceptedReceipt"].is_null(),
            "Original frozen pre-execution native snapshot changed"
        );
        drop(initial);
        drop(frame);
        let (evidence, receipt_name, receipt_stamp) =
            read_original_artifact(&root, receipt_reference, "receipt-")?;
        ensure!(
            evidence["workId"] == work["workId"]
                && evidence["metadataIdentity"] == capture["metadataIdentity"]
                && evidence["sourceSnapshotId"] == receipt_scope["sourceSnapshotId"]
                && evidence["sourceExpectedManifestAuth"]["operationId"] == expected.id.to_string()
                && receipt_scope["sourceExpectedManifestAuthHash"]
                    == hash_serialized(&evidence["sourceExpectedManifestAuth"],MAX_BINDING_BYTES)?,
            "Original device-authenticated sidecar does not contain the actual source expected-manifest envelope"
        );
        let evidence_digest = hash_serialized(&evidence, MAX_SOURCE_DOCUMENT)?;
        let expected_manifest_auth = evidence["sourceExpectedManifestAuth"].clone();
        Ok(Self {
            store,
            root,
            artifacts: vec![
                (frame_name, frame_stamp),
                (initial_name, initial_stamp),
                (receipt_name, receipt_stamp),
            ],
            grants,
            original_evidence: Mutex::new(Some(Arc::new(evidence))),
            evidence_digest,
            expected_manifest_auth,
        })
    }
    fn revalidate_native(&self) -> Result<()> {
        self.root.identity()?;
        for (kind, scope, grant) in &self.grants {
            ensure!(
                self.store.verify_grant(kind, scope, grant)?,
                "Original native frame/receipt authority changed or was revoked"
            );
        }
        for (name, stamp) in &self.artifacts {
            self.root.verify_file(name, stamp)?;
        }
        Ok(())
    }
}
impl NativeOriginalCaptureAuthority for DeviceOriginalCaptureAuthority {
    fn revalidate(&self) -> noland_state_core::Result<()> {
        self.revalidate_native()
            .map_err(|_| resume_error("Original device frame/receipt authority changed"))
    }
    fn original_evidence(&self) -> noland_state_core::Result<Arc<Value>> {
        self.original_evidence
            .lock()
            .map_err(|_| resume_error("Original receipt ownership lock failed"))?
            .take()
            .ok_or_else(|| resume_error("Original receipt evidence handoff was already consumed"))
    }
    fn verify_recovered(&self, evidence: &Value) -> noland_state_core::Result<()> {
        let actual = hash_serialized(evidence, MAX_SOURCE_DOCUMENT)
            .map_err(|_| resume_error("Recovered source receipt exceeds its bound"))?;
        if actual != self.evidence_digest {
            return Err(resume_error(
                "Recovered source receipt is not the original device-authenticated sidecar",
            ));
        }
        self.revalidate()
    }
}

fn verify_original_work(expected: &ExpectedBinding<'_>, work: &Value) -> Result<()> {
    let capture = expected
        .capture
        .context("Original signed batch capture is missing")?;
    let registration = expected.registration;
    ensure!(
        work["workId"] == capture["workId"]
            && work["softwareId"] == registration["id"]
            && work["appId"] == expected.instance
            && work["providerId"] == expected.provider
            && work["generation"] == capture["generation"]
            && work["captureSource"]["stage"] == "awaiting_native_capture_receipt"
            && work["captureSource"]["selectionKind"]
                == if expected.mode == "complete_application" {
                    "full_scope"
                } else {
                    "selected_nodes"
                }
            && work["captureSource"]["snapshotIdentity"] == capture["snapshotIdentity"]
            && work["captureSource"]["metadataSelection"]["workId"] == capture["workId"]
            && work["captureSource"]["metadataSelection"]["metadataIdentity"]
                == capture["metadataIdentity"]
            && work["captureSource"]["metadataSelection"]["nodeCount"] == capture["fileCount"]
            && work["fileIds"].as_array().is_some_and(
                |ids| ids.len() as u64 == capture["fileCount"].as_u64().unwrap_or(u64::MAX)
            )
            && digest(&work["fileIds"], MAX_SOURCE_DOCUMENT)?
                == text(capture, "selectionDigest", 64)?,
        "Recovery widened or recaptured the original signed Tracker work"
    );
    let tracking = &work["authorization"]["trackingScope"];
    ensure!(
        tracking["softwareId"] == registration["id"]
            && tracking["appId"] == expected.instance
            && work["authorization"]["trackingGrant"] == registration["trackingGrant"],
        "Original work changed its native tracking/installation authority"
    );
    let native_identity = registration
        .get("sourceIdentity")
        .filter(|value| !value.is_null());
    ensure!(
        work.get("sourceIdentity").filter(|value| !value.is_null()) == native_identity,
        "Original work canonical source identity changed"
    );
    // The exact signed source-root fingerprint is independently derived from
    // both records. Source/display metadata outside authority is not compared.
    let roots = work["roots"]
        .as_array()
        .context("Original native roots are missing")?;
    ensure!(
        frozen_native_roots_fingerprint(&expected.app, roots)? == expected.native_roots_fingerprint,
        "Original frozen work has different root layout/native identities"
    );
    Ok(())
}

fn read_original_artifact(
    root: &SafeRoot,
    reference: &Value,
    prefix: &str,
) -> Result<(Value, String, FileStamp)> {
    let leaf = text(reference, "name", 255)?;
    ensure!(
        leaf.starts_with(prefix)
            && leaf.ends_with(".json")
            && !leaf.contains(['/', '\\', ':', '\0'])
            && reference["scope"]["name"] == leaf
            && if prefix == "work-" {
                reference["scope"]["frameHash"] == reference["hash"]
            } else {
                reference["scope"]["hash"] == reference["hash"]
            },
        "Original private native sidecar reference is not confined"
    );
    let expected = text(reference, "hash", 64)?;
    valid_digest(expected)?;
    let name = format!("tracking-bundles/{leaf}");
    let (mut file, stamp) = root.read_file(&name)?;
    quicksave_platform::verify_private_file(&file)?;
    ensure!(
        stamp.size <= MAX_SOURCE_DOCUMENT as u64,
        "Original native sidecar exceeds its metadata bound"
    );
    if let Some(bytes) = reference.get("bytes") {
        ensure!(
            bytes.as_u64() == Some(stamp.size)
                && reference["scope"]["bytes"].as_u64() == Some(stamp.size),
            "Original native frame reference length changed"
        );
    }
    struct Reader<'a> {
        file: &'a mut std::fs::File,
        hash: blake3::Hasher,
        bytes: u64,
    }
    impl Read for Reader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.file.read(buffer)?;
            self.bytes = self
                .bytes
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("Original native sidecar size overflow"))?;
            if self.bytes > MAX_SOURCE_DOCUMENT as u64 {
                return Err(std::io::Error::other(
                    "Original native sidecar exceeds its bound",
                ));
            }
            self.hash.update(&buffer[..count]);
            Ok(count)
        }
    }
    let mut reader = Reader {
        file: &mut file,
        hash: blake3::Hasher::new(),
        bytes: 0,
    };
    let value: Value = serde_json::from_reader(BufReader::new(&mut reader))
        .context("Original native sidecar is invalid")?;
    ensure!(
        reader.bytes == stamp.size
            && equal_digest(reader.hash.finalize().to_hex().as_str(), expected),
        "Original native sidecar does not match its device-authenticated reference"
    );
    drop(reader);
    quicksave_platform::verify_private_file(&file)?;
    root.verify_file(&name, &stamp)?;
    Ok((value, name, stamp))
}

#[derive(Deserialize)]
struct OriginalPrepared {
    version: u32,
    storage_id: Option<String>,
    manifest: BundleManifest,
    #[serde(default)]
    capture: Option<Value>,
    #[serde(default)]
    packing: Option<Value>,
    pack_files: Vec<(String, PathBuf)>,
    checksums: BTreeMap<String, String>,
}

fn original_prepared_manifest(
    path: &Path,
    operation: Uuid,
    app: &AppId,
    mode: &str,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
) -> Result<(BundleManifest, FileStamp)> {
    let root = SafeRoot::open(path)?;
    let name = format!("resume/{operation}.enc");
    let (file, stamp) = root.read_file(&name)?;
    ensure!(
        stamp.size <= MAX_SOURCE_DOCUMENT as u64 + 1024 * 1024,
        "Original prepared backup metadata exceeds its encrypted source bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_DOCUMENT as u64 + 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_SOURCE_DOCUMENT + 1024 * 1024,
        "Original prepared backup metadata exceeds its source bound"
    );
    root.verify_file(&name, &stamp)?;
    let prepared: OriginalPrepared = noland_storage::open_metadata_with_limit(
        &noland_crypto::derive_keys(master).manifest,
        format!("backup-resume:{operation}").as_bytes(),
        bytes,
        MAX_SOURCE_DOCUMENT as u64,
    )
    .map_err(public_source_error)?;
    let repository = bound_session_identity(session, master)?;
    ensure!(
        matches!(prepared.version, 2 | 3)
            && prepared.storage_id.as_deref() == Some(repository.cache_key().as_str())
            && prepared.capture.is_none()
            && prepared.packing.is_none()
            && prepared.manifest.app.app_id == *app
            && prepared.manifest.mode.as_str() == mode
            && prepared.pack_files.len() <= MAX_NODES,
        "Original prepared backup is incomplete or has another repository/app/mode"
    );
    let mut seen = BTreeSet::new();
    for (id, pack) in &prepared.pack_files {
        let uuid = Uuid::parse_str(id).context("Original prepared pack ID is invalid")?;
        ensure!(
            uuid.to_string() == *id
                && seen.insert(id)
                && *pack
                    == path
                        .join(prepared.manifest.bundle_id.to_string())
                        .join(format!("{id}.pack"))
                && prepared.checksums.contains_key(id),
            "Original prepared backup changed its fixed pack identities"
        );
        // Only retained immutable ciphertext is opened here, never live app
        // files or plaintext CAS content. Actual source RetryOperation performs
        // the original checksum/journal/upload checks before publication.
        let relative = format!("{}/{id}.pack", prepared.manifest.bundle_id);
        let (file, pack_stamp) = root
            .read_file(&relative)
            .context("Original immutable captured pack bytes are missing")?;
        ensure!(
            file.metadata()?.is_file(),
            "Original captured pack is not a regular native file"
        );
        root.verify_file(&relative, &pack_stamp)?;
    }
    root.verify_file(&name, &stamp)?;
    Ok((prepared.manifest, stamp))
}

fn resume_error(message: &'static str) -> noland_state_core::StateError {
    noland_state_core::StateError::Conflict(message.into())
}

impl<'a> ExpectedBinding<'a> {
    fn parse(value: &'a Value) -> Result<Self> {
        bounded(value, MAX_BINDING_BYTES)?;
        ensure!(
            value["version"] == 1,
            "Unsupported native source binding version"
        );
        let id = uuid_field(value, "sourceId")?;
        let app = AppId(text(value, "canonicalAppId", 512)?.into());
        let instance = text(value, "trackerAppId", 512)?;
        let provider = text(value, "providerId", 128)?;
        let mode = value
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("complete_application");
        ensure!(
            matches!(mode, "complete_application" | "custom"),
            "Unsupported original native capture mode"
        );
        let root_authority = text(value, "rootAuthorityRevision", 64)?;
        for field in [
            "nativePlanDigest",
            "providerDigest",
            "rootAuthorityRevision",
        ] {
            valid_digest(text(value, field, 64)?)?;
        }
        let _ = uuid_field(value, "planSetId")?;
        let _ = uuid_field(value, "nativePlanId")?;
        if let Some(root_digest) = value.get("rootDigest") {
            valid_digest(
                root_digest
                    .as_str()
                    .context("Invalid native plan-set root digest")?,
            )?;
        }
        let registration = &value["registration"];
        ensure!(
            registration["id"] == value["softwareId"]
                && registration["appId"] == instance
                && registration["providerId"] == provider
                && registration["tracked"] == true,
            "Frozen native registration identity changed"
        );
        ensure!(
            registration
                .pointer("/sourceIdentity/app_id")
                .and_then(Value::as_str)
                .unwrap_or(instance)
                == app.as_str(),
            "Frozen native canonical application identity changed"
        );
        let roots = registration["roots"]
            .as_array()
            .context("Frozen native source roots are missing")?;
        ensure!(
            !roots.is_empty() && roots.len() <= 128,
            "Frozen native root count is outside its bound"
        );
        let native_roots_fingerprint = frozen_native_roots_fingerprint(&app, roots)?;
        let capture = value.get("capture").filter(|capture| !capture.is_null());
        let capture_digest = value.get("captureDigest").and_then(Value::as_str);
        match capture {
            Some(capture) => {
                let declared = capture_digest.context("Frozen capture digest is missing")?;
                valid_digest(declared)?;
                ensure!(
                    capture["version"] == 1
                        && capture["sourceId"] == id.to_string()
                        && capture["nativePlanDigest"] == value["nativePlanDigest"]
                        && digest(capture, MAX_BINDING_BYTES)? == declared,
                    "Original signed native capture binding changed"
                );
                valid_digest(text(capture, "selectionDigest", 64)?)?;
                let count = capture["fileCount"]
                    .as_u64()
                    .context("Frozen exact native node count is missing")?;
                ensure!(
                    count <= MAX_NODES as u64,
                    "Frozen native capture exceeds its bound"
                );
                text(capture, "workId", 128)?;
                text(capture, "metadataIdentity", 512)?;
                text(capture, "snapshotIdentity", 512)?;
                ensure!(
                    capture["snapshotIdentity"] == capture["metadataIdentity"],
                    "Frozen source snapshot and original metadata scope differ"
                );
            }
            None => ensure!(
                capture_digest.is_none(),
                "An uncaptured source cannot carry a capture digest"
            ),
        }
        Ok(Self {
            id,
            app,
            instance,
            provider,
            mode,
            root_authority,
            registration,
            roots,
            native_roots_fingerprint,
            capture,
            capture_digest,
            digest: digest(value, MAX_BINDING_BYTES)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn projection(
        &self,
        purpose: &str,
        presence: &str,
        state: Option<&str>,
        running: bool,
        progress: Option<Value>,
        binding: Option<&str>,
        completion: Option<&str>,
    ) -> Value {
        json!({
            "version":1,"sourceId":self.id,"purpose":purpose,
            "rootAuthorityRevision":self.root_authority,
            "captureDigest":self.capture_digest,
            "presence":presence,"state":state,"workerRunning":running,"progress":progress,
            "bindingDigest":binding,"completionDigest":completion,
        })
    }
}

fn authenticate_record(
    expected: &ExpectedBinding<'_>,
    operation: &OperationRecord,
    private: &PrivateAccess,
) -> Result<AuthenticatedSource> {
    ensure!(
        operation.operation_id == expected.id
            && operation.kind == "backup"
            && operation.app_id.as_ref() == Some(&expected.app)
            && operation.detail_json["client_operation_id"] == expected.id.to_string()
            && operation.detail_json["app_id"] == expected.app.as_str()
            && operation.detail_json["mode"] == expected.mode
            && operation.detail_json["performance_mode"] == "automatic"
            && operation.detail_json["regenerable_caches"] == "include"
            && private.provider_id == expected.provider,
        "Actual source does not match its frozen native backup identity/mode/policy"
    );
    bounded(
        &operation.detail_json["native_selection"],
        MAX_SOURCE_DOCUMENT,
    )?;
    let native = NativeSelection::parse(&operation.detail_json["native_selection"])
        .map_err(public_source_error)?;
    verify_selection(expected, &native)?;
    let selection = json!({
        "app_id":expected.app.as_str(),"mode":expected.mode,
        "performance_mode":"automatic","regenerable_caches":"include",
        "native_selection":native,
    });
    let repository = bound_session_identity(&private.session, &private.master)?;
    // Exact active-source submission domain/selection serialization, NOT a new
    // service MAC or a claim that the row's own digest authenticates itself.
    let submission = blake3::keyed_hash(
        &private.master.0,
        &serde_json::to_vec(&json!({
            "domain":"noland-operation-submission-v1",
            "kind":"backup","repository":repository,"selection":selection,
        }))?,
    )
    .to_hex()
    .to_string();
    let stored = text(&operation.detail_json, "submission_binding", 64)?;
    ensure!(
        equal_digest(stored, &submission),
        "Actual source replay/submission authentication failed"
    );
    let mut cache_hash = blake3::Hasher::new_keyed(&private.master.0);
    cache_hash.update(b"noland-repository-cache-v2\0");
    cache_hash.update(&serde_json::to_vec(&repository)?);
    let repository_binding = cache_hash.finalize().to_hex().to_string();
    let native_selection_digest = digest(&serde_json::to_value(&native)?, MAX_SOURCE_DOCUMENT)?;
    let binding_digest = digest(
        &json!({
            "domain":"QuickSave/actual-source-binding/v1",
            "expected":expected.digest,"submission":submission,
            "nativeSelection":native_selection_digest,"repository":repository_binding,
        }),
        MAX_BINDING_BYTES,
    )?;
    Ok(AuthenticatedSource {
        expected_digest: expected.digest.clone(),
        native_selection_digest,
        submission_binding: submission,
        repository_binding,
        binding_digest,
        app: expected.app.clone(),
        instance: expected.instance.into(),
        native_roots_fingerprint: expected.native_roots_fingerprint.clone(),
        scope_digest: hash_serialized(
            native
                .capture_scope
                .as_ref()
                .context("Actual source receipt scope is missing")?,
            MAX_BINDING_BYTES,
        )?,
        completion: Mutex::new(CompletionMemo::default()),
    })
}

fn verify_selection(expected: &ExpectedBinding<'_>, selection: &NativeSelection) -> Result<()> {
    let capture = expected
        .capture
        .context("Original native capture binding is missing")?;
    let scope = selection
        .capture_scope
        .as_ref()
        .context("Actual source lost the original native capture/receipt scope")?;
    ensure!(
        selection.version == 1
            && selection.destination.is_none()
            && selection.destination_identity.is_none()
            && selection.expected_files.is_none()
            && selection.coverage
                == if expected.mode == "complete_application" {
                    NativeCoverage::FullApprovedScope
                } else {
                    NativeCoverage::SelectedNodes
                }
            && selection.software_instance_id.as_deref() == Some(expected.instance)
            && selection.roots_fingerprint == expected.native_roots_fingerprint
            && selection.snapshot_identity.as_deref() == capture["metadataIdentity"].as_str()
            && scope.work_id == text(capture, "workId", 128)?
            && scope.metadata_identity == text(capture, "metadataIdentity", 512)?
            && scope.node_count as u64 == capture["fileCount"].as_u64().unwrap_or(u64::MAX)
            && if expected.mode == "complete_application" {
                scope
                    .full_scope
                    .as_ref()
                    .is_some_and(|full| full.root_count == expected.roots.len())
            } else {
                scope.full_scope.is_none()
            },
        "Actual source selection widened or changed its original signed roots/capture/instance"
    );
    scope.validate().map_err(public_source_error)?;
    let keys = selection
        .file_keys
        .as_ref()
        .context("Actual source exact file selection is missing")?;
    let allowed_roots = expected
        .roots
        .iter()
        .map(|root| {
            Ok((
                native_root_token(&expected.app, text(root, "id", 128)?),
                root,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut ids = BTreeSet::new();
    for key in keys {
        let root = allowed_roots
            .get(&key.logical_root)
            .context("Actual source includes an unapproved logical root")?;
        validate_native_relative(&key.relative_path).map_err(public_source_error)?;
        if let Some(leaves) = root["allowedFiles"].as_array() {
            ensure!(
                !key.relative_path.contains('/')
                    && leaves
                        .iter()
                        .any(|leaf| leaf.as_str() == Some(key.relative_path.as_str())),
                "Actual source widened an exact native manual-file allowlist"
            );
        }
        ensure!(
            ids.insert(native_file_id(&key.logical_root, &key.relative_path)),
            "Actual source has duplicate logical file IDs"
        );
    }
    verify_ids(expected, &ids)
}

fn verify_ids(expected: &ExpectedBinding<'_>, ids: &BTreeSet<String>) -> Result<()> {
    let capture = expected
        .capture
        .context("Original native capture is missing")?;
    ensure!(
        ids.len() <= MAX_NODES
            && ids.len() as u64 == capture["fileCount"].as_u64().unwrap_or(u64::MAX)
            && digest(&json!(ids), MAX_SOURCE_DOCUMENT)? == text(capture, "selectionDigest", 64)?,
        "Actual source file IDs differ from the original exact sorted frozen work"
    );
    Ok(())
}

/// Reproduce native_host::native_binding_fingerprint v3 from SIGNED roots, not
/// live row fields or whichever installation happens to be registered now. The
/// frozen `directory:false` discriminator denotes a direct file root; omitted
/// means an approved directory tree (including exact manual-leaf parent roots).
/// No roots are reopened: revoked/missing roots must still permit cancellation.
fn frozen_native_roots_fingerprint(app: &AppId, roots: &[Value]) -> Result<String> {
    let mut sorted = BTreeMap::new();
    for root in roots {
        ensure!(
            sorted.insert(text(root, "id", 128)?, root).is_none(),
            "Duplicate frozen native root ID"
        );
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"quicksave-native-roots-v3\0");
    hash.update(app.as_str().as_bytes());
    for (id, root) in sorted {
        let role = root["role"].as_str().unwrap_or("manual");
        noland_state_agent::native_host::NativeRootRole::parse(role)
            .map_err(public_source_error)?;
        let path = text(root, "path", 32768)?;
        ensure!(
            Path::new(path).is_absolute()
                && !Path::new(path).components().any(|part| matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )),
            "Frozen native root path is not canonical and absolute"
        );
        let directory = match root.get("directory") {
            None | Some(Value::Null) => true,
            Some(Value::Bool(directory)) => *directory,
            Some(_) => bail!("Frozen native root kind is not a directory/file discriminator"),
        };
        ensure!(
            directory || root.get("allowedFiles").is_none_or(Value::is_null),
            "A frozen manual-file allowlist requires its approved parent directory"
        );
        let leaf = Path::new(path)
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .context("Frozen native root has no UTF-8 layout basename")?;
        noland_state_core::native_layout::validate_native_layout_leaf(leaf)
            .map_err(public_source_error)?;
        let identity: quicksave_platform::RootIdentity =
            serde_json::from_value(root["identity"].clone())
                .context("Frozen native root lacks its original device/file identity")?;
        ensure!(
            identity.file_id[1] == 0,
            "Unsupported frozen Unix root identity"
        );
        hash.update(&(id.len() as u64).to_le_bytes());
        hash.update(id.as_bytes());
        hash.update(role.as_bytes());
        hash.update(&[0]);
        hash.update(if directory { b"directory\0" } else { b"file\0" });
        hash.update(&(leaf.len() as u64).to_le_bytes());
        hash.update(leaf.as_bytes());
        hash.update(path.as_bytes());
        hash.update(&identity.device.to_le_bytes());
        hash.update(&identity.file_id[0].to_le_bytes());
        match root.get("allowedFiles").filter(|leaves| !leaves.is_null()) {
            Some(leaves) => {
                let leaves = leaves
                    .as_array()
                    .context("Invalid frozen native leaf allowlist")?;
                ensure!(
                    !leaves.is_empty() && leaves.len() <= 4096,
                    "Invalid native leaf count"
                );
                let mut sorted = BTreeSet::new();
                for leaf in leaves {
                    let leaf = leaf.as_str().context("Invalid frozen native leaf")?;
                    validate_native_relative(leaf).map_err(public_source_error)?;
                    ensure!(
                        !leaf.contains('/') && sorted.insert(leaf),
                        "Duplicate or non-leaf native allowlist entry"
                    );
                }
                hash.update(b"allowed-files\0");
                for leaf in sorted {
                    hash.update(&(leaf.len() as u64).to_le_bytes());
                    hash.update(leaf.as_bytes());
                }
            }
            None => {
                hash.update(b"whole-root\0");
            }
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

/// Only the source writes this authenticated cache after COMMITTED/publication,
/// or after read_committed_manifest. Its exact original MAC domain is checked on
/// the same no-follow descriptor subsequently parsed; full ctime is retained.
fn read_cached_manifest(
    cache: &Path,
    app: &AppId,
    bundle: Uuid,
    repository_binding: &str,
    master: &MasterKey,
) -> Result<Option<BundleManifest>> {
    valid_digest(repository_binding)?;
    let root = SafeRoot::open(cache)?;
    let app_key = blake3::hash(app.as_str().as_bytes()).to_hex().to_string();
    let prefix = format!("manifests/{app_key}/{bundle}/{repository_binding}");
    let name = format!("{prefix}/manifest.json");
    let tag_name = format!("{prefix}/manifest.mac");
    let (mut file, stamp) = match root.read_file(&name) {
        Ok(file) => file,
        Err(error) if missing(&error) => return Ok(None),
        Err(_) => bail!("Native authenticated manifest cache cannot be opened safely"),
    };
    ensure!(
        stamp.size <= MAX_SOURCE_DOCUMENT as u64,
        "Native authenticated manifest cache exceeds the source metadata limit"
    );
    let (tag, tag_stamp) = match root.read_file(&tag_name) {
        Ok(tag) => tag,
        Err(error) if missing(&error) => return Ok(None),
        Err(_) => bail!("Native authenticated manifest tag cannot be opened safely"),
    };
    ensure!(
        tag_stamp.size == 64,
        "Invalid native authenticated manifest tag size"
    );
    let mut expected = String::new();
    tag.take(65).read_to_string(&mut expected)?;
    valid_digest(&expected)?;
    let mut hash = blake3::Hasher::new_keyed(&master.0);
    hash.update(b"noland-authenticated-cache-v1\0");
    hash.update(format!("parent:{repository_binding}:{app}:{bundle}:manifest").as_bytes());
    hash.update(&[0]);
    let mut buffer = [0u8; 64 * 1024];
    let mut read = 0usize;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count)
            .context("Manifest cache byte count overflow")?;
        ensure!(
            read <= MAX_SOURCE_DOCUMENT,
            "Manifest cache exceeded its metadata bound"
        );
        hash.update(&buffer[..count]);
    }
    ensure!(
        equal_digest(&expected, hash.finalize().to_hex().as_str()),
        "Native committed manifest cache authentication failed"
    );
    root.verify_file(&tag_name, &tag_stamp)?;
    root.verify_file(&name, &stamp)?;
    file.seek(SeekFrom::Start(0))?;
    let manifest = serde_json::from_reader(BufReader::new(
        (&mut file).take(MAX_SOURCE_DOCUMENT as u64 + 1),
    ))
    .context("Native authenticated source manifest is invalid")?;
    // Check the parsed descriptor too, not merely a same-name replacement.
    let after =
        noland_state_agent::native_capture::NativeCaptureStamp::from_metadata(&file.metadata()?)
            .map_err(public_source_error)?;
    ensure!(
        after.device == stamp.device
            && after.file_id == stamp.file_id
            && after.size == stamp.size
            && after.modified_seconds == stamp.modified_seconds
            && after.modified_nanoseconds == stamp.modified_nanoseconds
            && after.changed_seconds == stamp.changed_seconds
            && after.changed_nanoseconds == stamp.changed_nanoseconds,
        "Native authenticated manifest descriptor changed during verification"
    );
    root.verify_file(&name, &stamp)?;
    root.verify_file(&tag_name, &tag_stamp)?;
    Ok(Some(manifest))
}

// This is the active fork's exact stable account/endpoint identity allowlist.
// Unknown fields/accounts deliberately use the private exact-config fallback.
// No config, account identifier, root path or private hash is exposed to the UI.
fn bound_session_identity(
    session: &EphemeralRcloneSession,
    master: &MasterKey,
) -> Result<ProviderRootIdentity> {
    if let Some(identity) = session_identity(session) {
        return Ok(identity);
    }
    let mut hash = blake3::Hasher::new_keyed(&master.0);
    hash.update(b"noland-private-session-config-v1\0");
    hash.update(&serde_json::to_vec(&session.storage_identity())?);
    hash.update(&[0]);
    hash.update(session.config_ini.as_bytes());
    Ok(ProviderRootIdentity::new(
        &session.provider,
        &session.backend_type,
        format!("private-config-v1-{}", hash.finalize().to_hex()),
        &session.root,
    ))
}

fn session_identity(session: &EphemeralRcloneSession) -> Option<ProviderRootIdentity> {
    let mut fields = BTreeMap::new();
    let mut selected = false;
    let mut sections = 0;
    for line in session.config_ini.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            let name = line.strip_prefix('[')?.strip_suffix(']')?;
            selected = name == session.remote_name;
            sections += 1;
            continue;
        }
        if !selected {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        if fields.insert(key.trim(), value.trim()).is_some() {
            return None;
        }
    }
    if sections != 1 || fields.get("type").copied()? != session.backend_type {
        return None;
    }
    let get = |name| fields.get(name).copied().filter(|value| !value.is_empty());
    let mut namespace = BTreeMap::<&str, String>::new();
    let allowed: &[&str] = match session.backend_type.as_str() {
        "local" if Path::new(&session.root).is_absolute() => &["type", "nounc"],
        "sftp" => {
            namespace.insert("host", get("host")?.to_ascii_lowercase());
            namespace.insert("user", get("user")?.into());
            namespace.insert(
                "port",
                get("port").unwrap_or("22").parse::<u16>().ok()?.to_string(),
            );
            &[
                "type",
                "host",
                "user",
                "port",
                "pass",
                "key_pem",
                "key_file_pass",
                "host_keys",
            ]
        }
        "webdav" => {
            let url = get("url")?;
            if (!url.starts_with("https://") && !url.starts_with("http://"))
                || url.contains(['@', '?', '#'])
            {
                return None;
            }
            namespace.insert("url", url.trim_end_matches('/').into());
            namespace.insert("user", get("user")?.into());
            namespace.insert("vendor", get("vendor").unwrap_or("other").into());
            &[
                "type",
                "url",
                "user",
                "pass",
                "vendor",
                "nextcloud_chunk_size",
            ]
        }
        "azureblob" => {
            namespace.insert("account", get("account")?.into());
            if let Some(endpoint) = get("endpoint") {
                if endpoint.contains(['@', '?', '#']) {
                    return None;
                }
                namespace.insert("endpoint", endpoint.trim_end_matches('/').into());
            }
            &["type", "account", "key", "endpoint"]
        }
        "onedrive" => {
            namespace.insert("drive_id", get("drive_id")?.into());
            namespace.insert("drive_type", get("drive_type")?.into());
            &[
                "type",
                "drive_id",
                "drive_type",
                "token",
                "client_id",
                "client_secret",
            ]
        }
        "s3" if get("provider") == Some("Cloudflare") => {
            let host = get("endpoint")?
                .strip_prefix("https://")?
                .trim_end_matches('/');
            let account = host.strip_suffix(".r2.cloudflarestorage.com")?;
            if account.is_empty() || !account.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return None;
            }
            namespace.insert("endpoint", host.to_ascii_lowercase());
            &[
                "type",
                "provider",
                "endpoint",
                "region",
                "access_key_id",
                "secret_access_key",
                "session_token",
            ]
        }
        _ => return None,
    };
    if fields.keys().any(|key| !allowed.contains(key)) {
        return None;
    }
    let fingerprint =
        blake3::hash(&serde_json::to_vec(&(session.storage_identity(), namespace)).ok()?)
            .to_hex()
            .to_string();
    Some(ProviderRootIdentity::new(
        &session.provider,
        &session.backend_type,
        format!("namespace-v2-{fingerprint}"),
        &session.root,
    ))
}

fn batch_state(state: &str) -> &'static str {
    match state {
        "QUEUED" | "REQUESTED" => "queued",
        "DISCOVERING"
        | "RECONCILING"
        | "SNAPSHOTTING"
        | "HASHING"
        | "CAPTURING_AND_UPLOADING"
        | "PACKING"
        | "UPLOADING"
        | "COMMITTING"
        | "CHECKPOINTING" => "running",
        "COMPLETED" => "completed",
        "FAILED" => "failed",
        "CANCELLED" => "cancelled",
        "INTERRUPTED" => "interrupted",
        _ => "unknown",
    }
}

fn text<'a>(value: &'a Value, field: &str, max: usize) -> Result<&'a str> {
    let text = value[field]
        .as_str()
        .context("Native batch identity field is missing")?;
    ensure!(
        !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control),
        "Native batch identity field exceeds its bound"
    );
    Ok(text)
}

fn uuid_field(value: &Value, field: &str) -> Result<Uuid> {
    let raw = text(value, field, 36)?;
    let id = Uuid::parse_str(raw).context("Native batch source identity is not a UUID")?;
    ensure!(id.to_string() == raw, "Noncanonical native source UUID");
    Ok(id)
}

fn valid_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Invalid native source authority digest"
    );
    Ok(())
}

fn equal_digest(left: &str, right: &str) -> bool {
    if valid_digest(left).is_err() || valid_digest(right).is_err() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn bounded(value: &impl Serialize, max: usize) -> Result<()> {
    hash_serialized(value, max).map(|_| ())
}

fn hash_serialized(value: &impl Serialize, max: usize) -> Result<String> {
    struct Writer {
        hash: blake3::Hasher,
        bytes: usize,
        max: usize,
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("Native source document size overflow"))?;
            if self.bytes > self.max {
                return Err(std::io::Error::other(
                    "Native source document exceeds its bound",
                ));
            }
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        hash: blake3::Hasher::new(),
        bytes: 0,
        max,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.hash.finalize().to_hex().to_string())
}

fn digest(value: &Value, max: usize) -> Result<String> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Object(object) => {
                let mut sorted: serde_json::Map<String, Value> = object
                    .iter()
                    .map(|(key, value)| (key.clone(), canonical(value)))
                    .collect();
                sorted.sort_keys();
                Value::Object(sorted)
            }
            _ => value.clone(),
        }
    }
    // Bound before cloning the small plan/capture or once-only native selection.
    bounded(value, max)?;
    hash_serialized(&canonical(value), max)
}

fn missing(error: &anyhow::Error) -> bool {
    error.chain().any(|error| {
        error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use noland_rpc::{RpcHandler, RpcRequest};
    use noland_state_agent::{
        native_capture::{NativeCaptureScope, NativeFullScopeBinding},
        native_host::{ApprovedNativeRoot, NativeFileKey, NativeRootRole},
        rpc_handler::AgentRpc,
    };
    use noland_state_core::AppIdentity;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Fixture {
        _temp: tempfile::TempDir,
        engine: NativeEngine,
        private: Arc<PrivateAccess>,
        binding: Value,
        native: NativeSelection,
        vault: Arc<quicksave_state::MemoryVault>,
    }

    async fn fixture() -> Fixture {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let data = temp.path().join("quicksave");
        let home = temp.path().join("home");
        let source = temp.path().join("synthetic-application");
        for path in [&data, &home, &source] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(source.join("save.bin"), b"isolated native fixture").unwrap();
        let vault = Arc::new(quicksave_state::MemoryVault::default());
        let store = quicksave_state::WorkspaceStore::open_with_vault(&data, vault.clone()).unwrap();
        let engine = NativeEngine::open(&data, &home)
            .unwrap()
            .with_workspace(store)
            .unwrap();
        let app = AppId("steam:480".into());
        engine
            .agent
            .native_register(
                AppIdentity::new(app.clone(), "Synthetic application"),
                vec![ApprovedNativeRoot {
                    id: "save-root".into(),
                    path: source.clone(),
                    allowed_files: None,
                    expected_identity: None,
                    role: NativeRootRole::Save,
                }],
            )
            .unwrap();
        let metadata = std::fs::metadata(&source).unwrap();
        let roots = json!([{
            "id":"save-root","path":source,"role":"save","allowedFiles":null,
            "identity":{"device":metadata.dev(),"fileId":[metadata.ino(),0]},
        }]);
        let id = Uuid::new_v4();
        let work = Uuid::new_v4().to_string();
        let metadata_identity = "1".repeat(64);
        let logical = native_root_token(&app, "save-root");
        let ids = json!([native_file_id(&logical, "save.bin")]);
        let capture = json!({
            "version":1,"sourceId":id,"nativePlanDigest":"2".repeat(64),
            "workId":work,"generation":7,
            "snapshotIdentity":metadata_identity,"metadataIdentity":metadata_identity,
            "selectionDigest":digest(&ids,MAX_SOURCE_DOCUMENT).unwrap(),
            "fileCount":1,"rootsFingerprint":"3".repeat(64),
        });
        let binding = json!({
            "version":1,"sourceId":id,"planSetId":Uuid::new_v4(),"nativePlanId":Uuid::new_v4(),
            "rootDigest":"7".repeat(64),
            "nativePlanDigest":"2".repeat(64),"softwareId":"synthetic-installation",
            "canonicalAppId":app,"trackerAppId":"steam:480@synthetic-one",
            "providerId":"fixture-provider","providerDigest":"4".repeat(64),
            "rootAuthorityRevision":"5".repeat(64),
            "registration":{
                "id":"synthetic-installation","appId":"steam:480@synthetic-one",
                "providerId":"fixture-provider","name":"Synthetic application","tracked":true,
                "sourceIdentity":{"app_id":"steam:480"},"roots":roots,
            },
            "capture":capture,
            "captureDigest":digest(&capture,MAX_BINDING_BYTES).unwrap(),
        });
        let native = NativeSelection {
            version: 1,
            file_keys: Some(vec![NativeFileKey {
                logical_root: logical,
                relative_path: "save.bin".into(),
            }]),
            roots_fingerprint: engine.agent.native_binding_fingerprint(&app).unwrap(),
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(metadata_identity.clone()),
            expected_files: None,
            capture_scope: Some(NativeCaptureScope {
                version: 1,
                work_id: work,
                metadata_identity,
                node_count: 1,
                full_scope: Some(NativeFullScopeBinding {
                    version: 1,
                    evidence_hash: "6".repeat(64),
                    root_count: 1,
                    deleted_count: 0,
                }),
            }),
            coverage: NativeCoverage::FullApprovedScope,
            software_instance_id: Some("steam:480@synthetic-one".into()),
        };
        let session = EphemeralRcloneSession {
            operation_id: id.to_string(),
            provider: "local".into(),
            backend_type: "local".into(),
            remote_name: "fixture".into(),
            root: temp
                .path()
                .join("never-created-provider")
                .to_string_lossy()
                .into_owned(),
            config_ini: "[fixture]\ntype = local\n".into(),
            expires_at_unix: 0,
            upload_concurrency: None,
        };
        // Injected PRIVATE test session only. Production never constructs local
        // auth JSON or selects this fixture as a default provider.
        let access = ProviderAccess {
            provider_id: "fixture-provider".into(),
            session: serde_json::to_value(session).unwrap(),
            repository_key: [21; 32],
            read_only: true,
        };
        let private = Arc::new(PrivateAccess::from_access(&access).unwrap());
        Fixture {
            _temp: temp,
            engine,
            private,
            binding,
            native,
            vault,
        }
    }

    fn persist(fixture: &Fixture, state: &str) -> OperationRecord {
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        let selection = json!({
            "app_id":expected.app,"mode":"complete_application",
            "performance_mode":"automatic","regenerable_caches":"include",
            "native_selection":fixture.native,
        });
        let repository =
            bound_session_identity(&fixture.private.session, &fixture.private.master).unwrap();
        let binding = blake3::keyed_hash(
            &fixture.private.master.0,
            &serde_json::to_vec(&json!({
                "domain":"noland-operation-submission-v1","kind":"backup",
                "repository":repository,"selection":selection,
            }))
            .unwrap(),
        )
        .to_hex()
        .to_string();
        let mut details = selection;
        details["client_operation_id"] = json!(expected.id);
        details["submission_binding"] = json!(binding);
        let operation = OperationRecord {
            operation_id: expected.id,
            kind: "backup".into(),
            app_id: Some(expected.app),
            state: state.into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_error: None,
            detail_json: details,
        };
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        operation
    }

    #[tokio::test]
    async fn signed_root_fingerprint_matches_actual_native_root_handles() {
        let fixture = fixture().await;
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        assert_eq!(
            expected.native_roots_fingerprint,
            fixture.native.roots_fingerprint
        );
        let mut wrong_instance = fixture.binding.clone();
        wrong_instance["trackerAppId"] = json!("steam:480@synthetic-two");
        wrong_instance["registration"]["appId"] = json!("steam:480@synthetic-two");
        let expected = ExpectedBinding::parse(&wrong_instance).unwrap();
        assert!(verify_selection(&expected, &fixture.native).is_err());
    }

    #[tokio::test]
    async fn v3_fingerprint_matches_manual_parent_and_direct_installer_source_layouts() {
        let fixture = fixture().await;
        let app = AppId("steam:480".into());
        let source = Path::new(
            fixture.binding["registration"]["roots"][0]["path"]
                .as_str()
                .unwrap(),
        );
        std::fs::write(source.join("z-save.bin"), b"isolated second manual leaf").unwrap();
        let metadata = std::fs::metadata(source).unwrap();
        let manual = json!({
            "id":"manual-root","role":"manual","path":source,
            "identity":{"device":metadata.dev(),"fileId":[metadata.ino(),0]},
            // The source stores a BTreeSet. Signed input order is not hash order.
            "allowedFiles":["z-save.bin","save.bin"],
        });
        fixture
            .engine
            .agent
            .native_register(
                AppIdentity::new(app.clone(), "Synthetic application"),
                vec![ApprovedNativeRoot {
                    id: "manual-root".into(),
                    path: source.to_owned(),
                    allowed_files: Some(BTreeSet::from(["save.bin".into(), "z-save.bin".into()])),
                    expected_identity: Some((metadata.dev(), metadata.ino())),
                    role: NativeRootRole::Manual,
                }],
            )
            .unwrap();
        let actual_manual = fixture
            .engine
            .agent
            .native_binding_fingerprint(&app)
            .unwrap();
        assert_eq!(
            frozen_native_roots_fingerprint(&app, std::slice::from_ref(&manual)).unwrap(),
            actual_manual,
        );
        let mut invalid_manual = manual;
        invalid_manual["directory"] = json!(false);
        assert!(frozen_native_roots_fingerprint(&app, &[invalid_manual]).is_err());

        let installer = fixture._temp.path().join("SyntheticInstaller.msi");
        std::fs::write(&installer, b"isolated direct installer fixture").unwrap();
        let metadata = std::fs::metadata(&installer).unwrap();
        let direct_file = json!({
            "id":"installer-root","role":"installer","path":installer,
            "identity":{"device":metadata.dev(),"fileId":[metadata.ino(),0]},
            "directory":false,"allowedFiles":null,
        });
        fixture
            .engine
            .agent
            .native_register(
                AppIdentity::new(app.clone(), "Synthetic application"),
                vec![ApprovedNativeRoot {
                    id: "installer-root".into(),
                    path: installer,
                    allowed_files: None,
                    expected_identity: Some((metadata.dev(), metadata.ino())),
                    role: NativeRootRole::Installer,
                }],
            )
            .unwrap();
        let actual_file = fixture
            .engine
            .agent
            .native_binding_fingerprint(&app)
            .unwrap();
        assert_eq!(
            frozen_native_roots_fingerprint(&app, std::slice::from_ref(&direct_file)).unwrap(),
            actual_file,
        );
        let mut wrong_kind = direct_file.clone();
        wrong_kind.as_object_mut().unwrap().remove("directory");
        assert_ne!(
            frozen_native_roots_fingerprint(&app, &[wrong_kind]).unwrap(),
            actual_file,
        );
        // Windows device names are valid literal Unix filenames. Native source
        // fingerprints must preserve them, not impose Windows target rules.
        let mut unix_leaf = direct_file.clone();
        unix_leaf["path"] = json!("/isolated-fixture/CON");
        assert!(frozen_native_roots_fingerprint(&app, &[unix_leaf]).is_ok());
        let mut invalid_leaf = direct_file;
        invalid_leaf["path"] = json!("/isolated-fixture/invalid\0leaf");
        assert!(frozen_native_roots_fingerprint(&app, &[invalid_leaf]).is_err());
        assert!(fixture.engine.runtime.get().is_none());
    }

    #[tokio::test]
    async fn read_only_hmac_matches_actual_source_replay_without_starting_a_worker() {
        let fixture = fixture().await;
        let operation = persist(&fixture, "INTERRUPTED");
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        authenticate_record(&expected, &operation, &fixture.private).unwrap();
        let params = fixture
            .private
            .params(json!({
                "app_id":expected.app,"mode":"complete_application",
                "native_selection":fixture.native,"client_operation_id":expected.id,
            }))
            .unwrap();
        let response = AgentRpc(fixture.engine.agent.clone())
            .handle(&RpcRequest {
                id: "isolated-batch-replay".into(),
                method: "StartBackup".into(),
                params,
            })
            .await
            .unwrap();
        assert_eq!(response["operation_id"], expected.id.to_string());
        assert_eq!(response["state"], "INTERRUPTED");
        assert!(!fixture.engine.agent.operations.is_running(expected.id));
        assert!(!Path::new(&fixture.private.session.root).exists());
    }

    #[tokio::test]
    async fn empty_full_scope_preserves_exact_empty_ids_and_requires_the_full_scope_binding() {
        let mut fixture = fixture().await;
        fixture.binding["capture"]["fileCount"] = json!(0);
        fixture.binding["capture"]["selectionDigest"] =
            json!(digest(&json!([]), MAX_SOURCE_DOCUMENT).unwrap());
        fixture.binding["captureDigest"] =
            json!(digest(&fixture.binding["capture"], MAX_BINDING_BYTES).unwrap());
        fixture.native.file_keys = Some(Vec::new());
        fixture.native.capture_scope.as_mut().unwrap().node_count = 0;
        let operation = persist(&fixture, "INTERRUPTED");
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        authenticate_record(&expected, &operation, &fixture.private).unwrap();
        let params = fixture
            .private
            .params(json!({
                "app_id":expected.app,"mode":"complete_application",
                "native_selection":fixture.native,"client_operation_id":expected.id,
            }))
            .unwrap();
        let response = AgentRpc(fixture.engine.agent.clone())
            .handle(&RpcRequest {
                id: "isolated-empty-full-scope-replay".into(),
                method: "StartBackup".into(),
                params,
            })
            .await
            .unwrap();
        assert_eq!(response["operation_id"], expected.id.to_string());
        assert!(!fixture.engine.agent.operations.is_running(expected.id));

        let mut missing_capability = operation.clone();
        missing_capability.detail_json["native_selection"]["capture_scope"]["fullScope"] =
            Value::Null;
        assert!(authenticate_record(&expected, &missing_capability, &fixture.private).is_err());
        let mut missing_selection = operation;
        missing_selection.detail_json["native_selection"]["file_keys"] = Value::Null;
        assert!(authenticate_record(&expected, &missing_selection, &fixture.private).is_err());
        assert!(fixture.engine.runtime.get().is_none());
        assert!(!Path::new(&fixture.private.session.root).exists());
    }

    #[tokio::test]
    async fn actual_absence_and_cancel_do_not_require_credentials_or_rclone() {
        let fixture = fixture().await;
        let absent = fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .unwrap();
        assert_eq!(absent["presence"], "absent");
        let mut operation = persist(&fixture, "INTERRUPTED");
        operation.detail_json["submission_binding"] = json!("0".repeat(64));
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        let cancelled = fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "cancellation")
            .await
            .unwrap();
        assert_eq!(cancelled["presence"], "present");
        assert_eq!(cancelled["state"], "interrupted");
        assert!(cancelled["bindingDigest"].is_null());
        assert!(fixture.engine.runtime.get().is_none());
        assert!(fixture.engine.access.lock().unwrap().is_empty());
        assert!(fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn history_owners_uses_only_actual_monitoring_and_worker_owner_not_retry_json() {
        let fixture = fixture().await;
        let id = uuid_field(&fixture.binding, "sourceId").unwrap();
        let set = Uuid::new_v4().to_string();
        let root = "a".repeat(64);
        let keys = json!([{"sourceId":id,"canonicalAppId":"steam:480"}]);
        let absent = fixture
            .engine
            .batch_history_owners(&set, &root, keys.clone())
            .await
            .unwrap();
        assert_eq!(absent["items"][0]["presence"], "absent");
        let mut operation = persist(&fixture, "FAILED");
        operation.detail_json = json!({"not_a_valid_selection_or_submission":true});
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        let failed = fixture
            .engine
            .batch_history_owners(&set, &root, keys.clone())
            .await
            .unwrap();
        assert_eq!(failed["items"][0]["presence"], "present");
        assert_eq!(failed["items"][0]["state"], "failed");
        assert!(failed["items"][0].get("bindingDigest").is_none());
        // Source upserts deliberately preserve kind/app_id on conflict. Use
        // genuinely distinct foreign rows and verify the actual stored header.
        for (kind, app) in [
            ("backup", AppId("steam:481".into())),
            ("restore", AppId("steam:480".into())),
        ] {
            let mut foreign_operation = operation.clone();
            foreign_operation.operation_id = Uuid::new_v4();
            foreign_operation.kind = kind.into();
            foreign_operation.app_id = Some(app.clone());
            fixture
                .engine
                .agent
                .db
                .upsert_operation(&foreign_operation)
                .unwrap();
            let stored = fixture
                .engine
                .agent
                .db
                .operation_monitoring_snapshot(foreign_operation.operation_id)
                .unwrap()
                .unwrap()
                .operation;
            assert_eq!(stored.kind, kind);
            assert_eq!(stored.app_id, Some(app));
            let foreign = fixture
                .engine
                .batch_history_owners(
                    &set,
                    &root,
                    json!([{
                        "sourceId":foreign_operation.operation_id,"canonicalAppId":"steam:480",
                    }]),
                )
                .await
                .unwrap();
            assert_eq!(foreign["items"][0]["presence"], "unknown");
        }
        let missing = Uuid::new_v4();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        assert!(fixture.engine.agent.operations.spawn(
            missing,
            async move {
                let _ = wait.await;
            },
            |_| {}
        ));
        let owner = fixture
            .engine
            .batch_history_owners(
                &set,
                &root,
                json!([
                    {"sourceId":missing,"canonicalAppId":"steam:480"}
                ]),
            )
            .await
            .unwrap();
        assert_eq!(owner["items"][0]["presence"], "unknown");
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture.engine.agent.operations.is_running(missing) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(fixture.engine.runtime.get().is_none());
        assert!(fixture.engine.access.lock().unwrap().is_empty());
        assert!(fixture
            .engine
            .batch
            .lock()
            .unwrap()
            .authenticated
            .is_empty());
    }

    #[tokio::test]
    async fn cached_progress_never_reloads_file_keys_but_terminal_json_is_not_a_receipt() {
        let fixture = fixture().await;
        let mut operation = persist(&fixture, "UPLOADING");
        fixture
            .engine
            .reserve_private(operation.operation_id, fixture.private.clone())
            .unwrap();
        let first = fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .unwrap();
        assert!(first["bindingDigest"].as_str().is_some());
        operation.detail_json = json!({"not_a_valid_retry_or_selection":true});
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        // Full retry/selection JSON was authenticated once. Monitoring must not
        // parse it again at 4 Hz; the final barrier WILL authenticate it again.
        let progress = fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .unwrap();
        assert_eq!(progress["bindingDigest"], first["bindingDigest"]);
        operation.state = "COMPLETED".into();
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        assert!(fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn changed_root_metadata_selection_or_repository_never_authenticates() {
        let fixture = fixture().await;
        let operation = persist(&fixture, "UPLOADING");
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        for field in ["roots_fingerprint", "snapshot_identity"] {
            let mut changed = operation.clone();
            changed.detail_json["native_selection"][field] = json!("f".repeat(64));
            assert!(authenticate_record(&expected, &changed, &fixture.private).is_err());
        }
        let mut changed = operation.clone();
        changed.detail_json["native_selection"]["file_keys"][0]["relative_path"] =
            json!("other.bin");
        assert!(authenticate_record(&expected, &changed, &fixture.private).is_err());
        let mut wrong_repository = PrivateAccess::from_access(&ProviderAccess {
            provider_id: fixture.private.provider_id.clone(),
            session: serde_json::to_value(&fixture.private.session).unwrap(),
            repository_key: fixture.private.master.0,
            read_only: true,
        })
        .unwrap();
        wrong_repository.session.root.push_str("-different");
        assert!(authenticate_record(&expected, &operation, &wrong_repository).is_err());
    }

    #[tokio::test]
    async fn completed_source_needs_authenticated_exact_manifest_not_just_terminal_json() {
        let fixture = fixture().await;
        let mut operation = persist(&fixture, "COMPLETED");
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        let authenticated = authenticate_record(&expected, &operation, &fixture.private).unwrap();
        let mut manifest = BundleManifest::new(
            noland_state_core::ManifestApp::from(&AppIdentity::new(
                expected.app.clone(),
                "Synthetic application",
            )),
            noland_state_core::ManifestSource {
                instance_id: fixture.engine.agent.config.instance_id,
                image_id: "isolated-native-fixture".into(),
                captured_at: Utc::now(),
            },
            BackupMode::CompleteApplication,
        );
        manifest.environment["quicksave_native"] = json!({
            "coverage":"full_approved_scope",
            "software_instance_id":expected.instance,
            "consistency":"validated_stable_files","selection":fixture.native,
        });
        operation.detail_json["bundle_id"] = json!(manifest.bundle_id);
        operation.detail_json["commit_id"] = json!(manifest.commit_id);
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&operation)
            .unwrap();
        fixture
            .engine
            .reserve_private(operation.operation_id, fixture.private.clone())
            .unwrap();
        assert!(fixture
            .engine
            .verify_batch_source(None, fixture.binding.clone(), "observation")
            .await
            .is_err());
        // A locally authenticated but DIFFERENT exact selection is no completion
        // proof either. No source capture, provider or remote process is faked.
        let app_key = blake3::hash(expected.app.as_str().as_bytes())
            .to_hex()
            .to_string();
        let dir = fixture
            .engine
            .agent
            .config
            .paths
            .cache
            .join("manifests")
            .join(app_key)
            .join(manifest.bundle_id.to_string())
            .join(&authenticated.repository_binding);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut hash = blake3::Hasher::new_keyed(&fixture.private.master.0);
        hash.update(b"noland-authenticated-cache-v1\0");
        hash.update(
            format!(
                "parent:{}:{}:{}:manifest",
                authenticated.repository_binding, expected.app, manifest.bundle_id
            )
            .as_bytes(),
        );
        hash.update(&[0]);
        hash.update(&bytes);
        std::fs::write(dir.join("manifest.json"), bytes).unwrap();
        std::fs::write(dir.join("manifest.mac"), hash.finalize().to_hex().as_str()).unwrap();
        // A real source cache MAC authenticates these bytes; the completion
        // verifier still rejects the omitted frozen file instead of trusting
        // row state, matching app/bundle IDs, or a MAC's mere presence.
        assert!(read_cached_manifest(
            &fixture.engine.agent.config.paths.cache,
            &expected.app,
            manifest.bundle_id,
            &authenticated.repository_binding,
            &fixture.private.master,
        )
        .unwrap()
        .is_some());
        assert!(
            fixture
                .engine
                .authenticate_batch_completion(
                    &expected,
                    &authenticated,
                    Some(&fixture.private),
                    false,
                )
                .await
                .is_err()
        );
        std::fs::write(dir.join("manifest.mac"), "0".repeat(64)).unwrap();
        assert!(read_cached_manifest(
            &fixture.engine.agent.config.paths.cache,
            &expected.app,
            manifest.bundle_id,
            &authenticated.repository_binding,
            &fixture.private.master,
        )
        .is_err());
        assert!(fixture.engine.runtime.get().is_none());
    }

    struct CompletionSink {
        node: native_capture::NativeCaptureNode,
        receipt: Mutex<Option<Arc<NativeCaptureReceipt>>>,
    }
    impl NativeCaptureSink for CompletionSink {
        fn node_page(
            &self,
            _: &NativeCaptureScope,
            offset: usize,
            limit: usize,
        ) -> noland_state_core::Result<Vec<native_capture::NativeCaptureNode>> {
            Ok(if offset == 0 && limit > 0 {
                vec![self.node.clone()]
            } else {
                Vec::new()
            })
        }
        fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> noland_state_core::Result<()> {
            receipt.revalidate()?;
            *self.receipt.lock().unwrap() = Some(receipt);
            Ok(())
        }
    }

    /// Actual source capture and COMMITTED/AEAD bytes, real device receipt grants,
    /// and an isolated injected vault. No real provider or OS credential entry.
    async fn committed_selected_capture_fixture() -> (Fixture, Value, BundleManifest) {
        use noland_state_core::BackupPerformanceMode;
        let mut fixture = fixture().await;
        let store = fixture.engine.workspace.as_ref().unwrap().clone();
        // In-memory injected provider metadata only: no live vault/account or
        // health probe. Actual source I/O below uses LocalStorage in this temp.
        let configured = store
            .connect_provider(&json!({
                "kind":"backblaze_b2","name":"Isolated completion metadata",
                "bucket":"synthetic-bucket","prefix":"synthetic-prefix",
                "credentials":{"type":"backblaze_b2","value":{
                    "key_id":"synthetic-key","application_key":"synthetic-injected-secret",
                }},
            }))
            .unwrap();
        let provider = configured["providers"].as_array().unwrap().last().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        store
            .record_provider_health(
                &provider,
                &json!({
                    "canList":true,"canRead":true,"repositoryAccessible":true,
                    "repositoryEmpty":false,"keyVerified":true,
                }),
            )
            .unwrap(); // Explicit fixture observation, never a production default.
        fixture.binding["providerId"] = json!(provider);
        fixture.binding["registration"]["providerId"] = json!(provider);
        let mut software = fixture.binding["registration"].clone();
        software["dirtyGeneration"] = json!(8); // A newer local generation must remain dirty.
        software["dirty"] = json!(true);
        software["reconciliationRequired"] = json!(true);
        store.update_software(&software).unwrap();
        let software_id = software["id"].as_str().unwrap().to_owned();
        store.seal_tracking_grant(&software_id).unwrap();
        let software = store.software_record(&software_id).unwrap();
        let tracking = current_tracking_scope(&software).unwrap();
        fixture.private = Arc::new(
            PrivateAccess::from_access(&ProviderAccess {
                provider_id: provider.clone(),
                session: serde_json::to_value(&fixture.private.session).unwrap(),
                repository_key: fixture.private.master.0,
                read_only: false,
            })
            .unwrap(),
        );
        let operation = uuid_field(&fixture.binding, "sourceId").unwrap();
        let app = AppId("steam:480".into());
        fixture.native.coverage = NativeCoverage::SelectedNodes;
        fixture.native.capture_scope.as_mut().unwrap().full_scope = None;
        let scope = fixture.native.capture_scope.as_ref().unwrap().clone();
        let path = Path::new(software["roots"][0]["path"].as_str().unwrap()).join("save.bin");
        let logical = native_root_token(&app, "save-root");
        let sink = Arc::new(CompletionSink {
            node: native_capture::NativeCaptureNode {
                id: native_file_id(&logical, "save.bin"),
                root_id: "save-root".into(),
                logical_root: logical,
                path: "save.bin".into(),
                kind: "file".into(),
                size: std::fs::metadata(&path).unwrap().len(),
                stamp: native_capture::NativeCaptureStamp::from_metadata(
                    &std::fs::metadata(&path).unwrap(),
                )
                .unwrap(),
                link_target_hash: None,
            },
            receipt: Mutex::new(None),
        });
        native_capture::install(
            &fixture.engine.agent,
            operation,
            &app,
            scope.clone(),
            sink.clone(),
        )
        .unwrap();
        let detail = json!({
            "app_id":app,"mode":"custom","performance_mode":"automatic",
            "regenerable_caches":"include","native_selection":fixture.native,
        });
        let repository =
            bound_session_identity(&fixture.private.session, &fixture.private.master).unwrap();
        let submission = blake3::keyed_hash(
            &fixture.private.master.0,
            &serde_json::to_vec(&json!({
                "domain":"noland-operation-submission-v1","kind":"backup",
                "repository":repository,"selection":detail,
            }))
            .unwrap(),
        )
        .to_hex()
        .to_string();
        let mut detail = detail;
        detail["submission_binding"] = json!(submission);
        detail["client_operation_id"] = json!(operation);
        fixture
            .engine
            .agent
            .db
            .upsert_operation(&OperationRecord {
                operation_id: operation,
                kind: "backup".into(),
                app_id: Some(app.clone()),
                state: "QUEUED".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_error: None,
                detail_json: detail,
            })
            .unwrap();
        fixture
            .engine
            .agent
            .native_set_publication_guard(operation, Arc::new(|| Ok(())))
            .unwrap();
        let local = noland_storage::LocalStorage::new(PathBuf::from(&fixture.private.session.root));
        let captured = noland_state_agent::backup::run_backup(
            &fixture.engine.agent,
            &app,
            BackupMode::Custom,
            BackupPerformanceMode::Automatic,
            &local,
            &fixture.private.master,
            Some(operation),
        )
        .await
        .unwrap();
        let manifest = noland_storage::read_committed_manifest(
            &local,
            &fixture.private.master,
            &app,
            captured.bundle_id,
        )
        .await
        .unwrap();
        let evidence = sink
            .receipt
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .evidence()
            .unwrap();
        let receipt_scope = json!({
            "version":1,"softwareId":software_id,"providerId":provider,
            "workId":scope.work_id,"generation":7,"metadataIdentity":scope.metadata_identity,
            "trackingScopeHash":hash_serialized(&tracking,MAX_BINDING_BYTES).unwrap(),
            "unknownGeneration":0,"capturedSnapshotIdentity":"a".repeat(64),
            "expectedFilesHash":hash_serialized(&evidence["nodes"],MAX_SOURCE_DOCUMENT).unwrap(),
            "sourceSnapshotId":manifest.bundle_id,
            "sourceExpectedManifestAuthHash":hash_serialized(&evidence["sourceExpectedManifestAuth"],MAX_BINDING_BYTES).unwrap(),
            "fullScopeProofHash":hash_serialized(&Value::Null,MAX_BINDING_BYTES).unwrap(),
            "immutablePreparedCapture":true,
        });
        let receipt_grant = store
            .issue_grant("tracking_capture_receipt", &receipt_scope)
            .unwrap();
        let reference_scope = json!({
            "version":1,"tracking":tracking,"captureScope":receipt_scope,
            "name":"receipt-isolated-fixture.json","hash":"b".repeat(64),
        });
        let reference_grant = store
            .issue_grant("tracking_capture_receipt_sidecar", &reference_scope)
            .unwrap();
        let seal = json!({
            "scope":receipt_scope,"grant":receipt_grant,
            "reference":{"name":"receipt-isolated-fixture.json","hash":"b".repeat(64),
                "scope":reference_scope,"grant":reference_grant},
        });
        store
            .update_software(&json!({"id":software_id,"captureReceipt":seal}))
            .unwrap();
        fixture
            .engine
            .reserve_private(operation, fixture.private.clone())
            .unwrap();
        let binding = json!({
            "softwareId":software_id,"providerId":provider,"workId":scope.work_id,
            "generation":7,"metadataIdentity":scope.metadata_identity,
            "captureReceipt":seal,"sourceExpectedManifestAuth":evidence["sourceExpectedManifestAuth"],
        });
        (fixture, binding, manifest)
    }

    fn retain_actual_committed_manifest(fixture: &Fixture, manifest: &BundleManifest) {
        // The exact source SessionStorage MAC namespace, around actual
        // LocalStorage COMMITTED/AEAD bytes, never a manufactured result row.
        let repository =
            bound_session_identity(&fixture.private.session, &fixture.private.master).unwrap();
        let repository_binding =
            repository_cache_digest(&repository, &fixture.private.master).unwrap();
        let app = &manifest.app.app_id;
        let app_key = blake3::hash(app.as_str().as_bytes()).to_hex().to_string();
        let dir = fixture
            .engine
            .agent
            .config
            .paths
            .cache
            .join("manifests")
            .join(app_key)
            .join(manifest.bundle_id.to_string())
            .join(&repository_binding);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = serde_json::to_vec(manifest).unwrap();
        let mut cache_mac = blake3::Hasher::new_keyed(&fixture.private.master.0);
        cache_mac.update(b"noland-authenticated-cache-v1\0");
        cache_mac.update(
            format!(
                "parent:{repository_binding}:{app}:{}:manifest",
                manifest.bundle_id
            )
            .as_bytes(),
        );
        cache_mac.update(&[0]);
        cache_mac.update(&bytes);
        std::fs::write(dir.join("manifest.json"), bytes).unwrap();
        std::fs::write(
            dir.join("manifest.mac"),
            cache_mac.finalize().to_hex().as_str(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn single_capture_completion_requires_actual_post_committed_cache_not_a_completed_row() {
        let (fixture, binding, manifest) = committed_selected_capture_fixture().await;
        let store = fixture.engine.workspace.as_ref().unwrap();
        let operation = uuid_field(&fixture.binding, "sourceId").unwrap();
        let software_id = text(&binding, "softwareId", 512).unwrap();
        // COMPLETED + real prepared receipt + valid source submission HMAC are
        // still insufficient without the matching post-COMMITTED source cache.
        assert!(fixture
            .engine
            .verify_capture_completion(&operation.to_string(), binding.clone())
            .await
            .is_err());
        retain_actual_committed_manifest(&fixture, &manifest);
        let proof = fixture
            .engine
            .verify_capture_completion(&operation.to_string(), binding.clone())
            .await
            .unwrap();
        assert_eq!(proof["verified"], true);
        assert_eq!(proof["generation"], 7);
        assert_eq!(store.software_record(software_id).unwrap()["dirty"], true);
        assert!(fixture.engine.runtime.get().is_none());
        let mut wrong = binding;
        wrong["sourceExpectedManifestAuth"]["manifestHash"] =
            json!(format!("blake3:{}", "f".repeat(64)));
        assert!(fixture
            .engine
            .verify_capture_completion(&operation.to_string(), wrong)
            .await
            .is_err());
        assert!(fixture
            .engine
            .retry_original_capture_guarded(&operation.to_string(), Arc::new(|| Ok(())))
            .await
            .is_err());
        assert!(fixture.engine.runtime.get().is_none());
    }

    #[tokio::test]
    async fn cached_batch_commit_rejects_completed_json_without_cryptographic_proof() {
        let fixture = fixture().await;
        let operation = persist(&fixture, "COMPLETED");
        assert!(fixture
            .engine
            .verify_cached_batch_commit(&fixture.binding)
            .is_err());
        let expected = ExpectedBinding::parse(&fixture.binding).unwrap();
        let authenticated =
            Arc::new(authenticate_record(&expected, &operation, &fixture.private).unwrap());
        fixture
            .engine
            .reserve_private(expected.id, fixture.private.clone())
            .unwrap();
        fixture
            .engine
            .batch
            .lock()
            .unwrap()
            .authenticated
            .insert(expected.id, authenticated);
        // Even a genuinely HMAC-authenticated submission and terminal row mint
        // no COMMITTED result, no original receipt, and no finalization right.
        let before = fixture.vault.access_log().unwrap();
        assert!(fixture
            .engine
            .verify_cached_batch_commit(&fixture.binding)
            .is_err());
        assert_eq!(fixture.vault.access_log().unwrap(), before);
        assert!(fixture.engine.runtime.get().is_none());
        assert!(!Path::new(&fixture.private.session.root).exists());
    }

    #[tokio::test]
    async fn cached_batch_commit_binds_actual_manifest_original_capture_and_exact_native_owner() {
        let (fixture, receipt_binding, manifest) = committed_selected_capture_fixture().await;
        let store = fixture.engine.workspace.as_ref().unwrap();
        let mut binding = fixture.binding.clone();
        binding["mode"] = json!("custom");
        binding["registration"] = store
            .software_record(text(&receipt_binding, "softwareId", 512).unwrap())
            .unwrap();
        let document = store.document().unwrap();
        let provider = document
            .providers
            .iter()
            .find(|provider| provider.id == text(&binding, "providerId", 128).unwrap())
            .unwrap();
        binding["providerDigest"] =
            json!(batch_provider_digest(&serde_json::to_value(provider).unwrap()).unwrap());
        let expected = ExpectedBinding::parse(&binding).unwrap();
        let operation = fixture
            .engine
            .agent
            .db
            .get_operation(expected.id)
            .unwrap()
            .unwrap();
        let authenticated =
            Arc::new(authenticate_record(&expected, &operation, &fixture.private).unwrap());
        {
            // Original-sidecar seam only: these are the genuine device grants
            // and AEAD expected envelope of the ACTUAL source capture above.
            // This seeds NO commit proof; only the production verifier below
            // may mint that from the authenticated COMMITTED source manifest.
            authenticated.completion.lock().unwrap().original_capture =
                Some(Arc::new(OriginalCommitBinding {
                    receipt: receipt_binding["captureReceipt"].clone(),
                    expected_manifest_auth: receipt_binding["sourceExpectedManifestAuth"].clone(),
                }));
        }
        fixture
            .engine
            .batch
            .lock()
            .unwrap()
            .authenticated
            .insert(expected.id, authenticated.clone());
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        retain_actual_committed_manifest(&fixture, &manifest);
        let proof = fixture
            .engine
            .authenticate_batch_completion(&expected, &authenticated, Some(&fixture.private), false)
            .await
            .unwrap();
        assert_eq!(
            authenticated.completion.lock().unwrap().digest.as_deref(),
            Some(proof.as_str())
        );
        // A real completed-source proof still cannot be finalized without the
        // independently retained original device capture and expected envelope.
        let original = authenticated
            .completion
            .lock()
            .unwrap()
            .original_capture
            .take()
            .unwrap();
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        authenticated.completion.lock().unwrap().original_capture = Some(original);
        let before = fixture.vault.access_log().unwrap();
        fixture.vault.deny_access(true).unwrap();
        fixture.engine.verify_cached_batch_commit(&binding).unwrap();
        assert_eq!(fixture.vault.access_log().unwrap(), before);

        // Each edit below remains structurally valid but changes the EXACT
        // source/capture/root/plan expected digest authenticated by the source.
        for field in [
            "rootDigest",
            "rootAuthorityRevision",
            "providerDigest",
            "nativePlanDigest",
        ] {
            let mut changed = binding.clone();
            changed[field] = json!("f".repeat(64));
            if field == "nativePlanDigest" {
                changed["capture"]["nativePlanDigest"] = changed[field].clone();
                changed["captureDigest"] =
                    json!(digest(&changed["capture"], MAX_BINDING_BYTES).unwrap());
            }
            assert!(fixture.engine.verify_cached_batch_commit(&changed).is_err());
        }
        let mut another_set = binding.clone();
        another_set["planSetId"] = json!(Uuid::new_v4());
        assert!(fixture
            .engine
            .verify_cached_batch_commit(&another_set)
            .is_err());
        let mut another_capture = binding.clone();
        another_capture["capture"]["generation"] = json!(8);
        another_capture["captureDigest"] =
            json!(digest(&another_capture["capture"], MAX_BINDING_BYTES).unwrap());
        assert!(fixture
            .engine
            .verify_cached_batch_commit(&another_capture)
            .is_err());
        let mut another_operation = binding.clone();
        let foreign_id = Uuid::new_v4();
        another_operation["sourceId"] = json!(foreign_id);
        another_operation["capture"]["sourceId"] = json!(foreign_id);
        another_operation["captureDigest"] =
            json!(digest(&another_operation["capture"], MAX_BINDING_BYTES).unwrap());
        // Even transplanting the genuine cache owner under another lookup ID
        // cannot make its expected digest/proof authorize that foreign job.
        fixture
            .engine
            .batch
            .lock()
            .unwrap()
            .authenticated
            .insert(foreign_id, authenticated.clone());
        assert!(fixture
            .engine
            .verify_cached_batch_commit(&another_operation)
            .is_err());
        fixture
            .engine
            .batch
            .lock()
            .unwrap()
            .authenticated
            .remove(&foreign_id);

        let original_proof = authenticated
            .completion
            .lock()
            .unwrap()
            .digest
            .replace("0".repeat(64))
            .unwrap();
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        authenticated.completion.lock().unwrap().digest = Some(original_proof);
        fixture.engine.verify_cached_batch_commit(&binding).unwrap();
        let original_manifest = authenticated
            .completion
            .lock()
            .unwrap()
            .manifest_hash
            .replace(format!("blake3:{}", "0".repeat(64)))
            .unwrap();
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        authenticated.completion.lock().unwrap().manifest_hash = Some(original_manifest);

        // COMPLETED can coexist with a real owner which has not joined yet.
        // The sentinel owns no transfer/provider work; it exercises the actual
        // same-source OperationManager registration rather than status flags.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        assert!(fixture.engine.agent.operations.spawn(
            expected.id,
            async move {
                let _ = wait.await;
            },
            |_| {}
        ));
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture.engine.agent.operations.is_running(expected.id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.engine.verify_cached_batch_commit(&binding).unwrap();
        for (kind, app) in [
            ("restore", expected.app.clone()),
            ("backup", AppId("steam:481".into())),
        ] {
            let mut foreign = operation.clone();
            foreign.operation_id = Uuid::new_v4();
            foreign.kind = kind.into();
            foreign.app_id = Some(app.clone());
            fixture.engine.agent.db.upsert_operation(&foreign).unwrap();
            let stored = fixture
                .engine
                .agent
                .db
                .operation_monitoring_snapshot(foreign.operation_id)
                .unwrap()
                .unwrap()
                .operation;
            assert_eq!(stored.kind, kind);
            assert_eq!(stored.app_id, Some(app));
            let mut foreign_binding = binding.clone();
            foreign_binding["sourceId"] = json!(foreign.operation_id);
            foreign_binding["capture"]["sourceId"] = json!(foreign.operation_id);
            foreign_binding["captureDigest"] =
                json!(digest(&foreign_binding["capture"], MAX_BINDING_BYTES).unwrap());
            fixture
                .engine
                .batch
                .lock()
                .unwrap()
                .authenticated
                .insert(foreign.operation_id, authenticated.clone());
            assert!(fixture
                .engine
                .verify_cached_batch_commit(&foreign_binding)
                .is_err());
            fixture
                .engine
                .batch
                .lock()
                .unwrap()
                .authenticated
                .remove(&foreign.operation_id);
        }
        fixture.engine.verify_cached_batch_commit(&binding).unwrap();
        assert_eq!(fixture.vault.access_log().unwrap(), before);
        fixture.vault.deny_access(false).unwrap();

        // A fresh tracking nonce/root-policy revision invalidates this callback,
        // even if source bytes and the old cryptographic commit remain genuine.
        store
            .seal_tracking_grant(text(&receipt_binding, "softwareId", 512).unwrap())
            .unwrap();
        assert!(fixture.engine.verify_cached_batch_commit(&binding).is_err());
        assert!(fixture.engine.runtime.get().is_none());
    }
}
