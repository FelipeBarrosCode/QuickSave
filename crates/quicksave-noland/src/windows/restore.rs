// SPDX-License-Identifier: GPL-3.0-only
//! Frozen consent adapter for the shared No Land restore pipeline, not a second
//! restore implementation. Controller/ticket logic is derived from the Unix
//! restore_control adapter; all conflict, publication and recovery algorithms
//! remain in noland-restore (audited No Land e81238a7536aae201540956ce76981364fd36595).
use super::*;
use noland_restore::{
    NativeConflictMode, NativeExpectedGate, NativeObjectId, NativeRestoreAction,
    NativeRestoreControl, NativeRestorePreview, NativeRestoreRecoveryReport,
};
use noland_state_core::{
    native_layout::{native_root_layouts, project_native_root_layouts},
    RestoreMode,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;

const PREVIEW_TTL: Duration = Duration::from_secs(600);
const MAX_PREVIEWS: usize = 64;
const MAX_ATTEMPTS: usize = 32;

#[derive(Default)]
pub(super) struct RestoreState {
    previews: BTreeMap<Uuid, Arc<FrozenPreview>>,
}

struct FrozenPreview {
    preview: Arc<NativeRestorePreview>,
    provider: String,
    storage: String,
    commit: Uuid,
    manifest_hash: String,
    fingerprint: String,
    metadata_bytes: usize,
    created: Instant,
}

/// Native-private, create-new local recovery document. It deliberately needs no
/// cloud key, credential or helper to authenticate the original plan on recovery.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreDocument {
    version: u32,
    instance: Uuid,
    provider: String,
    storage: String,
    preview_id: Uuid,
    fingerprint: String,
    commit: Uuid,
    manifest_hash: String,
    preview: NativeRestorePreview,
    device_mac: [u8; 32],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreDocumentRef<'a> {
    version: u32,
    instance: Uuid,
    provider: &'a str,
    storage: &'a str,
    preview_id: Uuid,
    fingerprint: &'a str,
    commit: Uuid,
    manifest_hash: &'a str,
    preview: &'a NativeRestorePreview,
    device_mac: [u8; 32],
}

fn plan_name(id: Uuid) -> String {
    format!("{id}.restore.json")
}

fn authority(inner: &Inner) -> Result<Arc<dyn NativeRecoveryAuthority>> {
    inner
        .recovery
        .lock()
        .map_err(poison)?
        .clone()
        .context("native restore requires existing device-vault recovery authority")
}

fn fingerprint(provider: &str, id: Uuid, preview: &NativeRestorePreview) -> Result<String> {
    validate_id(provider)?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave frozen native restore ticket v1\0");
    hash.update(&(provider.len() as u64).to_le_bytes());
    hash.update(provider.as_bytes());
    hash.update(id.as_bytes());
    hash.update(preview.digest().map_err(source_error)?.as_bytes());
    Ok(hash.finalize().to_hex().to_string())
}

/// Stable provider identity excludes tokens but binds the original repository
/// key, native authority revision, backend/account/root and read-only policy.
fn storage_fingerprint(access: &PrivateAccess) -> Result<String> {
    ensure!(
        access.authority_revision.is_some(),
        "native restore requires the original workspace provider authority revision"
    );
    let s = &access.session;
    let fields = [&s.provider, &s.backend_type, &s.remote_name, &s.root];
    ensure!(
        fields.iter().all(|field| field.len() <= 32768),
        "native restore provider identity exceeds its bound"
    );
    Ok(blake3::hash(&serde_json::to_vec(&(
        &access.provider,
        s.storage_identity(),
        access.read_only,
        access.authority_revision,
        blake3::derive_key(
            "QuickSave restore preview repository binding v1",
            &access.master.0,
        ),
    ))?)
    .to_hex()
    .to_string())
}

fn needs_ack(preview: &NativeRestorePreview) -> bool {
    preview
        .entries
        .iter()
        .chain(&preview.tombstones)
        .chain(&preview.root_entries)
        .any(|entry| {
            matches!(
                entry.action,
                NativeRestoreAction::Replace
                    | NativeRestoreAction::Remove
                    | NativeRestoreAction::Metadata
            )
        })
}

fn summary(preview: &NativeRestorePreview) -> Result<Value> {
    let bytes = preview.entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.size)
            .context("native restore byte count overflow")
    })?;
    Ok(json!({
        "operationId":preview.job_id,"fileCount":preview.entries.len(),
        "logicalBytes":bytes,"tombstoneCount":preview.tombstones.len(),
        "conflictCount":preview.entries.iter().chain(&preview.tombstones).chain(&preview.root_entries)
            .filter(|entry| entry.action == NativeRestoreAction::Conflict).count(),
        "replacementCount":preview.entries.iter().filter(|entry| entry.action == NativeRestoreAction::Replace).count(),
        "metadataChangeCount":preview.entries.iter().chain(&preview.root_entries)
            .filter(|entry| entry.action == NativeRestoreAction::Metadata).count(),
        "rootChanges":preview.root_entries.iter().map(|entry| json!({
            "destinationRelative":entry.destination_relative,"kind":"directory",
            "action":entry.action,"requestedMode":entry.mode,"requestedMtimeNs":entry.mtime_ns,
            "requestedUid":entry.uid,"requestedGid":entry.gid,
        })).collect::<Vec<_>>(),
        "mode":match preview.conflict_mode {
            NativeConflictMode::CreateOnly=>"create_new",
            NativeConflictMode::Merge=>"merge", NativeConflictMode::Overwrite=>"replace",
        },
        "selectionKind":if preview.entire_manifest {"full_manifest"} else {"selected_files"},
        "sourceFullScope":preview.source_full_scope,"sourceAppName":preview.source_app_name,
        "rootMappingFingerprint":preview.root_mapping_digest().map_err(source_error)?,
        "reconstruction":if preview.root_layout.is_some() {"authenticated_native_layout"} else {"legacy_files_only"},
        "sourcePlatform":preview.root_layout.as_ref().map(|layout| layout.platform),
        "platformCompatible":preview.root_layout.as_ref().is_some_and(|layout| layout.platform.is_current()),
        "readiness":if preview.reconstruction_eligible() {"reconstruction_unverified"} else {"files_only"},
        "expiresInSeconds":PREVIEW_TTL.as_secs(),
    }))
}

fn root_scope(preview: &NativeRestorePreview) -> Value {
    // The real full 128-bit native identity, never an ino64/time surrogate.
    json!([{"path":preview.destination,"kind":"directory","identity":{
        "device":preview.destination_identity.device,"fileId":preview.destination_identity.file_id,
    }}])
}

fn scope(id: Uuid, frozen: &FrozenPreview) -> Result<Value> {
    frozen
        .preview
        .validate_native_destination()
        .map_err(source_error)?;
    Ok(json!({
        "previewId":id,"operationId":frozen.preview.job_id,"summary":summary(&frozen.preview)?,
        "requiresOverwriteAcknowledgement":needs_ack(&frozen.preview),
        "roots":root_scope(&frozen.preview),"providerId":frozen.provider,
        "appId":frozen.preview.app_id.as_str(),"bundleId":frozen.preview.bundle_id,
        "frozenPlanFingerprint":frozen.fingerprint,
    }))
}

/// Exact same selection/layout projection used by preview AND execution.
/// Tombstones describe authenticated history, not local deletion consent. Keep
/// them for whole revisions so a manual last-leaf omission retains its proof.
pub(super) fn select_payload(
    manifest: &mut BundleManifest,
    selected: Option<&BTreeSet<(String, String)>>,
) -> Result<()> {
    native_root_layouts(manifest).map_err(source_error)?;
    ensure!(
        manifest
            .files
            .len()
            .saturating_add(manifest.tombstones.len())
            <= MAX_FILES,
        "native restore manifest entry bound exceeded"
    );
    let mut present = BTreeSet::new();
    for file in &manifest.files {
        validate_relative(&file.relative_path)?;
        ensure!(
            present.insert((file.logical_root.clone(), file.relative_path.clone())),
            "authenticated restore manifest has duplicate entries"
        );
        ensure!(
            matches!(file.file_type.as_str(), "file" | "directory" | "symlink"),
            "authenticated restore manifest has an unsupported entry kind"
        );
    }
    if let Some(keys) = selected {
        ensure!(
            !keys.is_empty() && keys.len() <= MAX_FILES && keys.is_subset(&present),
            "restore selection differs from its original authenticated manifest"
        );
    }
    if let Some(keys) = selected {
        manifest
            .files
            .retain(|file| keys.contains(&(file.logical_root.clone(), file.relative_path.clone())));
        manifest.tombstones.clear();
    }
    manifest.environment["quicksave_native_download"] = json!({
        "whole_bundle":selected.is_none(),
    });
    project_native_root_layouts(manifest).map_err(source_error)?;
    ensure!(
        !manifest.files.is_empty()
            || native_root_layouts(manifest)
                .map_err(source_error)?
                .is_some_and(|layout| !layout.roots.is_empty()),
        "native restore has neither selected entries nor authenticated empty roots"
    );
    Ok(())
}

impl NativeEngine {
    fn retained_restore_preview(&self, id: Uuid) -> Result<Arc<FrozenPreview>> {
        let frozen = self
            .inner
            .restore
            .lock()
            .map_err(poison)?
            .previews
            .get(&id)
            .cloned()
            .context("native restore preview is unavailable; preview again")?;
        ensure!(
            frozen.created.elapsed() < PREVIEW_TTL,
            "native restore preview expired; preview again"
        );
        Ok(frozen)
    }

    pub async fn preview_restore(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        // Merely borrowing this installed capability does not access a vault.
        authority(&self.inner)?;
        self.preflight().await?;
        let _submission = self.inner.submission.lock().await;
        let _slot = self
            .inner
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let destination = PathBuf::from(
            selection["destination"]
                .as_str()
                .context("native restore preview requires its approved destination")?,
        );
        ensure!(
            destination.is_absolute(),
            "native restore destination must be absolute"
        );
        let root = SafeRoot::open(&destination)?;
        ensure!(
            !root.overlaps(&self.inner._data)?,
            "native restore destination overlaps QuickSave private state"
        );
        let identity = root.identity()?;
        approved_destination(&selection, &destination, &identity)?;
        let mode = match selection["mode"].as_str().unwrap_or("create_new") {
            "create_new" => NativeConflictMode::CreateOnly,
            "merge" => NativeConflictMode::Merge,
            "replace" => NativeConflictMode::Overwrite,
            _ => bail!("restore mode must be create_new, merge, or replace"),
        };
        let job_id = Uuid::new_v4();
        let private = self.private_access(&access, Some(job_id))?;
        let session = self.session(&private, None, Arc::new(AtomicBool::new(false)), false)?;
        let result = manifest(&session.provider, &private.master, &selection).await;
        let payload = session.finish(result)?;
        catalog::remember_manifest(&self.inner, &private, &payload)?;
        let commit = payload.commit_id;
        let manifest_hash = noland_storage::compact_json_hash(&payload).map_err(source_error)?;
        let selected = selected_manifest(&payload, &selection)?;
        let mut payload = payload;
        select_payload(&mut payload, selected.as_ref())?;
        let layout =
            noland_state_core::native_layout::native_restore_layout(&payload, &destination)
                .map_err(source_error)?;
        let roots = noland_state_core::native_layout::logical_root_map(&layout.roots)
            .map_err(source_error)?;
        let preview = NativeRestorePreview::prepare_for_mode(
            job_id,
            &payload,
            &roots,
            &destination,
            NativeObjectId {
                device: identity.device,
                file_id: identity.file_id,
            },
            mode,
            RestoreMode::CompleteApplication,
        )
        .map_err(source_error)?;
        let id = Uuid::new_v4();
        let (digest, metadata_bytes) = preview.digest_and_size().map_err(source_error)?;
        drop(digest);
        let frozen = Arc::new(FrozenPreview {
            fingerprint: fingerprint(&access.provider_id, id, &preview)?,
            provider: access.provider_id.clone(),
            storage: storage_fingerprint(&private)?,
            preview: Arc::new(preview),
            commit,
            manifest_hash,
            metadata_bytes,
            created: Instant::now(),
        });
        let mut result = scope(id, &frozen)?;
        let page = preview_page(id, &frozen.preview, 0, 200)?;
        let summary = result["summary"].clone();
        for (key, value) in summary
            .as_object()
            .context("native restore summary is invalid")?
        {
            result[key] = value.clone();
        }
        result["files"] = page["items"].clone();
        result["nextCursor"] = page["nextCursor"].clone();
        {
            let mut state = self.inner.restore.lock().map_err(poison)?;
            state
                .previews
                .retain(|_, entry| entry.created.elapsed() < PREVIEW_TTL);
            ensure!(
                state.previews.len() < MAX_PREVIEWS,
                "native restore preview cache is full"
            );
            let total = state
                .previews
                .values()
                .try_fold(metadata_bytes, |total, entry| {
                    total
                        .checked_add(entry.metadata_bytes)
                        .context("restore preview accounting overflow")
                })?;
            ensure!(
                total <= noland_restore::MAX_NATIVE_RESTORE_METADATA,
                "native restore preview cache exceeds its aggregate metadata budget"
            );
            state.previews.insert(id, frozen);
        }
        Ok(result)
    }

    /// TTL and exact pinned native identities only. No content reads, helper,
    /// provider, key access, conflict recomputation or tree walk occurs here.
    pub fn restore_preview_scope(&self, id: &str) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid native restore preview ID")?;
        let frozen = self.retained_restore_preview(id)?;
        scope(id, frozen.as_ref())
    }

    pub fn restore_preview_page(&self, id: &str, offset: usize, limit: usize) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid native restore preview ID")?;
        preview_page(
            id,
            &self.retained_restore_preview(id)?.preview,
            offset,
            limit,
        )
    }

    pub async fn download_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        gate: PublishGuard,
    ) -> Result<Value> {
        validate_download_request(&selection)?;
        gate()?;
        self.preflight().await?;
        let _submission = self.inner.submission.lock().await;
        let id = Uuid::parse_str(
            selection["restorePreviewId"]
                .as_str()
                .or_else(|| selection["previewId"].as_str())
                .context("download requires restorePreviewId")?,
        )?;
        let frozen = self.retained_restore_preview(id)?;
        frozen
            .preview
            .validate_native_destination()
            .map_err(source_error)?;
        ensure!(
            access.provider_id == frozen.provider,
            "native restore provider changed after preview"
        );
        check_ack(
            &frozen.preview,
            selection["overwriteAcknowledgement"].as_bool() == Some(true),
        )?;
        check_approved_root(&selection, &frozen.preview)?;
        let private = self.private_access(&access, Some(frozen.preview.job_id))?;
        ensure!(
            storage_fingerprint(&private)? == frozen.storage,
            "native restore storage/key/authority/read-only scope changed after preview"
        );
        // Incoming operationId is a service correlation ID, never a replacement
        // for preview.job_id. No editable destination/mapping/file set is accepted.
        let control = Arc::new(
            NativeRestoreControl::approve_shared(
                Arc::clone(&frozen.preview),
                authority(&self.inner)?,
                owned_gate(
                    &self.inner,
                    &private.provider,
                    frozen.preview.job_id,
                    Arc::clone(&gate),
                ),
            )
            .map_err(source_error)?,
        );
        gate()?;
        let document = RestoreDocumentRef {
            version: 1,
            instance: self.inner.instance,
            provider: &frozen.provider,
            storage: &frozen.storage,
            preview_id: id,
            fingerprint: &frozen.fingerprint,
            commit: frozen.commit,
            manifest_hash: &frozen.manifest_hash,
            preview: frozen.preview.as_ref(),
            device_mac: [0; 32],
        };
        self.persist_restore_document(document)?;
        let files = if frozen.preview.entire_manifest {
            None
        } else {
            Some(
                frozen
                    .preview
                    .entries
                    .iter()
                    .map(|entry| (entry.logical_root.clone(), entry.relative_path.clone()))
                    .collect(),
            )
        };
        let plan = FrozenPlan {
            version: 1,
            api: 22,
            operation: frozen.preview.job_id,
            instance: self.inner.instance,
            provider: private.provider.clone(),
            storage: private.session.root_cache_key(),
            created_at: chrono::Utc::now(),
            work: Work::Download {
                app: frozen.preview.app_id.clone(),
                bundle: frozen.preview.bundle_id,
                commit: frozen.commit,
                manifest_hash: frozen.manifest_hash.clone(),
                preview_id: id,
                frozen_plan_fingerprint: frozen.fingerprint.clone(),
                files,
                destination: frozen.preview.destination.clone(),
                identity: RootIdentity {
                    device: frozen.preview.destination_identity.device,
                    file_id: frozen.preview.destination_identity.file_id,
                },
            },
        };
        self.submit_owned(plan, private, Some(gate), None, Some(control))
    }

    fn persist_restore_document(&self, mut document: RestoreDocumentRef<'_>) -> Result<()> {
        document.device_mac = authority(&self.inner)?
            .mac(&document_message_ref(&document)?)
            .map_err(source_error)?;
        let name = plan_name(document.preview.job_id);
        match self.inner.plans.read_file(&name) {
            Ok((file, stamp)) => {
                verify_private_file(&file)?;
                let existing: RestoreDocument = read_document(file, stamp.size)?;
                self.inner.plans.verify_file(&name, &stamp)?;
                ensure!(
                    document_digest(&existing)? == document_digest(&document)?,
                    "native restore operation already has a different frozen local plan"
                );
                return Ok(());
            }
            Err(error) if missing(&error) => {}
            Err(error) => return Err(error),
        }
        self.inner.plans.write_new(&name, |file| {
            serde_json::to_writer(&mut BoundedWriter::new(file), &document)?;
            Ok(())
        })
    }

    fn read_restore_document(&self, id: Uuid) -> Result<RestoreDocument> {
        let name = plan_name(id);
        let (file, stamp) = self.inner.plans.read_file(&name)?;
        verify_private_file(&file)?;
        let plan: RestoreDocument = read_document(file, stamp.size)?;
        self.inner.plans.verify_file(&name, &stamp)?;
        validate_description(&plan, id, self.inner.instance)?;
        Ok(plan)
    }

    /// Non-authoritative UI hint: only the fixed private filename's native
    /// metadata and operation projection. No plan deserialization or vault I/O.
    pub fn restore_recovery_available(&self, id: Uuid) -> Result<bool> {
        if self.inner.active.lock().map_err(poison)?.contains_key(&id) {
            return Ok(false);
        }
        let Some(operation) = self
            .inner
            .db
            .projected_operation(id, false)
            .map_err(source_error)?
        else {
            return Ok(false);
        };
        if operation.kind != "restore"
            || !matches!(
                operation.state.as_str(),
                "FAILED" | "CANCELLED" | "INTERRUPTED"
            )
        {
            return Ok(false);
        }
        let name = plan_name(id);
        let Ok((file, stamp)) = self.inner.plans.read_file(&name) else {
            return Ok(false);
        };
        if stamp.size == 0
            || stamp.size > noland_restore::MAX_NATIVE_RESTORE_METADATA as u64
            || verify_private_file(&file).is_err()
        {
            return Ok(false);
        }
        Ok(self.inner.plans.verify_file(&name, &stamp).is_ok()
            && !self.inner.active.lock().map_err(poison)?.contains_key(&id))
    }

    /// Descriptive metadata, not authorization. Spend separately verifies the
    /// existing device key MAC before installing a control or replaying journals.
    pub fn restore_recovery_scope(&self, original_id: &str) -> Result<Value> {
        let id = Uuid::parse_str(original_id).context("invalid original native restore ID")?;
        let document = self.read_restore_document(id)?;
        // An interrupted transaction legitimately differs from its *pre-write*
        // entry observations. Scope checks the original root ID only; the
        // shared authenticated journal, not a fresh preview, validates each
        // partial/rollback/output identity at spend.
        let root = SafeRoot::open(&document.preview.destination)?;
        let identity = root.identity()?;
        ensure!(
            identity.device == document.preview.destination_identity.device
                && identity.file_id == document.preview.destination_identity.file_id,
            "original native recovery destination root changed"
        );
        Ok(json!({
            "operationId":id,"providerId":document.provider,
            "appId":document.preview.app_id.as_str(),"bundleId":document.preview.bundle_id,
            "roots":root_scope(&document.preview),"frozenPlanFingerprint":document.fingerprint,
            "filePlanDigest":document_digest(&document)?,
            "summary":format!("Recover the original local restore ({} selected entries); no cloud transfer or retry.",document.preview.entries.len()),
        }))
    }

    /// Synchronous local owner. No preflight, ProviderAccess, MasterKey,
    /// account lifecycle, rclone or remote calls, even after a restart/offline.
    pub fn recover_restore_local(&self, selection: Value, gate: PublishGuard) -> Result<Value> {
        validate_recovery_request(&selection)?;
        let id = recovery_id(&selection)?;
        let _submission = self
            .inner
            .submission
            .try_lock()
            .context("native restore submission or recovery is busy")?;
        ensure!(
            !self.inner.active.lock().map_err(poison)?.contains_key(&id),
            "original native restore worker has not stopped"
        );
        ensure!(!self.inner.finalization_failed.load(Ordering::Acquire),
            "native execution finalization is unverified; retain artifacts until owner recovery/restart");
        self.inner._owner.check()?;
        let operation = self
            .inner
            .db
            .projected_operation(id, false)
            .map_err(source_error)?
            .context("original native restore operation is unavailable")?;
        ensure!(
            operation.kind == "restore"
                && matches!(
                    operation.state.as_str(),
                    "FAILED" | "CANCELLED" | "INTERRUPTED" | "COMPLETED"
                ),
            "local recovery requires a stopped original native restore"
        );
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut owners = self.inner.active.lock().map_err(poison)?;
            ensure!(
                !owners.contains_key(&id),
                "original native restore worker has not stopped"
            );
            owners.insert(id, Arc::clone(&stop));
        }
        let _owner = LocalRecoveryOwner {
            inner: Arc::clone(&self.inner),
            id,
        };
        let active = Arc::new(AtomicBool::new(true));
        let _lease = LocalConsentLease(Arc::clone(&active));
        let expected_gate = local_gate(&self.inner, gate, active, stop);
        expected_gate().map_err(source_error)?;
        let document = self.read_restore_document(id)?;
        ensure!(
            selection["filePlanDigest"].as_str() == Some(document_digest(&document)?.as_str())
                && selection["frozenPlanFingerprint"].as_str()
                    == Some(document.fingerprint.as_str()),
            "local recovery plan changed after native approval"
        );
        check_approved_root(&selection, &document.preview)?;
        let control = authenticate_control(&self.inner, document, expected_gate)?;
        let reports = recover_recorded(&self.inner, id, &control)?;
        Ok(public_recovery(id, &reports))
    }

    /// Provider-backed retry remains a different action from local cleanup.
    /// It can only reattach the original authenticated encrypted operation and
    /// local preview, and runs on the same joined worker queue/operation UUID.
    pub async fn retry_restore_guarded(
        &self,
        access: ProviderAccess,
        original_id: &str,
        gate: PublishGuard,
    ) -> Result<Value> {
        gate()?;
        self.preflight().await?;
        let id = Uuid::parse_str(original_id).context("invalid original native restore ID")?;
        let _submission = self.inner.submission.lock().await;
        ensure!(
            !self.inner.active.lock().map_err(poison)?.contains_key(&id),
            "original native restore worker has not stopped"
        );
        let private = self.private_access(&access, Some(id))?;
        let plan = self.inner.read_plan(id, &private.master)?;
        let document = self.read_restore_document(id)?;
        ensure!(
            document.provider == private.provider
                && document.storage == storage_fingerprint(&private)?,
            "native restore retry differs from original provider/key/read-only scope"
        );
        let control = authenticate_control(
            &self.inner,
            document,
            owned_gate(&self.inner, &private.provider, id, Arc::clone(&gate)),
        )?;
        check_frozen_control(&plan, &control)?;
        self.enqueue(
            Arc::new(plan),
            private,
            Some(gate),
            true,
            None,
            Some(control),
        )
    }
}

fn owned_gate(
    inner: &Arc<Inner>,
    provider: &str,
    id: Uuid,
    gate: PublishGuard,
) -> NativeExpectedGate {
    let inner = Arc::downgrade(inner);
    let provider = provider.to_owned();
    Arc::new(move || {
        let inner = inner
            .upgrade()
            .ok_or_else(|| StateError::Conflict("native restore owner is unavailable".into()))?;
        let stop = inner
            .active
            .lock()
            .map_err(|_| StateError::Conflict("native restore owner lock failed".into()))?
            .get(&id)
            .cloned()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        inner.check(provider.clone(), false, Some(Arc::clone(&gate)), stop)()
    })
}

fn local_gate(
    inner: &Arc<Inner>,
    gate: PublishGuard,
    active: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> NativeExpectedGate {
    let inner = Arc::clone(inner);
    Arc::new(move || {
        if !active.load(Ordering::Acquire)
            || stop.load(Ordering::Acquire)
            || inner.stopping.load(Ordering::Acquire)
            || inner.finalization_failed.load(Ordering::Acquire)
        {
            return Err(StateError::Conflict(
                "local restore recovery consent has ended".into(),
            ));
        }
        inner
            ._owner
            .check()
            .map_err(|_| StateError::Conflict("native owner lock changed".into()))?;
        gate().map_err(|_| StateError::Conflict("local restore recovery consent changed".into()))
    })
}

struct LocalConsentLease(Arc<AtomicBool>);
impl Drop for LocalConsentLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct LocalRecoveryOwner {
    inner: Arc<Inner>,
    id: Uuid,
}
impl Drop for LocalRecoveryOwner {
    fn drop(&mut self) {
        if let Ok(mut owners) = self.inner.active.lock() {
            owners.remove(&self.id);
        } else {
            self.inner
                .finalization_failed
                .store(true, Ordering::Release);
        }
    }
}

fn check_ack(preview: &NativeRestorePreview, acknowledged: bool) -> Result<()> {
    ensure!(
        !needs_ack(preview) || acknowledged,
        "this exact native restore preview requires separate overwrite acknowledgement"
    );
    Ok(())
}

fn validate_download_request(value: &Value) -> Result<()> {
    request_keys(
        value,
        &[
            "restorePreviewId",
            "previewId",
            "overwriteAcknowledgement",
            "operationId",
            "_approvedPaths",
        ],
    )?;
    ensure!(
        value["restorePreviewId"].is_string() || value["previewId"].is_string(),
        "download requires its frozen native restorePreviewId; no create-only fallback"
    );
    if let (Some(left), Some(right)) = (value.get("restorePreviewId"), value.get("previewId")) {
        ensure!(left == right, "native restore preview IDs disagree");
    }
    if let Some(id) = value.get("operationId") {
        Uuid::parse_str(
            id.as_str()
                .context("invalid service restore correlation ID")?,
        )?;
    }
    if let Some(ack) = value.get("overwriteAcknowledgement") {
        ensure!(
            ack.is_boolean(),
            "overwrite acknowledgement must be an explicit boolean"
        );
    }
    Ok(())
}

fn validate_recovery_request(value: &Value) -> Result<()> {
    request_keys(
        value,
        &[
            "operationId",
            "nativeOperationId",
            "jobId",
            "filePlanDigest",
            "frozenPlanFingerprint",
            "_approvedPaths",
        ],
    )?;
    for field in ["filePlanDigest", "frozenPlanFingerprint"] {
        let hash = value[field]
            .as_str()
            .context("local recovery requires its frozen plan digests")?;
        ensure!(raw_digest(hash), "invalid local recovery plan digest");
    }
    Ok(())
}

fn request_keys(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("native restore request must be an object")?;
    ensure!(object.keys().all(|key| allowed.contains(&key.as_str())),
        "native restore accepts only the original frozen ticket, never editable destinations or mappings");
    let mut limit = BoundedWriter::with_limit(std::io::sink(), 1024 * 1024);
    serde_json::to_writer(&mut limit, value)?;
    ensure!(
        limit.written <= 1024 * 1024,
        "native restore request exceeds its bound"
    );
    Ok(())
}

fn check_approved_root(selection: &Value, preview: &NativeRestorePreview) -> Result<()> {
    ensure!(
        selection["_approvedPaths"]
            .as_array()
            .is_some_and(|proofs| proofs.len() == 1),
        "native restore requires the exact approved native directory proof"
    );
    approved_destination(
        selection,
        &preview.destination,
        &RootIdentity {
            device: preview.destination_identity.device,
            file_id: preview.destination_identity.file_id,
        },
    )
}

fn recovery_id(selection: &Value) -> Result<Uuid> {
    let mut selected = None;
    for field in ["operationId", "nativeOperationId", "jobId"] {
        if let Some(value) = selection.get(field) {
            let id = Uuid::parse_str(value.as_str().context("invalid original restore ID")?)?;
            ensure!(
                selected.is_none_or(|prior| prior == id),
                "conflicting original restore IDs"
            );
            selected = Some(id);
        }
    }
    selected
        .filter(|id| !id.is_nil())
        .context("local restore recovery requires its original operationId")
}

pub(super) fn check_frozen_control(
    plan: &FrozenPlan,
    control: &NativeRestoreControl,
) -> Result<()> {
    let Work::Download {
        app,
        bundle,
        destination,
        identity,
        preview_id,
        frozen_plan_fingerprint,
        files,
        ..
    } = &plan.work
    else {
        bail!("frozen restore control cannot authorize another operation kind")
    };
    let preview = control.preview();
    ensure!(
        preview.job_id == plan.operation
            && preview.app_id == *app
            && preview.bundle_id == *bundle
            && preview.destination == *destination
            && preview.destination_identity.device == identity.device
            && preview.destination_identity.file_id == identity.file_id
            && fingerprint(&plan.provider, *preview_id, preview)? == *frozen_plan_fingerprint,
        "native restore control differs from the original frozen operation"
    );
    if let Some(files) = files {
        ensure!(
            *files
                == preview
                    .entries
                    .iter()
                    .map(|entry| (entry.logical_root.clone(), entry.relative_path.clone()))
                    .collect(),
            "native restore control selection differs from original exact entries"
        );
    } else {
        ensure!(
            preview.entire_manifest,
            "native full restore control is not a whole manifest"
        );
    }
    Ok(())
}

fn raw_digest(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_description(document: &RestoreDocument, id: Uuid, instance: Uuid) -> Result<()> {
    ensure!(
        document.version == 1
            && document.instance == instance
            && document.preview.job_id == id
            && !id.is_nil()
            && !document.preview_id.is_nil()
            && !document.commit.is_nil()
            && raw_digest(&document.storage)
            && raw_digest(&document.fingerprint)
            && fingerprint(&document.provider, document.preview_id, &document.preview)?
                == document.fingerprint,
        "local restore plan does not describe this original native job"
    );
    canonical_hash(&document.manifest_hash)?;
    Ok(())
}

fn authenticate_control(
    inner: &Inner,
    document: RestoreDocument,
    gate: NativeExpectedGate,
) -> Result<Arc<NativeRestoreControl>> {
    validate_description(&document, document.preview.job_id, inner.instance)?;
    let authority = authority(inner)?;
    let expected = authority
        .mac(&document_message(&document)?)
        .map_err(source_error)?;
    ensure!(
        constant_equal(&expected, &document.device_mac),
        "native local restore plan device authentication failed"
    );
    Ok(Arc::new(
        NativeRestoreControl::approve(document.preview, authority, gate).map_err(source_error)?,
    ))
}

fn constant_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn document_message(document: &RestoreDocument) -> Result<Vec<u8>> {
    document_message_ref(&RestoreDocumentRef {
        version: document.version,
        instance: document.instance,
        provider: &document.provider,
        storage: &document.storage,
        preview_id: document.preview_id,
        fingerprint: &document.fingerprint,
        commit: document.commit,
        manifest_hash: &document.manifest_hash,
        preview: &document.preview,
        device_mac: document.device_mac,
    })
}

fn document_message_ref(document: &RestoreDocumentRef<'_>) -> Result<Vec<u8>> {
    let body = (
        document.version,
        document.instance,
        &document.provider,
        &document.storage,
        document.preview_id,
        &document.fingerprint,
        document.commit,
        &document.manifest_hash,
        &document.preview,
    );
    let mut hash = blake3::Hasher::new();
    serde_json::to_writer(&mut BoundedWriter::new(&mut hash), &body)?;
    let mut message = b"QuickSave Windows native local restore plan v1\0".to_vec();
    message.extend_from_slice(hash.finalize().as_bytes());
    Ok(message)
}

fn document_digest(document: &impl Serialize) -> Result<String> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave Windows restore approval file-plan v1\0");
    serde_json::to_writer(&mut BoundedWriter::new(&mut hash), document)?;
    Ok(hash.finalize().to_hex().to_string())
}

struct BoundedWriter<W> {
    inner: W,
    written: usize,
    limit: usize,
}
impl<W> BoundedWriter<W> {
    fn new(inner: W) -> Self {
        Self::with_limit(inner, noland_restore::MAX_NATIVE_RESTORE_METADATA)
    }
    fn with_limit(inner: W, limit: usize) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }
}
impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| std::io::Error::other("native restore metadata bound exceeded"))?;
        self.inner.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn read_document(file: File, size: u64) -> Result<RestoreDocument> {
    ensure!(
        size > 0 && size <= noland_restore::MAX_NATIVE_RESTORE_METADATA as u64,
        "local restore plan exceeds its metadata bound"
    );
    Ok(serde_json::from_reader(file.take(
        noland_restore::MAX_NATIVE_RESTORE_METADATA as u64 + 1,
    ))?)
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Only fixed UUID hints from our DB are considered, never a caller-supplied
/// recovery path. Hints are not authority: the shared journals authenticate every
/// scope/entry/native ownership ID against this exact in-process control.
pub(super) fn recover_recorded(
    inner: &Inner,
    id: Uuid,
    control: &Arc<NativeRestoreControl>,
) -> Result<Vec<NativeRestoreRecoveryReport>> {
    control.check_gate().map_err(source_error)?;
    let operation = inner
        .db
        .get_operation(id)
        .map_err(source_error)?
        .context("original native restore operation is unavailable")?;
    ensure!(
        operation.kind == "restore",
        "local recovery requires the original restore job"
    );
    let attempts = attempts(&operation)?;
    if operation.state == "COMPLETED"
        || operation.detail_json["native_restore_committed_attempt"].is_string()
    {
        control.require_committed_recovery();
    }
    // Only newest attempt. Older rolled-back attempts are immutable audit
    // history, and must not be re-audited against a later committed destination.
    let Some(attempt) = attempts.last() else {
        return Ok(Vec::new());
    };
    let operation_root = SafeRoot::open(&inner.paths.restore)?;
    let path = format!("{id}/{attempt}");
    let directory = operation_root.open_directory(&path)?;
    drop(directory); // Native recovery immediately reopens and pins all ancestors.
    let workspace = inner
        .paths
        .restore
        .join(id.to_string())
        .join(attempt.to_string());
    Ok(vec![noland_restore::recover_native_restore(
        &workspace,
        Arc::clone(control),
    )
    .map_err(source_error)?])
}

fn attempts(operation: &OperationRecord) -> Result<Vec<Uuid>> {
    let Some(values) = operation.detail_json.get("native_restore_attempts") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .context("native restore attempt history is malformed")?;
    ensure!(
        values.len() <= MAX_ATTEMPTS,
        "native restore attempt history is at capacity"
    );
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        let attempt = Uuid::parse_str(
            value
                .as_str()
                .context("invalid native restore attempt ID")?,
        )?;
        ensure!(
            !attempt.is_nil() && attempt != operation.operation_id && seen.insert(attempt),
            "native restore attempt IDs are invalid/duplicated"
        );
        output.push(attempt);
    }
    Ok(output)
}

pub(super) fn install_recorders(
    inner: &Arc<Inner>,
    id: Uuid,
    control: &Arc<NativeRestoreControl>,
) -> Result<()> {
    let expected = control.preview().digest().map_err(source_error)?;
    let db = inner.db.clone();
    let owner = Arc::downgrade(control);
    control
        .set_attempt_recorder(Arc::new(move |attempt| {
            let owner = owner.upgrade().ok_or_else(|| {
                StateError::Conflict("native restore control owner stopped".into())
            })?;
            if owner.preview().digest()? != expected || attempt.is_nil() || attempt == id {
                return Err(StateError::Conflict(
                    "native restore attempt plan binding changed".into(),
                ));
            }
            let mut operation = db
                .get_operation(id)?
                .ok_or_else(|| StateError::NotFound("original native restore operation".into()))?;
            let mut hints = attempts(&operation).map_err(|_| {
                StateError::Integrity("native restore attempt history is invalid".into())
            })?;
            if !hints.contains(&attempt) {
                if hints.len() >= MAX_ATTEMPTS {
                    return Err(StateError::Conflict(
                        "native restore attempt history is at capacity".into(),
                    ));
                }
                hints.push(attempt);
            }
            operation.detail_json["native_restore_attempts"] = json!(hints);
            operation.updated_at = chrono::Utc::now();
            db.upsert_operation(&operation)
        }))
        .map_err(source_error)?;
    let db = inner.db.clone();
    control
        .set_commit_recorder(Arc::new(move |attempt| {
            let mut operation = db
                .get_operation(id)?
                .ok_or_else(|| StateError::NotFound("original native restore operation".into()))?;
            if !attempts(&operation)
                .map_err(|_| {
                    StateError::Integrity("native restore attempt history is invalid".into())
                })?
                .contains(&attempt)
            {
                return Err(StateError::Integrity(
                    "committed native attempt was not recorded".into(),
                ));
            }
            operation.detail_json["native_restore_committed_attempt"] = json!(attempt);
            operation.updated_at = chrono::Utc::now();
            db.upsert_operation(&operation)
        }))
        .map_err(source_error)
}

pub(super) fn new_workspace(inner: &Inner, id: Uuid) -> Result<(Uuid, PathBuf)> {
    let operation = inner
        .db
        .get_operation(id)
        .map_err(source_error)?
        .context("native restore operation is unavailable")?;
    ensure!(
        attempts(&operation)?.len() < MAX_ATTEMPTS,
        "native restore attempt history is at capacity"
    );
    let root = SafeRoot::open(&inner.paths.restore)?;
    let attempt = Uuid::new_v4();
    let relative = format!("{id}/{attempt}");
    root.create_dir(&relative)?;
    let workspace = inner
        .paths
        .restore
        .join(id.to_string())
        .join(attempt.to_string());
    ensure_private_directory(&workspace)?;
    ensure!(
        SafeRoot::open(&workspace)?.metadata_entries()?.is_empty(),
        "new native restore attempt is not empty"
    );
    Ok((attempt, workspace))
}

fn public_recovery(id: Uuid, reports: &[NativeRestoreRecoveryReport]) -> Value {
    let recovered = !reports.is_empty()
        && reports.iter().all(|report| {
            (report.rolled_back || report.committed)
                && report.retained_artifacts.is_empty()
                && report.owned_artifacts_clean
                && report.metadata_only_workspace
        });
    json!({
        "operationId":id,"recovered":recovered,"localOnly":true,"newTransferStarted":false,
        "workspaceCount":reports.len(),"noRecordedWorkspaces":reports.is_empty(),
        "rolledBackWorkspaces":reports.iter().filter(|report| report.rolled_back).count(),
        "committedWorkspaces":reports.iter().filter(|report| report.committed).count(),
        "ownedArtifactsClean":!reports.is_empty() && reports.iter().all(|report| report.owned_artifacts_clean),
        "metadataOnlyWorkspaces":!reports.is_empty() && reports.iter().all(|report| report.metadata_only_workspace),
        "retainedArtifacts":reports.iter().any(|report| !report.retained_artifacts.is_empty()),
        "diagnostics":reports.iter().flat_map(|report| &report.retained_artifacts).take(32)
            .map(|_| "Native recovery retained an artifact; original native scope and journal require inspection.")
            .collect::<Vec<_>>(),
        "reports":reports.iter().map(|report| json!({
            "committed":report.committed,"rolledBack":report.rolled_back,
            "removedOwnedEntries":report.removed_owned_entries,
            "restoredOriginalEntries":report.restored_original_entries,
            "ownedArtifactsClean":report.owned_artifacts_clean,
            "metadataOnlyWorkspace":report.metadata_only_workspace,
            "retainedDiagnosticCount":report.retained_artifacts.len(),
        })).collect::<Vec<_>>(),
    })
}

fn preview_page(
    id: Uuid,
    preview: &NativeRestorePreview,
    offset: usize,
    limit: usize,
) -> Result<Value> {
    ensure!(
        limit > 0 && limit <= 200,
        "restore preview page limit is 1–200"
    );
    let total = preview.entries.len() + preview.tombstones.len();
    ensure!(
        offset <= total,
        "restore preview cursor is outside its revision"
    );
    let mut items = Vec::new();
    let mut bytes = 0usize;
    for entry in preview
        .entries
        .iter()
        .chain(&preview.tombstones)
        .skip(offset)
        .take(limit)
    {
        let item = json!({
            "id":file_id(&entry.logical_root,&entry.relative_path),"path":entry.relative_path,
            "rootId":format!("native-root-{}",blake3::hash(entry.logical_root.as_bytes()).to_hex()),
            "destinationRelative":entry.destination_relative,"kind":entry.kind,
            "action":entry.action,"size":entry.size,"sourceSize":entry.size,
            "requestedMode":entry.mode,"requestedMtimeNs":entry.mtime_ns,
            "requestedUid":entry.uid,"requestedGid":entry.gid,
            "existingKind":entry.expected.as_ref().map(|prior| prior.kind),
            "existingSize":entry.expected.as_ref().map(|prior| prior.size),
            "existingMode":entry.expected.as_ref().map(|prior| prior.mode),
        });
        let size = serde_json::to_vec(&item)?.len();
        ensure!(
            size <= 1024 * 1024,
            "restore preview entry exceeds IPC bound"
        );
        if !items.is_empty() && bytes + size > 1024 * 1024 {
            break;
        }
        bytes += size;
        items.push(item);
    }
    let next = offset + items.len();
    Ok(json!({"previewId":id,"jobId":preview.job_id,"items":items,
        "nextCursor":(next < total).then_some(next)}))
}
