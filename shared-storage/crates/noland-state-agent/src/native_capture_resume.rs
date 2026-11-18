// SPDX-License-Identifier: GPL-3.0-only
// Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! Child of native_capture, declared there with:
//! `#[path = "native_capture_resume.rs"] pub mod resume;`
//!
//! Resume reconstructs a native capability from ORIGINAL, independently
//! device-authenticated Tracker evidence plus the original source AEAD envelope
//! and encrypted capture proof. A repository key alone is never sufficient.
//! There is no call to install(), full_snapshot(), verify_full_inventory(), or
//! check_node(): those prepare today's files, not the frozen original capture.

use super::*;
use crate::native_host::NativeSelection;

const MAX_ORIGINAL_AUTH_BYTES: usize = 64 * 1024;

/// Mandatory native-only device authority for the original frozen work AND its
/// post-capture tracking_capture_receipt + tracking_capture_receipt_sidecar.
/// Implementations must authenticate private references/hashes/current grants,
/// not deserialize a boolean or trust the repository key. No default succeeds.
pub trait NativeOriginalCaptureAuthority: Send + Sync + 'static {
    fn revalidate(&self) -> Result<()>;
    fn original_evidence(&self) -> Result<Arc<Value>>;
    fn verify_recovered(&self, evidence: &Value) -> Result<()>;
}

/// Does not queue, retry, publish, recapture, scan, or hash live application data.
/// `manifest` is the authenticated original prepared manifest, or the actual
/// authenticated committed manifest when the source is already completed.
///
/// The caller MUST authenticate the source submission/repository/selection HMAC
/// before this native-only entry point. Fresh publication authorization remains
/// mandatory in native_host::native_check_publication_guard on the actual retry.
pub fn reattach_original_capture(
    agent: &StateAgent,
    operation: Uuid,
    selection: &NativeSelection,
    master: &MasterKey,
    manifest: &BundleManifest,
    sink: Arc<dyn NativeCaptureSink>,
    authority: Arc<dyn NativeOriginalCaptureAuthority>,
) -> Result<Arc<NativeCaptureReceipt>> {
    if !agent.config.native_host || operation.is_nil() || agent.operations.is_running(operation) {
        return Err(StateError::Conflict(
            "original native capture requires the exact drained source owner".into(),
        ));
    }
    let normalized = NativeSelection::parse(&serde_json::to_value(selection)?)?;
    if normalized != *selection
        || selection.destination.is_some()
        || selection.expected_files.is_some()
    {
        return Err(StateError::Invalid(
            "original native capture selection is not canonical".into(),
        ));
    }
    let scope = selection.capture_scope.as_ref().ok_or_else(|| {
        StateError::Invalid("original source capture has no native receipt scope".into())
    })?;
    let instance = selection.software_instance_id.as_deref().ok_or_else(|| {
        StateError::Invalid("original source capture lacks its installation identity".into())
    })?;
    let operation_record = agent
        .db
        .get_operation(operation)?
        .ok_or_else(|| StateError::NotFound("original source operation is missing".into()))?;
    if operation_record.kind != "backup"
        || operation_record.app_id.as_ref() != Some(&manifest.app.app_id)
        || operation_record.detail_json["client_operation_id"] != json!(operation)
        || operation_record.detail_json["mode"] != json!(manifest.mode.as_str())
        || NativeSelection::parse(&operation_record.detail_json["native_selection"])? != *selection
        || manifest.environment["quicksave_native"]["selection"] != json!(selection)
        || manifest.environment["quicksave_native"]["software_instance_id"] != instance
        || manifest.consistency == ConsistencyKind::BestEffort
    {
        return Err(StateError::Conflict(
            "original source operation/manifest differs from its frozen native capture".into(),
        ));
    }
    authority.revalidate()?;
    let original = authority.original_evidence()?;
    let original_auth = &original["sourceExpectedManifestAuth"];
    if original["workId"] != scope.work_id
        || original["metadataIdentity"] != scope.metadata_identity
        || original["sourceSnapshotId"] != manifest.bundle_id.to_string()
        || original_auth["operationId"] != json!(operation)
        || original_auth["aad"] != "quicksave-native-expected-manifest-v1"
        || original_auth["version"] != 1
        || original_auth["algorithm"] != "source-xchacha20poly1305-metadata"
    {
        return Err(StateError::Integrity(
            "device-authenticated receipt is not the original source capture".into(),
        ));
    }
    let encoded = original_auth["envelopeHex"].as_str().ok_or_else(|| {
        StateError::Integrity("original expected-manifest envelope is missing".into())
    })?;
    if encoded.len() > MAX_ORIGINAL_AUTH_BYTES * 2 || encoded.len() % 2 != 0 {
        return Err(StateError::Integrity(
            "original expected-manifest envelope exceeds its bound".into(),
        ));
    }
    let authentication = hex::decode(encoded).map_err(|_| {
        StateError::Integrity("original expected-manifest envelope is malformed".into())
    })?;
    let binding: ManifestAuthentication = noland_storage::open_metadata_with_limit(
        &noland_crypto::derive_keys(master).manifest,
        b"quicksave-native-expected-manifest-v1",
        authentication.clone(),
        MAX_ORIGINAL_AUTH_BYTES as u64,
    )?;
    let counters = Arc::new(Counters::default());
    let workspace = Arc::new(RootPin::open(
        agent.config.paths.packs.clone(),
        counters.clone(),
    )?);
    let retained = match session(agent, operation)? {
        Some(session) => {
            let retained = session
                .accepted
                .lock()
                .map_err(|_| StateError::Invalid("original retained receipt lock failed".into()))?
                .clone();
            retained
        }
        None => None,
    };
    let proof = if let Some(receipt) = &retained {
        receipt.revalidate()?;
        if receipt.binding != binding || receipt.authentication != authentication {
            return Err(StateError::Integrity(
                "retained native receipt belongs to another original capture".into(),
            ));
        }
        receipt.proof.clone()
    } else {
        read_proof(&workspace, &checkpoint(agent, operation), operation, master)?
            .ok_or_else(|| StateError::Conflict(
                "original immutable native capture proof is missing; no recapture was performed".into()
            ))?
    };
    let app = &manifest.app.app_id;
    let approved = agent.native_capture_root_pins(app)?;
    let fingerprint = agent.native_binding_fingerprint(app)?;
    let selected_roots = selection
        .file_keys
        .as_ref()
        .ok_or_else(|| StateError::Integrity("original exact native file keys are missing".into()))?
        .iter()
        .map(|key| key.logical_root.as_str())
        .collect::<BTreeSet<_>>();
    let layout_filter = if selection.coverage == NativeCoverage::FullApprovedScope {
        None
    } else {
        Some(&selected_roots)
    };
    let layouts = root_layouts_from_pins(app, instance, &approved, layout_filter)?;
    let proof_hash = hash_value(&proof)?;
    if binding.version != 1
        || binding.operation != operation
        || binding.app != *app
        || binding.scope != *scope
        || binding.roots_fingerprint != fingerprint
        || binding.roots_fingerprint != selection.roots_fingerprint
        || binding.source_snapshot_id != manifest.bundle_id
        || binding.manifest_hash != hash_value(manifest)?
        || binding.capture_proof_hash != proof_hash
        || binding.captured_files_hash != hash_value(&proof.files)?
        || binding.root_layouts_hash != hash_value(&layouts)?
        || proof.operation != operation
        || proof.app != *app
        || proof.scope != *scope
        || proof.roots_fingerprint != fingerprint
        || proof.software_instance_id.as_deref() != Some(instance)
        || proof.root_layouts.as_ref() != Some(&layouts)
        || manifest.environment["quicksave_native_root_layouts"] != layouts
        || original_auth["manifestHash"] != binding.manifest_hash
        || original_auth["capturedFilesHash"] != binding.captured_files_hash
        || original_auth["capturedProofHash"] != binding.capture_proof_hash
        || original_auth["rootLayoutsHash"] != binding.root_layouts_hash
    {
        return Err(StateError::Integrity(
            "original source proof/envelope/manifest/root-layout authentication failed".into(),
        ));
    }
    let actual = manifest
        .files
        .iter()
        .map(|file| {
            (
                NativeFileKey {
                    logical_root: file.logical_root.clone(),
                    relative_path: file.relative_path.clone(),
                },
                file,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual.len() != manifest.files.len() || actual.len() != proof.files.len() {
        return Err(StateError::Integrity(
            "original prepared manifest has another exact node count".into(),
        ));
    }
    for file in &proof.files {
        if !actual
            .get(&file.key)
            .map(|actual| manifest_matches_proof(actual, file))
            .transpose()?
            .unwrap_or(false)
        {
            return Err(StateError::Integrity(
                "original prepared manifest differs from captured immutable hashes/chunks".into(),
            ));
        }
    }
    let (nodes, roots, path_bytes) = frozen_nodes(
        scope,
        selection,
        sink.as_ref(),
        &approved,
        &proof,
        counters.clone(),
    )?;
    let full = original_full_snapshot(scope, app, instance, sink.as_ref(), &approved, &proof)?;
    let recovered = Arc::new(Session {
        operation,
        app: app.clone(),
        scope: scope.clone(),
        roots_fingerprint: fingerprint,
        software_instance_id: Mutex::new(Some(instance.into())),
        // Never import an old process's reuse epoch into a new capture.
        reuse_epoch: None,
        source_loss_generation: agent.observer.loss_generation(),
        nodes: Arc::new(nodes),
        roots,
        approved,
        full,
        history: Mutex::new(proof.history.clone()),
        workspace,
        sink,
        captured: Mutex::new(
            proof
                .files
                .iter()
                .cloned()
                .map(|file| (file.key.clone(), file))
                .collect(),
        ),
        accepted: Mutex::new(None),
        accepting: std::sync::atomic::AtomicBool::new(false),
        counters,
    });
    validate_history(&recovered, manifest, &proof)?;
    let operations = agent.operations.clone();
    let receipt = if let Some(receipt) = retained {
        receipt
    } else {
        Arc::new(NativeCaptureReceipt {
            binding,
            authentication,
            master: master.clone(),
            proof,
            proof_hash,
            nodes: recovered.nodes.clone(),
            roots: recovered.roots.clone(),
            approved: recovered.approved.clone(),
            workspace: recovered.workspace.clone(),
            cancelled: Arc::new(move || operations.cancel_requested(operation)),
        })
    };
    receipt.revalidate()?;
    // Equality preserves the ORIGINAL envelope/nonce and device-authenticated
    // full nodes/deletions/root captures; no replacement receipt is sealed here.
    let recovered_evidence = receipt.evidence()?;
    if &recovered_evidence != original.as_ref() {
        return Err(StateError::Integrity(
            "recovered source receipt differs from the device-authenticated original sidecar"
                .into(),
        ));
    }
    authority.verify_recovered(&recovered_evidence)?;
    authority.revalidate()?;
    // The trusted Tracker implementation reattaches this native capability to
    // its original signed Pending frame, without issuing new capture grants.
    recovered.sink.accept(receipt.clone())?;
    receipt.revalidate()?;
    authority.revalidate()?;
    *recovered
        .accepted
        .lock()
        .map_err(|_| StateError::Invalid("native resumed receipt lock failed".into()))? =
        Some(receipt.clone());
    recovered
        .counters
        .accepted_receipts
        .fetch_add(1, Ordering::Relaxed);
    install_recovered_session(agent, operation, recovered, path_bytes)?;
    Ok(receipt)
}

fn frozen_nodes(
    scope: &NativeCaptureScope,
    selection: &NativeSelection,
    sink: &dyn NativeCaptureSink,
    approved: &[Arc<NativeApprovedPin>],
    proof: &CaptureProof,
    counters: Arc<Counters>,
) -> Result<(
    BTreeMap<NativeFileKey, NativeCaptureNode>,
    BTreeMap<String, Arc<RootPin>>,
    usize,
)> {
    let expected_keys = selection
        .file_keys
        .as_ref()
        .ok_or_else(|| StateError::Integrity("original exact native selection is absent".into()))?;
    if proof.files.len() != scope.node_count
        || expected_keys.len() != scope.node_count
        || !proof
            .files
            .iter()
            .map(|file| &file.key)
            .eq(expected_keys.iter())
    {
        return Err(StateError::Integrity(
            "original native captured proof has another exact selection".into(),
        ));
    }
    let mut nodes = BTreeMap::new();
    let mut roots = BTreeMap::new();
    let mut path_bytes = 0usize;
    while nodes.len() < scope.node_count {
        let offset = nodes.len();
        let count = NATIVE_CAPTURE_PAGE.min(scope.node_count - offset);
        let page = sink.node_page(scope, offset, count)?;
        counters.frozen_pages.fetch_add(1, Ordering::Relaxed);
        if page.len() != count {
            return Err(StateError::Integrity(
                "original frozen node page added/omitted nodes".into(),
            ));
        }
        for node in page {
            validate_native_relative(&node.path)?;
            let pin = approved
                .iter()
                .find(|pin| pin.logical_root == node.logical_root)
                .ok_or_else(|| {
                    StateError::UnsafePath("original node has an unapproved native root".into())
                })?;
            let base = if pin.directory {
                pin.path.as_path()
            } else {
                pin.path.parent().ok_or_else(|| {
                    StateError::UnsafePath("native file root has no parent".into())
                })?
            };
            let in_scope = if let Some(leaves) = &pin.allowed_files {
                !node.path.contains('/') && leaves.contains(&node.path)
            } else if pin.directory {
                true
            } else {
                pin.path.file_name().and_then(|name| name.to_str()) == Some(node.path.as_str())
            };
            let key = NativeFileKey {
                logical_root: node.logical_root.clone(),
                relative_path: node.path.clone(),
            };
            let file = proof
                .files
                .binary_search_by(|file| file.key.cmp(&key))
                .ok()
                .map(|index| &proof.files[index])
                .ok_or_else(|| {
                    StateError::Integrity("original frozen node was not actually captured".into())
                })?;
            let valid_kind = match node.kind.as_str() {
                "file" => node.size == node.stamp.size && node.link_target_hash.is_none(),
                "directory" => node.size == 0 && node.link_target_hash.is_none(),
                "symlink" => {
                    node.size == 0
                        && node
                            .link_target_hash
                            .as_ref()
                            .is_some_and(|hash| canonical_raw_hash(hash))
                }
                _ => false,
            };
            if !in_scope
                || !valid_kind
                || node.root_id != pin.id
                || node.id != native_file_id(&node.logical_root, &node.path)
                || file.stamp != node.stamp
                || file.size != node.size
                || file.kind != node.kind
                || file.link_target_hash != node.link_target_hash
                || node.stamp.modified_nanoseconds >= 1_000_000_000
                || node.stamp.changed_nanoseconds >= 1_000_000_000
            {
                return Err(StateError::Integrity(
                    "original frozen node identity/stamp differs from actual captured proof".into(),
                ));
            }
            path_bytes = path_bytes.checked_add(node.path.len()).ok_or_else(|| {
                StateError::Invalid("native resume path-byte count overflow".into())
            })?;
            if path_bytes > MAX_CAPTURE_PATH_BYTES || nodes.insert(key, node).is_some() {
                return Err(StateError::Integrity(
                    "original frozen node bound/uniqueness failed".into(),
                ));
            }
            if !roots.contains_key(&pin.logical_root) {
                roots.insert(
                    pin.logical_root.clone(),
                    Arc::new(RootPin::open(base.to_owned(), counters.clone())?),
                );
            }
        }
    }
    hash_value(&nodes.values().collect::<Vec<_>>())?;
    Ok((nodes, roots, path_bytes))
}

fn original_full_snapshot(
    scope: &NativeCaptureScope,
    app: &AppId,
    instance: &str,
    sink: &dyn NativeCaptureSink,
    approved: &[Arc<NativeApprovedPin>],
    proof: &CaptureProof,
) -> Result<Option<FullSnapshot>> {
    let Some(binding) = scope.full_scope.as_ref() else {
        if proof.full_scope_evidence.is_some() || !proof.root_captures.is_empty() {
            return Err(StateError::Integrity(
                "selected original work cannot add full-scope proof".into(),
            ));
        }
        return Ok(None);
    };
    let owner = sink.full_scope_authority(scope)?.ok_or_else(|| {
        StateError::Conflict("original full snapshot has no current native grant owner".into())
    })?;
    owner.revalidate()?;
    let evidence = owner.evidence()?;
    if proof.full_scope_evidence.as_ref() != Some(&evidence)
        || NativeFullScopeBinding::from_evidence(&evidence)? != *binding
        || evidence["workId"] != scope.work_id
        || evidence["metadataIdentity"] != scope.metadata_identity
        || evidence
            .pointer("/sourceIdentity/app_id")
            .and_then(Value::as_str)
            .unwrap_or(instance)
            != app.as_str()
        || evidence["fullScope"] != true
        || evidence["keepsVersionHistory"] != true
        || evidence["completeFileList"] != true
        || proof.root_captures.len() != approved.len()
        || binding.root_count != approved.len()
        || proof.software_instance_id.as_deref() != Some(instance)
    {
        return Err(StateError::Integrity(
            "original full-scope grant/evidence/root identity changed".into(),
        ));
    }
    for pin in approved {
        pin.check()?; // Native root identity only, NOT today's mutable directory stamp.
        let capture = proof
            .root_captures
            .iter()
            .find(|capture| capture.id == pin.id)
            .ok_or_else(|| {
                StateError::Integrity("original root capture omitted an approved root".into())
            })?;
        if capture.logical_root != pin.logical_root
            || (capture.stamp.device, capture.stamp.file_id)
                != (pin.identity.0, [pin.identity.1, 0])
        {
            return Err(StateError::Integrity(
                "original root capture has another native identity".into(),
            ));
        }
    }
    let history = proof.history.as_ref().ok_or_else(|| {
        StateError::Integrity("original full-scope source history is missing".into())
    })?;
    let deleted = history
        .deleted
        .iter()
        .cloned()
        .map(|deleted| (deleted.key.clone(), deleted))
        .collect::<BTreeMap<_, _>>();
    if deleted.len() != history.deleted.len() || deleted.len() != binding.deleted_count {
        return Err(StateError::Integrity(
            "original deleted-node partition is not exact".into(),
        ));
    }
    owner.revalidate()?;
    Ok(Some(FullSnapshot {
        authority: owner,
        software_instance_id: proof.software_instance_id.clone().ok_or_else(|| {
            StateError::Integrity("original installation identity is missing".into())
        })?,
        evidence,
        deleted,
        roots: proof.root_captures.clone(),
    }))
}

fn install_recovered_session(
    agent: &StateAgent,
    operation: Uuid,
    recovered: Arc<Session>,
    live_path_bytes: usize,
) -> Result<()> {
    let mut bindings = agent.native_bindings.lock();
    if agent.operations.is_running(operation) {
        return Err(StateError::Conflict(
            "source owner restarted during original receipt recovery".into(),
        ));
    }
    let captures = &mut bindings.captures;
    let retained = captures.sessions.iter().filter(|(id, _)| **id != operation);
    let mut nodes =
        recovered.nodes.len() + recovered.full.as_ref().map_or(0, |full| full.deleted.len());
    let mut paths = live_path_bytes
        + recovered.full.as_ref().map_or(0, |full| {
            full.deleted
                .keys()
                .map(|key| key.relative_path.len())
                .sum::<usize>()
        });
    let mut handles = recovered.roots.len() + recovered.approved.len() + 1;
    let mut operations = 1usize;
    for (_, session) in retained {
        operations = operations.saturating_add(1);
        nodes = nodes.saturating_add(
            session.nodes.len() + session.full.as_ref().map_or(0, |full| full.deleted.len()),
        );
        handles = handles.saturating_add(session.roots.len() + session.approved.len() + 1);
        paths = paths
            .saturating_add(
                session
                    .nodes
                    .keys()
                    .map(|key| key.relative_path.len())
                    .sum::<usize>(),
            )
            .saturating_add(session.full.as_ref().map_or(0, |full| {
                full.deleted
                    .keys()
                    .map(|key| key.relative_path.len())
                    .sum::<usize>()
            }));
    }
    if operations > MAX_CAPTURE_OPERATIONS
        || nodes > MAX_CAPTURE_NODES
        || paths > MAX_CAPTURE_PATH_BYTES
        || handles > MAX_CAPTURE_ROOT_HANDLES
    {
        return Err(StateError::Conflict(
            "original native capture recovery exceeds bounded native capacity".into(),
        ));
    }
    captures.sessions.insert(operation, recovered);
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::native_host::{native_root_token, ApprovedNativeRoot, NativeRootRole};
    use noland_state_core::{AppIdentity, BackupPerformanceMode, OperationRecord};
    use noland_storage::{LocalStorage, SharedStorageProvider};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct TemporaryRoot(PathBuf);
    impl TemporaryRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "quicksave-native-original-resume-{}",
                Uuid::new_v4()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Sink {
        nodes: Vec<NativeCaptureNode>,
        receipt: Mutex<Option<Arc<NativeCaptureReceipt>>>,
    }
    impl NativeCaptureSink for Sink {
        fn node_page(
            &self,
            _: &NativeCaptureScope,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<NativeCaptureNode>> {
            Ok(self
                .nodes
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect())
        }
        fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> Result<()> {
            receipt.revalidate()?;
            *self.receipt.lock().unwrap() = Some(receipt);
            Ok(())
        }
    }
    /// Source-only injected device authority fixture. Production is the bridge's
    /// actual MemoryVault/WorkspaceStore-verified implementation, not this type.
    /// No source test opens an OS vault, provider account, tool, or network.
    struct Authority {
        evidence: Arc<Value>,
        device_tag: blake3::Hash,
    }
    impl Authority {
        fn new(evidence: Value) -> Self {
            let device_tag = blake3::keyed_hash(&[73; 32], &serde_json::to_vec(&evidence).unwrap());
            Self {
                evidence: Arc::new(evidence),
                device_tag,
            }
        }
    }
    impl NativeOriginalCaptureAuthority for Authority {
        fn revalidate(&self) -> Result<()> {
            if blake3::keyed_hash(&[73; 32], &serde_json::to_vec(self.evidence.as_ref())?)
                != self.device_tag
            {
                return Err(StateError::Integrity(
                    "injected original device authority changed".into(),
                ));
            }
            Ok(())
        }
        fn original_evidence(&self) -> Result<Arc<Value>> {
            self.revalidate()?;
            Ok(self.evidence.clone())
        }
        fn verify_recovered(&self, evidence: &Value) -> Result<()> {
            if blake3::keyed_hash(&[73; 32], &serde_json::to_vec(evidence)?) != self.device_tag {
                return Err(StateError::Integrity(
                    "recovered evidence differs from original device authority".into(),
                ));
            }
            Ok(())
        }
    }
    struct Fixture {
        _temp: TemporaryRoot,
        agent: StateAgent,
        master: MasterKey,
        manifest: BundleManifest,
        selection: NativeSelection,
        sink: Arc<Sink>,
        authority: Arc<Authority>,
        app_path: PathBuf,
        operation: Uuid,
    }
    async fn fixture() -> Fixture {
        let temp = TemporaryRoot::new();
        let app_path = temp.0.join("synthetic-application");
        std::fs::create_dir(&app_path).unwrap();
        std::fs::write(app_path.join("save.bin"), b"original captured bytes").unwrap();
        let app = AppId("quicksave.synthetic.original-resume".into());
        let operation = Uuid::new_v4();
        let mut config = crate::AgentConfig::isolated(temp.0.join("native-agent"));
        config.native_host = true;
        config.converge_complete_backups = false;
        let instance = config.instance_id;
        let agent = StateAgent::boot(config).unwrap();
        let root_id = std::fs::metadata(&app_path).unwrap();
        agent
            .native_register(
                AppIdentity::new(app.clone(), "Synthetic application"),
                vec![ApprovedNativeRoot {
                    id: "save-root".into(),
                    path: app_path.clone(),
                    allowed_files: None,
                    expected_identity: Some((root_id.dev(), root_id.ino())),
                    role: NativeRootRole::Save,
                }],
            )
            .unwrap();
        let metadata = std::fs::metadata(app_path.join("save.bin")).unwrap();
        let logical = native_root_token(&app, "save-root");
        let node = NativeCaptureNode {
            id: native_file_id(&logical, "save.bin"),
            root_id: "save-root".into(),
            logical_root: logical,
            path: "save.bin".into(),
            kind: "file".into(),
            size: metadata.len(),
            stamp: NativeCaptureStamp::from_metadata(&metadata).unwrap(),
            link_target_hash: None,
        };
        let sink = Arc::new(Sink {
            nodes: vec![node],
            receipt: Mutex::new(None),
        });
        let scope = NativeCaptureScope {
            version: 1,
            work_id: Uuid::new_v4().to_string(),
            metadata_identity: "2".repeat(64),
            node_count: 1,
            full_scope: None,
        };
        let keys =
            super::super::install(&agent, operation, &app, scope.clone(), sink.clone()).unwrap();
        let selection = NativeSelection {
            version: 1,
            file_keys: Some(keys),
            roots_fingerprint: agent.native_binding_fingerprint(&app).unwrap(),
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(scope.metadata_identity.clone()),
            expected_files: None,
            capture_scope: Some(scope),
            coverage: NativeCoverage::SelectedNodes,
            software_instance_id: Some("synthetic-installation-one".into()),
        };
        agent.db.upsert_operation(&OperationRecord {
            operation_id:operation,kind:"backup".into(),app_id:Some(app.clone()),state:"QUEUED".into(),
            created_at:chrono::Utc::now(),updated_at:chrono::Utc::now(),last_error:None,
            detail_json:json!({"app_id":app,"mode":"custom","performance_mode":"automatic",
                "regenerable_caches":"include","native_selection":selection,"client_operation_id":operation}),
        }).unwrap();
        agent
            .native_set_publication_guard(operation, Arc::new(|| Ok(())))
            .unwrap();
        let master = MasterKey::generate();
        let provider = LocalStorage::new(temp.0.join("isolated-provider"));
        let captured = crate::backup::run_backup(
            &agent,
            &app,
            BackupMode::Custom,
            BackupPerformanceMode::Automatic,
            &provider,
            &master,
            Some(operation),
        )
        .await
        .unwrap();
        let manifest =
            noland_storage::read_committed_manifest(&provider, &master, &app, captured.bundle_id)
                .await
                .unwrap(); // Actual immutable COMMITTED + AEAD, not synthetic terminal JSON.
        let receipt = sink.receipt.lock().unwrap().take().unwrap();
        let authority = Arc::new(Authority::new(receipt.evidence().unwrap()));
        drop(receipt);
        let nodes = sink.nodes.clone();
        drop(sink);
        drop(agent);
        std::fs::write(
            app_path.join("save.bin"),
            b"newer local work must survive original resume",
        )
        .unwrap();
        std::fs::write(
            app_path.join("newer.bin"),
            b"not part of the original captured selection",
        )
        .unwrap();
        let mut config = crate::AgentConfig::isolated(temp.0.join("native-agent"));
        config.instance_id = instance;
        config.native_host = true;
        config.converge_complete_backups = false;
        let agent = StateAgent::boot(config).unwrap();
        agent.recover().unwrap();
        agent
            .native_register(
                AppIdentity::new(app, "Synthetic application"),
                vec![ApprovedNativeRoot {
                    id: "save-root".into(),
                    path: app_path.clone(),
                    allowed_files: None,
                    expected_identity: Some((root_id.dev(), root_id.ino())),
                    role: NativeRootRole::Save,
                }],
            )
            .unwrap();
        Fixture {
            _temp: temp,
            agent,
            master,
            manifest,
            selection,
            sink: Arc::new(Sink {
                nodes,
                receipt: Mutex::new(None),
            }),
            authority,
            app_path,
            operation,
        }
    }

    #[tokio::test]
    async fn actual_source_receipt_resumes_after_reboot_without_reading_newer_application_files() {
        let fixture = fixture().await;
        let receipt = reattach_original_capture(
            &fixture.agent,
            fixture.operation,
            &fixture.selection,
            &fixture.master,
            &fixture.manifest,
            fixture.sink.clone(),
            fixture.authority.clone(),
        )
        .unwrap();
        receipt.revalidate().unwrap();
        assert_eq!(receipt.evidence().unwrap(), *fixture.authority.evidence);
        assert_eq!(
            std::fs::read(fixture.app_path.join("save.bin")).unwrap(),
            b"newer local work must survive original resume"
        );
        assert!(fixture.app_path.join("newer.bin").exists());
        let counters = super::super::counters(&fixture.agent, fixture.operation)
            .unwrap()
            .unwrap();
        assert_eq!(counters.metadata_file_opens, 0);
        assert_eq!(counters.inventory_nodes, 0);
        assert_eq!(counters.source_proofs_recorded, 0);
        assert_eq!(counters.reused_file_proofs, 0);
        assert!(!fixture.agent.operations.is_running(fixture.operation));
    }

    #[tokio::test]
    async fn missing_original_proof_or_changed_original_manifest_never_recaptures() {
        let fixture = fixture().await;
        let mut changed = fixture.manifest.clone();
        changed.files[0].size += 1;
        assert!(reattach_original_capture(
            &fixture.agent,
            fixture.operation,
            &fixture.selection,
            &fixture.master,
            &changed,
            fixture.sink.clone(),
            fixture.authority.clone(),
        )
        .is_err());
        std::fs::remove_file(checkpoint(&fixture.agent, fixture.operation)).unwrap();
        assert!(reattach_original_capture(
            &fixture.agent,
            fixture.operation,
            &fixture.selection,
            &fixture.master,
            &fixture.manifest,
            fixture.sink.clone(),
            fixture.authority.clone(),
        )
        .is_err());
        assert!(!super::super::is_installed(
            &fixture.agent,
            fixture.operation
        ));
        assert!(!fixture.agent.operations.is_running(fixture.operation));
        assert!(fixture.sink.receipt.lock().unwrap().is_none());
    }
}
