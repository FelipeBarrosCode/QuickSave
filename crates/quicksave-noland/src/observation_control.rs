// SPDX-License-Identifier: GPL-3.0-only
// Derived API integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! Child of native.rs, never an RPC dispatcher. Parent adds the module and an
//! `observation: Mutex<EngineObservationState>` field initialized with Default.
//! Uses the actual source DB/native bindings; never starts a collector, probes
//! processes, walks source trees, hashes content, or calls rclone/preflight.

use super::{public_source_error, NativeEngine};
use anyhow::{anyhow, ensure, Context, Result};
use chrono::{DateTime, Utc};
use noland_state_agent::native_host::{native_file_id, native_root_token, NativeRootRole};
use noland_state_core::{
    score_evidence, AppId, AppSession, Evidence, EvidenceKind, FileStateRecord, FileStateTrust,
    FileType, GraphRelation, PathAssociation, PathRecord, SessionSource,
};
use quicksave_platform::{FileStamp, RootIdentity, SafeRoot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

const MAX_APPS: usize = 4096;
const MAX_PROOFS: usize = 8192;
const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_SINGLE_INDEX: usize = 250_000;
const MAX_REGISTERED_ROOTS: usize = 4096;
const MAX_REGISTRATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENT: usize = 16 * 1024 * 1024;
const PAGE: usize = 256;

/// Redacted native import phase. Backend bodies/paths remain private causes.
#[derive(Debug)]
pub struct NativeIndexImportFailure {
    stage: &'static str,
    cause: anyhow::Error,
}
impl NativeIndexImportFailure {
    pub fn stage(&self) -> &'static str {
        self.stage
    }
}
impl std::fmt::Display for NativeIndexImportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native metadata import failed at {}", self.stage)
    }
}
impl std::error::Error for NativeIndexImportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// Callback capability over an ACTUAL immutable Tracker metadata index.
/// Neither method may reenter NativeEngine. No renderer-provided nodes, scans,
/// predicted content hashes, provider sessions or successful default verifier.
pub trait NativeIndexOwner: Send + Sync + 'static {
    fn root_authority(&self, scope: &NativeIndexScope) -> Result<Value>;
    fn verify_current(&self, scope: &NativeIndexScope) -> Result<()>;
    /// Already-pinned external key/marker IDs, never a request to open secrets.
    fn protected_file_ids(&self) -> Result<Vec<(u64, [u64; 2])>>;
    fn node_page(
        &self,
        scope: &NativeIndexScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::capture_control::FrozenCaptureNode>>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeIndexScope {
    pub software_id: String,
    pub app_id: String,
    pub instance_id: String,
    pub revision_id: String,
    pub snapshot_identity: String,
    pub tracking_scope_hash: String,
    pub node_count: usize,
}

/// This state is per engine/workspace, never a global PID table. Full native
/// proofs are ephemeral private evidence, NOT durable/replayable root authority.
/// Source DB sessions/associations persist; after restart an unproved legacy
/// PID slot fails explicitly rather than borrowing its PID-only identity.
#[derive(Default)]
pub(crate) struct EngineObservationState {
    indices: BTreeMap<String, IndexRecord>,
    cursors: BTreeMap<(String, Uuid), Cursor>,
    last_observer: BTreeMap<String, Uuid>,
    proofs: BTreeMap<Uuid, NativeObservationRecord>,
    proof_keys: BTreeMap<(String, Uuid, String), Uuid>,
    proof_bytes: usize,
}

struct IndexRecord {
    scope: NativeIndexScope,
    owner: Option<Arc<dyn NativeIndexOwner>>,
    registration: Arc<ApprovedRecord>,
    imported: usize,
    finished: bool,
}

struct Cursor {
    observer: Uuid,
    epoch: u64,
    page: u32,
    finished: bool,
}

/// The original source schema has no portable full-generation column. Keep
/// every native start/namespace/image field here, and in use evidence, rather
/// than compressing it into an invented u64 starttime or fake Linux FsEvent.
struct NativeObservationRecord {
    software: String,
    observer: Uuid,
    token: String,
    source_session: Uuid,
    proof: NativeProof,
    currently_observed: bool,
    end_reason: Option<String>,
    encoded_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    pid: u32,
    uid: u32,
    start: [u64; 2],
    namespace: [u64; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeProof {
    scope_fingerprint: String,
    generation: Generation,
    executable: PathBuf,
    executable_stamp: FileStamp,
    image_binding: String,
    bundle_identifier: Option<String>,
    app_id: String,
    registered_identity: bool,
    observed_at_ms: u64,
    source: String,
}
impl NativeProof {
    fn same_execution(&self, other: &Self) -> bool {
        self.scope_fingerprint == other.scope_fingerprint
            && self.generation == other.generation
            && self.executable == other.executable
            && self.executable_stamp == other.executable_stamp
            && self.image_binding == other.image_binding
            && self.bundle_identifier == other.bundle_identifier
            && self.app_id == other.app_id
            && self.registered_identity == other.registered_identity
            && self.source == other.source
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessSample {
    id: String,
    proof: NativeProof,
    current: bool,
    ended: bool,
    native_reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileSample {
    process: NativeProof,
    root_id: String,
    relative_path: String,
    stamp: FileStamp,
    descriptor: u64,
    confidence: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Frame {
    version: u32,
    observer_id: Uuid,
    epoch: u64,
    page: u32,
    final_page: bool,
    observed_at_ms: u64,
    scope_fingerprint: Option<String>,
    source: Value,
    processes: Vec<ProcessSample>,
    files: Vec<FileSample>,
    gaps: Vec<Value>,
    protected_native_files: Vec<NativeId>,
    completeness: String,
    clean: bool,
    application_atomic: bool,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativeId {
    device: u64,
    file_id: [u64; 2],
}
impl From<&FileStamp> for NativeId {
    fn from(stamp: &FileStamp) -> Self {
        Self {
            device: stamp.device,
            file_id: stamp.file_id,
        }
    }
}

struct Root {
    id: String,
    path: PathBuf,
    identity: RootIdentity,
    allowed: Option<BTreeSet<String>>,
    role: NativeRootRole,
    pin: SafeRoot,
}

struct ApprovedRecord {
    software: String,
    instance: String,
    app: AppId,
    source_identity: Value,
    scope_hash: String,
    native_fingerprint: String,
    roots: BTreeMap<String, Root>,
    exclusions: Vec<PathBuf>,
    // Only an explicitly verified register/materialize admission can mint this
    // per-instance proof. It never changes the source's capture root registry.
    registration: Option<Arc<ApprovedRecord>>,
}

impl NativeEngine {
    /// Release only our transient frozen read lease before explicit reimport.
    /// Keeps all source rows, history, pinned registration evidence, sessions and
    /// capture bindings; no data or saved generation is deleted or retired.
    pub fn native_release_index_owner(&self, software: &str) -> Result<()> {
        validate_id(software)?;
        let mut state = self
            .observation
            .try_lock()
            .map_err(|_| anyhow!("native source index owner is busy or poisoned"))?;
        if let Some(index) = state.indices.get_mut(software) {
            index.owner.take();
            index.finished = false;
        }
        Ok(())
    }

    /// Shared, bounded MAC scope constructor for the service's native signer.
    /// It does not issue a grant or mutate the source graph.
    pub fn native_observation_scope(
        record: &Value,
        authority: &Value,
        observation: &Value,
    ) -> Result<Value> {
        bounded(record, MAX_EVENT)?;
        bounded(authority, MAX_EVENT)?;
        bounded(observation, MAX_EVENT)?;
        Ok(json!({
            "version":1, "softwareId":text(&record["id"])?,
            "appId":text(&record["appId"])?, "sourceAppId":text(&record["sourceIdentity"]["app_id"])?,
            "trackingScopeHash":digest(&authority["scope"])?,
            "recordHash":digest(record)?, "observationHash":digest(observation)?,
        }))
    }

    /// Signed native evidence only, not exposed through generic IPC/RPC. The
    /// bound WorkspaceStore rechecks the MAC, current policy and tracking grants
    /// before any DB mutation. Every result remains dirty/VerifyRequired.
    pub fn native_observe_application(&self, event: Value) -> Result<Value> {
        bounded(&event, MAX_EVENT)?;
        let _submission = self
            .submission
            .try_lock()
            .context("native source graph admission is busy")?;
        let store = self
            .workspace
            .as_ref()
            .context("native source observation requires a bound workspace")?;
        let expected = Self::native_observation_scope(
            &event["record"],
            &event["rootAuthority"],
            &event["observation"],
        )?;
        ensure!(
            event["scope"] == expected
                && store.verify_grant("source_native_observation", &expected, &event["grant"])?,
            "native source observation signature is invalid or revoked"
        );
        let registration = {
            let state = self
                .observation
                .try_lock()
                .map_err(|_| anyhow!("native registration proof state is busy or poisoned"))?;
            event["record"]["id"]
                .as_str()
                .and_then(|id| state.indices.get(id))
                .map(|index| index.registration.clone())
        };
        let approved = ApprovedRecord::verify_with_registration(
            self,
            &event["record"],
            &event["rootAuthority"],
            registration,
        )?;
        let frame: Frame = serde_json::from_value(event["observation"].clone())
            .context("native source observation shape is invalid")?;
        approved.validate_frame(&frame)?;
        let mut state = self
            .observation
            .try_lock()
            .map_err(|_| anyhow!("native source observation state is busy or poisoned"))?;
        check_cursor(&state, &approved.software, &frame)?;
        if let Some(index) = state.indices.get_mut(&approved.software) {
            if event["record"]["bundleIndexSource"]["revisionId"] != index.scope.revision_id {
                index.finished = false;
            }
        }
        let new_count = frame
            .processes
            .iter()
            .filter(|sample| {
                sample.current
                    && !state.proof_keys.contains_key(&(
                        approved.software.clone(),
                        frame.observer_id,
                        sample.id.clone(),
                    ))
            })
            .count();
        ensure!(
            state.proofs.len().saturating_add(new_count) <= MAX_PROOFS
                && (state.cursors.len() < MAX_PROOFS
                    || state
                        .cursors
                        .contains_key(&(approved.software.clone(), frame.observer_id)))
                && (state.last_observer.len() < MAX_APPS
                    || state.last_observer.contains_key(&approved.software)),
            "native source proof/session retention bound reached"
        );
        let projected_bytes =
            frame
                .processes
                .iter()
                .try_fold(state.proof_bytes, |sum, sample| {
                    let key = (
                        approved.software.clone(),
                        frame.observer_id,
                        sample.id.clone(),
                    );
                    let old = state
                        .proof_keys
                        .get(&key)
                        .and_then(|id| state.proofs.get(id));
                    if old.is_none() && !sample.current {
                        return Ok(sum);
                    }
                    sum.checked_sub(old.map_or(0, |proof| proof.encoded_bytes))
                        .and_then(|sum| {
                            sum.checked_add(serde_json::to_vec(&sample.proof).ok()?.len())
                        })
                        .context("native proof size overflow")
                })?;
        ensure!(
            projected_bytes <= MAX_PROOF_BYTES,
            "native full-generation proof memory limit reached"
        );
        // Invalidate before partial writes as well. Never clear this obligation
        // because processes/files were absent or because a poll was incomplete.
        ApprovedRecord::verify_with_registration(
            self,
            &event["record"],
            &event["rootAuthority"],
            approved.registration.clone(),
        )?;
        self.agent
            .db
            .mark_dirty(&approved.app, None, true)
            .map_err(public_source_error)?;
        let now = Utc::now();
        for sample in &frame.processes {
            apply_process(self, &mut state, &approved, &frame, sample, now)?;
        }
        ensure!(
            state.proof_bytes == projected_bytes,
            "native proof memory accounting changed"
        );
        let mut current = BTreeMap::new();
        for sample in frame.processes.iter().filter(|sample| sample.current) {
            let id = state
                .proof_keys
                .get(&(
                    approved.software.clone(),
                    frame.observer_id,
                    sample.id.clone(),
                ))
                .context("native source session admission lost its full-generation key")?;
            current.insert(sample.proof.generation.pid, *id);
        }
        let mut grouped: BTreeMap<(&str, &str), BTreeMap<Uuid, &FileSample>> = BTreeMap::new();
        for file in &frame.files {
            let id = current
                .get(&file.process.generation.pid)
                .context("native open file lacks this exact proven source session")?;
            let source_record = &state.proofs[id];
            ensure!(
                source_record.proof.same_execution(&file.process),
                "native source open file generation changed"
            );
            let source_session = source_record.source_session;
            grouped
                .entry((&file.root_id, &file.relative_path))
                .or_default()
                .entry(source_session)
                .or_insert(file);
        }
        let mut entries = Vec::with_capacity(grouped.len());
        let mut states = Vec::with_capacity(grouped.len());
        for ((root_id, path), uses) in grouped {
            ensure!(
                uses.len() <= 16,
                "native file use exceeds bounded per-path session evidence"
            );
            let first = *uses
                .values()
                .next()
                .context("native file use group is empty")?;
            ensure!(
                uses.values().all(|file| file.stamp == first.stamp),
                "native sampled file has conflicting event-time stamps"
            );
            let root = &approved.roots[root_id];
            // This exact token was checked against source root layouts at
            // explicit registration. Current capture bindings may belong to a
            // different installation of the same canonical product; graph use
            // does not switch, union or borrow those capture bindings.
            approved.permit(root, path)?;
            let details = uses.into_iter().map(|(source_session,file)| (source_session, json!({
                "kind":"NativeProcessFileUse","relation":GraphRelation::AppUsesPath.as_str(),
                "operation":"open_fd_observed_not_a_witnessed_read_or_write","softwareInstanceId":approved.instance,
                "sourceSessionId":source_session,"nativeProof":file,
                "completeness":"unknown","ownershipGranted":false}))).collect();
            entries.push(make_entry(
                self,
                &approved,
                root,
                path,
                "file",
                first.stamp.size,
                &first.stamp,
                now,
                details,
            )?);
            states.push(make_state(
                &approved,
                root,
                path,
                "file",
                first.stamp.size,
                &first.stamp,
                now,
            )?);
        }
        approved.check_native(self)?;
        // Recheck after native callback/metadata work and before publishing rows.
        ensure!(
            store.verify_grant("source_native_observation", &expected, &event["grant"])?,
            "native graph observation was revoked before DB publication"
        );
        ApprovedRecord::verify_with_registration(
            self,
            &event["record"],
            &event["rootAuthority"],
            approved.registration.clone(),
        )?;
        self.agent
            .db
            .upsert_scanned_paths(&entries)
            .map_err(public_source_error)?;
        self.agent
            .db
            .reconcile_file_states(&states, false)
            .map_err(public_source_error)?;
        verify_written(self, &approved.app, &entries)?;
        state
            .last_observer
            .insert(approved.software.clone(), frame.observer_id);
        state.cursors.insert(
            (approved.software.clone(), frame.observer_id),
            Cursor {
                observer: frame.observer_id,
                epoch: frame.epoch,
                page: frame.page,
                finished: frame.final_page,
            },
        );
        Ok(
            json!({"softwareId":approved.software,"appId":approved.app.as_str(),
            "softwareInstanceId":approved.instance,"sourceSessions":frame.processes.iter().filter(|p|p.current).count(),
            "nativeFileAssociations":entries.len(),"nativeFileUseFacts":frame.files.len(),"dirty":true,"requiresReconciliation":true,
            "fileStateTrust":"VERIFY_REQUIRED","coverageTrusted":false,"complete":false,"cloudWrite":false}),
        )
    }

    /// Explicit materialization only, never status/worker polling. The parent
    /// first calls register(actual_bundle_record) even without a provider. This
    /// consumes the actual immutable index owner, not a list of guessed files.
    pub fn native_materialize_index(
        &self,
        record: Value,
        owner: Arc<dyn NativeIndexOwner>,
    ) -> Result<Value> {
        let mut stage = "source_import_admission";
        self.materialize_index_inner(record, owner, &mut stage)
            .map_err(|cause| NativeIndexImportFailure { stage, cause }.into())
    }

    fn materialize_index_inner(
        &self,
        record: Value,
        owner: Arc<dyn NativeIndexOwner>,
        stage: &mut &'static str,
    ) -> Result<Value> {
        bounded(&record, MAX_EVENT)?;
        let _submission = self
            .submission
            .try_lock()
            .context("native source index admission is busy")?;
        let mut scope = index_scope(&record)?;
        *stage = "source_import_verify_owner_authority";
        let authority = owner.root_authority(&scope)?;
        let approved = Arc::new(ApprovedRecord::verify_with_registration_staged(
            self, &record, &authority, None, stage,
        )?);
        scope.tracking_scope_hash = approved.scope_hash.clone();
        *stage = "source_import_recheck_owner_authority";
        owner.verify_current(&scope)?;
        let protected = owner.protected_file_ids()?;
        *stage = "source_import_reserve_index_capacity";
        ensure!(
            protected.len() <= 256,
            "native frozen index protection bound exceeded"
        );
        let mut state = self
            .observation
            .try_lock()
            .map_err(|_| anyhow!("native source index state is busy or poisoned"))?;
        ensure!(
            state.indices.len() < MAX_APPS || state.indices.contains_key(&scope.software_id),
            "native source index app limit reached"
        );
        let other_nodes: usize = state
            .indices
            .iter()
            .filter(|(id, _)| *id != &scope.software_id)
            .map(|(_, index)| index.scope.node_count)
            .sum();
        ensure!(
            other_nodes.saturating_add(scope.node_count) <= MAX_NODES,
            "native source index node limit reached"
        );
        let mut retained_roots = approved.roots.len();
        let mut retained_bytes = approved.registration_bytes()?;
        for (id, index) in &state.indices {
            if id == &scope.software_id {
                continue;
            }
            retained_roots = retained_roots
                .checked_add(index.registration.roots.len())
                .context("native registration root count overflow")?;
            retained_bytes = retained_bytes
                .checked_add(index.registration.registration_bytes()?)
                .context("native registration memory count overflow")?;
        }
        ensure!(
            retained_roots <= MAX_REGISTERED_ROOTS && retained_bytes <= MAX_REGISTRATION_BYTES,
            "native source per-instance root-handle/metadata retention limit reached"
        );
        *stage = "source_import_mark_dirty";
        self.agent
            .db
            .mark_dirty(&approved.app, None, true)
            .map_err(public_source_error)?;
        state.indices.insert(
            scope.software_id.clone(),
            IndexRecord {
                scope: scope.clone(),
                owner: Some(owner.clone()),
                registration: approved.clone(),
                imported: 0,
                finished: false,
            },
        );
        let mut seen = BTreeSet::new();
        let mut path_bytes = 0usize;
        let now = Utc::now();
        let mut offset = 0usize;
        while offset < scope.node_count {
            *stage = "source_import_revalidate_owner";
            owner.verify_current(&scope)?;
            approved.check_native(self)?;
            *stage = "source_import_read_frozen_page";
            let nodes = owner.node_page(&scope, offset, PAGE)?;
            ensure!(
                !nodes.is_empty()
                    && nodes.len() <= PAGE
                    && nodes.len() <= scope.node_count - offset,
                "native frozen index page count changed"
            );
            let mut entries = Vec::with_capacity(nodes.len());
            let mut states = Vec::with_capacity(nodes.len());
            for node in &nodes {
                *stage = "source_import_validate_node";
                ensure!(
                    node.id.len() <= 512
                        && node.logical_root.len() <= 4096
                        && node
                            .link_target_hash
                            .as_ref()
                            .is_none_or(|hash| hash.len() <= 128),
                    "native index node exceeds metadata field bounds"
                );
                let root = approved
                    .roots
                    .get(&node.root_id)
                    .context("native index root is not registered for this bundle")?;
                approved.permit(root, &node.path)?;
                let logical = native_root_token(&approved.app, &root.id);
                ensure!(
                    node.logical_root.is_empty() || node.logical_root == logical,
                    "native index logical root changed"
                );
                ensure!(
                    node.id == native_file_id(&logical, &node.path)
                        && seen.insert((node.root_id.clone(), node.path.clone())),
                    "native index file ID is changed or duplicated"
                );
                path_bytes = path_bytes
                    .checked_add(node.path.len())
                    .context("native index path budget overflow")?;
                ensure!(
                    path_bytes <= MAX_PATH_BYTES,
                    "native source index path memory limit reached"
                );
                let stamp: FileStamp = serde_json::from_value(serde_json::to_value(&node.stamp)?)?;
                ensure!(
                    !protected.contains(&(stamp.device, stamp.file_id)),
                    "native frozen index includes a protected marker/key alias"
                );
                *stage = "source_import_project_path";
                entries.push(make_entry(
                    self,
                    &approved,
                    root,
                    &node.path,
                    &node.kind,
                    node.size,
                    &stamp,
                    now,
                    vec![],
                )?);
                *stage = "source_import_project_file_state";
                states.push(make_state(
                    &approved, root, &node.path, &node.kind, node.size, &stamp, now,
                )?);
            }
            *stage = "source_import_verify_before_write";
            owner.verify_current(&scope)?;
            ApprovedRecord::verify(self, &record, &owner.root_authority(&scope)?)?;
            *stage = "source_import_write_paths";
            self.agent
                .db
                .upsert_scanned_paths(&entries)
                .map_err(public_source_error)?;
            *stage = "source_import_write_file_states";
            self.agent
                .db
                .reconcile_file_states(&states, false)
                .map_err(public_source_error)?;
            *stage = "source_import_verify_written_paths";
            verify_written(self, &approved.app, &entries)?;
            offset += nodes.len();
            state.indices.get_mut(&scope.software_id).unwrap().imported = offset;
        }
        *stage = "source_import_verify_terminal_page";
        ensure!(
            owner.node_page(&scope, offset, 1)?.is_empty(),
            "native frozen index has undeclared trailing nodes"
        );
        *stage = "source_import_verify_final_authority";
        owner.verify_current(&scope)?;
        approved.check_native(self)?;
        ApprovedRecord::verify(self, &record, &owner.root_authority(&scope)?)?;
        self.agent
            .db
            .mark_dirty(&approved.app, None, true)
            .map_err(public_source_error)?;
        state.indices.get_mut(&scope.software_id).unwrap().finished = true;
        Ok(
            json!({"softwareId":scope.software_id,"sourceAppId":scope.app_id,
            "softwareInstanceId":scope.instance_id,"revisionId":scope.revision_id,
            "sourceIndexedNodes":offset,"sourceIndexMaterialized":true,"rootsOnly":false,
            "metadataOnly":true,"fileStateTrust":"VERIFY_REQUIRED",
            "coverageTrusted":false,"complete":false,"saved":false,"cloudWrite":false}),
        )
    }

    /// Cached diagnostics only. No source walk, hash, process probe, vault or DB
    /// association enumeration. A roots-only registration is never "indexed".
    pub fn native_observation_status(&self, software: &str) -> Result<Value> {
        validate_id(software)?;
        let state = self
            .observation
            .try_lock()
            .map_err(|_| anyhow!("native observation status is busy or poisoned"))?;
        let index = state.indices.get(software);
        Ok(json!({"softwareId":software,
            "sourceIndexMaterialized":index.is_some_and(|index|index.finished),
            "sourceIndexedNodes":index.map_or(0,|index|index.imported),
            "sourceIndexRevision":index.map(|index|index.scope.revision_id.as_str()),
            "rootsOnly":index.is_none(),"privateNativeProofs":state.proofs.values().filter(|proof|proof.software==software).count(),
            "proofPersistence":"ephemeral_full_native_generation_no_pid_only_replay",
            "nativeUseHistoryPerPath":16,"nativeProofLimit":MAX_PROOFS,"nativeProofByteLimit":MAX_PROOF_BYTES,
            "coverageTrusted":false,"complete":false,"saved":false}))
    }
}

impl ApprovedRecord {
    fn registration_bytes(&self) -> Result<usize> {
        let mut bytes = serde_json::to_vec(&self.source_identity)?.len();
        for root in self.roots.values() {
            bytes = bytes
                .checked_add(root.id.len())
                .and_then(|bytes| bytes.checked_add(root.path.as_os_str().len()))
                .context("native root metadata size overflow")?;
            for leaf in root.allowed.iter().flatten() {
                bytes = bytes
                    .checked_add(leaf.len())
                    .context("native leaf metadata size overflow")?;
            }
        }
        for exclusion in &self.exclusions {
            bytes = bytes
                .checked_add(exclusion.as_os_str().len())
                .context("native exclusion metadata size overflow")?;
        }
        Ok(bytes)
    }

    fn verify(engine: &NativeEngine, record: &Value, authority: &Value) -> Result<Self> {
        Self::verify_with_registration(engine, record, authority, None)
    }

    fn verify_with_registration(
        engine: &NativeEngine,
        record: &Value,
        authority: &Value,
        registration: Option<Arc<ApprovedRecord>>,
    ) -> Result<Self> {
        Self::verify_with_registration_staged(
            engine,
            record,
            authority,
            registration,
            &mut "source_authority_admission",
        )
    }

    fn verify_with_registration_staged(
        engine: &NativeEngine,
        record: &Value,
        authority: &Value,
        registration: Option<Arc<ApprovedRecord>>,
        stage: &mut &'static str,
    ) -> Result<Self> {
        *stage = "source_import_verify_record_identity";
        bounded(record, MAX_EVENT)?;
        bounded(authority, MAX_EVENT)?;
        let store = engine
            .workspace
            .as_ref()
            .context("native source graph has no bound workspace")?;
        let software = text(&record["id"])?;
        let instance = text(&record["appId"])?;
        let source_identity = record["sourceIdentity"].clone();
        let canonical = text(&source_identity["app_id"])?;
        if let Some(id) = source_identity["steam_app_id"].as_u64() {
            ensure!(
                id > 0 && id <= u32::MAX as u64 && canonical == format!("steam:{id}"),
                "source canonical Steam identity changed"
            );
        }
        if let Some(id) = source_identity["desktop_entry_id"].as_str() {
            ensure!(
                canonical == format!("desktop:{id}"),
                "source desktop identity case changed"
            );
        }
        ensure!(
            !canonical.starts_with("quicksave.observed:") && record["tracked"] == true,
            "unconfirmed native identities cannot become source app ownership"
        );
        let app = AppId(canonical);
        {
            let software_bindings = engine
                .software
                .lock()
                .map_err(|_| anyhow!("native software binding lock poisoned"))?;
            let binding = software_bindings
                .get(&software)
                .context("register the actual bundle before source graph materialization")?;
            ensure!(
                binding.app == app && binding.instance == instance,
                "native source canonical/instance mapping changed"
            );
        }
        let scope = &authority["scope"];
        *stage = "source_import_verify_tracking_mac";
        ensure!(
            scope["version"] == 1
                && scope["softwareId"] == software
                && scope["appId"] == instance
                && scope["sourceIdentity"] == source_identity
                && authority["softwareId"] == software
                && authority["appId"] == instance
                && authority["sourceIdentity"] == source_identity
                && record["trackingGrant"] == authority["grant"]
                && store.verify_grant("tracking", scope, &authority["grant"])?,
            "source graph tracking MAC or identity is invalid"
        );
        let enrollment = &record["autoEnrollment"];
        *stage = "source_import_verify_discovery_policy";
        let policy = &enrollment["policyScope"];
        let policy_grant = &enrollment["policyGrant"];
        let current = store
            .app_tracking_policy()?
            .context("source observation policy is absent or revoked")?;
        ensure!(
            current["policyScope"] == *policy
                && current["policyGrant"] == *policy_grant
                && policy["enabled"] == true
                && store.verify_grant("app_tracking_policy", policy, policy_grant)?
                && store.verify_grant(
                    "bundle_discovery",
                    &enrollment["discoveryScope"],
                    &enrollment["discoveryGrant"]
                )?
                && enrollment["discoveryScope"]["policyHash"] == digest(policy)?
                && scope["autoEnrollment"]["policyHash"] == digest(policy)?
                && scope["autoEnrollment"]["discoveryHash"]
                    == digest(&enrollment["discoveryScope"])?,
            "source graph discovery/current native policy admission failed"
        );
        let scope_hash = digest(scope)?;
        *stage = "source_import_verify_index_scope_hash";
        let index = &record["bundleIndexSource"];
        ensure!(
            index["version"] == 1 && index["trackingScopeHash"] == scope_hash,
            "source graph requires a real authenticated materialized index"
        );
        for kind in ["index", "manifest"] {
            *stage = if kind == "index" {
                "source_import_verify_index_sidecar_mac"
            } else {
                "source_import_verify_manifest_sidecar_mac"
            };
            let part = &index[kind];
            let name = text(&part["name"])?;
            ensure!(
                !name.contains(['/', '\\']),
                "unsafe native index sidecar reference"
            );
            let signed = json!({"version":1,"tracking":scope,"revisionId":index["revisionId"],
                "snapshotIdentity":index["snapshotIdentity"],"kind":kind,"name":name,"hash":part["hash"]});
            ensure!(
                store.verify_grant(&format!("bundle_{kind}"), &signed, &part["grant"])?,
                "source graph materialized sidecar MAC is invalid or revoked"
            );
        }
        let input = record["roots"]
            .as_array()
            .context("source graph roots missing")?;
        *stage = "source_import_verify_exact_roots";
        let signed = scope["roots"]
            .as_array()
            .context("signed source graph roots missing")?;
        ensure!(
            !input.is_empty() && input.len() <= 48 && input.len() == signed.len(),
            "invalid exact native root count"
        );
        let mut roots = BTreeMap::new();
        let mut leaves = 0usize;
        for value in input {
            let id = text(&value["id"])?;
            let signed_root = signed
                .iter()
                .find(|root| root["id"] == id)
                .context("source graph root is not signed")?;
            for key in ["id", "path", "role", "identity", "allowedFiles"] {
                ensure!(
                    value[key] == signed_root[key],
                    "source graph root/selection widened"
                );
            }
            let path = absolute(&value["path"])?;
            let role =
                NativeRootRole::parse(value["role"].as_str().context("native root role missing")?)
                    .map_err(public_source_error)?;
            let identity: RootIdentity = serde_json::from_value(value["identity"].clone())?;
            let allowed = match value.get("allowedFiles").filter(|value| !value.is_null()) {
                None => None,
                Some(value) => {
                    let array = value
                        .as_array()
                        .context("native selected leaves malformed")?;
                    ensure!(
                        !array.is_empty() && array.len() <= 4096,
                        "native selected leaf limit"
                    );
                    leaves = leaves
                        .checked_add(array.len())
                        .context("native selected leaf overflow")?;
                    ensure!(leaves <= 16384, "native selected leaf global limit");
                    let mut set = BTreeSet::new();
                    for leaf in array {
                        let leaf = leaf.as_str().context("native selected leaf missing")?;
                        relative(leaf)?;
                        ensure!(
                            !leaf.contains('/') && set.insert(leaf.to_owned()),
                            "native selected leaf widened or duplicated"
                        );
                    }
                    Some(set)
                }
            };
            let pin = SafeRoot::open(&path)?;
            ensure!(
                pin.identity()? == identity,
                "native root changed before source graph admission"
            );
            ensure!(
                roots
                    .insert(
                        id.clone(),
                        Root {
                            id,
                            path,
                            identity,
                            allowed,
                            role,
                            pin
                        }
                    )
                    .is_none(),
                "duplicate source root ID"
            );
        }
        let mut exclusions = engine.agent.config.capture_exclusions.clone();
        for path in policy["excludedPaths"]
            .as_array()
            .context("native policy exclusions missing")?
        {
            exclusions.push(absolute(path)?);
        }
        ensure!(exclusions.len() <= 256, "native source exclusion limit");
        let native_fingerprint = if let Some(registered) = &registration {
            ensure!(
                registered.registration.is_none()
                    && registered.software == software
                    && registered.instance == instance
                    && registered.app == app
                    && registered.scope_hash == scope_hash,
                "this native instance needs a fresh explicit registered index admission"
            );
            registered.native_fingerprint.clone()
        } else {
            engine
                .agent
                .native_binding_fingerprint(&app)
                .map_err(public_source_error)?
        };
        let approved = Self {
            software,
            instance,
            app,
            source_identity,
            scope_hash,
            native_fingerprint,
            roots,
            exclusions,
            registration,
        };
        approved.check_native(engine)?;
        Ok(approved)
    }

    fn check_native(&self, engine: &NativeEngine) -> Result<()> {
        if let Some(registered) = &self.registration {
            // Do NOT waive native identity or consult historical DB roots.
            // These live handles were retained while this exact record matched
            // actual source-native registration/layout/role/file selections.
            ensure!(
                registered.registration.is_none()
                    && registered.software == self.software
                    && registered.instance == self.instance
                    && registered.app == self.app
                    && registered.scope_hash == self.scope_hash
                    && registered.native_fingerprint == self.native_fingerprint
                    && registered.roots.len() == self.roots.len(),
                "native instance registration evidence changed"
            );
            for (id, root) in &self.roots {
                let original = registered
                    .roots
                    .get(id)
                    .context("native instance root was not registered")?;
                ensure!(
                    root.path == original.path
                        && root.identity == original.identity
                        && root.allowed == original.allowed
                        && root.role == original.role
                        && root.pin.identity()? == root.identity
                        && original.pin.identity()? == original.identity,
                    "native instance root handle, role, identity or exact selection changed"
                );
            }
            return Ok(());
        }
        ensure!(
            engine
                .agent
                .native_binding_fingerprint(&self.app)
                .map_err(public_source_error)?
                == self.native_fingerprint,
            "native source root bindings changed"
        );
        let layouts = engine
            .agent
            .native_root_layouts(&self.app, &self.instance)
            .map_err(public_source_error)?;
        let layouts = layouts["roots"]
            .as_array()
            .context("native source root layout missing")?;
        ensure!(
            layouts.len() == self.roots.len(),
            "source registered a different root set/installation instance"
        );
        for root in self.roots.values() {
            ensure!(
                root.pin.identity()? == root.identity,
                "source graph root identity changed"
            );
            ensure!(
                layouts.iter().any(|layout| layout["root_id"] == root.id
                    && layout["logical_root"] == native_root_token(&self.app, &root.id)
                    && layout["role"] == root.role.as_str()),
                "source registered a different root/role"
            );
        }
        let actual = engine
            .agent
            .native_approved_roots(&self.app)
            .map_err(public_source_error)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = self
            .roots
            .values()
            .flat_map(|root| match &root.allowed {
                Some(leaves) => leaves
                    .iter()
                    .map(|leaf| root.path.join(leaf))
                    .collect::<Vec<_>>(),
                None => vec![root.path.clone()],
            })
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "native source path/file selection does not match this actual instance"
        );
        Ok(())
    }

    fn permit(&self, root: &Root, path: &str) -> Result<()> {
        relative(path)?;
        let absolute = root.path.join(path);
        ensure!(
            root.allowed
                .as_ref()
                .is_none_or(|leaves| leaves.contains(path))
                && !self
                    .exclusions
                    .iter()
                    .any(|excluded| absolute.starts_with(excluded)),
            "source native evidence is outside selected files or is protected"
        );
        Ok(())
    }

    fn validate_proof(&self, proof: &NativeProof, frame: &Frame) -> Result<()> {
        ensure!(
            proof.registered_identity
                && proof.app_id == self.instance
                && proof.image_binding == "mapped_image_native_file"
                && matches!(
                    proof.source.as_str(),
                    "mac_libproc" | "linux_procfs" | "injected_fixture"
                )
                && proof.generation.pid > 0
                && proof.generation.pid <= i32::MAX as u32
                && proof.observed_at_ms <= frame.observed_at_ms
                && frame.scope_fingerprint.as_deref() == Some(proof.scope_fingerprint.as_str())
                && proof.scope_fingerprint.len() == 64
                && proof
                    .scope_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "native source process generation/image binding is unconfirmed or unrepresentable"
        );
        ensure!(
            self.source_identity["canonical_executable"]
                .as_str()
                .is_some_and(|path| Path::new(path) == proof.executable),
            "native source process executable differs from canonical source identity"
        );
        if let Some(identifier) = self.app.as_str().strip_prefix("mac-bundle:") {
            ensure!(
                proof.bundle_identifier.as_deref() == Some(identifier),
                "native source bundle identifier is not verified"
            );
        }
        let root = self
            .roots
            .values()
            .find(|root| {
                matches!(
                    root.role,
                    NativeRootRole::Installation | NativeRootRole::Runtime
                ) && proof
                    .executable
                    .strip_prefix(&root.path)
                    .ok()
                    .and_then(Path::to_str)
                    .is_some_and(|relative| {
                        root.allowed
                            .as_ref()
                            .is_none_or(|leaves| leaves.contains(relative))
                    })
            })
            .context(
                "native source executable has no exact approved runtime/installation selection",
            )?;
        let relative = proof
            .executable
            .strip_prefix(&root.path)?
            .to_str()
            .context("native executable is not UTF-8")?;
        self.permit(root, relative)?;
        let (_, stamp) = root.pin.read_file(relative)?;
        ensure!(
            stamp == proof.executable_stamp,
            "native source executable stamp changed"
        );
        Ok(())
    }

    fn validate_frame(&self, frame: &Frame) -> Result<()> {
        ensure!(
            frame.version == 1
                && frame.epoch > 0
                && frame.processes.len() <= 4096
                && frame.files.len() <= PAGE
                && frame.gaps.len() <= 128
                && frame.protected_native_files.len() <= 256
                && frame.completeness == "unknown"
                && !frame.clean
                && !frame.application_atomic,
            "native source frame exceeds bounds or claims completeness"
        );
        ensure!(
            frame.source["complete_file_stream"] == false
                && frame.source["complete_lifecycle_stream"] == false
                && (frame.processes.is_empty()
                    || frame.source["running_image_native_identity"] == true)
                && (frame.files.is_empty() || frame.source["native_open_file_identity"] == true),
            "native source frame overstates its actual polling capability"
        );
        let mut tokens = BTreeSet::new();
        let mut current_pids = BTreeSet::new();
        let mut current_proofs = BTreeMap::new();
        for sample in &frame.processes {
            validate_id(&sample.id)?;
            ensure!(
                tokens.insert(&sample.id)
                    && sample.native_reason.len() <= 128
                    && !(sample.ended && sample.current),
                "native source session token/reason is invalid"
            );
            self.validate_proof(&sample.proof, frame)?;
            ensure!(
                !sample.current
                    || (current_pids.insert(sample.proof.generation.pid)
                        && sample.proof.observed_at_ms == frame.observed_at_ms),
                "native source current session generation is duplicated or stale"
            );
            if sample.current {
                current_proofs.insert(sample.proof.generation.pid, &sample.proof);
            }
            ensure!(
                frame.source["source"] == sample.proof.source,
                "native process proof source differs from its actual adapter"
            );
            ensure!(
                !frame
                    .protected_native_files
                    .contains(&NativeId::from(&sample.proof.executable_stamp)),
                "native source executable is a protected identity"
            );
        }
        for file in &frame.files {
            let root = self
                .roots
                .get(&file.root_id)
                .context("native observed file root is not owned by this actual bundle")?;
            self.permit(root, &file.relative_path)?;
            ensure!(
                file.confidence == "native_identity_matched_use"
                    && !frame
                        .protected_native_files
                        .contains(&NativeId::from(&file.stamp))
                    && current_proofs
                        .get(&file.process.generation.pid)
                        .is_some_and(|proof| proof.same_execution(&file.process)),
                "native file use lacks a matching full generation or is protected"
            );
            ensure!(
                file.process.observed_at_ms == frame.observed_at_ms,
                "native file proof is not frozen in this observation batch"
            );
            check_stamp(&file.stamp)?;
        }
        for gap in &frame.gaps {
            ensure!(
                gap["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty() && reason.len() <= 128)
                    && (gap["root_id"].is_null()
                        || gap["root_id"]
                            .as_str()
                            .is_some_and(|id| self.roots.contains_key(id))),
                "native source gap is outside the approved root set"
            );
        }
        Ok(())
    }
}

fn apply_process(
    engine: &NativeEngine,
    state: &mut EngineObservationState,
    approved: &ApprovedRecord,
    frame: &Frame,
    sample: &ProcessSample,
    now: DateTime<Utc>,
) -> Result<()> {
    let key = (
        approved.software.clone(),
        frame.observer_id,
        sample.id.clone(),
    );
    if let Some(id) = state.proof_keys.get(&key).copied() {
        let record = state
            .proofs
            .get_mut(&id)
            .context("native private proof record is missing")?;
        ensure!(
            record.token == sample.id
                && record.software == approved.software
                && record.observer == frame.observer_id
                && record.proof.same_execution(&sample.proof),
            "native session token collided with a different complete generation"
        );
        if sample.ended {
            if record.currently_observed {
                engine
                    .agent
                    .db
                    .end_session(id)
                    .map_err(public_source_error)?;
            }
            record.currently_observed = false;
            record.end_reason = Some(format!(
                "observed_boundary:{};not_an_OS_exit_guarantee",
                sample.native_reason
            ));
        } else {
            ensure!(
                record.end_reason.is_none() || !sample.current,
                "ended source observation session cannot reopen"
            );
            if sample.current {
                ensure!(
                    engine
                        .agent
                        .db
                        .session_for_pid(i32::try_from(sample.proof.generation.pid)?)
                        .map_err(public_source_error)?
                        .is_some_and(|session| session.session_id == id),
                    "source PID slot no longer belongs to this complete native generation"
                );
            }
            record.currently_observed = sample.current;
        }
        let bytes = serde_json::to_vec(&sample.proof)?.len();
        state.proof_bytes = state
            .proof_bytes
            .checked_sub(record.encoded_bytes)
            .and_then(|sum| sum.checked_add(bytes))
            .context("native proof memory accounting overflow")?;
        record.proof = sample.proof.clone();
        record.encoded_bytes = bytes;
        return Ok(());
    }
    if !sample.current {
        return Ok(());
    } // absence is never a new session/exit
    let pid =
        i32::try_from(sample.proof.generation.pid).context("source PID is not representable")?;
    if let Some(previous) = engine
        .agent
        .db
        .session_for_pid(pid)
        .map_err(public_source_error)?
    {
        let old = state.proofs.get_mut(&previous.session_id)
            .context("source PID slot has no retained full native generation; cannot replay PID-only sessions")?;
        ensure!(
            old.proof.generation.pid == sample.proof.generation.pid,
            "source PID slot and full proof disagree"
        );
        engine
            .agent
            .db
            .end_session(previous.session_id)
            .map_err(public_source_error)?;
        old.currently_observed = false;
        old.end_reason =
            Some("native_generation_or_observer_scope_replaced;not_an_OS_exit_guarantee".into());
    }
    let source_session = Uuid::new_v4();
    ensure!(
        !state.proofs.contains_key(&source_session),
        "native source session UUID collision"
    );
    // started_at is observation receipt time, NOT a fabricated conversion of
    // macOS timeval/Linux start ticks into source event time.
    let session = AppSession {
        session_id: source_session,
        app_id: approved.app.clone(),
        root_pid: pid,
        cgroup_path: String::new(),
        started_at: now,
        ended_at: None,
        source: SessionSource::Learned,
        identity_confidence: 1.0,
    };
    engine
        .agent
        .db
        .insert_session(&session)
        .map_err(public_source_error)?;
    engine
        .agent
        .db
        .attach_pid(source_session, pid, None, sample.proof.executable.to_str())
        .map_err(public_source_error)?;
    let encoded_bytes = serde_json::to_vec(&sample.proof)?.len();
    state.proof_bytes = state
        .proof_bytes
        .checked_add(encoded_bytes)
        .context("native proof size overflow")?;
    state.proof_keys.insert(key, source_session);
    state.proofs.insert(
        source_session,
        NativeObservationRecord {
            software: approved.software.clone(),
            observer: frame.observer_id,
            token: sample.id.clone(),
            source_session,
            proof: sample.proof.clone(),
            currently_observed: true,
            end_reason: None,
            encoded_bytes,
        },
    );
    Ok(())
}

fn check_cursor(state: &EngineObservationState, software: &str, frame: &Frame) -> Result<()> {
    let key = (software.to_owned(), frame.observer_id);
    ensure!(
        state
            .last_observer
            .get(software)
            .is_none_or(|last| *last == frame.observer_id)
            || !state.cursors.contains_key(&key),
        "native source observer scope was replaced; old signed frames cannot reopen it"
    );
    if let Some(old) = state.cursors.get(&key) {
        ensure!(
            old.observer == frame.observer_id,
            "native observer cursor identity changed"
        );
        ensure!(
            (frame.epoch > old.epoch && frame.page == 0)
                || (frame.epoch == old.epoch
                    && !old.finished
                    && frame.page == old.page.saturating_add(1)),
            "native source observation was replayed or its pages are out of order"
        );
    } else {
        ensure!(
            frame.page == 0,
            "native source observation must begin at page zero"
        );
    }
    Ok(())
}

fn make_entry(
    engine: &NativeEngine,
    approved: &ApprovedRecord,
    root: &Root,
    path: &str,
    kind: &str,
    size: u64,
    stamp: &FileStamp,
    now: DateTime<Utc>,
    usage: Vec<(Uuid, Value)>,
) -> Result<(PathRecord, PathAssociation, Option<PathAssociation>)> {
    approved.permit(root, path)?;
    check_stamp(stamp)?;
    let file_type = file_type(kind)?;
    ensure!(
        if kind == "file" {
            size == stamp.size
        } else {
            size == 0
        },
        "native index node size differs from its full stamp"
    );
    let absolute = root.path.join(path);
    let canonical = absolute
        .to_str()
        .context("native index path must be UTF-8")?
        .to_owned();
    let previous_path = engine
        .agent
        .db
        .get_path_by_canonical(&canonical)
        .map_err(public_source_error)?;
    let path_id = previous_path.as_ref().map_or(0, |record| record.path_id);
    let previous = if path_id == 0 {
        None
    } else {
        engine
            .agent
            .db
            .associations_for_path(path_id)
            .map_err(public_source_error)?
            .into_iter()
            .find(|association| association.app_id == approved.app)
    };
    // Reuse the source native role classifier; do not duplicate Linux pathname
    // heuristics or infer ownership from a display name or an observed open.
    let (class, role) = root.role.classification();
    let mut association = previous.clone().unwrap_or(PathAssociation {
        app_id: approved.app.clone(),
        path_id,
        confidence: 0.0,
        evidence: vec![],
        persistence_class: class,
        semantic_role: role,
        first_seen_at: now,
        last_seen_at: now,
    });
    if !association.evidence.iter().any(|evidence| {
        matches!(
            evidence.kind,
            EvidenceKind::ExplicitUserBinding | EvidenceKind::RestoredFromCommittedBundle
        )
    }) {
        association.persistence_class = class;
        association.semantic_role = role;
    }
    ensure!(
        association.evidence.len() <= 64,
        "source association evidence exceeds bound"
    );
    association.evidence.retain(|evidence| {
        evidence.detail.as_deref().is_none_or(|detail| {
            !(detail.starts_with("{\"quicksaveNative\":")
                && detail.contains("\"kind\":\"NativeOwnedRootEvidence\""))
        }) && !usage.iter().any(|(session, _)| {
            evidence.session_id == Some(*session)
                && evidence
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.starts_with("{\"quicksaveNative\":"))
        })
    });
    // Only recent use edges are bounded here, not source sessions, full native
    // proof records or backup version history. No complete history is asserted.
    let mut retained_uses = 0usize;
    let mut keep = Vec::with_capacity(association.evidence.len());
    for evidence in association.evidence.into_iter().rev() {
        let native_use = evidence.detail.as_deref().is_some_and(|detail| {
            detail.starts_with("{\"quicksaveNative\":")
                && detail.contains("\"kind\":\"NativeProcessFileUse\"")
        });
        if native_use {
            if retained_uses >= 16usize.saturating_sub(usage.len()) {
                continue;
            }
            retained_uses += 1;
        }
        keep.push(evidence);
    }
    keep.reverse();
    association.evidence = keep;
    ensure!(
        association.evidence.len() <= 64,
        "source association evidence exceeds bound"
    );
    let root_detail = json!({"quicksaveNative":{"kind":"NativeOwnedRootEvidence",
        "authority":"verified_current_tracking_MAC_and_registered_native_binding",
        "softwareId":approved.software,"softwareInstanceId":approved.instance,
        "rootId":root.id,"role":root.role.as_str(),"trackingScopeHash":approved.scope_hash,
        "nativeBindingFingerprint":approved.native_fingerprint,"relation":"APP_SCOPE_CONTAINS_METADATA",
        "complete":false}});
    association.evidence.push(Evidence {
        kind: EvidenceKind::KnownAppRoot,
        observed_at: now,
        detail: Some(serde_json::to_string(&root_detail)?),
        session_id: None,
    });
    for (session, detail) in usage {
        let detail = serde_json::to_string(&json!({"quicksaveNative":detail}))?;
        ensure!(
            detail.len() <= 32 * 1024,
            "source native file proof exceeds evidence bound"
        );
        association.evidence.push(Evidence {
            kind: EvidenceKind::ReadOnlyDependency,
            observed_at: now,
            detail: Some(detail),
            session_id: Some(session),
        });
    }
    association.confidence = association
        .confidence
        .max(score_evidence(&association.evidence).0);
    association.last_seen_at = now;
    let record = PathRecord {
        path_id,
        canonical_path: canonical,
        logical_root: Some(native_root_token(&approved.app, &root.id)),
        relative_path: Some(path.into()),
        file_type: Some(file_type.as_str().into()),
        inode: Some(i64::try_from(stamp.file_id[0])?),
        mount_id: Some(i64::try_from(stamp.device)?),
        size: Some(i64::try_from(stamp.size)?),
        mtime_ns: Some(mtime(stamp)?),
        mode: None,
        uid: None,
        gid: None,
        content_hash: None,
        last_scanned_at: Some(now.timestamp()),
    };
    Ok((record, association, previous))
}

fn make_state(
    approved: &ApprovedRecord,
    root: &Root,
    path: &str,
    kind: &str,
    _size: u64,
    stamp: &FileStamp,
    now: DateTime<Utc>,
) -> Result<FileStateRecord> {
    check_stamp(stamp)?;
    Ok(FileStateRecord {
        app_id: approved.app.clone(),
        logical_root: native_root_token(&approved.app, &root.id),
        relative_path: path.into(),
        canonical_path: Some(
            root.path
                .join(path)
                .to_str()
                .context("native graph path is not UTF-8")?
                .into(),
        ),
        file_type: file_type(kind)?,
        size: stamp.size,
        mtime_ns: mtime(stamp)?,
        inode: Some(stamp.file_id[0]),
        mount_id: Some(stamp.device),
        mode: None,
        content_hash: None,
        trust: FileStateTrust::VerifyRequired,
        last_seen_at: now,
        last_hashed_at: None,
    })
}

fn verify_written(
    engine: &NativeEngine,
    app: &AppId,
    entries: &[(PathRecord, PathAssociation, Option<PathAssociation>)],
) -> Result<()> {
    let mut ids = Vec::with_capacity(entries.len());
    for (record, _, _) in entries {
        ids.push(
            engine
                .agent
                .db
                .get_path_by_canonical(&record.canonical_path)
                .map_err(public_source_error)?
                .context("source DB did not persist the native metadata path")?
                .path_id,
        );
    }
    let associations = engine
        .agent
        .db
        .associations_for_paths(&ids)
        .map_err(public_source_error)?;
    ensure!(
        ids.iter().all(|id| associations
            .get(id)
            .is_some_and(|rows| rows.iter().any(|row| &row.app_id == app))),
        "source DB did not persist the actual native app/path association"
    );
    Ok(())
}

fn index_scope(record: &Value) -> Result<NativeIndexScope> {
    let index = &record["bundleIndexSource"];
    let count = ["fileCount", "directoryCount", "symlinkCount"]
        .into_iter()
        .try_fold(0u64, |sum, key| {
            sum.checked_add(
                index[key]
                    .as_u64()
                    .with_context(|| format!("native index {key} missing"))?,
            )
            .context("native index node count overflow")
        })?;
    let node_count = usize::try_from(count)?;
    ensure!(
        node_count <= MAX_SINGLE_INDEX,
        "native source metadata index exceeds node bound"
    );
    Ok(NativeIndexScope {
        software_id: text(&record["id"])?,
        app_id: text(&record["sourceIdentity"]["app_id"])?,
        instance_id: text(&record["appId"])?,
        revision_id: text(&index["revisionId"])?,
        snapshot_identity: text(&index["snapshotIdentity"])?,
        tracking_scope_hash: text(&index["trackingScopeHash"])?,
        node_count,
    })
}

fn check_stamp(stamp: &FileStamp) -> Result<()> {
    ensure!(
        stamp.file_id[1] == 0
            && stamp.modified_nanoseconds < 1_000_000_000
            && stamp.changed_nanoseconds < 1_000_000_000,
        "source DB cannot represent this full native ID/stamp"
    );
    let _ = i64::try_from(stamp.file_id[0])
        .context("source DB cannot losslessly represent this native file ID")?;
    let _ = i64::try_from(stamp.device)
        .context("source DB cannot losslessly represent this native device ID")?;
    let _ =
        i64::try_from(stamp.size).context("source DB cannot represent this native file size")?;
    mtime(stamp)?;
    Ok(())
}
fn mtime(stamp: &FileStamp) -> Result<i64> {
    stamp
        .modified_seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i64::from(stamp.modified_nanoseconds)))
        .context("source DB cannot represent this native mtime without truncation")
}
fn file_type(kind: &str) -> Result<FileType> {
    match kind {
        "file" => Ok(FileType::File),
        "directory" => Ok(FileType::Directory),
        "symlink" => Ok(FileType::Symlink),
        _ => anyhow::bail!("unsupported native source metadata node kind"),
    }
}
fn text(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .context("native source identity/reference missing")?;
    validate_id(text)?;
    Ok(text.into())
}
// Opaque metadata IDs, not filesystem names. Preserve exact Tracker instance
// suffixes and canonical desktop case; native.rs's older restrictive validator
// is deliberately not reused for these identities.
fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && !value.chars().any(char::is_control)
            && !value.contains(['/', '\\']),
        "invalid exact native observation metadata identity"
    );
    Ok(())
}
fn absolute(value: &Value) -> Result<PathBuf> {
    let path = PathBuf::from(value.as_str().context("native source path missing")?);
    let text = path.to_str().context("native source path is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && text.len() <= 4096
            && !text.contains(['\0', '\\'])
            && !text.split('/').any(|part| part == "." || part == "..")
            && !path.components().any(private_component),
        "invalid/protected native source path"
    );
    Ok(path)
}
fn relative(path: &str) -> Result<()> {
    noland_state_agent::native_host::validate_native_relative(path).map_err(public_source_error)?;
    ensure!(
        path.len() <= 4096 && !Path::new(path).components().any(private_component),
        "protected native source file metadata is excluded"
    );
    Ok(())
}
fn private_component(component: Component<'_>) -> bool {
    let Component::Normal(value) = component else {
        return false;
    };
    let Some(value) = value.to_str() else {
        return true;
    };
    let value = value.to_ascii_lowercase();
    matches!(
        value.as_str(),
        ".ssh"
            | ".gnupg"
            | ".aws"
            | ".azure"
            | ".git"
            | ".env"
            | "keychains"
            | "credentials"
            | "credentials.json"
            | "rootnativemarker"
            | ".quicksave-root"
            | ".quicksave-root-marker"
            | "com.noland.connect"
            | "noland-state"
            | "noland-runtime"
            | ".noland"
            | "noland"
            | "no land"
            | "no land.app"
            | "noland.app"
            | "id_rsa"
            | "id_ed25519"
            | "id_ecdsa"
            | "id_dsa"
            | "recovery.key"
            | "master.key"
    ) || [".key", ".pem", ".p12", ".pfx", ".p8", ".keychain-db"]
        .iter()
        .any(|suffix| value.ends_with(suffix))
}

fn bounded(value: &Value, limit: usize) -> Result<()> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        ensure!(
            depth <= 32 && nodes <= 1_000_000,
            "native graph document exceeds structural bounds"
        );
        let charge = match value {
            Value::String(value) => value.len().saturating_mul(6).saturating_add(2),
            Value::Array(values) => values.len().saturating_add(2),
            Value::Object(values) => values.keys().fold(2usize, |sum, key| {
                sum.saturating_add(key.len().saturating_mul(6) + 4)
            }),
            _ => 32,
        };
        bytes = bytes
            .checked_add(charge)
            .context("native graph document size overflow")?;
        ensure!(bytes <= limit, "native graph document exceeds byte bounds");
        match value {
            Value::Array(values) => {
                ensure!(
                    values.len() <= 1_000_000,
                    "native graph array exceeds bound"
                );
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => stack.extend(values.values().map(|value| (value, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

struct HashWriter(blake3::Hasher);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn digest(value: &Value) -> Result<String> {
    bounded(value, MAX_EVENT)?;
    let mut writer = HashWriter(blake3::Hasher::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quicksave_state::{MemoryVault, WorkspaceStore};
    use quicksave_tracking::{Tracker, TrackingPolicy, TrackingStore};
    use std::{fs, sync::Mutex};

    struct TestStore {
        store: WorkspaceStore,
        records: Mutex<BTreeMap<String, Value>>,
    }
    impl TrackingStore for TestStore {
        fn load_records(&self) -> Result<Vec<Value>> {
            Ok(vec![])
        }
        fn save_record(&self, record: &Value) -> Result<()> {
            self.records
                .lock()
                .unwrap()
                .insert(record["id"].as_str().unwrap().into(), record.clone());
            Ok(())
        }
        fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
            self.store.issue_grant(kind, scope)
        }
        fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
            self.store.verify_grant(kind, scope, grant)
        }
        fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
            self.store.revoke_grant(kind, scope)
        }
        fn provider_writable(&self, _: &str) -> Result<bool> {
            Ok(false)
        }
    }
    struct Owner {
        scope: NativeIndexScope,
        authority: Value,
        nodes: Vec<crate::capture_control::FrozenCaptureNode>,
    }
    impl NativeIndexOwner for Owner {
        fn root_authority(&self, scope: &NativeIndexScope) -> Result<Value> {
            self.verify_current(scope)?;
            Ok(self.authority.clone())
        }
        fn verify_current(&self, scope: &NativeIndexScope) -> Result<()> {
            ensure!(scope == &self.scope, "injected index revision changed");
            Ok(())
        }
        fn protected_file_ids(&self) -> Result<Vec<(u64, [u64; 2])>> {
            Ok(vec![])
        }
        fn node_page(
            &self,
            scope: &NativeIndexScope,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<crate::capture_control::FrozenCaptureNode>> {
            self.verify_current(scope)?;
            ensure!(
                limit > 0 && limit <= PAGE && offset <= self.nodes.len(),
                "bad injected index page"
            );
            Ok(self
                .nodes
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect())
        }
    }
    struct Fixture {
        engine: NativeEngine,
        tracker: Tracker,
        store: WorkspaceStore,
        record: Value,
        authority: Value,
        root: PathBuf,
        executable: PathBuf,
        _temp: tempfile::TempDir,
    }
    impl Fixture {
        async fn new() -> Self {
            // Synthetic metadata only. Native host mode explicitly prevents
            // source recover/discovery from bootstrapping Linux process probes.
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let temp = tempfile::tempdir_in(base).unwrap();
            let data = temp.path().join("state");
            let home = temp.path().join("isolated-home");
            let apps = temp.path().join("Applications");
            let root = apps.join("Synthetic");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir(&home).unwrap();
            let executable = root.join("game.bin");
            fs::write(&executable, b"synthetic image never executed").unwrap();
            fs::write(root.join("slot.dat"), b"synthetic data").unwrap();
            let store =
                WorkspaceStore::open_with_vault(&data, Arc::new(MemoryVault::default())).unwrap();
            let mut policy = TrackingPolicy::new(&data);
            policy.supports_metadata_snapshots = true;
            let adapter = Arc::new(TestStore {
                store: store.clone(),
                records: Mutex::new(BTreeMap::new()),
            });
            let tracker = Tracker::open(adapter, Arc::new(|_| Ok(())), policy).unwrap();
            let app = "steam:480@synthetic-native-install";
            let policy = json!({"version":1,"policyId":"source-graph-fixture","rolePolicyVersion":1,
                "source":"verified_native_discovery","enabled":true,
                "baseDirectories":[{"id":"synthetic-base","path":apps,
                    "identity":SafeRoot::open(&apps).unwrap().identity().unwrap(),
                    "allowedRoles":["runtime"],"ownershipRules":["native_executable_handle"]}],
                "appIdentityPolicy":{"allowedAppIds":[app,"steam:480@second-native-install"],"allowNewVerifiedApps":false,
                    "allowedEvidenceKinds":["native_executable_handle"],"allowNativeInstallationOnly":false},
                "excludedPaths":[data]});
            let policy_grant = store.issue_grant("app_tracking_policy", &policy).unwrap();
            store
                .set_app_tracking_policy(&json!({"policyScope":policy,"policyGrant":policy_grant}))
                .unwrap();
            let identity = SafeRoot::open(&root).unwrap().identity().unwrap();
            let native = json!({"platform":"unix","kind":"directory","device":identity.device,"inode":identity.file_id[0]});
            let evidence =
                json!([{"kind":"native_executable_handle","identifier":"fixture-runtime"}]);
            let candidates = json!([{"appId":app,"productId":"steam:480","displayName":"Synthetic",
                "sourceIdentity":{"app_id":"steam:480","display_name":"Synthetic",
                    "canonical_executable":executable,"desktop_entry_id":null,"steam_app_id":480,
                    "launcher":"steam","aliases":[],"identity_confidence":1.0,"icon_path":null},
                "identityEvidence":evidence,"rootsComplete":false,"unresolvedRoots":[],"unresolvedReasons":[],
                "sourceRoots":[{"rootId":"fixture-runtime","path":root,"classification":"runtime","roles":["runtime"],
                    "status":"verified_candidate","nativeIdentity":native,"evidence":evidence,"ownership":"exact_native_runtime"}]}]);
            let discovery = json!({"version":1,"source":"verified_native_discovery",
                "policyHash":digest(&policy).unwrap(),"candidatesHash":digest(&candidates).unwrap()});
            let discovery_grant = store.issue_grant("bundle_discovery", &discovery).unwrap();
            let output = tracker
                .materialize_bundles(
                    candidates.as_array().unwrap(),
                    &json!({
                        "policyScope":policy,"policyGrant":policy_grant,
                        "discoveryScope":discovery,"discoveryGrant":discovery_grant,
                    }),
                )
                .unwrap();
            let id = output["bundles"][0]["id"].as_str().unwrap();
            let record = tracker.bundle_record(id).unwrap();
            let authority = tracker.root_authority(id).unwrap();
            let engine = NativeEngine::open(&data, &home)
                .unwrap()
                .with_workspace(store.clone())
                .unwrap();
            engine.register(&record).await.unwrap();
            Self {
                engine,
                tracker,
                store,
                record,
                authority,
                root,
                executable,
                _temp: temp,
            }
        }
        fn stamp(&self, leaf: &str) -> FileStamp {
            SafeRoot::open(&self.root)
                .unwrap()
                .read_file(leaf)
                .unwrap()
                .1
        }
        fn owner(&self) -> Owner {
            let scope = index_scope(&self.record).unwrap();
            let root = self.record["roots"][0]["id"].as_str().unwrap();
            let logical = native_root_token(&AppId("steam:480".into()), root);
            let nodes = ["game.bin", "slot.dat"]
                .into_iter()
                .map(|leaf| {
                    let stamp = self.stamp(leaf);
                    crate::capture_control::FrozenCaptureNode {
                        id: native_file_id(&logical, leaf),
                        root_id: root.into(),
                        logical_root: logical.clone(),
                        path: leaf.into(),
                        kind: "file".into(),
                        size: stamp.size,
                        stamp: serde_json::from_value(serde_json::to_value(stamp).unwrap())
                            .unwrap(),
                        link_target_hash: None,
                    }
                })
                .collect();
            Owner {
                scope,
                authority: self.authority.clone(),
                nodes,
            }
        }
        fn event(&self, observer: Uuid, epoch: u64, start: [u64; 2], token: &str) -> Value {
            let proof = json!({"scope_fingerprint":"b".repeat(64),
                "generation":{"pid":41,"uid":501,"start":start,"namespace":[9,7]},
                "executable":self.executable,"executable_stamp":self.stamp("game.bin"),
                "image_binding":"mapped_image_native_file","bundle_identifier":null,
                "app_id":self.record["appId"],"registered_identity":true,"observed_at_ms":epoch,
                "source":"injected_fixture"});
            let observation = json!({"version":1,"observerId":observer,"epoch":epoch,"page":0,"finalPage":true,
                "observedAtMs":epoch,"scopeFingerprint":"b".repeat(64),
                "source":{"source":"injected_fixture","complete_file_stream":false,"complete_lifecycle_stream":false,
                    "running_image_native_identity":true,"native_open_file_identity":true},
                "processes":[{"id":token,"proof":proof,"current":true,"ended":false,"nativeReason":"run_observed"}],
                "files":[{"process":proof,"root_id":self.record["roots"][0]["id"],"relative_path":"slot.dat",
                    "stamp":self.stamp("slot.dat"),"descriptor":7,"confidence":"native_identity_matched_use"}],
                "gaps":[{"reason":"polling_cannot_observe_short_lived_opens","root_id":null}],
                "protectedNativeFiles":[],"completeness":"unknown","clean":false,"applicationAtomic":false});
            self.sign(observation)
        }
        fn sign(&self, observation: Value) -> Value {
            let scope =
                NativeEngine::native_observation_scope(&self.record, &self.authority, &observation)
                    .unwrap();
            let grant = self
                .store
                .issue_grant("source_native_observation", &scope)
                .unwrap();
            json!({"record":self.record,"rootAuthority":self.authority,
                "observation":observation,"scope":scope,"grant":grant})
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.tracker.shutdown();
        }
    }

    #[tokio::test]
    async fn source_import_reports_tracking_mac_stage_without_exposing_private_cause() {
        let fixture = Fixture::new().await;
        let mut record = fixture.record.clone();
        record["trackingGrant"] = json!({"privateFixture":"must-not-be-logged"});
        let error = fixture
            .engine
            .native_materialize_index(record, Arc::new(fixture.owner()))
            .unwrap_err();
        let failure = error.downcast_ref::<NativeIndexImportFailure>().unwrap();
        assert_eq!(failure.stage(), "source_import_verify_tracking_mac");
        assert!(!failure.to_string().contains("must-not-be-logged"));
    }

    #[tokio::test]
    async fn actual_source_database_receives_metadata_index_without_a_provider_or_content_hash() {
        let fixture = Fixture::new().await;
        let software = fixture.record["id"].as_str().unwrap();
        assert_eq!(
            fixture.engine.native_observation_status(software).unwrap()["rootsOnly"],
            true
        );
        let result = fixture
            .engine
            .native_materialize_index(fixture.record.clone(), Arc::new(fixture.owner()))
            .unwrap();
        assert_eq!(result["sourceIndexedNodes"], 2);
        assert_eq!(result["complete"], false);
        let app = AppId("steam:480".into());
        assert_eq!(fixture.engine.agent.db.list_apps().unwrap().len(), 1);
        assert_eq!(
            fixture
                .engine
                .agent
                .db
                .get_app(&app)
                .unwrap()
                .unwrap()
                .app_id,
            app
        );
        assert_eq!(
            fixture
                .engine
                .agent
                .db
                .known_roots(Some(&app))
                .unwrap()
                .len(),
            1
        );
        let rows = fixture.engine.agent.db.associations_for_app(&app).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|(path, association)| path.content_hash.is_none()
                && association.app_id == app
                && association.evidence.iter().any(|evidence| evidence
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("NativeOwnedRootEvidence")))));
        assert!(fixture
            .engine
            .agent
            .db
            .list_file_states(&app, None)
            .unwrap()
            .iter()
            .all(|state| state.trust == FileStateTrust::VerifyRequired
                && state.content_hash.is_none()));
        assert!(fixture
            .engine
            .agent
            .db
            .list_dirty_apps()
            .unwrap()
            .iter()
            .any(|dirty| dirty.app_id == app && dirty.requires_reconciliation));
        assert!(fixture.engine.runtime.get().is_none());
        assert!(fixture.engine.agent.hub.drain().is_empty());
    }

    #[tokio::test]
    async fn actual_source_sessions_keep_full_generations_and_never_inject_linux_exec_or_fs_events()
    {
        let fixture = Fixture::new().await;
        let observer = Uuid::new_v4();
        fixture
            .engine
            .native_observe_application(fixture.event(observer, 1, [9, 4], "first-native-session"))
            .unwrap();
        let first = fixture
            .engine
            .agent
            .db
            .session_for_pid(41)
            .unwrap()
            .unwrap();
        assert_eq!(first.app_id.as_str(), "steam:480");
        assert!(first.cgroup_path.is_empty());
        fixture
            .engine
            .native_observe_application(fixture.event(
                observer,
                2,
                [10, 4],
                "second-native-session",
            ))
            .unwrap();
        let second = fixture
            .engine
            .agent
            .db
            .session_for_pid(41)
            .unwrap()
            .unwrap();
        assert_ne!(first.session_id, second.session_id);
        let state = fixture.engine.observation.lock().unwrap();
        assert_eq!(
            state.proofs[&first.session_id].proof.generation.start,
            [9, 4]
        );
        assert_eq!(
            state.proofs[&second.session_id].proof.generation.start,
            [10, 4]
        );
        assert!(!state.proofs[&first.session_id].currently_observed);
        assert_eq!(
            state.proofs[&second.session_id].proof.app_id,
            fixture.record["appId"].as_str().unwrap()
        );
        drop(state);
        let rows = fixture
            .engine
            .agent
            .db
            .associations_for_app(&AppId("steam:480".into()))
            .unwrap();
        assert!(rows.iter().any(
            |(_, association)| association
                .evidence
                .iter()
                .any(|evidence| evidence.session_id == Some(second.session_id)
                    && evidence
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("NativeProcessFileUse")))
        ));
        assert!(fixture.engine.agent.hub.drain().is_empty());
        assert!(fixture.engine.runtime.get().is_none());
    }

    #[tokio::test]
    async fn multiple_sessions_use_one_actual_source_path() {
        let fixture = Fixture::new().await;
        let mut frame =
            fixture.event(Uuid::new_v4(), 1, [9, 4], "first-session")["observation"].clone();
        let mut process = frame["processes"][0].clone();
        process["id"] = json!("second-session");
        process["proof"]["generation"]["pid"] = json!(42);
        let mut file = frame["files"][0].clone();
        file["process"] = process["proof"].clone();
        frame["processes"].as_array_mut().unwrap().push(process);
        frame["files"].as_array_mut().unwrap().push(file);
        let result = fixture
            .engine
            .native_observe_application(fixture.sign(frame))
            .unwrap();
        assert_eq!(result["nativeFileAssociations"], 1);
        assert_eq!(result["nativeFileUseFacts"], 2);
        let rows = fixture
            .engine
            .agent
            .db
            .associations_for_app(&AppId("steam:480".into()))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]
                .1
                .evidence
                .iter()
                .filter(|evidence| evidence.session_id.is_some())
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn earlier_installation_graph_uses_its_retained_handles_without_switching_capture_roots()
    {
        let fixture = Fixture::new().await;
        fixture
            .engine
            .native_materialize_index(fixture.record.clone(), Arc::new(fixture.owner()))
            .unwrap();
        let second_root = fixture.root.parent().unwrap().join("SecondSynthetic");
        fs::create_dir(&second_root).unwrap();
        fs::write(
            second_root.join("game.bin"),
            b"second synthetic image, never executed",
        )
        .unwrap();
        fs::write(second_root.join("slot.dat"), b"second synthetic state").unwrap();
        let identity = SafeRoot::open(&second_root).unwrap().identity().unwrap();
        let source = json!({"app_id":"steam:480","display_name":"Synthetic second installation",
            "canonical_executable":second_root.join("game.bin"),"desktop_entry_id":null,"steam_app_id":480,
            "launcher":"steam","aliases":[],"identity_confidence":1.0,"icon_path":null});
        let evidence = json!([{"kind":"native_executable_handle","identifier":"second-runtime"}]);
        let candidates = json!([{"appId":"steam:480@second-native-install","productId":"steam:480",
            "displayName":"Synthetic second installation","sourceIdentity":source,"identityEvidence":evidence,
            "rootsComplete":false,"unresolvedRoots":[],"unresolvedReasons":[],
            "sourceRoots":[{"rootId":"second-runtime","path":second_root,"classification":"runtime","roles":["runtime"],
                "status":"verified_candidate","nativeIdentity":{"platform":"unix","kind":"directory",
                    "device":identity.device,"inode":identity.file_id[0]},"evidence":evidence,"ownership":"exact_native_runtime"}]}]);
        let policy = fixture.store.app_tracking_policy().unwrap().unwrap();
        let discovery = json!({"version":1,"source":"verified_native_discovery",
            "policyHash":digest(&policy["policyScope"]).unwrap(),"candidatesHash":digest(&candidates).unwrap()});
        let discovery_grant = fixture
            .store
            .issue_grant("bundle_discovery", &discovery)
            .unwrap();
        let output = fixture
            .tracker
            .materialize_bundles(
                candidates.as_array().unwrap(),
                &json!({
                    "policyScope":policy["policyScope"],"policyGrant":policy["policyGrant"],
                    "discoveryScope":discovery,"discoveryGrant":discovery_grant,
                }),
            )
            .unwrap();
        let id = output["bundles"][0]["id"].as_str().unwrap();
        let record = fixture.tracker.bundle_record(id).unwrap();
        fixture.engine.register_materialized(&record).unwrap();
        let root = record["roots"][0]["id"].as_str().unwrap();
        let logical = native_root_token(&AppId("steam:480".into()), root);
        let nodes = ["game.bin", "slot.dat"]
            .into_iter()
            .map(|leaf| {
                let stamp = SafeRoot::open(&second_root)
                    .unwrap()
                    .read_file(leaf)
                    .unwrap()
                    .1;
                crate::capture_control::FrozenCaptureNode {
                    id: native_file_id(&logical, leaf),
                    root_id: root.into(),
                    logical_root: logical.clone(),
                    path: leaf.into(),
                    kind: "file".into(),
                    size: stamp.size,
                    stamp: serde_json::from_value(serde_json::to_value(stamp).unwrap()).unwrap(),
                    link_target_hash: None,
                }
            })
            .collect();
        let owner = Owner {
            scope: index_scope(&record).unwrap(),
            authority: fixture.tracker.root_authority(id).unwrap(),
            nodes,
        };
        fixture
            .engine
            .native_materialize_index(record, Arc::new(owner))
            .unwrap();
        let active = fixture
            .engine
            .agent
            .native_binding_fingerprint(&AppId("steam:480".into()))
            .unwrap();
        fixture
            .engine
            .native_observe_application(fixture.event(
                Uuid::new_v4(),
                1,
                [9, 4],
                "first-instance-session",
            ))
            .unwrap();
        assert_eq!(
            fixture
                .engine
                .agent
                .native_binding_fingerprint(&AppId("steam:480".into()))
                .unwrap(),
            active
        );
        assert_eq!(
            fixture
                .engine
                .agent
                .native_approved_roots(&AppId("steam:480".into()))
                .unwrap(),
            vec![second_root]
        );
        assert_eq!(
            fixture
                .engine
                .agent
                .db
                .associations_for_app(&AppId("steam:480".into()))
                .unwrap()
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn unknown_poll_cannot_close_a_session_or_trust_absence() {
        let fixture = Fixture::new().await;
        let observer = Uuid::new_v4();
        fixture
            .engine
            .native_observe_application(fixture.event(observer, 1, [9, 4], "session"))
            .unwrap();
        let before = fixture
            .engine
            .agent
            .db
            .session_for_pid(41)
            .unwrap()
            .unwrap();
        let mut frame = fixture.event(observer, 2, [9, 4], "session")["observation"].clone();
        frame["processes"][0]["current"] = json!(false);
        frame["processes"][0]["proof"]["observed_at_ms"] = json!(1);
        frame["files"] = json!([]);
        frame["gaps"] = json!([{"reason":"source_unavailable","root_id":null}]);
        let result = fixture
            .engine
            .native_observe_application(fixture.sign(frame))
            .unwrap();
        assert_eq!(result["complete"], false);
        assert_eq!(
            fixture
                .engine
                .agent
                .db
                .session_for_pid(41)
                .unwrap()
                .unwrap()
                .session_id,
            before.session_id
        );
        let state = fixture.engine.observation.lock().unwrap();
        assert!(!state.proofs[&before.session_id].currently_observed);
        assert!(state.proofs[&before.session_id].end_reason.is_none());
        drop(state);
        assert!(fixture
            .engine
            .agent
            .db
            .list_file_states(&AppId("steam:480".into()), None)
            .unwrap()
            .iter()
            .all(|state| state.trust == FileStateTrust::VerifyRequired));
    }

    #[tokio::test]
    async fn retired_observer_scopes_cannot_reopen() {
        let fixture = Fixture::new().await;
        let old = fixture.event(Uuid::new_v4(), 1, [9, 4], "session-one");
        fixture
            .engine
            .native_observe_application(old.clone())
            .unwrap();
        fixture
            .engine
            .native_observe_application(fixture.event(Uuid::new_v4(), 1, [9, 4], "session-two"))
            .unwrap();
        let app = AppId("steam:480".into());
        let before = fixture.engine.agent.db.capture_generation(&app).unwrap();
        assert!(fixture.engine.native_observe_application(old).is_err());
        assert_eq!(
            fixture.engine.agent.db.capture_generation(&app).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn tampering_replay_and_revocation_do_not_mutate_the_actual_source_graph() {
        let fixture = Fixture::new().await;
        let app = AppId("steam:480".into());
        let observer = Uuid::new_v4();
        let good = fixture.event(observer, 1, [9, 4], "first-native-session");
        let before = fixture.engine.agent.db.capture_generation(&app).unwrap();
        let mut tampered = good.clone();
        tampered["observation"]["files"][0]["relative_path"] = json!("unapproved/../slot.dat");
        assert!(fixture.engine.native_observe_application(tampered).is_err());
        assert_eq!(
            fixture.engine.agent.db.capture_generation(&app).unwrap(),
            before
        );
        fixture
            .engine
            .native_observe_application(good.clone())
            .unwrap();
        let before = fixture.engine.agent.db.capture_generation(&app).unwrap();
        assert!(fixture.engine.native_observe_application(good).is_err());
        assert_eq!(
            fixture.engine.agent.db.capture_generation(&app).unwrap(),
            before
        );
        let event = fixture.event(observer, 2, [9, 4], "first-native-session");
        fixture.store.clear_app_tracking_policy().unwrap();
        assert!(fixture.engine.native_observe_application(event).is_err());
        assert_eq!(
            fixture.engine.agent.db.capture_generation(&app).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn source_schema_rejects_unrepresentable_native_file_ids_without_fabricating_a_hash_identity(
    ) {
        let fixture = Fixture::new().await;
        let mut owner = fixture.owner();
        owner.nodes[0].stamp.file_id[1] = 1;
        assert!(fixture
            .engine
            .native_materialize_index(fixture.record.clone(), Arc::new(owner))
            .is_err());
        let status = fixture
            .engine
            .native_observation_status(fixture.record["id"].as_str().unwrap())
            .unwrap();
        assert_eq!(status["sourceIndexMaterialized"], false);
        assert_eq!(status["sourceIndexedNodes"], 0);
        assert!(fixture
            .engine
            .agent
            .db
            .associations_for_app(&AppId("steam:480".into()))
            .unwrap()
            .is_empty());
    }
}
