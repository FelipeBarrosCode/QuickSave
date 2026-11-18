// SPDX-License-Identifier: GPL-3.0-only
//! Windows-native composition of the portable No Land engine libraries.
//! Protocol provenance: audited fork of No Land
//! e81238a7536aae201540956ce76981364fd36595. No Linux agent/collector, remote
//! process, provisioning code, production account or vault is opened here.
pub mod capture;
mod catalog;
mod completion;
mod deletion;
mod full_scope;
mod lock;
mod pipeline;
mod plan;
mod provider;
mod restore;
mod runtime;
#[cfg(test)]
mod tests;

use anyhow::{bail, ensure, Context, Result};
use noland_crypto::MasterKey;
use noland_rclone_adapter::{
    EphemeralRcloneSession, ProviderKind, TransferTuning, TransferWorkload,
};
use noland_restore::NativeRecoveryAuthority;
use noland_state_core::{
    AgentPaths, AppId, AppIdentity, BundleManifest, OperationProgress, OperationRecord, StateError,
};
use noland_state_db::StateDb;
use noland_storage::{
    clear_repository_activity, load_catalog, prepare_full_deletion_selected,
    read_committed_manifest, repository_activities, write_guarded_ephemeral_session,
    EphemeralSessionGuard, FullDeletionPlan, NativeCredentialSinkRegistration,
    NativePrivateCredentialSink, RcloneStorage, RepositoryAccess, RepositoryGuard,
    SharedStorageProvider,
};
use plan::*;
use provider::{Check, CheckedProvider};
use quicksave_platform::{
    ensure_private_directory, verify_private_file, EntryKind, FileStamp, PrivateDirectory,
    RootIdentity, SafeRoot,
};
use quicksave_state::{ProviderAccess, WorkspaceStore};
pub use runtime::SourceRuntime;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OnceCell, Semaphore};
use uuid::Uuid;

type PublishGuard = Arc<dyn Fn() -> Result<()> + Send + Sync>;
/// Native state callback: reload/reverify device-HMAC scope and provider
/// revocation, without returning credentials or accepting a UI authorization bit.
pub type NativeAuthorityGuard = Arc<dyn Fn(&str, bool) -> Result<()> + Send + Sync>;
pub type NativeOperationAuthority = Arc<dyn Fn(&[u8]) -> Result<[u8; 32]> + Send + Sync>;
pub fn native_capture_root_token(app: &str, root: &str) -> Result<String> {
    validate_id(app)?;
    validate_id(root)?;
    Ok(logical_token(app, root))
}
const MAX_QUEUE: usize = 8;
const MAX_ACTIVE: usize = 2;
const MAX_SESSION: usize = 2 * 1024 * 1024;
const MAX_REATTACH: usize = 16;

struct BoundRoot {
    spec: RootSpec,
    handle: SafeRoot,
    scope: ScopeIds,
}
type NativeId = (u64, [u64; 2]);
#[derive(Default)]
struct ScopeIds {
    directories: BTreeSet<NativeId>,
    files: BTreeSet<NativeId>,
}
impl ScopeIds {
    fn from_root(root: &SafeRoot) -> Result<Self> {
        let mut scope = Self::default();
        let id = root.identity()?;
        scope.directories.insert((id.device, id.file_id));
        for entry in root.metadata_entries()? {
            let id = (entry.stamp.device, entry.stamp.file_id);
            if entry.kind == EntryKind::Directory {
                scope.directories.insert(id);
            } else if entry.kind == EntryKind::File {
                scope.files.insert(id);
            }
        }
        Ok(scope)
    }
    fn overlaps(&self, other: &Self) -> bool {
        !self.directories.is_disjoint(&other.directories) || !self.files.is_disjoint(&other.files)
    }
}
struct SoftwareBinding {
    id: String,
    app: AppId,
    instance: String,
    name: String,
    identity: AppIdentity,
    identity_fingerprint: String,
    roots: Vec<Arc<BoundRoot>>,
    // Metadata browse projection only. Never execution/root authority.
    index: Vec<Value>,
    index_revision: String,
    source_revision: Option<String>,
}
struct PrivateAccess {
    provider: String,
    session: EphemeralRcloneSession,
    master: MasterKey,
    read_only: bool,
    authority_revision: Option<u64>,
    _sink: Option<NativeCredentialSinkRegistration>,
    lifecycle: Option<Arc<crate::provider_lifecycle::NativeProviderLifecycle>>,
}
struct Reattachment {
    access: PrivateAccess,
    created: Instant,
    controller: Option<Arc<dyn capture::NativeCaptureController>>,
}
struct Preview {
    provider: String,
    storage: String,
    plan: FullDeletionPlan,
    frozen: crate::catalog_control::FrozenFullDeletionPlan,
    created: Instant,
}
struct PublicationProof {
    guard: PublishGuard,
    roots: Vec<RootSpec>,
    capture: Option<Weak<capture::PreparedCaptureReceipt>>,
}
struct Job {
    plan: Arc<FrozenPlan>,
    access: Arc<PrivateAccess>,
    guard: Option<PublishGuard>,
    stop: Arc<AtomicBool>,
    controller: Option<Arc<dyn capture::NativeCaptureController>>,
    restore: Option<Arc<noland_restore::NativeRestoreControl>>,
}

struct Inner {
    db: StateDb,
    paths: AgentPaths,
    instance: Uuid,
    state: Arc<PrivateDirectory>,
    plans: SafeRoot,
    _data: SafeRoot,
    _home: SafeRoot,
    _owner: lock::EngineOwner,
    repository: tokio::sync::Mutex<()>,
    software: Mutex<BTreeMap<String, Arc<SoftwareBinding>>>,
    reattached: Mutex<HashMap<Uuid, Reattachment>>,
    previews: Mutex<HashMap<Uuid, Preview>>,
    active: Mutex<HashMap<Uuid, Arc<AtomicBool>>>,
    proofs: Mutex<HashMap<Uuid, PublicationProof>>,
    captures: Mutex<BTreeMap<Uuid, (String, Weak<capture::PreparedCaptureReceipt>)>>,
    completion: Mutex<completion::CompletionState>,
    catalog: Mutex<catalog::CatalogState>,
    authority: Mutex<Option<NativeAuthorityGuard>>,
    operation_authority: Mutex<Option<NativeOperationAuthority>>,
    recovery: Mutex<Option<Arc<dyn NativeRecoveryAuthority>>>,
    restore: Mutex<restore::RestoreState>,
    sinks: Mutex<BTreeMap<String, NativePrivateCredentialSink>>,
    submission: tokio::sync::Mutex<()>,
    reads: Semaphore,
    runtime: OnceCell<Arc<SourceRuntime>>,
    stopping: AtomicBool,
    finalization_failed: Arc<AtomicBool>,
}

/// Joined bounded native owner. No Debug/serde exposes keys, source paths,
/// provider configuration or callable native consent capabilities.
pub struct NativeEngine {
    inner: Arc<Inner>,
    sender: mpsc::Sender<Job>,
    worker: Mutex<Option<JoinHandle<()>>>,
    workspace: Option<WorkspaceStore>,
}

impl NativeEngine {
    pub fn open(data_dir: &Path, home: &Path) -> Result<Self> {
        ensure!(
            data_dir.is_absolute() && home.is_absolute(),
            "native data/home paths must be absolute"
        );
        ensure_private_directory(data_dir)?;
        let data = SafeRoot::open(data_dir)?;
        let home_handle = SafeRoot::open(home)?;
        data.create_dir("shared-storage")?;
        let private = data_dir.join("shared-storage");
        ensure_private_directory(&private)?;
        let owner_dir = PrivateDirectory::open(&private)?;
        let owner = lock::EngineOwner::open(&private)?;
        owner.check()?;
        let private_root = SafeRoot::open(&private)?;
        let instance = match owner_dir.read("instance-id", 64)? {
            Some((bytes, _)) => Uuid::parse_str(std::str::from_utf8(&bytes)?)?,
            None => {
                let id = Uuid::new_v4();
                owner_dir.replace("instance-id", id.to_string().as_bytes(), None)?;
                id
            }
        };
        ensure!(!instance.is_nil(), "native instance identity is invalid");
        private_root.create_dir("state")?;
        private_root.create_dir("run")?;
        let paths = AgentPaths::from_roots(private.join("state"), private.join("run"));
        for directory in [
            &paths.state_root,
            &paths.run_root,
            &paths.staging,
            &paths.snapshots,
            &paths.packs,
            &paths.restore,
            &paths.checkpoints,
            &paths.cache,
        ] {
            ensure_private_directory(directory)?;
        }
        let state = Arc::new(PrivateDirectory::open(&paths.state_root)?);
        let state_root = SafeRoot::open(&paths.state_root)?;
        state_root.create_dir("native-plans")?;
        let plans = SafeRoot::open(&paths.state_root.join("native-plans"))?;
        let db = StateDb::open_native(&paths.db_path).map_err(source_error)?;
        ensure!(
            db.integrity_check().map_err(source_error)? == "ok",
            "native SQLite integrity check failed"
        );
        // The held native owner proves old local execution stopped, not that an
        // unacknowledged remote request settled. Repository claims remain intact.
        let unfinished = db.unfinished_operations().map_err(source_error)?;
        ensure!(
            unfinished.len() <= 1024,
            "native recovery journal exceeds its bound"
        );
        for mut operation in unfinished {
            if operation.state == "INTERRUPTED" {
                continue;
            }
            operation.state = "INTERRUPTED".into();
            operation.updated_at = chrono::Utc::now();
            operation.last_error = Some("Native execution stopped; reattach fresh native access to the original authenticated plan.".into());
            db.upsert_operation(&operation).map_err(source_error)?;
        }
        let inner = Arc::new(Inner {
            db,
            paths,
            instance,
            state,
            plans,
            _data: data,
            _home: home_handle,
            _owner: owner,
            repository: tokio::sync::Mutex::new(()),
            software: Mutex::new(BTreeMap::new()),
            reattached: Mutex::new(HashMap::new()),
            previews: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
            proofs: Mutex::new(HashMap::new()),
            captures: Mutex::new(BTreeMap::new()),
            completion: Mutex::new(completion::CompletionState::default()),
            catalog: Mutex::new(catalog::CatalogState::default()),
            authority: Mutex::new(None),
            operation_authority: Mutex::new(None),
            recovery: Mutex::new(None),
            restore: Mutex::new(restore::RestoreState::default()),
            sinks: Mutex::new(BTreeMap::new()),
            submission: tokio::sync::Mutex::new(()),
            reads: Semaphore::new(2),
            runtime: OnceCell::new(),
            stopping: AtomicBool::new(false),
            finalization_failed: Arc::new(AtomicBool::new(false)),
        });
        let (sender, receiver) = mpsc::channel(MAX_QUEUE);
        let native = Arc::clone(&inner);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("quicksave-win-engine".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .max_blocking_threads(4)
                    .enable_all()
                    .build();
                let runtime = match runtime {
                    Ok(runtime) => {
                        let _ = ready_tx.send(true);
                        runtime
                    }
                    Err(_) => {
                        let _ = ready_tx.send(false);
                        return;
                    }
                };
                runtime.block_on(work_loop(native, receiver));
                // Runtime teardown joins all blocking tasks after work_loop has
                // joined admitted jobs and every owned capture/packing thread.
            })?;
        if ready_rx.recv()? != true {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("native Windows engine worker panicked"))?;
            bail!("native Windows engine runtime could not initialize");
        }
        Ok(Self {
            inner,
            sender,
            worker: Mutex::new(Some(worker)),
            workspace: None,
        })
    }

    /// Same native-only factory as Unix. Opening/binding performs no vault
    /// reads; callbacks verify current native state when real work is requested.
    pub fn with_workspace(mut self, store: WorkspaceStore) -> Result<Self> {
        ensure!(
            self.workspace.is_none(),
            "the native workspace is already bound"
        );
        let authority_store = store.clone();
        self.install_authority_guard(Arc::new(move |provider, write| {
            let document = authority_store.document()?;
            let record = document
                .providers
                .iter()
                .find(|record| record.id == provider)
                .context("native provider was removed")?;
            ensure!(
                record.status != "disconnected",
                "native provider was disconnected"
            );
            if write {
                ensure!(
                    record.status == "connected" && authority_store.provider_writable(provider)?,
                    "current native provider write authority is unavailable"
                );
            }
            Ok(())
        }))?;
        self.install_recovery_authority(Arc::new(WorkspaceRecovery(store.clone())))?;
        let operation_store = store.clone();
        self.install_operation_authority(Arc::new(move |bytes| {
            operation_store.operation_mac_existing(bytes)
        }))?;
        completion::bind_workspace(&self.inner, store.clone())?;
        self.workspace = Some(store);
        Ok(self)
    }

    /// Call once from trusted native state wiring. No vault read occurs on open.
    pub fn install_authority_guard(&self, guard: NativeAuthorityGuard) -> Result<()> {
        let mut slot = self.inner.authority.lock().map_err(poison)?;
        ensure!(
            slot.is_none(),
            "native authority guard is already installed"
        );
        *slot = Some(guard);
        Ok(())
    }

    pub fn install_operation_authority(&self, authority: NativeOperationAuthority) -> Result<()> {
        let mut slot = self.inner.operation_authority.lock().map_err(poison)?;
        ensure!(
            slot.is_none(),
            "native device-key operation authority is already installed"
        );
        *slot = Some(authority);
        Ok(())
    }

    /// Device-key HMAC authority for authenticated native restore journals.
    /// Repository keys must never be substituted for this native capability.
    pub fn install_recovery_authority(
        &self,
        authority: Arc<dyn NativeRecoveryAuthority>,
    ) -> Result<()> {
        let mut slot = self.inner.recovery.lock().map_err(poison)?;
        ensure!(
            slot.is_none(),
            "native recovery authority is already installed"
        );
        *slot = Some(authority);
        Ok(())
    }

    pub fn bind_credential_sink(
        &self,
        provider: &str,
        sink: NativePrivateCredentialSink,
    ) -> Result<()> {
        validate_id(provider)?;
        let mut sinks = self.inner.sinks.lock().map_err(poison)?;
        ensure!(
            sinks.len() < 64 || sinks.contains_key(provider),
            "native credential callback bound exceeded"
        );
        sinks.insert(provider.into(), sink);
        Ok(())
    }

    pub async fn preflight(&self) -> Result<Value> {
        ensure!(!self.inner.finalization_failed.load(Ordering::Acquire),
            "native transport finalization is unverified; retain artifacts and recover/restart the native owner before new work");
        ensure!(
            !self.inner.stopping.load(Ordering::Acquire),
            "native engine is stopping"
        );
        let runtime = self
            .inner
            .runtime
            .get_or_try_init(|| async {
                Ok::<_, anyhow::Error>(Arc::new(SourceRuntime::discover().await?))
            })
            .await?;
        runtime.check()?;
        self.inner._owner.check()?;
        Ok(runtime.sanitized())
    }

    /// Metadata indexing is explicit and cached. Dashboard/status/file-page
    /// polling never walks a source tree or hashes installation contents.
    pub async fn register(&self, software: &Value) -> Result<()> {
        let _submission = self.inner.submission.lock().await;
        let id = identifier(software, "id")?;
        let instance = software["appId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("quicksave:{id}"));
        bounded_text(&instance, 512)?;
        let name = bounded_text(
            software["name"].as_str().context("software name missing")?,
            256,
        )?;
        let mut source_identity = match software.get("sourceIdentity") {
            Some(value) if !value.is_null() => serde_json::from_value::<AppIdentity>(value.clone())
                .context("verified source application identity is invalid")?,
            _ => AppIdentity::new(AppId(instance.clone()), &name),
        };
        let app = source_identity.app_id.0.clone();
        validate_id(&app)?;
        if let Some(steam) = app.strip_prefix("steam:") {
            ensure!(steam.parse::<u32>().ok().is_some_and(|steam| app == AppId::steam(steam).0),
                "Steam source identity must retain its original canonical product ID, not an installation instance");
        }
        if let Some(steam) = source_identity.steam_app_id {
            ensure!(
                source_identity.app_id == AppId::steam(steam),
                "Steam identity differs from its exact application ID"
            );
        }
        if let Some(executable) = &source_identity.canonical_executable {
            ensure!(
                executable.is_absolute(),
                "source application executable must be absolute"
            );
            let parent = executable
                .parent()
                .context("native application executable parent missing")?;
            let leaf = executable
                .file_name()
                .and_then(|name| name.to_str())
                .context("native executable filename is not Unicode")?;
            SafeRoot::open(parent)?.read_file(leaf)?;
        }
        source_identity.display_name = name.clone();
        ensure!(
            serde_json::to_vec(&source_identity)?.len() <= 1024 * 1024,
            "native source application identity exceeds its document bound"
        );
        let identity_fingerprint =
            noland_storage::compact_json_hash(&source_identity).map_err(source_error)?;
        let source_revision = software["revisionId"]
            .as_str()
            .map(|revision| bounded_text(revision, 512))
            .transpose()?;
        let roots = software["roots"]
            .as_array()
            .context("approved native software roots missing")?;
        ensure!(
            !roots.is_empty() && roots.len() <= 128,
            "approve 1–128 native roots"
        );
        let mut specs = Vec::new();
        for root in roots {
            let root_id = identifier(root, "id")?;
            let path = PathBuf::from(
                root["path"]
                    .as_str()
                    .context("approved root path missing")?,
            );
            ensure!(path.is_absolute(), "approved Windows root must be absolute");
            let handle = SafeRoot::open(&path)?;
            let identity = handle.identity()?;
            if !root["identity"].is_null() {
                let expected: RootIdentity = serde_json::from_value(root["identity"].clone())
                    .context("approved native 128-bit root identity is malformed")?;
                ensure!(identity == expected, "approved native root was replaced");
            }
            let allowed_files = match root.get("allowedFiles") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let leaves = value
                        .as_array()
                        .context("allowedFiles must be an exact leaf array")?;
                    ensure!(
                        !leaves.is_empty() && leaves.len() <= MAX_FILES,
                        "invalid manual leaf scope"
                    );
                    let mut allowed = BTreeSet::new();
                    for leaf in leaves {
                        let leaf = leaf.as_str().context("manual leaf must be text")?;
                        validate_relative(leaf)?;
                        ensure!(
                            !leaf.contains('/') && allowed.insert(leaf.to_owned()),
                            "invalid duplicate/manual leaf"
                        );
                    }
                    Some(allowed)
                }
            };
            let role = NativeRootRole::parse(root["role"].as_str().unwrap_or("manual"))?;
            ensure!(role != NativeRootRole::Installer || allowed_files.is_some(),
                "installer capture requires approved exact files; an installer directory is not execution or broad scan authority");
            specs.push((
                RootSpec {
                    id: root_id.clone(),
                    logical: logical_token(&app, &root_id),
                    path,
                    identity,
                    allowed_files,
                    role,
                },
                handle,
            ));
        }
        {
            let bindings = self.inner.software.lock().map_err(poison)?;
            ensure!(
                bindings.len() < 1024 || bindings.contains_key(&id),
                "native registration bound exceeded"
            );
            if bindings.get(&id).is_some_and(|prior| {
                prior.app.as_str() == app
                    && prior.instance == instance
                    && prior.name == name
                    && prior.identity_fingerprint == identity_fingerprint
                    && prior.source_revision == source_revision
                    && prior
                        .roots
                        .iter()
                        .map(|r| &r.spec)
                        .eq(specs.iter().map(|(s, _)| s))
            }) {
                // Same native identities/scope: reuse the actual metadata index.
                return Ok(());
            }
        }
        let mut bound = Vec::new();
        let mut index = Vec::new();
        let mut index_path_bytes = 0usize;
        let mut ids = BTreeSet::new();
        // The private tree is ours to inspect. Never walk a manually selected
        // file's parent or unrelated siblings merely to test overlap.
        let internal = ScopeIds::from_root(&self.inner._data)?;
        for (spec, handle) in specs {
            ensure!(ids.insert(spec.id.clone()), "duplicate native root ID");
            let mut scope = ScopeIds::default();
            if let Some(leaves) = &spec.allowed_files {
                // Never enumerate a manual file's parent or unrelated siblings.
                for leaf in leaves {
                    index_path_bytes = index_path_bytes
                        .checked_add(leaf.len())
                        .filter(|size| *size <= 32 * 1024 * 1024)
                        .context("native metadata index path memory bound exceeded")?;
                    let (_, stamp) = handle.read_file(leaf)?;
                    scope.files.insert((stamp.device, stamp.file_id));
                    index.push(file_item(&spec.logical, leaf, "file", stamp.size)?);
                    ensure!(
                        index.len() <= MAX_FILES,
                        "native manual file index exceeds its bound"
                    );
                }
            } else {
                let root_id = handle.identity()?;
                scope.directories.insert((root_id.device, root_id.file_id));
                for entry in handle.metadata_entries()? {
                    index_path_bytes = index_path_bytes
                        .checked_add(entry.relative_path.len())
                        .filter(|size| *size <= 32 * 1024 * 1024)
                        .context("native metadata index path memory bound exceeded")?;
                    let kind = match entry.kind {
                        EntryKind::File => "file",
                        EntryKind::Directory => "directory",
                        EntryKind::Symlink => "symlink",
                    };
                    index.push(file_item(
                        &spec.logical,
                        &entry.relative_path,
                        kind,
                        entry.stamp.size,
                    )?);
                    let id = (entry.stamp.device, entry.stamp.file_id);
                    if entry.kind == EntryKind::Directory {
                        scope.directories.insert(id);
                    } else if entry.kind == EntryKind::File {
                        scope.files.insert(id);
                    }
                    ensure!(
                        index.len() <= MAX_FILES,
                        "native metadata index exceeds its bound"
                    );
                }
            }
            let native_root = (spec.identity.device, spec.identity.file_id);
            ensure!(
                !internal.directories.contains(&native_root) && !scope.overlaps(&internal),
                "approved source scope overlaps QuickSave private data or its native file aliases"
            );
            for prior in &bound {
                let prior: &Arc<BoundRoot> = prior;
                let prior_root = (prior.spec.identity.device, prior.spec.identity.file_id);
                ensure!(
                    !scope.overlaps(&prior.scope)
                        && !(spec.allowed_files.is_some()
                            && prior.scope.directories.contains(&native_root))
                        && !(prior.spec.allowed_files.is_some()
                            && scope.directories.contains(&prior_root)),
                    "approved native root/file scopes overlap"
                );
            }
            bound.push(Arc::new(BoundRoot {
                spec,
                handle,
                scope,
            }));
        }
        index.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let index_revision = noland_storage::compact_json_hash(&index).map_err(source_error)?;
        let app = AppId(app);
        self.inner
            .db
            .upsert_app(&source_identity)
            .map_err(source_error)?;
        self.inner.software.lock().map_err(poison)?.insert(
            id.clone(),
            Arc::new(SoftwareBinding {
                id,
                app,
                instance,
                name,
                identity: source_identity,
                identity_fingerprint,
                roots: bound,
                index,
                index_revision,
                source_revision,
            }),
        );
        Ok(())
    }

    pub async fn software_files(&self, params: &Value) -> Result<Value> {
        let binding = self.binding(params)?;
        let mut value = indexed_page(&binding.index, params, &binding.index_revision)?;
        value["contentState"] = json!("metadata_index_not_capture_authority");
        Ok(value)
    }

    pub async fn probe(&self, access: &ProviderAccess) -> Result<Value> {
        self.preflight().await?;
        let _slot = self
            .inner
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let private = self.private_access(access, None)?;
        let session = self.session(&private, None, Arc::new(AtomicBool::new(false)), false)?;
        let result = async {
            let observed = chrono::Utc::now();
            let health = session.provider.health_check().await.map_err(source_error)?;
            ensure!(health.ok, "provider listing failed; private provider output withheld");
            let head = session.provider.stat(&noland_storage::RemoteKey::new(
                noland_state_core::catalog_latest_key(),
            )).await.map_err(source_error)?;
            if head.is_none() {
                for prefix in ["catalog", "bundles", "packs", "checkpoints", "instances", "maintenance", "deletions"] {
                    let entries = session.provider.list_prefix(&noland_storage::RemoteKey::new(prefix))
                        .await.map_err(source_error)?;
                    if entries.iter().any(|entry| !entry.is_prefix) {
                        return Ok(json!({
                            "providerId":private.provider,"canList":true,"canRead":false,
                            "repositoryAccessible":false,"repositoryEmpty":false,"keyVerified":false,
                            "observedAt":observed,"evidence":"missing_catalog_head_with_existing_repository_objects",
                            "error":"Existing repository lacks a verifiable catalog head; recovery is required.",
                        }));
                    }
                }
                return Ok(json!({
                    "providerId":private.provider,"canList":true,"canRead":false,
                    "repositoryAccessible":true,"repositoryEmpty":true,"keyVerified":false,
                    "observedAt":observed,"evidence":"provider_root_list_and_empty_repository_namespace_inventory",
                    "error":null,
                }));
            }
            let verified = load_catalog(&session.provider, &private.master).await.is_ok();
            Ok(json!({
                "providerId":private.provider,"canList":true,"canRead":verified,
                "repositoryAccessible":verified,"repositoryEmpty":false,"keyVerified":verified,
                "observedAt":observed,
                "evidence":if verified {"authenticated_live_catalog"} else {"catalog_authentication_or_read_failed"},
                "error":if verified {None} else {Some("Existing repository could not be authenticated with this key.")},
            }))
        }.await;
        session.finish(result)
    }

    pub async fn health(&self, access: &ProviderAccess) -> Result<Value> {
        self.probe(access).await
    }

    pub async fn files(&self, access: &ProviderAccess, selection: &Value) -> Result<Value> {
        self.preflight().await?;
        let _slot = self
            .inner
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let private = self.private_access(access, None)?;
        let session = self.session(&private, None, Arc::new(AtomicBool::new(false)), false)?;
        let result = async {
            let manifest = manifest(&session.provider, &private.master, selection).await?;
            catalog::remember_manifest(&self.inner, &private, &manifest)?;
            let files = manifest
                .files
                .iter()
                .map(|file| {
                    file_item(
                        &file.logical_root,
                        &file.relative_path,
                        &file.file_type,
                        file.size,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            page(files, selection)
        }
        .await;
        session.finish(result)
    }

    pub async fn upload(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        let _ = (access, selection);
        bail!("native upload requires operation-bound device-HMAC publication authority; use upload_guarded")
    }

    pub async fn upload_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> Result<Value> {
        guard()?;
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; native write authority is required"
        );
        let _submission = self.inner.submission.lock().await;
        let id = operation_id(&selection)?;
        let private = self.private_access(&access, Some(id))?;
        let binding = self.binding(&selection)?;
        let files = freeze_files(&binding, &selection)?;
        let coverage = capture_coverage(&selection)?;
        ensure!(coverage != NativeCoverage::FullApprovedScope,
            "full native upload requires the original Rust full-scope authority and actual source-capture receipt");
        let (metadata, complete_approved_scope) = freeze_metadata(&binding, &files, coverage)?;
        guard()?;
        let plan = FrozenPlan {
            version: 1,
            api: 22,
            operation: id,
            instance: self.inner.instance,
            provider: private.provider.clone(),
            storage: private.session.root_cache_key(),
            created_at: chrono::Utc::now(),
            work: Work::Upload {
                software: binding.id.clone(),
                software_instance_id: binding.instance.clone(),
                app: binding.app.clone(),
                name: binding.name.clone(),
                source_identity: binding.identity.clone(),
                roots: binding.roots.iter().map(|r| r.spec.clone()).collect(),
                snapshot: bounded_text(
                    selection["captureSource"]["snapshotIdentity"]
                        .as_str()
                        .context("tracker snapshotIdentity is required")?,
                    512,
                )?,
                files,
                metadata,
                complete_approved_scope,
                coverage,
                capture_scope: None,
                capture_origin: None,
                full_snapshot: None,
                reuse_epoch: None,
                bundle: Uuid::new_v4(),
                commit: Uuid::new_v4(),
            },
        };
        self.submit(plan, private, Some(guard))
    }

    pub async fn upload_captured_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
        controller: Arc<dyn capture::NativeCaptureController>,
    ) -> Result<Value> {
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; native write authority is required"
        );
        ensure!(
            selection["captureSource"]["stage"] == "awaiting_native_capture_receipt",
            "actual native capture requires a metadata-only frozen scope"
        );
        let _submission = self.inner.submission.lock().await;
        let id = operation_id(&selection)?;
        let private = self.private_access(&access, Some(id))?;
        let binding = self.binding(&selection)?;
        let metadata = &selection["captureSource"]["metadataSelection"];
        let coverage = capture_coverage(&selection)?;
        let mut scope = CaptureScope {
            version: 1,
            work_id: identifier(&selection, "workId")?,
            metadata_identity: bounded_text(
                metadata["metadataIdentity"]
                    .as_str()
                    .context("native frozen metadata identity is missing")?,
                512,
            )?,
            node_count: metadata["nodeCount"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .context("native frozen node count is missing")?,
            full_scope: None,
        };
        if coverage == NativeCoverage::FullApprovedScope {
            let full = controller.full_scope_authority(&scope)?.context(
                "full/empty native capture requires its original Rust full-scope authority",
            )?;
            full.revalidate()?;
            scope.full_scope = Some(capture::full_scope_from_evidence(&full.evidence()?)?);
        }
        scope.validate()?;
        ensure!(
            metadata["workId"] == scope.work_id,
            "native capture work identity changed"
        );
        let (files, metadata, full_snapshot) =
            capture::freeze(&binding, &scope, controller.as_ref(), &private.provider)?;
        ensure!(
            full_snapshot.is_some() == (coverage == NativeCoverage::FullApprovedScope),
            "native complete coverage lacks its actual frozen full-scope proof"
        );
        let reuse_epoch = controller.reuse_epoch(&scope)?;
        if let Some(epoch) = &reuse_epoch {
            bounded_text(epoch, 512)?;
        }
        let plan = FrozenPlan {
            version: 1,
            api: 22,
            operation: id,
            instance: self.inner.instance,
            provider: private.provider.clone(),
            storage: private.session.root_cache_key(),
            created_at: chrono::Utc::now(),
            work: Work::Upload {
                software: binding.id.clone(),
                software_instance_id: binding.instance.clone(),
                app: binding.app.clone(),
                name: binding.name.clone(),
                source_identity: binding.identity.clone(),
                roots: binding.roots.iter().map(|root| root.spec.clone()).collect(),
                snapshot: scope.metadata_identity.clone(),
                files,
                metadata,
                complete_approved_scope: coverage == NativeCoverage::FullApprovedScope,
                coverage,
                capture_scope: Some(scope),
                capture_origin: Some(CaptureOrigin {
                    generation: selection["generation"]
                        .as_u64()
                        .context("actual native capture generation is missing")?,
                    automatic: selection["automatic"]
                        .as_bool()
                        .context("actual native capture automatic/manual scope is missing")?,
                    authorization: selection["authorization"].clone(),
                }),
                full_snapshot,
                reuse_epoch,
                bundle: Uuid::new_v4(),
                commit: Uuid::new_v4(),
            },
        };
        self.submit_with_controller(plan, private, Some(guard), Some(controller))
    }

    pub async fn download(&self, _access: ProviderAccess, _selection: Value) -> Result<Value> {
        bail!("native download requires its original frozen restorePreviewId and a fresh native consent guard; preview and approve the exact plan")
    }

    pub async fn preview_delete(&self, access: &ProviderAccess, selection: Value) -> Result<Value> {
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; deletion requires native write authority"
        );
        let _submission = self.inner.submission.lock().await;
        let id = Uuid::new_v4();
        let private = self.private_access(access, Some(id))?;
        let session = self.session(&private, None, Arc::new(AtomicBool::new(false)), true)?;
        let owner = owner(&private.master, self.inner.instance);
        let result = async {
            let _repository = self.inner.repository.lock().await;
            let _local = self.inner.state.lock("repository-admission.lock")?;
            // Reuses original authenticated lease semantics; no time-based expiry.
            recover_own_claims(
                &session.provider,
                &private.master,
                self.inner.instance,
                &owner,
            )
            .await?;
            let lease = RepositoryGuard::acquire_for_instance(
                &session.provider,
                &private.master,
                id,
                &owner,
                self.inner.instance,
                RepositoryAccess::Exclusive,
            )
            .await
            .map_err(source_error)?;
            let result = prepare_full_deletion_selected(
                &session.provider,
                &private.master,
                &[(
                    AppId(identifier(&selection, "appId")?),
                    parse_uuid(&selection, "bundleId")?,
                )],
                id,
                &owner,
            )
            .await
            .map_err(source_error);
            let release = lease.release().await.map_err(source_error);
            let plan = result?;
            release?;
            Ok(plan)
        }
        .await;
        let plan = session.finish(result)?;
        let requested = vec![crate::catalog_control::DeletionSelection {
            app_id: identifier(&selection, "appId")?,
            bundle_id: parse_uuid(&selection, "bundleId")?.to_string(),
        }];
        let frozen = deletion::projection(&plan, &requested)?;
        let result = deletion::summary(&private.provider, &plan, &frozen)?;
        catalog::remember_requested(&self.inner, &private, &plan, requested)?;
        let storage = deletion::storage_binding(&private)?;
        let mut previews = self.inner.previews.lock().map_err(poison)?;
        previews.clear();
        previews.insert(
            id,
            Preview {
                provider: private.provider.clone(),
                storage,
                plan,
                frozen,
                created: Instant::now(),
            },
        );
        Ok(result)
    }

    /// Bounded exact dependency identities from the original authenticated
    /// preview. Never expand/recompute a confirmed closure during pagination.
    pub async fn deletion_preview_targets(&self, id: &str, params: &Value) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid deletion preview ID")?;
        let previews = self.inner.previews.lock().map_err(poison)?;
        let preview = previews
            .get(&id)
            .context("native deletion preview is unavailable")?;
        ensure!(
            preview.created.elapsed() < Duration::from_secs(600),
            "native deletion preview expired"
        );
        let revision = &preview.frozen.digest;
        let targets = preview
            .plan
            .targets
            .iter()
            .map(|target| {
                json!({
                    "appId":target.deletion.app_id,"bundleId":target.deletion.bundle_id,
                    "commitId":target.deletion.commit_id,"logicalBytes":target.logical_bytes,
                    "name":target.name,
                })
            })
            .collect::<Vec<_>>();
        let mut page = indexed_page(&targets, params, revision)?;
        let object = page.as_object_mut().unwrap();
        let targets = object.remove("files").unwrap();
        object.insert("targets".into(), targets);
        object.insert("previewId".into(), json!(id));
        object.insert("planDigest".into(), json!(revision));
        Ok(page)
    }

    pub async fn delete(&self, _access: ProviderAccess, _selection: Value) -> Result<Value> {
        bail!("native deletion requires its exact frozen preview and native consent/publication guard; use delete_guarded")
    }

    /// Spend only the original Source plan authorized by the native ticket.
    pub async fn delete_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> Result<Value> {
        guard()?;
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; deletion requires native write authority"
        );
        let _submission = self.inner.submission.lock().await;
        guard()?;
        let id = parse_uuid(&selection, "previewId")?;
        {
            let previews = self.inner.previews.lock().map_err(poison)?;
            let preview = previews
                .get(&id)
                .context("deletion preview is unavailable; preview again")?;
            ensure!(
                preview.provider == access.provider_id
                    && preview.created.elapsed() < Duration::from_secs(600),
                "deletion preview expired or provider changed"
            );
        }
        let private = self.private_access(&access, Some(id))?;
        let ack = {
            let previews = self.inner.previews.lock().map_err(poison)?;
            let preview = previews
                .get(&id)
                .context("deletion preview is unavailable; preview again")?;
            deletion::check_preview(preview, &private, &selection)?
        };
        // No preview is consumed before the fresh native guard and exact
        // original dependency/digest/provider checks have all succeeded.
        guard()?;
        let preview = {
            let mut previews = self.inner.previews.lock().map_err(poison)?;
            let current = previews
                .get(&id)
                .context("deletion preview is unavailable; preview again")?;
            ensure!(
                current.created.elapsed() < Duration::from_secs(600),
                "deletion preview expired before native admission"
            );
            previews
                .remove(&id)
                .context("deletion preview is unavailable; preview again")?
        };
        self.submit(
            FrozenPlan {
                version: 1,
                api: 22,
                operation: id,
                instance: self.inner.instance,
                provider: private.provider.clone(),
                storage: private.session.root_cache_key(),
                created_at: chrono::Utc::now(),
                work: Work::Delete {
                    plan: preview.plan,
                    dependency_ack: ack,
                },
            },
            private,
            Some(guard),
        )
    }

    pub async fn status(&self, id: &str) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid operation ID")?;
        let snapshot = self
            .inner
            .db
            .operation_monitoring_snapshot(id)
            .map_err(source_error)?
            .context("native operation not found")?;
        let operation = &snapshot.operation;
        let running = self.inner.active.lock().map_err(poison)?.contains_key(&id);
        let terminal = matches!(
            operation.state.as_str(),
            "COMPLETED" | "FAILED" | "CANCELLED" | "INTERRUPTED"
        );
        let state = if running {
            "running"
        } else {
            match operation.state.as_str() {
                "QUEUED" => "queued",
                "COMPLETED" => "completed",
                "FAILED" => "failed",
                "CANCELLED" => "cancelled",
                "INTERRUPTED" => "interrupted",
                _ => "interrupted",
            }
        };
        let kind = match operation.kind.as_str() {
            "backup" => "upload",
            "restore" => "download",
            "delete" => "delete",
            _ => bail!("unknown native operation kind"),
        };
        let software = self.inner.software.lock().map_err(poison)?;
        let record_id = snapshot
            .progress
            .as_ref()
            .and_then(|progress| progress.detail_json["native_software_id"].as_str());
        let binding = record_id.and_then(|id| software.get(id));
        let mut value = json!({
            "id":id,"kind":kind,"state":state,
            "name":binding.map(|b| b.name.as_str()).unwrap_or(match kind {
                "upload"=>"Upload","download"=>"Download",_=>"Cloud deletion",
            }),
            "softwareId":binding.map(|b| b.id.as_str()),
            "canCancel":running && !terminal,
            "canRetry":!running && !self.inner.finalization_failed.load(Ordering::Acquire)
                && matches!(state, "failed"|"cancelled"|"interrupted"),
            "startedAt":operation.created_at,
            "finishedAt":if !running && terminal {Some(operation.updated_at)} else {None},
            "error":if matches!(state, "failed"|"interrupted") {
                Some("Native storage work stopped. Reattach fresh authorized access to its original frozen plan; retained artifacts are not automatically removed.")
            } else {None},
        });
        if let Some(progress) = snapshot.progress {
            value["providerId"] = progress.detail_json["native_provider_id"].clone();
            value["phase"] = json!(safe_phase(&progress.phase));
            if progress.unit.as_deref() == Some("files") {
                value["completedFiles"] = json!(progress.completed_units);
                value["totalFiles"] = json!(progress.total_units);
            } else if progress.unit.as_deref() == Some("bytes") {
                value["completedBytes"] = json!(progress.completed_units);
                value["totalBytes"] = json!(progress.total_units);
            }
        }
        // No plan/credential fetch, recursive walk or full-file hashing for UI.
        if kind == "download" {
            value["localRecoveryAvailable"] = json!(self.restore_recovery_available(id)?);
        }
        if kind == "upload" && state == "completed" {
            // Publication callbacks may read grant nonces. UI monitoring never
            // invokes them, fetches a provider/key or scans current source files.
            value["committedCaptureVerified"] = json!(completion::verified_hint(&self.inner, id)?);
            value["sourceCurrent"] = json!(false);
            value["currentRootStatus"] = json!("requires_tracker_confirmation");
        }
        Ok(value)
    }

    pub async fn recent(&self) -> Result<Vec<Value>> {
        let records = self
            .inner
            .db
            .recent_matching_operations(None, 50)
            .map_err(source_error)?;
        let mut values = Vec::with_capacity(records.len());
        for record in records {
            values.push(self.status(&record.operation_id.to_string()).await?);
        }
        Ok(values)
    }

    pub async fn cancel(&self, id: &str) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid operation ID")?;
        {
            let active = self.inner.active.lock().map_err(poison)?;
            active
                .get(&id)
                .context("native operation is not running")?
                .store(true, Ordering::Release);
        }
        self.status(&id.to_string()).await
    }

    pub async fn reattach(&self, access: ProviderAccess, id: &str) -> Result<()> {
        self.reattach_with_controller(access, id, None).await
    }

    pub async fn reattach_captured(
        &self,
        access: ProviderAccess,
        id: &str,
        controller: Arc<dyn capture::NativeCaptureController>,
    ) -> Result<()> {
        self.reattach_with_controller(access, id, Some(controller))
            .await
    }

    async fn reattach_with_controller(
        &self,
        access: ProviderAccess,
        id: &str,
        controller: Option<Arc<dyn capture::NativeCaptureController>>,
    ) -> Result<()> {
        self.preflight().await?;
        let id = Uuid::parse_str(id).context("invalid operation ID")?;
        let _submission = self.inner.submission.lock().await;
        ensure!(
            !self.inner.active.lock().map_err(poison)?.contains_key(&id),
            "native operation is still owned by a worker"
        );
        let private = self.private_access(&access, Some(id))?;
        let plan = self.inner.read_plan(id, &private.master)?;
        check_access(&plan, &private, self.inner.instance)?;
        ensure!(
            matches!(
                &plan.work,
                Work::Upload {
                    capture_scope: Some(_),
                    ..
                }
            ) == controller.is_some(),
            "metadata-captured retry requires reattaching its original native capture controller"
        );
        let operation = self
            .inner
            .db
            .get_operation(id)
            .map_err(source_error)?
            .context("native operation not found")?;
        ensure!(
            operation.kind == plan.kind() && operation.state != "COMPLETED",
            "operation does not accept reattachment"
        );
        let mut reattached = self.inner.reattached.lock().map_err(poison)?;
        reattached.retain(|_, entry| entry.created.elapsed() < Duration::from_secs(60));
        ensure!(
            reattached.len() < MAX_REATTACH || reattached.contains_key(&id),
            "native reattachment is at capacity"
        );
        reattached.insert(
            id,
            Reattachment {
                access: private,
                created: Instant::now(),
                controller,
            },
        );
        Ok(())
    }

    pub async fn retry(&self, id: &str) -> Result<Value> {
        self.retry_inner(id, None).await
    }

    pub async fn retry_guarded(&self, id: &str, guard: PublishGuard) -> Result<Value> {
        guard()?;
        self.retry_inner(id, Some(guard)).await
    }

    async fn retry_inner(&self, id: &str, guard: Option<PublishGuard>) -> Result<Value> {
        self.preflight().await?;
        let id = Uuid::parse_str(id).context("invalid operation ID")?;
        let _submission = self.inner.submission.lock().await;
        let attachment = self
            .inner
            .reattached
            .lock()
            .map_err(poison)?
            .remove(&id)
            .context("retry requires freshly reattached native provider access")?;
        ensure!(
            attachment.created.elapsed() < Duration::from_secs(60),
            "native reattachment expired"
        );
        let plan = self.inner.read_plan(id, &attachment.access.master)?;
        check_access(&plan, &attachment.access, self.inner.instance)?;
        if let Work::Upload { roots, .. } = &plan.work {
            guard
                .as_ref()
                .context("backup retry requires a fresh device-HMAC publication guard")?(
            )?;
            check_roots(roots)?;
        }
        self.enqueue(
            Arc::new(plan),
            attachment.access,
            guard,
            true,
            attachment.controller,
            None,
        )
    }

    /// Stops new admission, cancels queued work and joins every actual owner.
    /// This intentionally cannot report clean shutdown while native I/O is alive.
    pub async fn shutdown(&self) -> Result<()> {
        self.join()
    }

    fn join(&self) -> Result<()> {
        self.inner.stopping.store(true, Ordering::Release);
        for stop in self.inner.active.lock().map_err(poison)?.values() {
            stop.store(true, Ordering::Release);
        }
        self.inner.reattached.lock().map_err(poison)?.clear();
        if let Some(worker) = self.worker.lock().map_err(poison)?.take() {
            worker.join().map_err(|_| {
                anyhow::anyhow!("native engine worker panicked; shutdown is not verified")
            })?;
        }
        ensure!(
            self.inner.active.lock().map_err(poison)?.is_empty(),
            "native engine still has unjoined work"
        );
        ensure!(!self.inner.finalization_failed.load(Ordering::Acquire),
            "native transport/session finalization is unverified; shutdown is not confirmed clean and private recovery artifacts are retained");
        completion::clear(&self.inner)?;
        catalog::clear(&self.inner)?;
        Ok(())
    }

    fn binding(&self, selection: &Value) -> Result<Arc<SoftwareBinding>> {
        let id = identifier(selection, "softwareId")?;
        let binding = self
            .inner
            .software
            .lock()
            .map_err(poison)?
            .get(&id)
            .cloned()
            .context("software has no registered approved native roots")?;
        if let Some(instance) = selection["appId"].as_str() {
            ensure!(
                instance == binding.instance,
                "native selection changed its actual software installation instance"
            );
        }
        if let Some(canonical) = selection
            .pointer("/sourceIdentity/app_id")
            .and_then(Value::as_str)
        {
            ensure!(
                canonical == binding.app.as_str(),
                "native selection changed its original canonical source application ID"
            );
        }
        Ok(binding)
    }

    fn private_access(
        &self,
        access: &ProviderAccess,
        operation: Option<Uuid>,
    ) -> Result<PrivateAccess> {
        validate_id(&access.provider_id)?;
        ensure!(
            serde_json::to_vec(&access.session)?.len() <= MAX_SESSION,
            "provider session exceeds its bound"
        );
        let operation_id = operation.unwrap_or_else(Uuid::new_v4).to_string();
        let context = self
            .workspace
            .as_ref()
            .map(|store| {
                crate::provider_lifecycle::prepare_native_provider_context(
                    store.clone(),
                    access,
                    &operation_id,
                    &self.inner.paths.run_root,
                )
            })
            .transpose()?;
        let access = context
            .as_ref()
            .map(|context| &context.access)
            .unwrap_or(access);
        ensure!(
            serde_json::to_vec(&access.session)?.len() <= MAX_SESSION,
            "recovered native provider session exceeds its bound"
        );
        let mut session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
            .map_err(|_| anyhow::anyhow!("invalid native No Land provider session"))?;
        ensure!(
            session.config_ini.len() <= MAX_SESSION,
            "native provider config exceeds its bound"
        );
        let kind =
            ProviderKind::parse(&session.provider).context("unknown native storage provider")?;
        ensure!(
            kind != ProviderKind::Local || cfg!(test),
            "local remotes are isolated test fixtures only"
        );
        session.operation_id = operation_id;
        let sink = if kind.is_oauth() && context.is_none() {
            let callback = self.inner.sinks.lock().map_err(poison)?.get(&access.provider_id).cloned()
                .context("OAuth storage requires the checked native-vault refresh callback for this provider")?;
            let authority = self
                .inner
                .authority
                .lock()
                .map_err(poison)?
                .clone()
                .context("native device-HMAC authority guard is not installed")?;
            let provider = access.provider_id.clone();
            let sink: NativePrivateCredentialSink = Arc::new(move |rotation| {
                authority(&provider, false)
                    .map_err(|_| StateError::Conflict("native provider was revoked".into()))?;
                callback(rotation)
            });
            Some(
                noland_storage::register_native_private_credential_sink(&session, sink)
                    .map_err(source_error)?,
            )
        } else {
            None
        };
        let provider = access.provider_id.clone();
        let master = MasterKey::from_bytes(access.repository_key);
        let read_only = access.read_only;
        let authority_revision = access
            .session
            .get("native_authority_revision")
            .map(|value| {
                value
                    .as_u64()
                    .context("native provider authority revision is invalid")
            })
            .transpose()?;
        let lifecycle = context.map(|context| Arc::new(context.lifecycle));
        Ok(PrivateAccess {
            provider,
            session,
            master,
            read_only,
            authority_revision,
            _sink: sink,
            lifecycle,
        })
    }

    fn session(
        &self,
        access: &PrivateAccess,
        guard: Option<PublishGuard>,
        stop: Arc<AtomicBool>,
        write: bool,
    ) -> Result<Session> {
        self.inner.session(access, guard, stop, write)
    }

    fn submit(
        &self,
        plan: FrozenPlan,
        access: PrivateAccess,
        guard: Option<PublishGuard>,
    ) -> Result<Value> {
        self.submit_with_controller(plan, access, guard, None)
    }

    fn submit_with_controller(
        &self,
        plan: FrozenPlan,
        access: PrivateAccess,
        guard: Option<PublishGuard>,
        controller: Option<Arc<dyn capture::NativeCaptureController>>,
    ) -> Result<Value> {
        self.submit_owned(plan, access, guard, controller, None)
    }

    fn submit_owned(
        &self,
        plan: FrozenPlan,
        access: PrivateAccess,
        guard: Option<PublishGuard>,
        controller: Option<Arc<dyn capture::NativeCaptureController>>,
        restore: Option<Arc<noland_restore::NativeRestoreControl>>,
    ) -> Result<Value> {
        plan.validate()?;
        deletion::check_guard(&plan, guard.as_ref())?;
        ensure!(
            matches!(
                &plan.work,
                Work::Upload {
                    capture_scope: Some(_),
                    ..
                }
            ) == controller.is_some(),
            "frozen native metadata scope lacks its owned Rust capture controller"
        );
        check_access(&plan, &access, self.inner.instance)?;
        ensure!(
            self.inner
                .db
                .get_operation(plan.operation)
                .map_err(source_error)?
                .is_none(),
            "operation ID already exists; retry its original authenticated frozen plan"
        );
        let bytes = plan.seal(&access.master)?;
        let authority = self
            .inner
            .operation_authority
            .lock()
            .map_err(poison)?
            .clone()
            .context("native operation plans require the installed device-key HMAC authority")?;
        let device_mac = authority(&bytes)?;
        let name = format!("{}.plan", plan.operation);
        self.inner.plans.write_new(&name, |file| {
            file.write_all(&bytes)?;
            Ok(())
        })?;
        self.inner
            .plans
            .write_new(&format!("{}.device", plan.operation), |file| {
                file.write_all(&device_mac)?;
                Ok(())
            })?;
        self.enqueue(Arc::new(plan), access, guard, false, controller, restore)
    }

    fn enqueue(
        &self,
        plan: Arc<FrozenPlan>,
        access: PrivateAccess,
        guard: Option<PublishGuard>,
        retry: bool,
        controller: Option<Arc<dyn capture::NativeCaptureController>>,
        restore: Option<Arc<noland_restore::NativeRestoreControl>>,
    ) -> Result<Value> {
        deletion::check_guard(&plan, guard.as_ref())?;
        ensure!(
            !self.inner.stopping.load(Ordering::Acquire),
            "native engine is stopping"
        );
        ensure!(
            matches!(
                &plan.work,
                Work::Upload {
                    capture_scope: Some(_),
                    ..
                }
            ) == controller.is_some(),
            "native metadata capture lost its original Rust receipt controller"
        );
        ensure!(
            matches!(&plan.work, Work::Download { .. }) == restore.is_some(),
            "native restore lost its original frozen in-process control"
        );
        if let Some(control) = &restore {
            restore::check_frozen_control(&plan, control)?;
            control.check_gate().map_err(source_error)?;
        }
        let permit = self
            .sender
            .try_reserve()
            .context("native engine queue is full or stopped")?;
        let id = plan.operation;
        let mut active = self.inner.active.lock().map_err(poison)?;
        ensure!(
            !active.contains_key(&id),
            "original native worker has not joined"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let now = chrono::Utc::now();
        let mut operation = if retry {
            let operation = self
                .inner
                .db
                .get_operation(id)
                .map_err(source_error)?
                .context("native retry operation disappeared")?;
            ensure!(
                matches!(
                    operation.state.as_str(),
                    "FAILED" | "CANCELLED" | "INTERRUPTED"
                ),
                "native operation is not retryable"
            );
            operation
        } else {
            OperationRecord {
                operation_id: id,
                kind: plan.kind().into(),
                app_id: plan.app(),
                state: "QUEUED".into(),
                created_at: now,
                updated_at: now,
                last_error: None,
                detail_json: json!({
                    "version":1,"provider_id":plan.provider,"storage":plan.storage,
                    "plan_hash":noland_storage::compact_json_hash(&*plan).map_err(source_error)?,
                }),
            }
        };
        operation.state = "QUEUED".into();
        operation.updated_at = now;
        operation.last_error = None;
        self.inner
            .db
            .upsert_operation(&operation)
            .map_err(source_error)?;
        let mut progress = OperationProgress::new("queued", 0);
        progress.detail_json = json!({"native_provider_id":plan.provider});
        if let Work::Upload {
            software,
            software_instance_id,
            ..
        } = &plan.work
        {
            progress.detail_json["native_software_id"] = json!(software);
            progress.detail_json["native_software_instance_id"] = json!(software_instance_id);
        }
        self.inner
            .db
            .set_operation_progress(id, Some(&progress))
            .map_err(source_error)?;
        active.insert(id, Arc::clone(&stop));
        drop(active);
        permit.send(Job {
            plan,
            access: Arc::new(access),
            guard,
            stop,
            controller,
            restore,
        });
        // After the durable row + infallible reserved send, ALWAYS return its ID.
        // Later errors belong to the monitored owned operation, not admission.
        Ok(json!({"operationId":id}))
    }
}

impl Drop for NativeEngine {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

impl Inner {
    fn bound_upload_guard(
        self: &Arc<Self>,
        plan: &FrozenPlan,
        guard: PublishGuard,
    ) -> Result<PublishGuard> {
        let Work::Upload {
            software,
            software_instance_id,
            source_identity,
            roots,
            ..
        } = &plan.work
        else {
            return Ok(guard);
        };
        let software = software.clone();
        let software_instance_id = software_instance_id.clone();
        let fingerprint =
            noland_storage::compact_json_hash(source_identity).map_err(source_error)?;
        let roots = roots.clone();
        let inner = Arc::downgrade(self);
        Ok(Arc::new(move || {
            guard()?;
            let inner = inner
                .upgrade()
                .context("native engine owner is unavailable")?;
            let registered = inner
                .software
                .lock()
                .map_err(poison)?
                .get(&software)
                .cloned()
                .context("native approved software binding was removed")?;
            ensure!(
                registered.instance == software_instance_id
                    && registered.identity_fingerprint == fingerprint
                    && registered
                        .roots
                        .iter()
                        .map(|root| &root.spec)
                        .eq(roots.iter()),
                "native application identity, role, leaf scope or root binding changed"
            );
            check_roots(&roots)
        }))
    }

    fn read_plan(&self, id: Uuid, master: &MasterKey) -> Result<FrozenPlan> {
        let name = format!("{id}.plan");
        let (file, stamp) = self.plans.read_file(&name)?;
        verify_private_file(&file)?;
        ensure!(
            stamp.size <= (MAX_PLAN_BYTES + 1024 * 1024) as u64,
            "native plan exceeds its bound"
        );
        let mut bytes = Vec::new();
        file.take((MAX_PLAN_BYTES + 1024 * 1024 + 1) as u64)
            .read_to_end(&mut bytes)?;
        self.plans.verify_file(&name, &stamp)?;
        let authority = self
            .operation_authority
            .lock()
            .map_err(poison)?
            .clone()
            .context("native device-key operation authority is unavailable")?;
        let expected = authority(&bytes)?;
        let device_name = format!("{id}.device");
        let (mut file, signature_stamp) = self.plans.read_file(&device_name)?;
        verify_private_file(&file)?;
        ensure!(
            signature_stamp.size == 32,
            "native device-HMAC receipt has an invalid size"
        );
        let mut observed = [0u8; 32];
        file.read_exact(&mut observed)?;
        self.plans.verify_file(&device_name, &signature_stamp)?;
        let difference = observed
            .iter()
            .zip(expected)
            .fold(0u8, |difference, (a, b)| difference | (*a ^ b));
        ensure!(
            difference == 0,
            "native frozen-plan device-HMAC verification failed"
        );
        let plan = FrozenPlan::open(bytes, master)?;
        ensure!(
            plan.operation == id && plan.instance == self.instance,
            "foreign native frozen plan"
        );
        Ok(plan)
    }

    fn check(
        self: &Arc<Self>,
        provider: String,
        write: bool,
        guard: Option<PublishGuard>,
        stop: Arc<AtomicBool>,
    ) -> Check {
        let inner = Arc::clone(self);
        Arc::new(move || {
            if stop.load(Ordering::Acquire)
                || inner.stopping.load(Ordering::Acquire)
                || inner.finalization_failed.load(Ordering::Acquire)
            {
                return Err(StateError::Conflict(
                    "native operation cancelled or stopping".into(),
                ));
            }
            inner
                ._owner
                .check()
                .map_err(|_| StateError::Conflict("native owner lock changed".into()))?;
            let authority = inner
                .authority
                .lock()
                .map_err(|_| StateError::Conflict("native authority lock poisoned".into()))?
                .clone();
            match (&authority, &guard) {
                (Some(authority), _) => authority(&provider, write).map_err(|_| {
                    StateError::Conflict("native provider/device-HMAC authority changed".into())
                })?,
                (None, Some(_)) if write => {}
                _ => {
                    return Err(StateError::Conflict(
                        "native device-HMAC authority guard is not installed".into(),
                    ))
                }
            }
            if let Some(guard) = &guard {
                guard().map_err(|_| {
                    StateError::Conflict("native publication authority changed".into())
                })?;
            }
            Ok(())
        })
    }

    fn session(
        self: &Arc<Self>,
        access: &PrivateAccess,
        guard: Option<PublishGuard>,
        stop: Arc<AtomicBool>,
        write: bool,
    ) -> Result<Session> {
        let stream_stop = Arc::clone(&stop);
        let check = self.check(access.provider.clone(), write, guard, stop);
        check().map_err(source_error)?;
        let (config, session) =
            write_guarded_ephemeral_session(&self.paths.run_root, &access.session)
                .map_err(source_error)?;
        let kind = ProviderKind::parse(&access.session.provider)
            .context("native provider kind missing")?;
        let tuning = TransferTuning::automatic(kind, TransferWorkload::Throughput);
        let inner = RcloneStorage::try_from_session(&access.session, &config)
            .map_err(source_error)?
            .with_transfer_tuning(tuning);
        Ok(Session {
            provider: CheckedProvider {
                inner,
                check,
                read_only: access.read_only,
                stream_stop,
                lifecycle: access.lifecycle.clone(),
                publication: None,
            },
            guard: Some(session),
            finalization_failed: Arc::clone(&self.finalization_failed),
        })
    }

    pub(super) fn progress(
        &self,
        id: Uuid,
        phase: &str,
        done: u64,
        total: Option<u64>,
        unit: &str,
    ) -> Result<()> {
        let mut progress = self
            .db
            .get_operation_progress(id)
            .map_err(source_error)?
            .unwrap_or_else(|| OperationProgress::new(phase, done));
        progress.phase = phase.into();
        progress.completed_units = done;
        progress.updated_at = chrono::Utc::now();
        progress.total_units = total;
        progress.unit = Some(unit.into());
        self.db
            .set_operation_progress(id, Some(&progress))
            .map_err(source_error)
    }

    fn state(&self, id: Uuid, state: &str, reason: Option<&str>) -> Result<()> {
        let mut operation = self
            .db
            .get_operation(id)
            .map_err(source_error)?
            .context("native journal row missing")?;
        operation.state = state.into();
        operation.updated_at = chrono::Utc::now();
        operation.last_error = reason.map(str::to_owned);
        self.db.upsert_operation(&operation).map_err(source_error)
    }
}

struct Session {
    provider: CheckedProvider,
    guard: Option<EphemeralSessionGuard>,
    finalization_failed: Arc<AtomicBool>,
}
impl Session {
    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        // All actual transport futures/workers have drained before this call.
        let checkpoint = self
            .provider
            .lifecycle
            .as_ref()
            .map(|lifecycle| lifecycle.checkpoint())
            .transpose();
        let finish = self
            .guard
            .take()
            .context("native session already finalized")
            .and_then(|guard| guard.finish().map_err(source_error));
        if checkpoint.is_err() || finish.is_err() {
            // A failed guard can mean an unconfirmed child reap. Do not treat
            // an empty Rust work queue as proof that native execution stopped.
            self.finalization_failed.store(true, Ordering::Release);
        }
        let value = result?;
        checkpoint?;
        finish?;
        Ok(value)
    }
}

async fn work_loop(inner: Arc<Inner>, mut receiver: mpsc::Receiver<Job>) {
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        if inner.stopping.load(Ordering::Acquire) {
            receiver.close();
        }
        // A reattachment is single-use and short-lived, never a permanent
        // credential cache after work/restart/revocation.
        if let Ok(mut pending) = inner.reattached.lock() {
            pending.retain(|_, entry| entry.created.elapsed() < Duration::from_secs(60));
        }
        tokio::select! {
            joined = jobs.join_next(), if !jobs.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    // The durable nonterminal row remains interrupted, never a
                    // fabricated terminal success if an owner panics.
                    inner.stopping.store(true, Ordering::Release);
                }
            }
            job = receiver.recv(), if jobs.len() < MAX_ACTIVE => {
                match job {
                    Some(job) => {
                        let inner = Arc::clone(&inner);
                        jobs.spawn(async move { run_owned(inner, job).await; });
                    }
                    None if jobs.is_empty() => break,
                    None => {
                        while jobs.join_next().await.is_some() {}
                        break;
                    }
                }
            }
            // Bounded wake for synchronous Drop/shutdown without detached wake
            // tasks or depending on another caller to send into a full queue.
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

struct WorkspaceRecovery(WorkspaceStore);
impl NativeRecoveryAuthority for WorkspaceRecovery {
    fn mac(&self, bytes: &[u8]) -> noland_state_core::Result<[u8; 32]> {
        self.0.recovery_mac_existing(bytes).map_err(|_| {
            StateError::Conflict("native device-key recovery authority is unavailable".into())
        })
    }
}

async fn run_owned(inner: Arc<Inner>, job: Job) {
    let id = job.plan.operation;
    let result = execute(&inner, &job).await;
    // execute has drained native workers and finalized the real session, on
    // success AND failure. Only now may registrations be invalidated; doing so
    // while a child can still rotate its token would prevent its checked handoff.
    let invalidated = (|| {
        ensure!(!inner.finalization_failed.load(Ordering::Acquire),
            "native execution finalization is unverified; retained handoffs require checked recovery");
        if let Some(lifecycle) = &job.access.lifecycle {
            lifecycle.invalidate()?;
        }
        if let Some(sink) = &job.access._sink {
            sink.invalidate().map_err(source_error)?;
        }
        Ok::<_, anyhow::Error>(())
    })();
    if invalidated.is_err() {
        inner.finalization_failed.store(true, Ordering::Release);
    }
    let result = result
        .and(invalidated)
        .and_then(|()| completion::finalize(&inner, &job));
    let cancelled = job.stop.load(Ordering::Acquire) || inner.stopping.load(Ordering::Acquire);
    let terminal = if result.is_ok() {
        "COMPLETED"
    } else if cancelled {
        "CANCELLED"
    } else {
        "FAILED"
    };
    let recorded = inner.state(id, terminal, result.as_ref().err().map(|_| {
        "Native storage operation stopped; private provider details withheld. Resume only the original frozen plan with fresh native access."
    }));
    // Only joined success retains bounded, original completion-only access.
    // It cannot create a transport/retry and is never serialized to native state.
    if recorded.is_ok() && result.is_ok() {
        if completion::retain(&inner, &job).is_err() {
            inner.finalization_failed.store(true, Ordering::Release);
        }
    } else if completion::discard_pending(&inner, id).is_err() {
        inner.finalization_failed.store(true, Ordering::Release);
    }
    drop(job);
    if recorded.is_ok() {
        if let Ok(mut active) = inner.active.lock() {
            active.remove(&id);
        }
    } else {
        // Failed durable terminalization intentionally keeps shutdown blocked.
        inner.stopping.store(true, Ordering::Release);
    }
}

async fn execute(inner: &Arc<Inner>, job: &Job) -> Result<()> {
    deletion::check_guard(&job.plan, job.guard.as_ref())?;
    check_access(&job.plan, &job.access, inner.instance)?;
    let write = !matches!(job.plan.work, Work::Download { .. });
    let publication_guard = match &job.guard {
        Some(guard) => Some(inner.bound_upload_guard(&job.plan, Arc::clone(guard))?),
        None => None,
    };
    let mut session = inner.session(
        &job.access,
        publication_guard.clone(),
        Arc::clone(&job.stop),
        write,
    )?;
    if let Some(controller) = &job.controller {
        let controller = Arc::clone(controller);
        session.provider.publication = Some(Arc::new(move || {
            controller.verify_publication().map_err(|_| {
                StateError::Conflict(
                    "native tracking refused the accepted source receipt before publication".into(),
                )
            })
        }));
    }
    let result = async {
        let _repository = inner.repository.lock().await;
        let _local = inner.state.lock("repository-admission.lock")?;
        let owner = owner(&job.access.master, inner.instance);
        recover_own_claims(
            &session.provider,
            &job.access.master,
            inner.instance,
            &owner,
        )
        .await?;
        inner.state(job.plan.operation, "RUNNING", None)?;
        let scope = if write {
            RepositoryAccess::Exclusive
        } else {
            RepositoryAccess::RestoreRead
        };
        let lease = RepositoryGuard::acquire_for_instance(
            &session.provider,
            &job.access.master,
            job.plan.operation,
            &owner,
            inner.instance,
            scope,
        )
        .await
        .map_err(source_error)?;
        let result = match &job.plan.work {
            Work::Upload { .. } => pipeline::upload(inner, job, &session.provider).await,
            Work::Download { .. } => pipeline::download(inner, job, &session.provider).await,
            Work::Delete { plan, .. } => {
                let observer = pipeline::DeletionProgressSink { inner, job };
                noland_storage::execute_full_deletion_observed(
                    &session.provider,
                    &job.access.master,
                    plan,
                    Some(&observer),
                )
                .await
                .map_err(source_error)
            }
        };
        // Borrowed portable transfer windows and native workers have all drained
        // before releasing this execution's unique repository claim.
        let released = lease.release().await.map_err(source_error);
        if released.is_err() {
            inner
                .db
                .journal_put(
                    &job.plan.operation.to_string(),
                    "repository-admission",
                    "control",
                    "CLEANUP_REQUIRED",
                    Some("exact execution claim cleanup unconfirmed"),
                )
                .map_err(source_error)?;
        }
        result?;
        released?;
        (session.provider.check)().map_err(source_error)?;
        if let Work::Upload { roots, .. } = &job.plan.work {
            check_roots(roots)?;
            let guard = publication_guard
                .clone()
                .context("native publication guard missing")?;
            guard()?;
            let mut proofs = inner.proofs.lock().map_err(poison)?;
            if proofs.len() >= 128 {
                proofs.clear();
            }
            proofs.insert(
                job.plan.operation,
                PublicationProof {
                    guard,
                    roots: roots.clone(),
                    capture: inner
                        .captures
                        .lock()
                        .map_err(poison)?
                        .get(&job.plan.operation)
                        .map(|(_, receipt)| Weak::clone(receipt)),
                },
            );
        }
        Ok(())
    }
    .await;
    session.finish(result)
}

fn freeze_files(binding: &SoftwareBinding, selection: &Value) -> Result<Vec<ExpectedFile>> {
    let ids = selection["fileIds"]
        .as_array()
        .context("native upload requires frozen explicit fileIds")?;
    let evidence = selection["captureSource"]["expectedFiles"]
        .as_array()
        .context("native upload requires canonical tracker expectedFiles")?;
    ensure!(
        !ids.is_empty() && ids.len() <= MAX_FILES && evidence.len() == ids.len(),
        "capture selection/evidence bound or count mismatch"
    );
    let selected = ids
        .iter()
        .map(|id| id.as_str().context("file ID must be text"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(selected.len() == ids.len(), "duplicate selected file");
    let lookup = binding
        .index
        .iter()
        .filter_map(|item| item["id"].as_str().map(|id| (id, item)))
        .collect::<BTreeMap<_, _>>();
    let mut files = BTreeMap::new();
    for expected in evidence {
        let id = expected["id"]
            .as_str()
            .context("expected file ID missing")?;
        ensure!(
            selected.contains(id),
            "expected file is outside the exact selected set"
        );
        let item = lookup
            .get(id)
            .context("selected file is outside the native metadata index")?;
        ensure!(item["fileType"].as_str() == Some("file"),
            "canonical tracker expectedFiles authorizes regular files only; link/directory work requires its native metadata receipt");
        let root = binding
            .roots
            .iter()
            .find(|r| Some(r.spec.logical.as_str()) == item["rootId"].as_str())
            .context("selected logical root is no longer bound")?;
        ensure!(
            root.handle.identity()? == root.spec.identity,
            "approved native root changed"
        );
        let relative = item["path"].as_str().context("selected path missing")?;
        validate_relative(relative)?;
        let (_, stamp) = root.handle.read_file(relative)?;
        let size = expected["size"]
            .as_u64()
            .context("expected file size missing")?;
        ensure!(
            stamp.size == size,
            "source size differs from frozen tracker evidence"
        );
        let hash = canonical_hash(
            expected["fileHash"]
                .as_str()
                .context("expected file hash missing")?,
        )?;
        ensure!(
            files
                .insert(
                    id.to_owned(),
                    ExpectedFile {
                        id: id.into(),
                        root: root.spec.logical.clone(),
                        relative: relative.into(),
                        stamp,
                        size,
                        hash,
                    }
                )
                .is_none(),
            "duplicate expected capture evidence"
        );
    }
    ensure!(
        files.len() == selected.len(),
        "expected evidence omits selected files"
    );
    Ok(files.into_values().collect())
}

fn freeze_metadata(
    binding: &SoftwareBinding,
    files: &[ExpectedFile],
    coverage: NativeCoverage,
) -> Result<(Vec<FrozenMetadata>, bool)> {
    if coverage != NativeCoverage::FullApprovedScope {
        return Ok((Vec::new(), false));
    }
    let selected = files
        .iter()
        .map(|file| file.id.as_str())
        .collect::<BTreeSet<_>>();
    let indexed_regular = binding
        .index
        .iter()
        .filter(|entry| entry["fileType"] == "file")
        .filter_map(|entry| entry["id"].as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        selected == indexed_regular,
        "full approved-scope capture differs from its exact native file index"
    );
    let expected = files
        .iter()
        .map(|file| (file.id.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut observed_regular = BTreeSet::new();
    let mut metadata = Vec::new();
    for root in &binding.roots {
        ensure!(
            root.handle.identity()? == root.spec.identity,
            "native root changed before metadata capture"
        );
        if let Some(leaves) = &root.spec.allowed_files {
            for leaf in leaves {
                observed_regular.insert(file_id(&root.spec.logical, leaf));
            }
            continue;
        }
        // One metadata walk belongs to explicit capture, never UI polling.
        // A stale real index cannot masquerade as a complete application graph.
        for entry in root.handle.metadata_entries()? {
            let id = file_id(&root.spec.logical, &entry.relative_path);
            if entry.kind == EntryKind::File {
                let frozen = expected.get(id.as_str()).context(
                    "source metadata index changed; refresh its native index before capture",
                )?;
                ensure!(
                    frozen.stamp == entry.stamp,
                    "source changed while freezing native metadata"
                );
                observed_regular.insert(id);
            } else {
                metadata.push(FrozenMetadata {
                    root: root.spec.logical.clone(),
                    relative: entry.relative_path,
                    directory: entry.kind == EntryKind::Directory,
                    stamp: entry.stamp,
                    link: entry.link,
                });
            }
            ensure!(
                metadata.len().saturating_add(files.len()) <= MAX_FILES,
                "native complete capture metadata bound exceeded"
            );
        }
    }
    ensure!(
        observed_regular
            .iter()
            .map(String::as_str)
            .eq(selected.iter().copied()),
        "source file set changed; refresh its native index before capture"
    );
    Ok((metadata, true))
}

pub(super) fn check_roots(roots: &[RootSpec]) -> Result<()> {
    for root in roots {
        ensure!(
            SafeRoot::open(&root.path)?.identity()? == root.identity,
            "native approved root changed"
        );
    }
    Ok(())
}

fn check_access(plan: &FrozenPlan, access: &PrivateAccess, instance: Uuid) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.instance == instance
            && plan.provider == access.provider
            && plan.storage == access.session.root_cache_key()
            && access.session.operation_id == plan.operation.to_string(),
        "native provider, repository root or operation binding changed"
    );
    ensure!(
        matches!(plan.work, Work::Download { .. }) || !access.read_only,
        "native provider write authority is read-only"
    );
    Ok(())
}

async fn manifest(
    provider: &dyn SharedStorageProvider,
    master: &MasterKey,
    selection: &Value,
) -> Result<BundleManifest> {
    let manifest = read_committed_manifest(
        provider,
        master,
        &AppId(identifier(selection, "appId")?),
        parse_uuid(selection, "bundleId")?,
    )
    .await
    .map_err(source_error)?;
    ensure!(
        manifest.files.len() <= MAX_FILES,
        "authenticated manifest entry bound exceeded"
    );
    Ok(manifest)
}

async fn recover_own_claims(
    provider: &dyn SharedStorageProvider,
    master: &MasterKey,
    instance: Uuid,
    owner: &str,
) -> Result<()> {
    for activity in repository_activities(provider, master)
        .await
        .map_err(source_error)?
    {
        if activity.owner == owner && activity.instance_id == Some(instance) {
            // Caller holds the same durable agent's native process/OS admission
            // locks; no timestamp is used to infer another execution's death.
            clear_repository_activity(provider, master, &activity)
                .await
                .map_err(source_error)?;
        }
    }
    Ok(())
}

fn owner(master: &MasterKey, instance: Uuid) -> String {
    blake3::keyed_hash(&master.0, instance.to_string().as_bytes())
        .to_hex()
        .to_string()
}

fn approved_destination(selection: &Value, path: &Path, pinned: &RootIdentity) -> Result<()> {
    let Some(proofs) = selection.get("_approvedPaths") else {
        return Ok(());
    };
    let proofs = proofs
        .as_array()
        .context("native approved path proofs must be an array")?;
    ensure!(proofs.len() <= 256, "native approval path bound exceeded");
    let matches = proofs
        .iter()
        .filter(|p| p["path"].as_str() == path.to_str())
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1 && matches[0]["kind"].as_str() == Some("directory"),
        "destination lacks its exact native directory approval"
    );
    let expected: RootIdentity = serde_json::from_value(matches[0]["identity"].clone())?;
    ensure!(
        &expected == pinned,
        "native destination changed after confirmation"
    );
    Ok(())
}

fn parse_uuid(value: &Value, key: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(
        value[key]
            .as_str()
            .with_context(|| format!("{key} is required"))?,
    )?;
    ensure!(!id.is_nil(), "native UUID is nil");
    Ok(id)
}
fn operation_id(value: &Value) -> Result<Uuid> {
    if value.get("operationId").is_some() {
        parse_uuid(value, "operationId")
    } else {
        Ok(Uuid::new_v4())
    }
}
fn safe_phase(phase: &str) -> String {
    phase
        .chars()
        .take(80)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '))
        .collect()
}
fn poison<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("native engine lock poisoned")
}
pub(super) fn source_error(error: StateError) -> anyhow::Error {
    anyhow::anyhow!(match error {
        StateError::UnsafePath(_) =>
            "native storage rejected an unsafe path or changed filesystem identity",
        StateError::Integrity(_) | StateError::Crypto(_) =>
            "shared-storage authentication or integrity verification failed",
        StateError::Conflict(_) =>
            "native authorization changed, operation stopped, or repository admission is busy",
        StateError::NotFound(_) => "native shared-storage item was not found",
        StateError::Database(_) => "native SQLite operation failed",
        StateError::Io(_) => "native filesystem/flush or packaged-tool operation failed",
        StateError::Invalid(_) => "native request or original frozen selection is invalid",
        _ => "native storage operation failed; private provider details withheld",
    })
}
