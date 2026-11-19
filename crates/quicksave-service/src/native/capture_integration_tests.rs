// SPDX-License-Identifier: GPL-3.0-only
// Derived fixture/API patterns: No Land e81238a7536aae201540956ce76981364fd36595,
// shared-storage/crates/noland-testkit/tests/native_optimized_pipeline.rs.
//! Real service Tracker/WorkspaceStore/MemoryVault -> CaptureController ->
//! source native capture -> encrypted LocalStorage commit -> Tracker baseline.
//! This is not an RPC, live-provider, OS-vault, observer, or packaging test.
//! Fresh capture uses the production sink/controller. Restart adapters delegate
//! only actual private source receipts and real device grants; commit witnesses
//! require authenticated LocalStorage objects, never a successful DB status.

use super::*;
use anyhow::Context;
use bytes::Bytes;
use chrono::Utc;
use noland_crypto::MasterKey;
use noland_rpc::{RpcHandler, RpcRequest};
use noland_snapshot::SourcePath;
use noland_state_agent::{
    backup::run_backup,
    native_capture,
    native_host::{
        native_file_id, ApprovedNativeRoot, NativeCoverage, NativeRootRole, NativeSelection,
    },
    AgentConfig, StateAgent,
};
use noland_state_core::{
    bundle_dir, pack_key, AgentPaths, AppId, AppIdentity, AppMutationKind, AppMutationRecord,
    BackupMode, BackupPerformanceMode, BundleManifest, LauncherKind, OperationMetrics,
    OperationRecord, Result as SourceResult, StateError,
};
use noland_storage::{
    DownloadObserver, DownloadStreamConsumer, EphemeralRcloneSession, Health, LocalStorage,
    MetadataReadMetrics, ProviderRootIdentity, RemoteEntry, RemoteKey, RemoteMeta,
    SharedStorageProvider, StorageOperationMetrics,
};
use quicksave_noland::capture_control::{
    self, CaptureScope, NativeCaptureController, NativeFullScopeBinding,
};
use quicksave_platform::{FileStamp, SafeRoot};
use quicksave_state::MemoryVault;
use quicksave_tracking::NativeFrozenWork;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    future::Future,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use uuid::Uuid;

// Workspace row IDs are filename-safe opaque IDs. They are NOT canonical app
// IDs or installation identities; keep all three domains genuinely distinct.
const SOFTWARE: &str = "fixture-steam-software";
const INSTANCE: &str = "steam:480@fixture-installation";
const CANONICAL: &str = "steam:480";
const MAX_APP_FILES: usize = 64;
const MAX_APP_BYTES: usize = 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_IO_KEYS: usize = 1024;
type SourceFuture<'a, T> = Pin<Box<dyn Future<Output = SourceResult<T>> + Send + 'a>>;

#[derive(Clone, Default)]
struct FixtureIo {
    operations: StorageOperationMetrics,
    metadata: MetadataReadMetrics,
    pack_uploads: u64,
    pack_bytes: u64,
    writes: Vec<String>,
    deletions: Vec<String>,
}

struct MarkerPause {
    entered: oneshot::Sender<RemoteKey>,
    release: oneshot::Receiver<()>,
}

/// Instrumentation and one deterministic publication barrier only. Every byte,
/// immutable comparison, read, write, fsync, and repository-claim removal still
/// goes through the actual source LocalStorage. No provider SDK/session is run.
struct FixtureStorage {
    inner: LocalStorage,
    io: Mutex<FixtureIo>,
    marker_pause: Mutex<Option<MarkerPause>>,
}

impl FixtureStorage {
    fn new(root: PathBuf) -> Self {
        Self {
            inner: LocalStorage::new(root),
            io: Mutex::new(FixtureIo::default()),
            marker_pause: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> FixtureIo {
        self.io.lock().unwrap().clone()
    }

    fn pause_next_bundle_marker(&self) -> (oneshot::Receiver<RemoteKey>, oneshot::Sender<()>) {
        let (entered, receiver) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let previous = self.marker_pause.lock().unwrap().replace(MarkerPause {
            entered,
            release: resume,
        });
        assert!(previous.is_none(), "only one bounded marker barrier");
        (receiver, release)
    }

    fn record_write(&self, key: &RemoteKey, size: u64) {
        let mut io = self.io.lock().unwrap();
        assert!(io.writes.len() < MAX_IO_KEYS, "bounded fixture write log");
        io.writes.push(key.as_str().to_owned());
        io.operations.remote_upload_calls += 1;
        io.operations.bytes_uploaded += size;
        if key.as_str().starts_with("packs/") {
            io.pack_uploads += 1;
            io.pack_bytes += size;
        }
    }
}

// Explicit async-trait boxed-future ABI, as in the source integration fixture.
// Keep streaming/targeted capabilities rather than changing the real pipeline.
impl SharedStorageProvider for FixtureStorage {
    fn health_check<'a, 't>(&'a self) -> SourceFuture<'t, Health>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.inner.health_check().await })
    }

    fn ensure_root<'a, 't>(&'a self) -> SourceFuture<'t, ()>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.inner.ensure_root().await })
    }

    fn stat<'a, 'b, 't>(&'a self, key: &'b RemoteKey) -> SourceFuture<'t, Option<RemoteMeta>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.io.lock().unwrap().operations.remote_stat_calls += 1;
            self.inner.stat(key).await
        })
    }

    fn upload_immutable<'a, 'b, 'c, 't>(
        &'a self,
        local: &'b Path,
        key: &'c RemoteKey,
    ) -> SourceFuture<'t, RemoteMeta>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        Self: 't,
    {
        Box::pin(async move {
            let written = self.inner.upload_immutable(local, key).await?;
            self.record_write(key, written.size);
            Ok(written)
        })
    }

    fn download<'a, 'b, 'c, 't>(
        &'a self,
        key: &'b RemoteKey,
        destination: &'c Path,
    ) -> SourceFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.inner.download(key, destination).await?;
            let size = fs::metadata(destination)?.len();
            let mut io = self.io.lock().unwrap();
            io.operations.remote_download_calls += 1;
            io.operations.bytes_downloaded += size;
            Ok(())
        })
    }

    fn read_small<'a, 'b, 't>(&'a self, key: &'b RemoteKey, limit: u64) -> SourceFuture<'t, Vec<u8>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            {
                let mut io = self.io.lock().unwrap();
                io.metadata.read_calls += 1;
                io.metadata.attempts += 1;
            }
            let bytes = self.inner.read_small(key, limit).await?;
            let mut io = self.io.lock().unwrap();
            io.metadata.bytes_received += bytes.len() as u64;
            io.operations.remote_download_calls += 1;
            io.operations.bytes_downloaded += bytes.len() as u64;
            Ok(bytes)
        })
    }

    fn list_prefix<'a, 'b, 't>(
        &'a self,
        prefix: &'b RemoteKey,
    ) -> SourceFuture<'t, Vec<RemoteEntry>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.io.lock().unwrap().operations.remote_list_calls += 1;
            self.inner.list_prefix(prefix).await
        })
    }

    fn put_small_versioned<'a, 'b, 't>(
        &'a self,
        bytes: Bytes,
        key: &'b RemoteKey,
    ) -> SourceFuture<'t, RemoteMeta>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            let pause =
                if key.as_str().starts_with("bundles/") && key.as_str().ends_with("/COMMITTED") {
                    self.marker_pause.lock().unwrap().take()
                } else {
                    None
                };
            if let Some(pause) = pause {
                pause.entered.send(key.clone()).map_err(|_| {
                    StateError::Storage("isolated publication barrier was abandoned".into())
                })?;
                pause.release.await.map_err(|_| {
                    StateError::Storage("isolated publication barrier was not released".into())
                })?;
            }
            let written = self.inner.put_small_versioned(bytes, key).await?;
            self.record_write(key, written.size);
            Ok(written)
        })
    }

    fn delete_object<'a, 'b, 't>(&'a self, key: &'b RemoteKey) -> SourceFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            // Exact repository-activity cleanup is not version retirement.
            if !key.as_str().starts_with("maintenance/activity/") {
                return Err(StateError::Storage(
                    "capture fixture forbids payload/history deletion".into(),
                ));
            }
            self.inner.delete_object(key).await?;
            let mut io = self.io.lock().unwrap();
            assert!(io.deletions.len() < MAX_IO_KEYS);
            io.deletions.push(key.as_str().to_owned());
            Ok(())
        })
    }

    fn supports_targeted_uploads(&self) -> bool {
        self.inner.supports_targeted_uploads()
    }

    fn supports_streaming_downloads(&self) -> bool {
        self.inner.supports_streaming_downloads()
    }

    fn download_stream_observed<'a, 'b, 'c, 'd, 'e, 'f, 't>(
        &'a self,
        key: &'b RemoteKey,
        scratch: &'c Path,
        consumer: &'d dyn DownloadStreamConsumer,
        observer: Option<&'e (dyn DownloadObserver + 'f)>,
    ) -> SourceFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        'd: 't,
        'e: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.inner
                .download_stream_observed(key, scratch, consumer, observer)
                .await
        })
    }

    fn storage_identity(&self) -> Option<ProviderRootIdentity> {
        self.inner.storage_identity()
    }

    fn operation_metrics(&self) -> StorageOperationMetrics {
        self.io.lock().unwrap().operations
    }

    fn metadata_read_metrics(&self) -> MetadataReadMetrics {
        self.io.lock().unwrap().metadata
    }
}

struct PreparedWork {
    operation: Uuid,
    work: Value,
    scope: CaptureScope,
    selection: NativeSelection,
    full_evidence: Option<Value>,
    controller: Arc<crate::capture::CaptureController>,
    publication_checks: Arc<AtomicUsize>,
}

struct Fixture {
    agent: Arc<StateAgent>,
    tracking: Arc<TrackingAdapter>,
    store: WorkspaceStore,
    vault: Arc<MemoryVault>,
    storage: FixtureStorage,
    master: MasterKey,
    provider_id: String,
    app: AppId,
    source: PathBuf,
    data: PathBuf,
    initial_files: BTreeMap<String, Vec<u8>>,
    // Last: all native workers/handles are drained/dropped before temp cleanup.
    _temporary: TempDir,
}

impl Fixture {
    fn create() -> Result<Self> {
        let temporary_parent = std::env::temp_dir().canonicalize()?;
        let approved = temporary_parent.join("opencode");
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-service-capture-")
            .tempdir_in(if approved.is_dir() {
                approved
            } else {
                temporary_parent
            })?;
        let base = temporary.path().canonicalize()?;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
        let data = base.join("workspace");
        let source_data = base.join("source-native-state");
        let source = base.join("Isolated Fixture.app");
        let home = base.join("synthetic-home");
        let remote = base.join("isolated-local-provider");
        for path in [&source, &home, &remote, &source_data] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let initial_files = BTreeMap::from([
            ("save.dat".to_owned(), vec![0x51; 8 * 1024]),
            ("profile/slot.dat".to_owned(), vec![0x62; 4 * 1024]),
        ]);
        ensure!(
            initial_files.len() <= MAX_APP_FILES
                && initial_files.values().map(Vec::len).sum::<usize>() <= MAX_APP_BYTES,
            "bounded synthetic application fixture"
        );
        fs::create_dir(source.join("profile"))?;
        fs::create_dir(source.join("profile/empty"))?;
        for (relative, bytes) in &initial_files {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(source.join(relative))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        std::os::unix::fs::symlink("../save.dat", source.join("profile/current-save"))?;

        let vault = Arc::new(MemoryVault::default());
        let store = WorkspaceStore::open_with_vault(&data, vault.clone())
            .context("fixture creation: open isolated WorkspaceStore with MemoryVault")?;
        // Local profile construction/validation only. These synthetic credentials
        // are never passed to RcloneStorage, an SDK, or an external executable.
        let configured = store
            .connect_provider(&json!({
                "kind":"generic_s3","name":"Synthetic capture authority (no network)",
                "bucket":"synthetic-fixture-bucket","prefix":"synthetic-capture",
                "readOnly":true,
                "fields":{"endpoint":"https://capture-fixture.example.invalid"},
                "credentials":{"type":"s3","value":{
                    "access_key_id":"SYNTHETIC-CAPTURE-ACCESS",
                    "secret_access_key":"SYNTHETIC-CAPTURE-SECRET","session_token":null,
                }},
            }))
            .context("fixture creation: configure synthetic provider locally (no network)")?;
        let provider_id = configured["providers"][0]["id"]
            .as_str()
            .context("synthetic provider profile was not persisted")?
            .to_owned();
        assert!(!store.provider_writable(&provider_id)?);
        // Explicit injected fixture report, NOT a successful real S3 health
        // check. A real production account is neither opened nor contacted.
        store.record_provider_health(
            &provider_id,
            &json!({
                "providerId":provider_id,"canList":true,"repositoryAccessible":true,
                "repositoryEmpty":true,"canRead":false,"keyVerified":false,
                "evidence":{"fixture":"injected_synthetic_empty_repository_report","network":false},
            }),
        ).context("fixture creation: persist explicitly injected synthetic health report")?;
        assert!(!store.provider_writable(&provider_id)?);
        store
            .grant_provider_write(&provider_id)
            .context("fixture creation: grant synthetic provider writes")?;
        assert!(store.provider_writable(&provider_id)?);
        let access = store
            .provider_access(&provider_id, "isolated-source-key-handoff")
            .context("fixture creation: read synthetic key through MemoryVault provider access")?;
        let master = MasterKey::from_bytes(access.repository_key);
        drop(access);

        let mut policy = TrackingPolicy::new(&data);
        policy.supports_metadata_snapshots = true;
        policy.supports_deletion_snapshots = true;
        policy.max_file_bytes = MAX_APP_BYTES as u64;
        policy.audit_interval = Duration::from_secs(3600);
        policy.excluded_paths = vec![source_data.clone(), home.clone(), remote.clone()];
        let tracking = Arc::new(TrackingAdapter {
            tracker: Mutex::new(None),
            store: store.clone(),
            engine: None,
            observation: Mutex::new(None),
            observation_enabled: false,
            bootstrap: Some(TrackingBootstrap {
                store: Arc::new(StoreAdapter(store.clone(), None)),
                enqueue: Arc::new(|_| bail!("this fixture has no automatic enqueue consent")),
                policy,
            }),
        });
        assert_eq!(
            tracking
                .refresh_observation()
                .context("fixture creation: disable native graph observation")?["state"],
            "disabled"
        );
        assert!(tracking.engine.is_none());
        assert!(tracking.observation.lock().unwrap().is_none());

        let app = AppId::steam(480);
        let mut identity = AppIdentity::new(app.clone(), "Synthetic native capture fixture");
        identity.steam_app_id = Some(480);
        identity.launcher = Some(LauncherKind::Steam);
        identity.identity_confidence = 1.0;
        let root =
            SafeRoot::open(&source).context("fixture creation: open actual native consent root")?;
        let root_identity = root
            .identity()
            .context("fixture creation: obtain actual native root identity")?;
        // Both the installation identity and its canonical source identity are
        // signed by actual Tracker approval, not patched into state afterwards.
        tracking.call(
            "approve_software",
            &json!({
                "softwareId":SOFTWARE,"appId":INSTANCE,"name":identity.display_name,
                "sourceIdentity":identity,"providerId":provider_id,
                "roots":[{"path":source,"role":"save"}],
                "_approvedPaths":[{"path":source,"kind":"directory","identity":root_identity}],
            }),
        ).context("fixture creation: real Tracker approval of distinct workspace, installation, and canonical IDs")?;
        assert!(store
            .verify_tracking_grant(SOFTWARE)
            .context("fixture creation: verify real Tracker-issued device grant")?);
        let record = store
            .software_record(SOFTWARE)
            .context("fixture creation: read approved workspace software row")?;
        assert_eq!(record["id"], SOFTWARE);
        assert_eq!(record["appId"], INSTANCE);
        assert_eq!(record["sourceIdentity"]["app_id"], CANONICAL);
        assert_ne!(SOFTWARE, INSTANCE);
        assert_ne!(SOFTWARE, CANONICAL);
        assert_ne!(INSTANCE, CANONICAL);

        // Explicit fixture-only native boot; do not use AgentConfig::from_env,
        // Harness::exec, recover(), observer.start(), or source host discovery.
        let paths = AgentPaths::from_roots(source_data.join("state"), source_data.join("run"));
        paths.ensure_dirs()?;
        for path in [
            &paths.state_root,
            &paths.run_root,
            &paths.staging,
            &paths.snapshots,
            &paths.packs,
            &paths.restore,
            &paths.checkpoints,
            &paths.cache,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let agent = Arc::new(
            StateAgent::boot(AgentConfig {
                instance_id: Uuid::new_v4(),
                image_id: "isolated-service-source-capture-fixture".into(),
                paths,
                home: home.clone(),
                user: "isolated-fixture".into(),
                converge_complete_backups: false,
                native_host: true,
                capture_exclusions: vec![data.clone(), source_data, home, remote.clone()],
            })
            .context("fixture creation: boot explicit native-only source StateAgent")?,
        );
        let source_identity: AppIdentity =
            serde_json::from_value(record["sourceIdentity"].clone())?;
        let approved_roots = record["roots"]
            .as_array()
            .context("actual signed Tracker roots are unavailable")?
            .iter()
            .map(|root| {
                let identity: quicksave_state::NativeFileStampID =
                    serde_json::from_value(root["identity"].clone())?;
                Ok(ApprovedNativeRoot {
                    id: dto::id(root, "id")?.to_owned(),
                    path: serde_json::from_value(root["path"].clone())?,
                    allowed_files: serde_json::from_value(root["allowedFiles"].clone())?,
                    expected_identity: Some((identity.device, identity.file_id[0])),
                    role: NativeRootRole::parse(dto::text(root, "role", 32)?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        agent
            .native_register(source_identity, approved_roots)
            .context(
                "fixture creation: register canonical source identity with actual approved roots",
            )?;
        assert!(agent.config.native_host);
        assert!(!agent.config.converge_complete_backups);
        assert!(agent.config.paths.state_root.starts_with(&base));
        assert!(agent.config.home.starts_with(&base));
        assert!(agent.roots.lock().home.is_none());
        assert!(agent.steam.lock().is_none());
        assert!(!agent.config.paths.rpc_socket.exists());
        assert!(!source.starts_with(&data));
        assert!(!remote.starts_with(&source));
        let state = fs::read_to_string(data.join("state.json"))?;
        assert!(!state.contains("SYNTHETIC-CAPTURE-ACCESS"));
        assert!(!state.contains("SYNTHETIC-CAPTURE-SECRET"));
        Ok(Self {
            agent,
            tracking,
            store,
            vault,
            storage: FixtureStorage::new(remote),
            master,
            provider_id,
            app,
            source,
            data,
            initial_files,
            _temporary: temporary,
        })
    }

    fn prepare(&self, selected: Option<&[String]>) -> Result<PreparedWork> {
        let input = json!({
            "softwareId":SOFTWARE,"providerId":self.provider_id,"fileIds":selected,
        });
        let work = self
            .tracking
            .call("prepare_upload_scope", &input)
            .context("fixture prepare: freeze actual Tracker metadata work")?;
        assert_eq!(work["softwareId"], SOFTWARE);
        assert_eq!(work["appId"], INSTANCE);
        assert_eq!(work["sourceIdentity"]["app_id"], CANONICAL);
        assert_eq!(
            work["authorization"]["trackingScope"]["softwareId"],
            SOFTWARE
        );
        assert_eq!(work["authorization"]["trackingScope"]["appId"], INSTANCE);
        assert_eq!(
            work["authorization"]["trackingScope"]["sourceIdentity"]["app_id"],
            CANONICAL
        );
        let frozen = self
            .store
            .software_record(SOFTWARE)
            .context("fixture prepare: read actual persisted pending-work pointer")?;
        assert!(
            frozen["pendingWork"].is_object(),
            "real frozen work must have a durable pointer"
        );
        assert_eq!(frozen["pendingWork"]["scope"]["softwareId"], SOFTWARE);
        assert_eq!(frozen["pendingWork"]["scope"]["appId"], INSTANCE);
        assert_eq!(frozen["pendingWork"]["scope"]["workId"], work["workId"]);
        assert_eq!(
            work["captureSource"]["stage"],
            "awaiting_native_capture_receipt"
        );
        assert!(work["captureSource"].get("expectedFiles").is_none());
        let controller = Arc::new(
            crate::capture::CaptureController::new(self.tracking.clone(), &work)
                .context("fixture prepare: construct production service CaptureController")?,
        );
        let metadata = &work["captureSource"]["metadataSelection"];
        let mut scope = CaptureScope {
            version: 1,
            work_id: dto::id(&work, "workId")?.to_owned(),
            metadata_identity: dto::text(metadata, "metadataIdentity", 512)?.to_owned(),
            node_count: metadata["nodeCount"]
                .as_u64()
                .context("native node count")? as usize,
            full_scope: None,
        };
        assert!(scope.node_count <= MAX_APP_FILES);
        let full_evidence = match controller.full_scope_authority(&scope)? {
            Some(authority) => {
                authority.revalidate()?;
                let evidence = authority.evidence()?;
                let untouched = evidence.clone();
                scope.full_scope =
                    Some(NativeFullScopeBinding::from_evidence(&evidence).context(
                        "fixture prepare: bind untouched real Tracker full-scope evidence",
                    )?);
                assert_eq!(evidence["softwareId"], SOFTWARE);
                assert_eq!(
                    evidence["expectedFullScope"]["scope"]["softwareId"],
                    SOFTWARE
                );
                assert_eq!(
                    evidence["authorization"]["trackingScope"]["softwareId"],
                    SOFTWARE
                );
                assert_eq!(
                    evidence["authorization"]["trackingScope"]["appId"],
                    INSTANCE
                );
                assert_eq!(evidence["sourceIdentity"]["app_id"], CANONICAL);
                assert_eq!(
                    evidence, untouched,
                    "never rewrite an original signed digest/grant"
                );
                assert!(self.store.verify_grant(
                    "tracking_full_capture",
                    &evidence["expectedFullScope"]["scope"],
                    &evidence["expectedFullScope"]["grant"],
                )?);
                assert!(self.store.verify_grant(
                    "tracking",
                    &evidence["authorization"]["trackingScope"],
                    &evidence["authorization"]["trackingGrant"],
                )?);
                for path in [
                    "/metadataIdentity",
                    "/expectedFullScope/scope/metadataIdentity",
                    "/expectedFullScope/scope/trackingScopeHash",
                    "/expectedFullScope/scope/expectedNodeIdsHash",
                    "/expectedFullScope/scope/deletedNodeIdsHash",
                ] {
                    assert_raw_metadata_digest(evidence.pointer(path).context("tracker digest")?);
                }
                Some(evidence)
            }
            None => None,
        };
        assert_eq!(scope.full_scope.is_some(), selected.is_none());
        let operation = Uuid::new_v4();
        let keys = capture_control::install(
            &self.agent,
            operation,
            &self.app,
            scope.clone(),
            controller.clone(),
        )
        .context("fixture prepare: install production capture bridge on canonical source app")?;
        assert_eq!(keys.len(), scope.node_count);
        for key in &keys {
            let root_id =
                noland_state_agent::native_host::native_tracking_root_id(&key.logical_root)
                    .context("actual source key must retain its approved Tracker root ID")?;
            assert_eq!(
                key.logical_root,
                quicksave_noland::native_capture_root_token(CANONICAL, &root_id)?
            );
            assert_ne!(
                key.logical_root,
                quicksave_noland::native_capture_root_token(INSTANCE, &root_id)?,
                "source logical roots bind the canonical app, not the installation ID"
            );
        }
        let selection = NativeSelection {
            version: 1,
            file_keys: Some(keys),
            roots_fingerprint: self.agent.native_binding_fingerprint(&self.app)?,
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(scope.metadata_identity.clone()),
            expected_files: None,
            capture_scope: Some(scope.clone()),
            coverage: if selected.is_none() {
                NativeCoverage::FullApprovedScope
            } else {
                NativeCoverage::SelectedNodes
            },
            software_instance_id: Some(INSTANCE.into()),
        };
        let selection = NativeSelection::parse(&serde_json::to_value(selection)?).context(
            "fixture prepare: validate typed source selection with installation binding",
        )?;
        let record = self.store.software_record(SOFTWARE)?;
        let pin = self.tracking.pin_scope(&record)?;
        let access = Arc::new(
            self.store
                .provider_access(&self.provider_id, &operation.to_string())?,
        );
        ensure!(
            !access.read_only && access.repository_key == self.master.0,
            "native synthetic provider key/write authority changed"
        );
        // Direct LocalStorage execution still gets the exact source SDK
        // submission MAC. A restart must pass the REAL SDK's read-only replay
        // verifier before reattachment; the test cannot authorize itself using
        // an operation row's own JSON digest.
        let mut source_details = source_submission_selection(&self.app, &selection);
        let submission = synthetic_s3_submission_mac(&access, &source_details)?;
        source_details["client_operation_id"] = json!(operation);
        source_details["submission_binding"] = json!(submission);
        let tracking = self.tracking.clone();
        let store = self.store.clone();
        let guard_work = work.clone();
        let guard_controller = controller.clone();
        let publication_checks = Arc::new(AtomicUsize::new(0));
        let checked = publication_checks.clone();
        self.agent.native_set_publication_guard(
            operation,
            Arc::new(move || {
                // Exactly the production controller's post-acceptance proof gate,
                // plus current service/root/provider authority. No `{verified:true}`
                // fixture and no unconditional Ok publication callback.
                let result = (|| -> Result<()> {
                    guard_controller.verify_publication()?;
                    pin.verify()?;
                    tracking.verify_upload_authority(
                        SOFTWARE,
                        &access.provider_id,
                        false,
                        &guard_work,
                    )?;
                    let current =
                        store.provider_access(&access.provider_id, &operation.to_string())?;
                    ensure!(
                        !current.read_only
                            && current.provider_id == access.provider_id
                            && current.repository_key == access.repository_key
                            && current.session == access.session,
                        "original native provider profile/credentials/root changed"
                    );
                    checked.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                })();
                result.map_err(|_| {
                    StateError::Conflict(
                        "real service capture/root/provider authority refused publication".into(),
                    )
                })
            }),
        )?;
        let now = Utc::now();
        self.agent.db.upsert_operation(&OperationRecord {
            operation_id: operation,
            kind: "backup".into(),
            app_id: Some(self.app.clone()),
            state: "QUEUED".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: source_details,
        })?;
        Ok(PreparedWork {
            operation,
            work,
            scope,
            selection,
            full_evidence,
            controller,
            publication_checks,
        })
    }

    async fn execute(&self, prepared: &PreparedWork) -> Result<BundleManifest> {
        let mode = if prepared.selection.coverage == NativeCoverage::FullApprovedScope {
            BackupMode::CompleteApplication
        } else {
            BackupMode::Custom
        };
        let manifest = run_backup(
            &self.agent,
            &self.app,
            mode,
            BackupPerformanceMode::Automatic,
            &self.storage,
            &self.master,
            Some(prepared.operation),
        )
        .await
        .context("fixture execute: actual source backup/capture/receipt/publication pipeline")?;
        let operation = self
            .agent
            .db
            .get_operation(prepared.operation)?
            .context("source operation")?;
        assert_eq!(operation.kind, "backup");
        assert_eq!(
            operation.state, "COMPLETED",
            "only real source completion counts"
        );
        assert_eq!(
            operation.detail_json["repository_admission"]["status"],
            "RELEASED"
        );
        assert!(prepared.publication_checks.load(Ordering::Acquire) >= 2);
        let counters = native_capture::counters(&self.agent, prepared.operation)?
            .context("actual native capture counters")?;
        assert_eq!(counters.accepted_receipts, 1);
        assert_eq!(
            counters.source_proofs_recorded,
            prepared.scope.node_count as u64
        );
        let metrics: OperationMetrics =
            serde_json::from_value(operation.detail_json["metrics"].clone())?;
        assert_eq!(metrics.num_rclone_invocations, 0);
        let committed = noland_storage::read_committed_manifest(
            &self.storage,
            &self.master,
            &self.app,
            manifest.bundle_id,
        )
        .await?;
        assert_eq!(
            serde_json::to_value(&committed)?,
            serde_json::to_value(&manifest)?
        );
        native_capture::verify_prepared(&self.agent, prepared.operation, &committed)?;
        self.assert_real_receipt(prepared, &committed)?;
        assert_marker_order(&self.storage.snapshot());
        Ok(committed)
    }

    fn assert_real_receipt(
        &self,
        prepared: &PreparedWork,
        manifest: &BundleManifest,
    ) -> Result<()> {
        prepared.controller.verify_publication()?;
        let record = self.store.software_record(SOFTWARE)?;
        let sealed = &record["captureReceipt"];
        assert!(self.store.verify_grant(
            "tracking_capture_receipt",
            &sealed["scope"],
            &sealed["grant"],
        )?);
        assert_eq!(sealed["scope"]["softwareId"], SOFTWARE);
        assert_eq!(sealed["scope"]["providerId"], self.provider_id);
        assert_eq!(sealed["grant"]["algorithm"], "hmac-sha256");
        let mut changed_scope = sealed["scope"].clone();
        changed_scope["softwareId"] = json!("different-fixture-software");
        assert!(
            !self.store.verify_grant(
                "tracking_capture_receipt",
                &changed_scope,
                &sealed["grant"],
            )?,
            "the actual device MAC must bind the original workspace row ID"
        );
        assert_eq!(sealed["scope"]["workId"], prepared.work["workId"]);
        assert_eq!(sealed["scope"]["generation"], prepared.work["generation"]);
        assert_eq!(
            sealed["scope"]["metadataIdentity"],
            prepared.scope.metadata_identity
        );
        assert_eq!(
            sealed["scope"]["sourceSnapshotId"],
            manifest.bundle_id.to_string()
        );
        assert_eq!(sealed["scope"]["immutablePreparedCapture"], true);
        let reference = &sealed["reference"];
        assert!(self.store.verify_grant(
            "tracking_capture_receipt_sidecar",
            &reference["scope"],
            &reference["grant"],
        )?);
        let evidence = read_signed_json(&self.data.join("tracking-bundles"), reference)?;
        assert_eq!(evidence["workId"], prepared.work["workId"]);
        assert_eq!(evidence["sourceSnapshotId"], manifest.bundle_id.to_string());
        assert_eq!(
            evidence["nodes"]
                .as_array()
                .context("source receipt nodes")?
                .len(),
            prepared.scope.node_count
        );
        let auth = &evidence["sourceExpectedManifestAuth"];
        let encoded = auth["envelopeHex"]
            .as_str()
            .context("source AEAD authentication")?;
        ensure!(
            encoded.len() <= 16 * 1024 && encoded.len() % 2 == 0,
            "bounded actual source authentication envelope"
        );
        let envelope = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
            .collect::<Result<Vec<_>>>()?;
        let authenticated: Value = noland_storage::open_metadata(
            &noland_crypto::derive_keys(&self.master).manifest,
            b"quicksave-native-expected-manifest-v1",
            envelope,
        )?;
        assert_eq!(
            authenticated["scope"],
            serde_json::to_value(&prepared.scope)?
        );
        assert_eq!(
            authenticated["source_snapshot_id"],
            manifest.bundle_id.to_string()
        );
        assert_eq!(
            authenticated["manifest_hash"],
            noland_storage::compact_json_hash(manifest)?
        );
        assert_eq!(auth["manifestHash"], authenticated["manifest_hash"]);
        assert_eq!(
            evidence["rootLayouts"],
            manifest.environment["quicksave_native_root_layouts"]
        );
        let completion = self
            .tracking
            .call(
                "capture_completion_binding",
                &json!({
                    "workId":prepared.work["workId"],
                }),
            )
            .context("fixture receipt: verify actual Tracker completion binding and device MAC")?;
        assert_eq!(completion["softwareId"], SOFTWARE);
        assert_eq!(completion["appId"], CANONICAL);
        assert_eq!(completion["softwareInstanceId"], INSTANCE);
        assert_eq!(completion["captureReceipt"]["scope"], sealed["scope"]);
        assert_eq!(completion["captureReceipt"]["grant"], sealed["grant"]);
        assert_eq!(
            completion["sourceExpectedManifestAuth"],
            evidence["sourceExpectedManifestAuth"]
        );
        Ok(())
    }

    fn complete(&self, prepared: &PreparedWork) -> Result<Value> {
        // Only call after execute() checked real source DB completion, durable
        // encrypted readback, source proof revalidation, and the real receipt.
        let operation = self
            .agent
            .db
            .get_operation(prepared.operation)?
            .context("source completion")?;
        ensure!(
            operation.state == "COMPLETED",
            "cannot acknowledge a queued/running capture"
        );
        let result = self
            .tracking
            .call(
                "complete_upload",
                &json!({
                    "workId":prepared.work["workId"],
                    "generation":prepared.work["generation"],"success":true,
                }),
            )
            .context("fixture complete: retire exact original work after real source completion")?;
        assert_eq!(result["workId"], prepared.work["workId"]);
        assert_eq!(result["generation"], prepared.work["generation"]);
        Ok(result)
    }

    fn assert_baseline(&self, prepared: &PreparedWork, full: bool) -> Result<Value> {
        let record = self.store.software_record(SOFTWARE)?;
        assert_eq!(record["baselineFullScope"], full);
        let reference = &record["baseline"];
        let scope = json!({
            "version":1,"tracking":prepared.work["authorization"]["trackingScope"],
            "providerId":self.provider_id,"name":reference["name"],"hash":reference["hash"],
            "fullScope":full,
        });
        assert!(self
            .store
            .verify_grant("tracking_baseline", &scope, &reference["grant"])?);
        read_signed_json(&self.data.join("tracking-baselines"), reference)
    }

    async fn read_payload(&self, manifest: &BundleManifest, relative: &str) -> Result<Vec<u8>> {
        // Independent actual source pack AEAD/decompression/hash verification,
        // not a read from the live source or QuickSave's other storage engine.
        let file = manifest
            .files
            .iter()
            .find(|file| file.relative_path == relative)
            .context("authenticated manifest omitted requested fixture file")?;
        ensure!(
            file.file_type == "file" && file.size <= MAX_APP_BYTES as u64,
            "bounded regular fixture payload"
        );
        let index = noland_storage::read_pack_index(
            &self.storage,
            &self.master,
            &self.app,
            manifest.bundle_id,
        )
        .await?;
        ensure!(
            index.len() <= MAX_APP_FILES * 8,
            "bounded fixture pack index"
        );
        let by_hash = index
            .iter()
            .map(|entry| (entry.chunk_hash.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut bytes = Vec::with_capacity(file.size as usize);
        for chunk in &file.chunks {
            let entry = by_hash
                .get(chunk.hash.as_str())
                .context("actual source pack entry")?;
            let plaintext = noland_pack::extract_chunk(
                &self.storage.inner.root.join(pack_key(&entry.pack_id)),
                entry,
                &self.master,
            )?;
            ensure!(
                plaintext.len() as u64 == chunk.size
                    && bytes.len() + plaintext.len() <= MAX_APP_BYTES,
                "bounded authenticated chunk assembly"
            );
            bytes.extend_from_slice(&plaintext);
        }
        assert_eq!(bytes.len() as u64, file.size);
        assert_eq!(
            format!("blake3:{}", blake3::hash(&bytes).to_hex()),
            file.file_hash
        );
        Ok(bytes)
    }

    fn file_id(&self, relative: &str) -> Result<String> {
        let page = self.tracking.call(
            "file_listing",
            &json!({
                "softwareId":SOFTWARE,"limit":MAX_APP_FILES,
            }),
        )?;
        assert!(page["nextCursor"].is_null());
        page["files"]
            .as_array()
            .context("actual Tracker file listing")?
            .iter()
            .find(|file| file["path"] == relative)
            .and_then(|file| file["id"].as_str())
            .map(str::to_owned)
            .context("requested native node was not actually indexed")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Public Tracker::open owns real notify handles, confined to the exact
        // fixture roots. Join them before TempDir cleanup even after an assertion.
        let _ = self.tracking.shutdown();
    }
}

fn assert_raw_metadata_digest(value: &Value) {
    let digest = value.as_str().expect("actual Tracker metadata digest");
    assert_eq!(digest.len(), 64);
    assert!(digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}

fn read_signed_json(directory: &Path, reference: &Value) -> Result<Value> {
    let name = reference["name"]
        .as_str()
        .context("authenticated sidecar name")?;
    ensure!(
        !name.contains(['/', '\\']) && !name.is_empty(),
        "exact sidecar leaf only"
    );
    let root = SafeRoot::open(directory)?;
    let (file, stamp) = root.read_file(name)?;
    ensure!(stamp.size <= MAX_DOCUMENT_BYTES, "bounded fixture sidecar");
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.size,
        "fixture sidecar changed while reading"
    );
    assert_eq!(
        blake3::hash(&bytes).to_hex().as_str(),
        reference["hash"].as_str().unwrap()
    );
    root.verify_file(name, &stamp)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn assert_marker_order(io: &FixtureIo) {
    let mut bundles = 0;
    for (offset, key) in io.writes.iter().enumerate() {
        if let Some(prefix) = key
            .strip_suffix("/COMMITTED")
            .filter(|key| key.starts_with("bundles/"))
        {
            for ordinary in ["manifest.enc", "index.enc"] {
                assert!(io.writes[..offset].contains(&format!("{prefix}/{ordinary}")));
            }
            bundles += 1;
        }
        if key.starts_with("catalog/commits/") && key.ends_with(".COMMITTED") {
            let base = key.strip_suffix(".COMMITTED").unwrap();
            assert!(io.writes[..offset].contains(&format!("{base}.enc")));
        }
    }
    assert!(bundles > 0, "actual source visibility markers were written");
    assert!(io
        .deletions
        .iter()
        .all(|key| key.starts_with("maintenance/activity/")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_tracker_source_capture_confirms_original_work_and_additive_empty_history(
) -> Result<()> {
    actual_full_capture_history(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_state_migration_preserves_actual_capture_empty_history_and_source_optimizations(
) -> Result<()> {
    actual_full_capture_history(true).await
}

async fn actual_full_capture_history(encrypted_state: bool) -> Result<()> {
    let fixture = Fixture::create()?;
    if encrypted_state {
        fixture.store.migrate_to_encrypted_state()?;
        assert_eq!(
            fixture.store.encrypted_vault_status()?["format"],
            "encrypted_state"
        );
        assert!(fixture.store.verify_tracking_grant(SOFTWARE)?);
    }
    let first_work = fixture
        .prepare(None)
        .context("full history: prepare first capture after optional migration")?;
    assert_eq!(
        fixture.tracking.tracker()?.performance_counters()["bytesRead"],
        0
    );
    assert_eq!(
        fixture.tracking.tracker()?.performance_counters()["filesHashed"],
        0
    );
    let first = fixture.execute(&first_work).await?;
    assert_eq!(first.mode, BackupMode::CompleteApplication);
    assert_eq!(first.app.app_id.as_str(), "steam:480");
    assert_eq!(first.chunking.algorithm, "fastcdc");
    assert_eq!(first.hash.algorithm, "blake3");
    let first_operation = fixture
        .agent
        .db
        .get_operation(first_work.operation)?
        .context("actual first source operation")?;
    let first_metrics: OperationMetrics =
        serde_json::from_value(first_operation.detail_json["metrics"].clone())?;
    assert_eq!(
        first_metrics.bytes_hashed,
        fixture.initial_files.values().map(Vec::len).sum::<usize>() as u64,
        "actual source hash input; not tracker prehash or fixture completion"
    );
    let layouts = &first.environment["quicksave_native_root_layouts"];
    assert_eq!(layouts["app_id"], "steam:480");
    assert_eq!(layouts["software_instance_id"], INSTANCE);
    assert_eq!(layouts["roots"][0]["role"], "save");
    assert_eq!(layouts["roots"][0]["leaf_name"], "Isolated Fixture.app");
    assert_eq!(first.files.len(), first_work.scope.node_count);
    let directory = first
        .files
        .iter()
        .find(|file| file.relative_path == "profile/empty")
        .unwrap();
    assert_eq!(directory.file_type, "directory");
    assert!(directory.chunks.is_empty() && directory.file_hash.is_empty());
    let link = first
        .files
        .iter()
        .find(|file| file.relative_path == "profile/current-save")
        .unwrap();
    assert_eq!(link.file_type, "symlink");
    assert_eq!(link.symlink_target.as_deref(), Some("../save.dat"));
    assert!(link.chunks.is_empty());
    for (relative, bytes) in &fixture.initial_files {
        assert_eq!(fixture.read_payload(&first, relative).await?, *bytes);
    }
    let confirmed = fixture
        .complete(&first_work)
        .context("full history: confirm first capture")?;
    assert_eq!(confirmed["sourceConfirmed"], true);
    assert!(
        fixture.store.software_record(SOFTWARE)?["pendingWork"].is_null(),
        "real Tracker completion must retire the persisted pointer, not preserve an omitted stale field"
    );
    let baseline = fixture.assert_baseline(&first_work, true)?;
    assert_eq!(
        baseline["nodes"].as_object().unwrap().len(),
        first.files.len()
    );
    assert_eq!(
        confirmed["software"]["lastConfirmedUploadedGeneration"],
        first_work.work["generation"]
    );
    // The optimized bridge never prehashes or rehashes payloads for completion.
    assert_eq!(
        fixture.tracking.tracker()?.performance_counters()["bytesRead"],
        0
    );

    let removed = "profile/slot.dat";
    let removed_id = fixture.file_id(removed)?;
    fs::remove_file(fixture.source.join(removed))?;
    fixture
        .tracking
        .call("scan_metadata", &json!({"softwareId":SOFTWARE}))?;
    let before = fixture.storage.snapshot();
    let second_work = fixture
        .prepare(None)
        .context("full history: prepare deletion capture")?;
    let evidence = second_work.full_evidence.as_ref().unwrap();
    assert_eq!(evidence["deletedFileIds"], json!([removed_id]));
    assert_eq!(evidence["baseline"]["kind"], "full");
    assert!(fixture.store.verify_grant(
        "tracking_baseline",
        &evidence["baseline"]["scope"],
        &evidence["baseline"]["reference"]["grant"],
    )?);
    let second = fixture.execute(&second_work).await?;
    assert_eq!(second.mode, BackupMode::CompleteApplication);
    assert_eq!(second.parent_bundle_id, Some(first.bundle_id));
    assert_eq!(second.tombstones.len(), 1);
    assert_eq!(second.tombstones[0].relative_path, removed);
    assert!(!second
        .files
        .iter()
        .any(|file| file.relative_path == removed));
    assert_eq!(fixture.storage.snapshot().pack_uploads, before.pack_uploads);
    assert_eq!(fixture.storage.snapshot().pack_bytes, before.pack_bytes);
    assert_eq!(fixture.complete(&second_work)?["sourceConfirmed"], true);
    fixture.assert_baseline(&second_work, true)?;

    // Delete only exact nodes of this owned fixture, deepest directories last;
    // the approved native root itself is retained, never recursively replaced.
    for file in second
        .files
        .iter()
        .filter(|file| file.file_type != "directory")
    {
        fs::remove_file(fixture.source.join(&file.relative_path))?;
    }
    let mut directories = second
        .files
        .iter()
        .filter(|file| file.file_type == "directory")
        .map(|file| file.relative_path.clone())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.split('/').count()));
    for directory in directories {
        fs::remove_dir(fixture.source.join(directory))?;
    }
    fixture
        .tracking
        .call("scan_metadata", &json!({"softwareId":SOFTWARE}))?;
    let empty_work = fixture
        .prepare(None)
        .context("full history: prepare empty capture")?;
    assert_eq!(empty_work.scope.node_count, 0);
    assert!(empty_work.selection.file_keys.as_ref().unwrap().is_empty());
    assert_eq!(empty_work.scope.full_scope.as_ref().unwrap().root_count, 1);
    let evidence = empty_work.full_evidence.as_ref().unwrap();
    assert_eq!(
        evidence["deletedNodes"].as_array().unwrap().len(),
        second.files.len()
    );
    let root_id = evidence["roots"][0]["id"].as_str().unwrap();
    let held_root = SourcePath::new(&fixture.source)?.open_directory()?;
    assert_eq!(
        evidence["rootStamps"][root_id],
        serde_json::to_value(
            quicksave_noland::capture_control::CaptureStamp::from_metadata(&held_root.metadata()?)?
        )?
    );
    let empty = fixture.execute(&empty_work).await?;
    assert_eq!(empty.mode, BackupMode::CompleteApplication);
    assert!(empty.files.is_empty());
    assert_eq!(empty.parent_bundle_id, Some(second.bundle_id));
    let expected = second
        .files
        .iter()
        .map(|file| native_file_id(&file.logical_root, &file.relative_path))
        .collect::<BTreeSet<_>>();
    let omitted = empty
        .tombstones
        .iter()
        .map(|file| native_file_id(&file.logical_root, &file.relative_path))
        .collect::<BTreeSet<_>>();
    assert_eq!(omitted, expected);
    assert_eq!(
        empty.environment["quicksave_native"]["full_scope"]["rootCaptures"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        empty.environment["quicksave_native"]["full_scope"]["keepsVersionHistory"],
        true
    );
    let empty_operation = fixture
        .agent
        .db
        .get_operation(empty_work.operation)?
        .context("actual empty source operation")?;
    let empty_metrics: OperationMetrics =
        serde_json::from_value(empty_operation.detail_json["metrics"].clone())?;
    assert_eq!(empty_metrics.bytes_hashed, 0);
    assert_eq!(fixture.storage.snapshot().pack_uploads, before.pack_uploads);
    assert_eq!(fixture.storage.snapshot().pack_bytes, before.pack_bytes);
    assert_eq!(fixture.complete(&empty_work)?["sourceConfirmed"], true);
    assert!(fixture.assert_baseline(&empty_work, true)?["nodes"]
        .as_object()
        .unwrap()
        .is_empty());

    let catalog = noland_storage::load_catalog(&fixture.storage, &fixture.master).await?;
    let app = catalog
        .apps
        .iter()
        .find(|app| app.app_id == fixture.app)
        .unwrap();
    for manifest in [&first, &second, &empty] {
        assert!(app
            .bundles
            .iter()
            .any(|entry| entry.bundle_id == manifest.bundle_id));
        let old = noland_storage::read_committed_manifest(
            &fixture.storage,
            &fixture.master,
            &fixture.app,
            manifest.bundle_id,
        )
        .await?;
        assert_eq!(old.commit_id, manifest.commit_id);
    }
    let old = noland_storage::read_committed_manifest(
        &fixture.storage,
        &fixture.master,
        &fixture.app,
        first.bundle_id,
    )
    .await?;
    assert_eq!(
        fixture.read_payload(&old, removed).await?,
        fixture.initial_files[removed]
    );
    assert_marker_order(&fixture.storage.snapshot());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_selected_capture_is_custom_and_empty_selection_never_grants_full_permission(
) -> Result<()> {
    let fixture = Fixture::create()?;
    fixture
        .tracking
        .call("scan_metadata", &json!({"softwareId":SOFTWARE}))?;
    assert!(fixture
        .tracking
        .call(
            "prepare_upload_scope",
            &json!({
                "softwareId":SOFTWARE,"providerId":fixture.provider_id,"fileIds":[],
            })
        )
        .is_err());
    let selected = [fixture.file_id("save.dat")?];
    let partial_work = fixture
        .prepare(Some(&selected))
        .context("initial selected capture")?;
    assert_eq!(
        partial_work.work["captureSource"]["selectionKind"],
        "selected_nodes"
    );
    assert!(partial_work.scope.full_scope.is_none());
    assert!(partial_work.full_evidence.is_none());
    assert!(partial_work
        .controller
        .full_scope_authority(&partial_work.scope)?
        .is_none());
    let mut empty = partial_work.selection.clone();
    empty.file_keys = Some(Vec::new());
    assert!(NativeSelection::parse(&serde_json::to_value(empty)?).is_err());
    let mut no_owner = partial_work.scope.clone();
    no_owner.node_count = 0;
    assert!(no_owner.validate().is_err());
    let mut widened = partial_work.selection.clone();
    widened.coverage = NativeCoverage::FullApprovedScope;
    assert!(NativeSelection::parse(&serde_json::to_value(widened)?).is_err());

    let partial = fixture.execute(&partial_work).await?;
    assert_eq!(partial.mode, BackupMode::Custom);
    assert_eq!(partial.files.len(), 1);
    assert_eq!(partial.files[0].relative_path, "save.dat");
    assert!(partial.tombstones.is_empty());
    assert_eq!(
        partial.environment["quicksave_native"]["coverage"],
        "selected_nodes"
    );
    let catalog = noland_storage::load_catalog(&fixture.storage, &fixture.master).await?;
    assert_eq!(catalog.apps[0].latest_complete_bundle_id, None);
    let completed = fixture.complete(&partial_work)?;
    assert_eq!(completed["sourceConfirmed"], true);
    assert_eq!(completed["software"]["lastConfirmedUploadedGeneration"], 0);
    assert_ne!(completed["software"]["status"], "saved");
    let baseline = fixture.assert_baseline(&partial_work, false)?;
    assert_eq!(baseline["nodes"].as_object().unwrap().len(), 1);

    let whole_work = fixture
        .prepare(None)
        .context("whole capture after selected completion")?;
    let whole = fixture.execute(&whole_work).await?;
    assert_eq!(whole.mode, BackupMode::CompleteApplication);
    assert_eq!(fixture.complete(&whole_work)?["sourceConfirmed"], true);
    fixture.assert_baseline(&whole_work, true)?;
    let later_partial_work = fixture
        .prepare(Some(&selected))
        .context("selected capture after whole completion")?;
    let later_partial = fixture.execute(&later_partial_work).await?;
    assert_eq!(later_partial.mode, BackupMode::Custom);
    let catalog = noland_storage::load_catalog(&fixture.storage, &fixture.master).await?;
    assert_eq!(catalog.apps[0].latest_bundle_id, later_partial.bundle_id);
    assert_eq!(
        catalog.apps[0].latest_complete_bundle_id,
        Some(whole.bundle_id)
    );
    fixture.complete(&later_partial_work)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_source_capture_publishes_old_bytes_but_never_confirms_later_tracker_mutation(
) -> Result<()> {
    let fixture = Fixture::create()?;
    let prepared = fixture.prepare(None)?;
    let original = fixture.initial_files["save.dat"].clone();
    let newer = vec![0x73; original.len()];
    let (entered, release) = fixture.storage.pause_next_bundle_marker();
    let mutate = async {
        let marker = entered
            .await
            .context("source never reached its real COMMITTED barrier")?;
        assert!(marker.as_str().starts_with("bundles/"));
        assert!(marker.as_str().ends_with("/COMMITTED"));
        assert!(fixture.storage.inner.stat(&marker).await?.is_none());
        // The receipt is already owned and authenticated by the actual Tracker;
        // mutation happens strictly after its acceptance, before provider commit.
        prepared.controller.verify_publication()?;
        assert_eq!(
            native_capture::counters(&fixture.agent, prepared.operation)?
                .context("actual capture counters")?
                .accepted_receipts,
            1
        );
        assert_ne!(
            fixture
                .agent
                .db
                .get_operation(prepared.operation)?
                .unwrap()
                .state,
            "COMPLETED"
        );
        let path = fixture.source.join("save.dat");
        let modified = fs::metadata(&path)?.modified()?;
        let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
        file.write_all(&newer)?;
        file.set_times(fs::FileTimes::new().set_modified(modified))?;
        file.sync_all()?;
        let tracked = fixture
            .tracking
            .call("scan_metadata", &json!({"softwareId":SOFTWARE}))?;
        assert_eq!(tracked["software"]["dirty"], true);
        assert!(
            tracked["software"]["dirtyGeneration"].as_u64().unwrap()
                > prepared.work["generation"].as_u64().unwrap()
        );
        // Source and Tracker each retain their own real post-capture generation.
        let indexed = fixture
            .agent
            .db
            .get_path_by_canonical(path.to_str().unwrap())?
            .context("real source path index")?;
        fixture
            .agent
            .db
            .mark_dirty(&fixture.app, Some(indexed.path_id), false)?;
        fixture
            .agent
            .db
            .append_app_mutation(&AppMutationRecord::new(
                fixture.app.clone(),
                path.to_str().unwrap(),
                AppMutationKind::Modify,
            ))?;
        prepared.controller.verify_publication()?;
        release
            .send(())
            .map_err(|_| anyhow!("source publication barrier disappeared"))?;
        Ok::<_, anyhow::Error>(tracked["software"]["dirtyGeneration"].clone())
    };
    // Both futures are owned and awaited. An early source error cancels the
    // pending barrier instead of inventing a backend completion or hanging it.
    let (captured, changed_generation) = tokio::try_join!(fixture.execute(&prepared), mutate)?;
    assert_eq!(fixture.read_payload(&captured, "save.dat").await?, original);
    assert_eq!(fs::read(fixture.source.join("save.dat"))?, newer);
    assert!(!fixture
        .agent
        .db
        .pending_app_mutations(&fixture.app, MAX_APP_FILES)?
        .is_empty());
    let completed = fixture.complete(&prepared)?;
    assert_eq!(completed["sourceConfirmed"], false);
    assert_eq!(completed["software"]["dirty"], true);
    assert_ne!(completed["software"]["status"], "saved");
    assert!(
        completed["software"]["dirtyGeneration"].as_u64().unwrap()
            >= changed_generation.as_u64().unwrap()
    );
    assert!(
        completed["software"]["lastConfirmedUploadedGeneration"]
            .as_u64()
            .unwrap()
            < prepared.work["generation"].as_u64().unwrap()
    );
    assert!(fixture.store.software_record(SOFTWARE)?["baseline"].is_null());
    assert_marker_order(&fixture.storage.snapshot());
    Ok(())
}

fn source_submission_selection(app: &AppId, selection: &NativeSelection) -> Value {
    json!({
        "app_id":app,
        "mode":if selection.coverage == NativeCoverage::FullApprovedScope {
            "complete_application"
        } else {
            "custom"
        },
        "performance_mode":"automatic","regenerable_caches":"include",
        "native_selection":selection,
    })
}

/// Exact source submission domain, derived from rpc_handler/submission.rs and
/// storage_scope.rs at the source commit above. This factory is deliberately
/// limited to this fixture's Generic S3 PRIVATE session; it is not an SDK or a
/// substitute verifier. The real AgentRpc replay below independently verifies
/// this MAC before original source proof recovery, without executing a transfer.
fn synthetic_s3_submission_mac(access: &ProviderAccess, selection: &Value) -> Result<String> {
    let session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
        .context("synthetic source submission: decode actual vault-backed private session")?;
    ensure!(
        session.provider == "generic_s3" && session.backend_type == "s3" && !access.read_only,
        "fixture submission factory accepts only its actual synthetic Generic S3 write profile"
    );
    // Generic S3 has no stable account identifier in source storage_scope.
    // Its exact config must use this conservative, source-authored keyed branch.
    let mut private = blake3::Hasher::new_keyed(&access.repository_key);
    private.update(b"noland-private-session-config-v1\0");
    private.update(&serde_json::to_vec(&session.storage_identity())?);
    private.update(&[0]);
    private.update(session.config_ini.as_bytes());
    let repository = ProviderRootIdentity::new(
        &session.provider,
        &session.backend_type,
        format!("private-config-v1-{}", private.finalize().to_hex()),
        &session.root,
    );
    Ok(blake3::keyed_hash(
        &access.repository_key,
        &serde_json::to_vec(&json!({
            "domain":"noland-operation-submission-v1","kind":"backup",
            "repository":repository,"selection":selection,
        }))?,
    )
    .to_hex()
    .to_string())
}

fn metadata_digest(value: &Value) -> Result<String> {
    dto::bounded(value, MAX_DOCUMENT_BYTES as usize)?;
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

/// Exact bounded native file observation. A same-length rewrite/replacement
/// cannot become an unchanged sidecar or committed object by returning DB JSON.
struct PinnedArtifact {
    root: Arc<SafeRoot>,
    name: String,
    stamp: FileStamp,
    bytes: Vec<u8>,
}

impl PinnedArtifact {
    fn open(root: Arc<SafeRoot>, name: &str) -> Result<Self> {
        let (file, stamp) = root.read_file(name)?;
        quicksave_platform::verify_private_file(&file)?;
        ensure!(stamp.size <= MAX_DOCUMENT_BYTES, "bounded restart artifact");
        let mut bytes = Vec::new();
        file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == stamp.size,
            "restart artifact changed length while reading"
        );
        root.verify_file(name, &stamp)?;
        Ok(Self {
            root,
            name: name.into(),
            stamp,
            bytes,
        })
    }

    fn reference(root: Arc<SafeRoot>, reference: &Value, prefix: &str) -> Result<(Self, Value)> {
        let name = dto::text(reference, "name", 255)?;
        ensure!(
            name.starts_with(prefix)
                && name.ends_with(".json")
                && !name.contains(['/', '\\', ':'])
                && reference["scope"]["name"] == name,
            "original private reference must name one confined sidecar"
        );
        let artifact = Self::open(root, name)?;
        ensure!(
            blake3::hash(&artifact.bytes).to_hex().as_str()
                == reference["hash"].as_str().unwrap_or(""),
            "original private sidecar does not match its device-authenticated hash"
        );
        if let Some(length) = reference["bytes"].as_u64() {
            ensure!(
                length == artifact.stamp.size && reference["scope"]["bytes"] == length,
                "original frozen frame reference length changed"
            );
        }
        let value = serde_json::from_slice(&artifact.bytes)?;
        Ok((artifact, value))
    }

    fn revalidate(&self) -> Result<()> {
        self.root.verify_file(&self.name, &self.stamp)?;
        Ok(())
    }
}

/// Created ONLY after actual source read_committed_manifest, independent AEAD
/// opening of the pinned manifest ciphertext, and an exact COMMITTED UUID check.
/// The native receipt's immutable manifest authentication is checked again by
/// verify_for_receipt. No DB state or caller-provided success boolean is stored.
struct LocalCommitWitness {
    manifest: BundleManifest,
    manifest_hash: String,
    operation: Uuid,
    marker: PinnedArtifact,
    ciphertext: PinnedArtifact,
    hash_file: PinnedArtifact,
    verify_calls: AtomicUsize,
}

impl LocalCommitWitness {
    async fn open(fixture: &Fixture, prepared: &PreparedWork) -> Result<Arc<Self>> {
        let record = fixture.store.software_record(SOFTWARE)?;
        let bundle = Uuid::parse_str(
            record["captureReceipt"]["scope"]["sourceSnapshotId"]
                .as_str()
                .context("actual source snapshot UUID")?,
        )?;
        let manifest = noland_storage::read_committed_manifest(
            &fixture.storage,
            &fixture.master,
            &fixture.app,
            bundle,
        )
        .await
        .context("restart commit witness: actual source COMMITTED + manifest AEAD reader")?;
        let root = Arc::new(SafeRoot::open(&fixture.storage.inner.root)?);
        let prefix = bundle_dir(&fixture.app, bundle);
        let marker = PinnedArtifact::open(root.clone(), &format!("{prefix}/COMMITTED"))?;
        ensure!(
            marker.bytes.as_slice() == manifest.commit_id.to_string().as_bytes(),
            "actual COMMITTED marker does not name the authenticated manifest commit"
        );
        let ciphertext = PinnedArtifact::open(root.clone(), &format!("{prefix}/manifest.enc"))?;
        let decoded: BundleManifest = noland_storage::open_metadata_with_limit(
            &noland_crypto::derive_keys(&fixture.master).manifest,
            b"manifest",
            ciphertext.bytes.clone(),
            MAX_DOCUMENT_BYTES,
        )?;
        ensure!(
            serde_json::to_value(&decoded)? == serde_json::to_value(&manifest)?,
            "pinned source ciphertext differs from actual committed manifest"
        );
        let manifest_hash = noland_storage::compact_json_hash(&manifest)?;
        let hash_file = PinnedArtifact::open(root, &format!("{prefix}/manifest.hash"))?;
        ensure!(
            hash_file.bytes.as_slice() == manifest_hash.as_bytes(),
            "stored source manifest hash differs from its actual authenticated bytes"
        );
        ensure!(
            record["captureReceipt"]["scope"]["workId"] == prepared.work["workId"]
                && record["captureReceipt"]["scope"]["generation"] == prepared.work["generation"],
            "commit witness must use the actual original accepted work"
        );
        let witness = Arc::new(Self {
            manifest,
            manifest_hash,
            operation: prepared.operation,
            marker,
            ciphertext,
            hash_file,
            verify_calls: AtomicUsize::new(0),
        });
        witness.revalidate_objects()?;
        Ok(witness)
    }

    fn revalidate_objects(&self) -> Result<()> {
        self.marker.revalidate()?;
        self.ciphertext.revalidate()?;
        self.hash_file.revalidate()?;
        ensure!(
            self.marker.bytes.as_slice() == self.manifest.commit_id.to_string().as_bytes()
                && self.hash_file.bytes.as_slice() == self.manifest_hash.as_bytes(),
            "native committed-object witness changed"
        );
        Ok(())
    }

    fn verify_for_receipt(&self, receipt: &native_capture::NativeCaptureReceipt) -> Result<()> {
        receipt.revalidate()?;
        let evidence = receipt.evidence()?;
        ensure!(
            evidence["sourceSnapshotId"] == self.manifest.bundle_id.to_string()
                && evidence["sourceExpectedManifestAuth"]["operationId"]
                    == self.operation.to_string()
                && evidence["sourceExpectedManifestAuth"]["manifestHash"] == self.manifest_hash
                && evidence["rootLayouts"]
                    == self.manifest.environment["quicksave_native_root_layouts"],
            "actual source receipt differs from the authenticated LocalStorage commit witness"
        );
        self.revalidate_objects()?;
        self.verify_calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct SavedCapture {
    operation: Uuid,
    work: Value,
    selection: NativeSelection,
    frame_reference: Value,
    receipt: Value,
    source_record: Value,
    witness: Arc<LocalCommitWitness>,
}

/// Constructed only by a successful ACTUAL source SDK submission replay. It is
/// not a durability verdict; only LocalCommitWitness provides that evidence.
struct VerifiedReplay {
    operation: Uuid,
    source_record: Value,
}

impl VerifiedReplay {
    fn revalidate(&self, agent: &StateAgent) -> Result<()> {
        ensure!(
            !agent.operations.is_running(self.operation)
                && serde_json::to_value(
                    agent
                        .db
                        .get_operation(self.operation)?
                        .context("verified source row disappeared")?
                )? == self.source_record,
            "actual SDK-authenticated original source operation changed or restarted"
        );
        Ok(())
    }
}

impl Fixture {
    async fn save_completed_before_ack(&self, prepared: &PreparedWork) -> Result<SavedCapture> {
        let source = self
            .agent
            .db
            .get_operation(prepared.operation)?
            .context("completed source")?;
        ensure!(
            source.state == "COMPLETED" && !self.agent.operations.is_running(prepared.operation),
            "restart fixture requires the real source pipeline to be completed and drained"
        );
        let record = self.store.software_record(SOFTWARE)?;
        ensure!(
            record["pendingWork"]["scope"]["stage"] == "source_receipt_accepted"
                && record["baseline"].is_null(),
            "simulate lost Tracker acknowledgement, not an already retired work frame"
        );
        let witness = LocalCommitWitness::open(self, prepared).await?;
        Ok(SavedCapture {
            operation: prepared.operation,
            work: prepared.work.clone(),
            selection: prepared.selection.clone(),
            frame_reference: record["pendingWork"].clone(),
            receipt: record["captureReceipt"].clone(),
            source_record: serde_json::to_value(source)?,
            witness,
        })
    }

    fn restart_tracker_before_ack(&mut self, saved: &SavedCapture) -> Result<()> {
        ensure!(
            !self.agent.operations.is_running(saved.operation),
            "drain the original source owner before removing its in-memory receipt session"
        );
        native_capture::remove(&self.agent, saved.operation)?;
        ensure!(
            !native_capture::is_installed(&self.agent, saved.operation),
            "old capture session survived"
        );
        // Drop the source's old controller/Tracker Arc, without replacing it
        // with successful authorization. Completed source work must not restart.
        self.agent.native_set_publication_guard(
            saved.operation,
            Arc::new(|| {
                Err(StateError::Conflict(
                    "completed fixture source cannot be resubmitted during restart".into(),
                ))
            }),
        )?;
        let policy = self
            .tracking
            .bootstrap
            .as_ref()
            .context("fixture policy")?
            .policy
            .clone();
        self.tracking.shutdown()?;
        let store = WorkspaceStore::open_with_vault(&self.data, self.vault.clone())
            .context("restart: reopen same private workspace with the SAME MemoryVault")?;
        let tracking = Arc::new(TrackingAdapter {
            tracker: Mutex::new(None),
            store: store.clone(),
            engine: None,
            observation: Mutex::new(None),
            observation_enabled: false,
            bootstrap: Some(TrackingBootstrap {
                store: Arc::new(StoreAdapter(store.clone(), None)),
                enqueue: Arc::new(|_| bail!("restarted fixture has no autosave consent")),
                policy,
            }),
        });
        let previous = std::mem::replace(&mut self.tracking, tracking);
        self.store = store;
        drop(previous);
        self.tracking
            .tracker()
            .context("restart: open real Tracker from original durable records")?;
        let record = self.store.software_record(SOFTWARE)?;
        ensure!(
            record["pendingWork"] == saved.frame_reference
                && record["captureReceipt"] == saved.receipt,
            "reopening must preserve exact original frame/receipt grants"
        );
        ensure!(
            record["unknownGeneration"]
                .as_u64()
                .context("restart unknown generation")?
                > saved.receipt["scope"]["unknownGeneration"]
                    .as_u64()
                    .context("original unknown generation")?,
            "Tracker restart must persist actual uncertainty instead of trusting old event silence"
        );
        Ok(())
    }

    fn load_original(&self, saved: &SavedCapture) -> Result<Arc<NativeFrozenWork>> {
        let original = self
            .tracking
            .tracker()?
            .original_work(
                SOFTWARE,
                dto::id(&saved.work, "workId")?,
                saved.work["generation"]
                    .as_u64()
                    .context("original generation")?,
                dto::text(&saved.frame_reference["scope"], "trackingScopeHash", 64)?,
            )
            .context("restart: authenticate and reload ONLY the original frozen native frame")?;
        ensure!(
            original.work()? == saved.work
                && original.header()?["frameReference"] == saved.frame_reference
                && original.accepted_receipt()?.as_ref() == Some(&saved.receipt),
            "original loader widened work or replaced accepted device grants"
        );
        Ok(original)
    }

    async fn verify_source_replay(&self, saved: &SavedCapture) -> Result<VerifiedReplay> {
        let before = self
            .agent
            .db
            .get_operation(saved.operation)?
            .context("original source row")?;
        ensure!(
            before.state == "COMPLETED"
                && serde_json::to_value(&before)? == saved.source_record
                && !self.agent.operations.is_running(saved.operation),
            "SDK verification is permitted only as replay of this existing completed source"
        );
        let access = self
            .store
            .provider_access(&self.provider_id, &saved.operation.to_string())?;
        ensure!(
            !access.read_only && access.repository_key == self.master.0,
            "current original provider authority changed"
        );
        // Exact source key, obtained again through the new WorkspaceStore and
        // same MemoryVault; no plaintext key is put in state.json or RPC JSON.
        *self.agent.master_key.lock() = Some(MasterKey::from_bytes(access.repository_key));
        let mut params = source_submission_selection(&self.app, &saved.selection);
        params["client_operation_id"] = json!(saved.operation);
        params["session"] = access.session.clone();
        let request = RpcRequest {
            id: Uuid::new_v4().to_string(),
            method: "StartBackup".into(),
            params,
        };
        dto::bounded(&request.params, 2 * MAX_DOCUMENT_BYTES as usize)?;
        let rpc = noland_state_agent::rpc_handler::AgentRpc(self.agent.clone());
        // Same existing UUID with different selection MUST fail the real source
        // submission MAC. Neither call below can create a new source UUID/worker.
        let mut changed = request.clone();
        changed.params["mode"] = json!("custom");
        ensure!(
            rpc.handle(&changed).await.is_err(),
            "actual SDK accepted a changed original selection"
        );
        let replay = rpc
            .handle(&request)
            .await
            .context("restart: ACTUAL source SDK submission/repository/selection HMAC replay")?;
        dto::bounded(&replay, noland_rpc::MAX_RPC_RESPONSE_BYTES)?;
        ensure!(
            replay["operation_id"] == saved.operation.to_string() && replay["running"] == false,
            "source SDK did not replay the original drained UUID"
        );
        let verified = VerifiedReplay {
            operation: saved.operation,
            source_record: serde_json::to_value(
                self.agent
                    .db
                    .get_operation(saved.operation)?
                    .context("SDK replay lost source row")?,
            )?,
        };
        ensure!(
            verified.source_record == saved.source_record,
            "SDK replay modified original source state"
        );
        verified.revalidate(&self.agent)?;
        Ok(verified)
    }
}

/// Real MemoryVault/WorkspaceStore authority, not a new fixture MAC. All JSON
/// below came from the NativeFrozenWork loader and its actual signed sidecars.
struct OriginalDeviceAuthority {
    original: Arc<NativeFrozenWork>,
    store: WorkspaceStore,
    reference: Value,
    receipt: Value,
    evidence: Arc<Value>,
    grants: Vec<(&'static str, Value, Value)>,
    artifacts: Vec<PinnedArtifact>,
}

impl OriginalDeviceAuthority {
    fn open(fixture: &Fixture, original: Arc<NativeFrozenWork>) -> Result<Arc<Self>> {
        original.revalidate()?;
        let work = original.work()?;
        let header = original.header()?;
        let reference = header["frameReference"].clone();
        let receipt = original
            .accepted_receipt()?
            .context("real original source receipt is absent")?;
        let authorization = &work["authorization"];
        let mut grants = vec![
            (
                "tracking",
                authorization["trackingScope"].clone(),
                authorization["trackingGrant"].clone(),
            ),
            (
                "tracking_frozen_work",
                reference["scope"].clone(),
                reference["grant"].clone(),
            ),
            (
                "tracking_capture_receipt",
                receipt["scope"].clone(),
                receipt["grant"].clone(),
            ),
            (
                "tracking_capture_receipt_sidecar",
                receipt["reference"]["scope"].clone(),
                receipt["reference"]["grant"].clone(),
            ),
        ];
        if work["captureSource"]["selectionKind"] == "full_scope" {
            grants.push((
                "tracking_full_capture",
                work["captureSource"]["expectedFullScope"]["scope"].clone(),
                work["captureSource"]["expectedFullScope"]["grant"].clone(),
            ));
        }
        for (kind, scope, grant) in &grants {
            ensure!(
                fixture.store.verify_grant(kind, scope, grant)?,
                "original device grant is invalid or revoked"
            );
        }
        let root = Arc::new(SafeRoot::open(&fixture.data.join("tracking-bundles"))?);
        let (frame_pin, frame) = PinnedArtifact::reference(root.clone(), &reference, "work-")?;
        ensure!(
            frame["request"] == work
                && frame["record"] == original.record()?
                && frame["acceptedReceipt"] == receipt
                && reference["scope"]["stage"] == "source_receipt_accepted"
                && reference["scope"]["captureReceiptHash"] == metadata_digest(&receipt)?
                && reference["scope"]["trackingScopeHash"]
                    == metadata_digest(&authorization["trackingScope"])?
                && reference["scope"]["trackingGrantHash"]
                    == metadata_digest(&authorization["trackingGrant"])?
                && reference["scope"]["authorizationHash"] == metadata_digest(authorization)?,
            "original frozen frame does not bind its actual request/tracking/accepted receipt"
        );
        let initial_reference = &frame["originalReference"];
        ensure!(
            initial_reference.is_object()
                && reference["scope"]["originalReferenceHash"]
                    == metadata_digest(initial_reference)?
                && initial_reference["scope"]["workId"] == work["workId"]
                && initial_reference["scope"]["generation"] == work["generation"],
            "accepted device frame lost original pre-execution provenance"
        );
        let (initial_pin, initial) =
            PinnedArtifact::reference(root.clone(), initial_reference, "work-")?;
        ensure!(
            initial["request"] == work
                && initial["metadata"] == frame["metadata"]
                && initial["acceptedReceipt"].is_null(),
            "original frozen metadata was replaced rather than resumed"
        );
        let (receipt_pin, evidence) =
            PinnedArtifact::reference(root, &receipt["reference"], "receipt-")?;
        ensure!(
            receipt["reference"]["scope"]["tracking"] == authorization["trackingScope"]
                && receipt["reference"]["scope"]["captureScope"] == receipt["scope"]
                && evidence["workId"] == work["workId"]
                && evidence["metadataIdentity"] == work["captureSource"]["snapshotIdentity"]
                && evidence["sourceSnapshotId"] == receipt["scope"]["sourceSnapshotId"]
                && receipt["scope"]["sourceExpectedManifestAuthHash"]
                    == metadata_digest(&evidence["sourceExpectedManifestAuth"])?
                && frame["sourceExpectedManifestAuth"] == evidence["sourceExpectedManifestAuth"],
            "device-authenticated source receipt sidecar differs from original source preparation"
        );
        let authority = Arc::new(Self {
            original,
            store: fixture.store.clone(),
            reference,
            receipt,
            evidence: Arc::new(evidence),
            grants,
            artifacts: vec![frame_pin, initial_pin, receipt_pin],
        });
        authority.verify_native()?;
        Ok(authority)
    }

    fn verify_native(&self) -> Result<()> {
        self.original.revalidate()?;
        let current = self.store.software_record(SOFTWARE)?;
        ensure!(
            current["pendingWork"] == self.reference && current["captureReceipt"] == self.receipt,
            "current workspace changed original device frame or accepted receipt"
        );
        for (kind, scope, grant) in &self.grants {
            ensure!(
                self.store.verify_grant(kind, scope, grant)?,
                "original frame/receipt/tracking device MAC was revoked"
            );
        }
        for artifact in &self.artifacts {
            artifact.revalidate()?;
        }
        Ok(())
    }
}

impl native_capture::resume::NativeOriginalCaptureAuthority for OriginalDeviceAuthority {
    fn revalidate(&self) -> SourceResult<()> {
        self.verify_native().map_err(|_| {
            StateError::Integrity("real original native frame/receipt authority changed".into())
        })
    }

    fn original_evidence(&self) -> SourceResult<Arc<Value>> {
        self.verify_native().map_err(|_| {
            StateError::Integrity("original device sidecar authentication failed".into())
        })?;
        Ok(self.evidence.clone())
    }

    fn verify_recovered(&self, evidence: &Value) -> SourceResult<()> {
        if evidence != self.evidence.as_ref() {
            return Err(StateError::Integrity(
                "recovered receipt differs from actual original device-authenticated sidecar"
                    .into(),
            ));
        }
        native_capture::resume::NativeOriginalCaptureAuthority::revalidate(self)
    }
}

struct OriginalFullScope(Arc<NativeFrozenWork>);
impl native_capture::NativeFullScopeAuthority for OriginalFullScope {
    fn evidence(&self) -> SourceResult<Value> {
        self.0.full_scope_evidence().map_err(|_| {
            StateError::Conflict("original native full-scope evidence is unavailable".into())
        })
    }
    fn revalidate(&self) -> SourceResult<()> {
        self.0.revalidate().map_err(|_| {
            StateError::Conflict("original full-scope device grant/root authority changed".into())
        })
    }
}

/// Both methods delegate an ACTUAL private source receipt. The additional
/// verify_committed method can succeed only through the real LocalStorage
/// object/AEAD witness, and never reenters Tracker from its held completion lock.
struct RecoveredReceipt {
    source: Arc<native_capture::NativeCaptureReceipt>,
    committed: Arc<LocalCommitWitness>,
}
impl quicksave_tracking::NativeCaptureReceipt for RecoveredReceipt {
    fn evidence(&self) -> Result<Value> {
        Ok(self.source.evidence()?)
    }
    fn revalidate(&self) -> Result<()> {
        Ok(self.source.revalidate()?)
    }
    fn immutable_prepared_capture(&self) -> bool {
        true // Only this actual source-owned opaque receipt can construct Self.
    }
    fn verify_committed(&self) -> Result<()> {
        self.committed.verify_for_receipt(&self.source)
    }
}

struct OriginalRecoverySink {
    original: Arc<NativeFrozenWork>,
    tracker: Arc<Tracker>,
    authority: Arc<OriginalDeviceAuthority>,
    scope: CaptureScope,
    committed: Arc<LocalCommitWitness>,
    accepted: Mutex<Option<Value>>,
}
impl native_capture::NativeCaptureSink for OriginalRecoverySink {
    fn node_page(
        &self,
        scope: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> SourceResult<Vec<native_capture::NativeCaptureNode>> {
        let result = (|| -> Result<Vec<_>> {
            ensure!(
                scope == &self.scope && limit <= MAX_APP_FILES,
                "original source page changed exact work scope"
            );
            let page = self.original.node_page(offset, limit)?;
            let record = self.original.record()?;
            let app = dto::text(&record["sourceIdentity"], "app_id", 512)?;
            let nodes = page["nodes"]
                .as_array()
                .context("original immutable native node page")?;
            nodes
                .iter()
                .map(|node| {
                    let root = dto::id(node, "rootId")?;
                    Ok(native_capture::NativeCaptureNode {
                        id: dto::id(node, "id")?.into(),
                        root_id: root.into(),
                        logical_root: quicksave_noland::native_capture_root_token(app, root)?,
                        path: dto::text(node, "path", 32_768)?.into(),
                        kind: dto::text(node, "kind", 32)?.into(),
                        size: node["size"].as_u64().context("original node size")?,
                        stamp: serde_json::from_value(node["stamp"].clone())?,
                        link_target_hash: node["linkTargetHash"].as_str().map(str::to_owned),
                    })
                })
                .collect()
        })();
        result.map_err(|_| {
            StateError::Conflict("actual original frozen native page is unavailable".into())
        })
    }

    fn full_scope_authority(
        &self,
        scope: &CaptureScope,
    ) -> SourceResult<Option<Arc<dyn native_capture::NativeFullScopeAuthority>>> {
        if scope != &self.scope {
            return Err(StateError::Conflict(
                "original full-scope work changed".into(),
            ));
        }
        Ok(scope.full_scope.as_ref().map(|_| {
            Arc::new(OriginalFullScope(self.original.clone()))
                as Arc<dyn native_capture::NativeFullScopeAuthority>
        }))
    }

    fn accept(&self, receipt: Arc<native_capture::NativeCaptureReceipt>) -> SourceResult<()> {
        let result = (|| -> Result<()> {
            self.authority.verify_native()?;
            receipt.revalidate()?;
            self.committed.revalidate_objects()?;
            let resumed = self.tracker.resume_pending(
                self.original.clone(),
                Arc::new(RecoveredReceipt {
                    source: receipt,
                    committed: self.committed.clone(),
                }),
            )?;
            ensure!(
                resumed["originalWorkRestored"] == true,
                "Tracker did not restore the actual original work"
            );
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| anyhow!("original sink ownership lock"))?;
            ensure!(
                accepted.is_none(),
                "original source receipt was accepted twice"
            );
            *accepted = Some(resumed);
            Ok(())
        })();
        result.map_err(|_| {
            StateError::Conflict("real Tracker refused original source receipt recovery".into())
        })
    }
}

fn recover_original(
    fixture: &Fixture,
    saved: &SavedCapture,
    original: Arc<NativeFrozenWork>,
    authority: Arc<OriginalDeviceAuthority>,
    replay: &VerifiedReplay,
) -> Result<(
    Arc<native_capture::NativeCaptureReceipt>,
    Arc<OriginalRecoverySink>,
)> {
    replay.revalidate(&fixture.agent)?;
    ensure!(
        replay.operation == saved.operation,
        "SDK verified another original source UUID"
    );
    let sink = Arc::new(OriginalRecoverySink {
        original,
        tracker: fixture.tracking.tracker()?,
        authority: authority.clone(),
        scope: saved
            .selection
            .capture_scope
            .clone()
            .context("original source capture scope")?,
        committed: saved.witness.clone(),
        accepted: Mutex::new(None),
    });
    let receipt = native_capture::resume::reattach_original_capture(
        &fixture.agent,
        saved.operation,
        &saved.selection,
        &fixture.master,
        &saved.witness.manifest,
        sink.clone(),
        authority,
    )
    .context("restart: actual source ENCRYPTED proof reload and native receipt reattachment")?;
    replay.revalidate(&fixture.agent)?;
    Ok((receipt, sink))
}

fn assert_no_source_recapture(
    fixture: &Fixture,
    saved: &SavedCapture,
    before: &FixtureIo,
) -> Result<()> {
    let now = fixture.storage.snapshot();
    assert_eq!(now.pack_uploads, before.pack_uploads);
    assert_eq!(now.pack_bytes, before.pack_bytes);
    assert_eq!(
        now.writes, before.writes,
        "completed source must never publish again"
    );
    assert_eq!(
        serde_json::to_value(fixture.agent.db.get_operation(saved.operation)?.unwrap())?,
        saved.source_record,
        "no source retry, reset, new hash counter, or fabricated completion"
    );
    assert_eq!(
        fixture.tracking.tracker()?.performance_counters()["bytesRead"],
        0
    );
    assert!(!fixture.agent.operations.is_running(saved.operation));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_completed_capture_reloads_original_encrypted_proof_after_tracker_restart_and_keeps_newer_dirt(
) -> Result<()> {
    let mut fixture = Fixture::create()?;
    let prepared = fixture.prepare(None)?;
    fixture.execute(&prepared).await?;
    let saved = fixture.save_completed_before_ack(&prepared).await?;
    drop(prepared); // No original controller/Tracker owner may serve recovery.
    fixture.restart_tracker_before_ack(&saved)?;
    assert!(native_capture::counters(&fixture.agent, saved.operation)?.is_none());

    let newer = vec![0x7b; fixture.initial_files["save.dat"].len()];
    let path = fixture.source.join("save.dat");
    let modified = fs::metadata(&path)?.modified()?;
    let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
    file.write_all(&newer)?;
    file.set_times(fs::FileTimes::new().set_modified(modified))?;
    file.sync_all()?;
    let mut new_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.source.join("after-restart.dat"))?;
    new_file.write_all(b"new local data outside the immutable old capture")?;
    new_file.sync_all()?;
    fixture
        .tracking
        .call("scan_metadata", &json!({"softwareId":SOFTWARE}))?;
    let current = fixture.store.software_record(SOFTWARE)?;
    assert_eq!(current["dirty"], true);
    assert_eq!(
        current["fileCount"],
        fixture.initial_files.len() as u64 + 1,
        "the new file must be present in today's real metadata index before historical resume"
    );
    let current_files = fixture.tracking.call(
        "file_listing",
        &json!({"softwareId":SOFTWARE,"limit":MAX_APP_FILES}),
    )?;
    assert!(current_files["files"]
        .as_array()
        .context("actual newer native index page")?
        .iter()
        .any(|file| file["path"] == "after-restart.dat" && file["status"] != "saved"));
    assert_ne!(
        current["bundleIndexSource"]["snapshotIdentity"],
        saved.frame_reference["scope"]["metadataIdentity"],
        "recovery must tolerate a genuinely newer index, not suppress reconciliation to retain old nonces"
    );
    assert!(
        current["dirtyGeneration"].as_u64().unwrap() > saved.work["generation"].as_u64().unwrap()
    );
    let original = fixture.load_original(&saved)?;
    let authority = OriginalDeviceAuthority::open(&fixture, original.clone())?;
    let before = fixture.storage.snapshot();
    let source_scans = fixture.agent.metrics.snapshot().reconciliations_total;
    let replay = fixture.verify_source_replay(&saved).await?;
    let (receipt, sink) = recover_original(&fixture, &saved, original.clone(), authority, &replay)?;
    assert_eq!(
        receipt.evidence()?,
        read_signed_json(
            &fixture.data.join("tracking-bundles"),
            &saved.receipt["reference"]
        )?
    );
    assert_eq!(
        sink.accepted.lock().unwrap().as_ref().unwrap()["generation"],
        saved.work["generation"]
    );
    let attached = fixture.store.software_record(SOFTWARE)?;
    assert_eq!(
        attached["captureReceipt"], saved.receipt,
        "original device receipt MAC/nonce must be identical"
    );
    assert_eq!(
        attached["pendingWork"], saved.frame_reference,
        "no new frozen work or grants on resume"
    );
    assert_eq!(saved.witness.verify_calls.load(Ordering::Acquire), 0);
    let counters = native_capture::counters(&fixture.agent, saved.operation)?
        .context("recovered source counters")?;
    assert!(
        counters.checkpoint_read_bytes > 0 && counters.checkpoint_read_bytes <= MAX_DOCUMENT_BYTES,
        "remove() must force the actual encrypted capture proof to be read from disk"
    );
    assert_eq!(counters.metadata_file_opens, 0);
    assert_eq!(counters.inventory_nodes, 0);
    assert_eq!(counters.source_proofs_recorded, 0);
    assert_eq!(counters.reused_file_proofs, 0);
    assert!(counters.frozen_pages <= 1 && counters.directory_pin_validations <= 512);
    assert_eq!(
        fixture.agent.metrics.snapshot().reconciliations_total,
        source_scans
    );
    assert_no_source_recapture(&fixture, &saved, &before)?;

    let completed = fixture
        .tracking
        .call(
            "complete_upload",
            &json!({
                "workId":saved.work["workId"],"generation":saved.work["generation"],"success":true,
            }),
        )
        .context("restart: complete recovered original only through actual COMMITTED witness")?;
    assert_eq!(completed["workId"], saved.work["workId"]);
    assert_eq!(completed["generation"], saved.work["generation"]);
    assert_eq!(completed["sourceConfirmed"], true);
    assert_eq!(completed["historicalBaselineConfirmed"], true);
    assert_eq!(completed["currentGenerationConfirmed"], false);
    assert!(saved.witness.verify_calls.load(Ordering::Acquire) > 0);
    let after = fixture.store.software_record(SOFTWARE)?;
    assert_eq!(after["dirty"], true);
    assert_ne!(after["status"], "saved");
    assert!(
        after["dirtyGeneration"].as_u64().unwrap() >= current["dirtyGeneration"].as_u64().unwrap()
    );
    assert!(
        after["unknownGeneration"].as_u64().unwrap()
            > saved.receipt["scope"]["unknownGeneration"]
                .as_u64()
                .unwrap()
    );
    assert_eq!(
        after["lastConfirmedUploadedGeneration"],
        current["lastConfirmedUploadedGeneration"]
    );
    assert!(after["pendingWork"].is_null());
    assert_eq!(after["captureReceipt"], saved.receipt);
    assert!(
        original.revalidate().is_err(),
        "retired original frame must not be replayable"
    );
    let baseline_reference = &after["baseline"];
    let baseline_scope = json!({
        "version":1,"tracking":saved.work["authorization"]["trackingScope"],
        "providerId":fixture.provider_id,"name":baseline_reference["name"],
        "hash":baseline_reference["hash"],"fullScope":true,
    });
    assert!(fixture.store.verify_grant(
        "tracking_baseline",
        &baseline_scope,
        &baseline_reference["grant"]
    )?);
    let baseline = read_signed_json(&fixture.data.join("tracking-baselines"), baseline_reference)?;
    assert_eq!(
        baseline["nodes"].as_object().unwrap().len(),
        saved.witness.manifest.files.len()
    );
    assert!(!baseline["nodes"]
        .as_object()
        .unwrap()
        .values()
        .any(|node| node["path"] == "after-restart.dat"));
    assert_eq!(fs::read(&path)?, newer);
    assert!(fixture.source.join("after-restart.dat").is_file());
    assert_eq!(
        fixture
            .read_payload(&saved.witness.manifest, "save.dat")
            .await?,
        fixture.initial_files["save.dat"],
        "independent stored-pack AEAD readback must still yield the original generation"
    );
    assert_no_source_recapture(&fixture, &saved, &before)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_original_device_frame_rejects_same_length_receipt_sidecar_tamper_without_recapture(
) -> Result<()> {
    let mut fixture = Fixture::create()?;
    let prepared = fixture.prepare(None)?;
    fixture.execute(&prepared).await?;
    let saved = fixture.save_completed_before_ack(&prepared).await?;
    drop(prepared);
    fixture.restart_tracker_before_ack(&saved)?;
    let original = fixture.load_original(&saved)?;
    let before = fixture.storage.snapshot();
    let replay = fixture.verify_source_replay(&saved).await?;
    let name = dto::text(&saved.receipt["reference"], "name", 255)?;
    let sidecar = fixture.data.join("tracking-bundles").join(name);
    let mut tampered = fs::read(&sidecar)?;
    ensure!(
        tampered.len() <= MAX_DOCUMENT_BYTES as usize && !tampered.is_empty(),
        "bounded sidecar tamper"
    );
    // Same native file and length; retain mtime too. Neither the still-valid
    // device frame MAC nor COMPLETED source state can authenticate changed bytes.
    let modified = fs::metadata(&sidecar)?.modified()?;
    let index = tampered
        .iter()
        .position(|byte| *byte == b'a')
        .context("actual sidecar contains hex data")?;
    tampered[index] = b'b';
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&sidecar)?;
    file.write_all(&tampered)?;
    file.set_times(fs::FileTimes::new().set_modified(modified))?;
    file.sync_all()?;
    assert!(fixture.store.verify_grant(
        "tracking_frozen_work",
        &saved.frame_reference["scope"],
        &saved.frame_reference["grant"]
    )?);
    assert!(fixture.store.verify_grant(
        "tracking_capture_receipt",
        &saved.receipt["scope"],
        &saved.receipt["grant"]
    )?);
    let error = match OriginalDeviceAuthority::open(&fixture, original) {
        Ok(_) => bail!("modified actual receipt sidecar acquired original native authority"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("device-authenticated hash"));
    replay.revalidate(&fixture.agent)?;
    assert!(!native_capture::is_installed(
        &fixture.agent,
        saved.operation
    ));
    assert!(native_capture::counters(&fixture.agent, saved.operation)?.is_none());
    let record = fixture.store.software_record(SOFTWARE)?;
    assert_eq!(record["pendingWork"], saved.frame_reference);
    assert!(record["baseline"].is_null());
    assert_ne!(record["status"], "saved");
    assert_no_source_recapture(&fixture, &saved, &before)?;
    Ok(())
}
