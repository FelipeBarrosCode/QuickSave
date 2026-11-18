// SPDX-License-Identifier: GPL-3.0-only
// Derived fixture/API patterns: No Land e81238a7536aae201540956ce76981364fd36595,
// state-agent backup/{scale,optimizations}.rs and QuickSave NativeEngine source tests.
//! Actual native-approved StateAgent -> FastCDC/CAS -> encrypted zstd packs ->
//! immutable LocalStorage metadata -> authenticated streaming native restore.
//! No QuickSave local-format engine, rclone, provider account, OS vault, observer
//! startup, discovery of host applications, or Linux BPF privilege is involved.
#![cfg(unix)]

use bytes::Bytes;
use chrono::Utc;
use noland_crypto::MasterKey;
use noland_restore::{
    NativeConflictMode, NativeRecoveryAuthority, NativeRestoreControl, NativeRestorePreview,
    PipelineOptions, PipelineProgress,
};
use noland_snapshot::SourcePath;
use noland_state_agent::{
    backup::run_backup,
    native_capture::{
        self, NativeCaptureNode, NativeCaptureReceipt, NativeCaptureScope, NativeCaptureSink,
        NativeCaptureStamp, NativeFullScopeAuthority, NativeFullScopeBinding,
    },
    native_host::{
        native_file_id, native_restore_roots, ApprovedNativeRoot, NativeCoverage, NativeSelection,
    },
    AgentConfig, StateAgent,
};
use noland_state_core::*;
use noland_state_db::StateDb;
use noland_storage::{
    AdaptiveConcurrency, DownloadObserver, DownloadStreamConsumer, Health,
    LocalStorage as NativeLocalStorage, MetadataReadMetrics, ProviderRootIdentity, RemoteEntry,
    RemoteErrorClass, RemoteKey, RemoteMeta, SharedStorageProvider, StorageOperationMetrics,
    TransferTuning,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    future::Future,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use uuid::Uuid;

const SOURCE_COMMIT: &str = "e81238a7536aae201540956ce76981364fd36595";
const MIB: u64 = 1024 * 1024;
const GENERATION_BUFFER: usize = 64 * 1024;
const MAX_FIXTURE_BYTES: u64 = 256 * MIB;
const MAX_FIXTURE_FILES: usize = 4096;
const POLL_ROWS: usize = 250_000;
type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Clone, Default)]
struct Counters {
    io: StorageOperationMetrics,
    metadata: MetadataReadMetrics,
    pack_uploads: u64,
    pack_uploaded_bytes: u64,
    stream_downloaded_bytes: u64,
    stream_keys: Vec<String>,
    writes: Vec<String>,
}

impl Counters {
    fn remote_delta(&self, previous: &Self) -> Value {
        let io = self.io.saturating_sub(previous.io);
        json!({
            "uploaded": io.bytes_uploaded,
            "downloaded": io.bytes_downloaded,
            "packUploaded": self.pack_uploaded_bytes - previous.pack_uploaded_bytes,
            "streamDownloaded": self.stream_downloaded_bytes - previous.stream_downloaded_bytes,
            "scope": "actual filesystem-fixture object payloads; not live network/protocol bytes",
        })
    }
}

/// Instrumentation delegates every byte and durability operation to the actual
/// source LocalStorage. Defaults retain source transfer and MetadataBatch code.
/// In particular, the wrapper must not lose streaming/targeted-upload capabilities.
struct CountedNativeLocalStorage {
    inner: NativeLocalStorage,
    counts: Mutex<Counters>,
    operation: Mutex<Option<(StateDb, Uuid)>>,
    fail_bundle_marker: AtomicBool,
}

impl CountedNativeLocalStorage {
    fn new(root: PathBuf) -> Self {
        Self {
            inner: NativeLocalStorage::new(root),
            counts: Mutex::new(Counters::default()),
            operation: Mutex::new(None),
            fail_bundle_marker: AtomicBool::new(false),
        }
    }

    fn snapshot(&self) -> Counters {
        self.counts.lock().unwrap().clone()
    }

    fn bind_operation(&self, db: &StateDb, id: Uuid) {
        *self.operation.lock().unwrap() = Some((db.clone(), id));
    }

    fn record_write(&self, key: &RemoteKey, bytes: u64, pack: bool) -> Result<()> {
        if key.as_str().ends_with("COMMITTED") {
            if let Some((db, id)) = self.operation.lock().unwrap().as_ref() {
                if db
                    .operation_monitoring_snapshot(*id)?
                    .is_some_and(|snapshot| snapshot.operation.state == "COMPLETED")
                {
                    return Err(StateError::Integrity(
                        "operation claimed completion before metadata/claim finalization".into(),
                    ));
                }
            }
        }
        let mut counters = self.counts.lock().unwrap();
        assert!(counters.writes.len() < 10_000, "bounded fixture event log");
        counters.writes.push(key.as_str().into());
        counters.io.remote_upload_calls += 1;
        counters.io.bytes_uploaded += bytes;
        if pack {
            counters.pack_uploads += 1;
            counters.pack_uploaded_bytes += bytes;
        }
        Ok(())
    }
}

// Spell out async-trait's stable boxed-future ABI so this integration fixture
// needs no new direct dependency or changes outside its assigned file.
impl SharedStorageProvider for CountedNativeLocalStorage {
    fn health_check<'a, 't>(&'a self) -> LocalFuture<'t, Health>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.inner.health_check().await })
    }

    fn ensure_root<'a, 't>(&'a self) -> LocalFuture<'t, ()>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.inner.ensure_root().await })
    }

    fn stat<'a, 'b, 't>(&'a self, key: &'b RemoteKey) -> LocalFuture<'t, Option<RemoteMeta>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.counts.lock().unwrap().io.remote_stat_calls += 1;
            self.inner.stat(key).await
        })
    }

    fn upload_immutable<'a, 'b, 'c, 't>(
        &'a self,
        local: &'b Path,
        key: &'c RemoteKey,
    ) -> LocalFuture<'t, RemoteMeta>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        Self: 't,
    {
        Box::pin(async move {
            let meta = self.inner.upload_immutable(local, key).await?;
            self.record_write(key, meta.size, key.as_str().starts_with("packs/"))?;
            Ok(meta)
        })
    }

    fn download<'a, 'b, 'c, 't>(
        &'a self,
        key: &'b RemoteKey,
        destination: &'c Path,
    ) -> LocalFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.inner.download(key, destination).await?;
            let size = fs::metadata(destination)?.len();
            let mut counters = self.counts.lock().unwrap();
            counters.io.remote_download_calls += 1;
            counters.io.bytes_downloaded += size;
            Ok(())
        })
    }

    fn read_small<'a, 'b, 't>(&'a self, key: &'b RemoteKey, limit: u64) -> LocalFuture<'t, Vec<u8>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            {
                let mut counters = self.counts.lock().unwrap();
                counters.metadata.read_calls += 1;
                counters.metadata.attempts += 1;
            }
            let bytes = self.inner.read_small(key, limit).await?;
            let mut counters = self.counts.lock().unwrap();
            counters.metadata.bytes_received += bytes.len() as u64;
            counters.io.remote_download_calls += 1;
            counters.io.bytes_downloaded += bytes.len() as u64;
            Ok(bytes)
        })
    }

    fn list_prefix<'a, 'b, 't>(&'a self, prefix: &'b RemoteKey) -> LocalFuture<'t, Vec<RemoteEntry>>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            self.counts.lock().unwrap().io.remote_list_calls += 1;
            self.inner.list_prefix(prefix).await
        })
    }

    fn put_small_versioned<'a, 'b, 't>(
        &'a self,
        bytes: Bytes,
        key: &'b RemoteKey,
    ) -> LocalFuture<'t, RemoteMeta>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            if key.as_str().starts_with("bundles/")
                && key.as_str().ends_with("/COMMITTED")
                && self.fail_bundle_marker.swap(false, Ordering::AcqRel)
            {
                return Err(StateError::Storage(
                    "synthetic fault before durable bundle marker".into(),
                ));
            }
            let result = self.inner.put_small_versioned(bytes, key).await?;
            self.record_write(key, result.size, false)?;
            Ok(result)
        })
    }

    fn supports_streaming_downloads(&self) -> bool {
        self.inner.supports_streaming_downloads()
    }

    fn supports_targeted_uploads(&self) -> bool {
        self.inner.supports_targeted_uploads()
    }

    fn delete_object<'a, 'b, 't>(&'a self, key: &'b RemoteKey) -> LocalFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        // Required for exact authenticated repository-claim cleanup, NOT history
        // convergence or payload deletion. Source key/path guards still apply.
        Box::pin(async move {
            if !key.as_str().starts_with("maintenance/activity/") {
                return Err(StateError::Storage(
                    "benchmark forbids payload/history deletion".into(),
                ));
            }
            self.inner.delete_object(key).await
        })
    }

    fn download_stream_observed<'a, 'b, 'c, 'd, 'e, 'f, 't>(
        &'a self,
        key: &'b RemoteKey,
        scratch: &'c Path,
        consumer: &'d dyn DownloadStreamConsumer,
        observer: Option<&'e (dyn DownloadObserver + 'f)>,
    ) -> LocalFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        'c: 't,
        'd: 't,
        'e: 't,
        Self: 't,
    {
        Box::pin(async move {
            {
                let mut counters = self.counts.lock().unwrap();
                assert!(counters.stream_keys.len() < 10_000);
                counters.stream_keys.push(key.as_str().into());
                counters.io.remote_download_calls += 1;
            }
            let measured = CountingConsumer {
                downstream: consumer,
                counters: &self.counts,
            };
            self.inner
                .download_stream_observed(key, scratch, &measured, observer)
                .await
        })
    }

    fn storage_identity(&self) -> Option<ProviderRootIdentity> {
        self.inner.storage_identity()
    }

    fn operation_metrics(&self) -> StorageOperationMetrics {
        self.counts.lock().unwrap().io
    }

    fn metadata_read_metrics(&self) -> MetadataReadMetrics {
        self.counts.lock().unwrap().metadata
    }
}

struct CountingConsumer<'a> {
    downstream: &'a dyn DownloadStreamConsumer,
    counters: &'a Mutex<Counters>,
}

impl DownloadStreamConsumer for CountingConsumer<'_> {
    fn restart<'a, 't>(&'a self) -> LocalFuture<'t, ()>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.downstream.restart().await })
    }

    fn write<'a, 'b, 't>(&'a self, bytes: &'b [u8]) -> LocalFuture<'t, ()>
    where
        'a: 't,
        'b: 't,
        Self: 't,
    {
        Box::pin(async move {
            {
                let mut counters = self.counters.lock().unwrap();
                counters.stream_downloaded_bytes += bytes.len() as u64;
                counters.io.bytes_downloaded += bytes.len() as u64;
            }
            self.downstream.write(bytes).await
        })
    }

    fn finish<'a, 't>(&'a self) -> LocalFuture<'t, ()>
    where
        'a: 't,
        Self: 't,
    {
        Box::pin(async move { self.downstream.finish().await })
    }
}

struct OwnedFixtureRoot {
    path: PathBuf,
    identity: (u64, u64),
}

impl OwnedFixtureRoot {
    fn create() -> Result<Self> {
        let preferred =
            Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
        let parent = std::env::var_os("QUICKSAVE_NATIVE_BENCH_SANDBOX")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if preferred.is_dir() {
                    preferred.to_path_buf()
                } else {
                    std::env::temp_dir()
                }
            });
        // Resolve only a temporary parent. All app/data/provider paths below it
        // are freshly created; no production-state getter is ever consulted.
        let parent = fs::canonicalize(parent)?;
        let path = parent.join(format!("native-shared-storage-fixture-{}", Uuid::new_v4()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let metadata = SourcePath::new(&path)?.metadata()?;
        Ok(Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl Drop for OwnedFixtureRoot {
    fn drop(&mut self) {
        // Never remove an unowned/replaced directory, including after a failure.
        if SourcePath::new(&self.path)
            .and_then(|source| source.metadata())
            .is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.is_symlink()
                    && (metadata.dev(), metadata.ino()) == self.identity
            })
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Test-local explicit config, NOT a production config/vault discovery API.
/// It pins the actual source StateAgent data root and enables native-host mode.
struct NoLandNativeConfig {
    data_root: PathBuf,
    home: PathBuf,
}

impl NoLandNativeConfig {
    fn boot(self) -> Result<StateAgent> {
        fs::create_dir(&self.data_root)?;
        fs::set_permissions(&self.data_root, fs::Permissions::from_mode(0o700))?;
        let paths =
            AgentPaths::from_roots(self.data_root.join("state"), self.data_root.join("run"));
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
        let agent = StateAgent::boot(AgentConfig {
            instance_id: Uuid::new_v4(),
            image_id: "synthetic-native-optimization-fixture".into(),
            paths,
            home: self.home,
            user: "isolated-fixture".into(),
            converge_complete_backups: false,
            native_host: true,
            capture_exclusions: vec![self.data_root],
        })?;
        assert!(agent.config.native_host);
        assert!(!agent.config.converge_complete_backups);
        assert!(agent.roots.lock().home.is_none());
        assert!(!agent.config.paths.rpc_socket.exists());
        // No observer.start(), recover procfs walk, remote RPC, or host discovery.
        Ok(agent)
    }
}

#[derive(Clone)]
struct FixtureFile {
    relative: String,
    size: u64,
    hash: String,
}

struct Fixture {
    // Declared last: source engine/provider handles drain before root cleanup.
    agent: StateAgent,
    provider: CountedNativeLocalStorage,
    app: AppId,
    source: PathBuf,
    files: Vec<FixtureFile>,
    master: MasterKey,
    fixture_hash_reads: u64,
    reuse_epoch: String,
    _owned: OwnedFixtureRoot,
}

impl Fixture {
    fn create(bytes: u64, count: usize) -> Result<Self> {
        Self::create_for_app(
            bytes,
            count,
            AppId("quicksave:isolated-native-optimization".into()),
        )
    }

    fn create_for_app(bytes: u64, count: usize, app: AppId) -> Result<Self> {
        assert!((MIB..=MAX_FIXTURE_BYTES).contains(&bytes));
        assert!((8..=MAX_FIXTURE_FILES).contains(&count));
        let owned = OwnedFixtureRoot::create()?;
        // Conservative fixture admission, not an RSS or peak-disk measurement.
        // Even the explicit 256 MiB workload cannot request a 34 GB copy.
        let (_, available) = disk::available(&owned.path)?;
        assert!(
            available >= bytes.saturating_mul(8).saturating_add(256 * MIB),
            "insufficient isolated fixture scratch space"
        );
        let source = owned.path.join("approved-source");
        let home = owned.path.join("synthetic-home");
        let cloud = owned.path.join("synthetic-provider");
        for path in [&source, &home, &cloud] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let agent = NoLandNativeConfig {
            data_root: owned.path.join("source-native-data-root"),
            home,
        }
        .boot()?;
        assert!(agent.config.paths.state_root.starts_with(&owned.path));
        let metadata = SourcePath::new(&source)?.metadata()?;
        agent.native_register(
            AppIdentity::new(app.clone(), "Synthetic Native Optimization"),
            vec![ApprovedNativeRoot {
                id: "payload".into(),
                path: source.clone(),
                allowed_files: None,
                expected_identity: Some((metadata.dev(), metadata.ino())),
                role: noland_state_agent::native_host::NativeRootRole::Data,
            }],
        )?;
        let mut fixture = Self {
            agent,
            provider: CountedNativeLocalStorage::new(cloud),
            app,
            source,
            files: Vec::with_capacity(count),
            master: MasterKey::generate(),
            fixture_hash_reads: 0,
            reuse_epoch: format!("isolated-native-fixture-{}:gap-0", Uuid::new_v4()),
            _owned: owned,
        };
        let large = bytes / 4;
        fixture.generate(
            "assets/large-00.bin".into(),
            large,
            0x123456789abcdef,
            false,
        )?;
        // Same content generated independently: actual cross-file chunk dedup.
        fixture.generate(
            "assets/large-01-duplicate.bin".into(),
            large,
            0x123456789abcdef,
            false,
        )?;
        fixture.generate("assets/large-02-compressible.bin".into(), large, 7, true)?;
        let remaining_files = count - 3;
        let remaining = bytes - large * 3;
        for index in 0..remaining_files {
            let length = remaining / remaining_files as u64
                + u64::from((index as u64) < remaining % remaining_files as u64);
            fixture.generate(
                format!("state/{:03}/save-{index:05}.bin", index / 128),
                length,
                0xa11ce + index as u64,
                index % 4 == 0,
            )?;
        }
        assert_eq!(
            fixture.files.iter().map(|file| file.size).sum::<u64>(),
            bytes
        );
        assert_eq!(fixture.files.len(), count);
        Ok(fixture)
    }

    fn generate(
        &mut self,
        relative: String,
        length: u64,
        mut seed: u64,
        zeros: bool,
    ) -> Result<()> {
        let path = self.source.join(&relative);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut buffer = [0u8; GENERATION_BUFFER];
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            if !zeros {
                for byte in &mut buffer[..count] {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    *byte = (seed >> 32) as u8;
                }
            }
            file.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
        self.fixture_hash_reads += length;
        self.files.push(FixtureFile {
            relative,
            size: length,
            hash: noland_cas::blake3_file(&path)?,
        });
        Ok(())
    }

    fn selection(&self, relative: Option<&str>) -> Result<NativeSelection> {
        let mut keys = Vec::new();
        let mut expected = Vec::new();
        // A deterministic fixture owns all writes. Known expected bytes are
        // verification evidence only; they never certify native "no events = clean".
        // The real engine still performs its own guarded capture/revalidation.
        for file in self
            .files
            .iter()
            .filter(|file| relative.is_none_or(|relative| relative == file.relative))
        {
            let logical = self
                .agent
                .native_logical_path(&self.app, &self.source.join(&file.relative))?;
            let token = logical.logical_root.as_token();
            keys.push(json!({"logical_root":token,"relative_path":file.relative}));
            expected.push(json!({
                "id":native_file_id(&token, &file.relative),
                "size":file.size, "fileHash":file.hash,
            }));
        }
        assert!(!keys.is_empty());
        let identity = noland_cas::blake3_hex(&serde_json::to_vec(&expected)?);
        NativeSelection::parse(&json!({
            "version":1, "file_keys":keys,
            "roots_fingerprint":self.agent.native_binding_fingerprint(&self.app)?,
            "destination":null, "destination_identity":null,
            "snapshot_identity":identity, "expected_files":expected,
            "coverage":"selected_nodes",
            "software_instance_id":"isolated-metadata-native-instance",
        }))
    }

    fn queue(&self, selection: NativeSelection) -> Result<Uuid> {
        let id = Uuid::new_v4();
        self.queue_as(id, selection)
    }

    fn queue_as(&self, id: Uuid, selection: NativeSelection) -> Result<Uuid> {
        let source = self.source.clone();
        let held = Arc::new(SourcePath::new(&source)?.open_directory()?);
        let identity = held.metadata()?;
        let expected = (identity.dev(), identity.ino());
        self.agent.native_set_publication_guard(
            id,
            Arc::new(move || {
                let current = SourcePath::new(&source)?.metadata()?;
                let pinned = held.metadata()?;
                if current.is_dir()
                    && !current.is_symlink()
                    && (current.dev(), current.ino()) == expected
                    && (pinned.dev(), pinned.ino()) == expected
                {
                    Ok(())
                } else {
                    Err(StateError::Conflict(
                        "synthetic native consent/root changed".into(),
                    ))
                }
            }),
        )?;
        let now = Utc::now();
        let mode = if selection.coverage == NativeCoverage::SelectedNodes {
            "custom"
        } else {
            "complete_application"
        };
        self.agent.db.upsert_operation(&OperationRecord {
            operation_id: id,
            kind: "backup".into(),
            app_id: Some(self.app.clone()),
            state: "QUEUED".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: json!({
                "native_selection":selection, "mode":mode,
                "performance_mode":"automatic", "regenerable_caches":"include",
            }),
        })?;
        self.provider.bind_operation(&self.agent.db, id);
        Ok(id)
    }

    async fn execute(&self, id: Uuid) -> Result<BundleManifest> {
        run_backup(
            &self.agent,
            &self.app,
            BackupMode::parse(
                self.agent.db.get_operation(id)?.unwrap().detail_json["mode"]
                    .as_str()
                    .unwrap(),
            ),
            BackupPerformanceMode::Automatic,
            &self.provider,
            &self.master,
            Some(id),
        )
        .await
    }

    async fn capture(&self, relative: Option<&str>) -> Result<(BundleManifest, Value)> {
        self.capture_with_scope(relative, true).await
    }

    async fn capture_legacy(&self, relative: Option<&str>) -> Result<(BundleManifest, Value)> {
        self.capture_with_scope(relative, false).await
    }

    async fn capture_with_scope(
        &self,
        relative: Option<&str>,
        metadata_only: bool,
    ) -> Result<(BundleManifest, Value)> {
        let started = Instant::now();
        let before = self.provider.snapshot();
        let scans = self.agent.metrics.snapshot().reconciliations_total;
        let id = if metadata_only {
            queue_metadata_capture_selected(self, relative, false, Some(self.reuse_epoch.clone()))?
                .0
        } else {
            self.queue(self.selection(relative)?)?
        };
        let manifest = self.execute(id).await?;
        let operation = self.agent.db.get_operation(id)?.unwrap();
        assert_eq!(operation.state, "COMPLETED");
        assert_eq!(
            operation.detail_json["repository_admission"]["status"],
            "RELEASED"
        );
        let metrics: OperationMetrics =
            serde_json::from_value(operation.detail_json["metrics"].clone())?;
        let authenticated = noland_storage::read_committed_manifest(
            &self.provider,
            &self.master,
            &self.app,
            manifest.bundle_id,
        )
        .await?;
        assert_eq!(authenticated.commit_id, manifest.commit_id);
        assert_eq!(authenticated.files.len(), manifest.files.len());
        let index = noland_storage::read_pack_index(
            &self.provider,
            &self.master,
            &self.app,
            manifest.bundle_id,
        )
        .await?;
        let reused_hashes = index
            .iter()
            .filter(|entry| {
                before
                    .writes
                    .iter()
                    .any(|key| *key == pack_key(&entry.pack_id))
            })
            .map(|entry| entry.chunk_hash.as_str())
            .collect::<BTreeSet<_>>();
        let after = self.provider.snapshot();
        let reused_chunks = manifest
            .files
            .iter()
            .flat_map(|file| &file.chunks)
            .filter(|chunk| reused_hashes.contains(chunk.hash.as_str()))
            .count();
        let sample = json!({
            "elapsedSeconds":started.elapsed().as_secs_f64(),
            "bytesRead":metrics.bytes_hashed,
            "bytesReadScope":"source hash input; staging/copy physical read syscalls are uninstrumented",
            "physicalBytesRead":null,
            "filesRehashed":metrics.num_files_rehashed,
            "sourceFilesReused":metrics.num_files_skipped_fast_identity,
            "chunksReused":reused_chunks,
            "chunksReusedScope":"manifest chunk references mapped to packs actually uploaded before this capture",
            "hashWorkerChunksReused":metrics.num_chunks_reused,
            "chunksCreated":metrics.num_chunks_created,
            "newPacks":after.pack_uploads - before.pack_uploads,
            "remoteBytes":after.remote_delta(&before),
            "readback":null, "peakBuffers":capture_buffers(&operation),
            "fullScans":self.agent.metrics.snapshot().reconciliations_total - scans,
            "filesScanned":metrics.num_files_scanned,
            "selectedFiles":manifest.files.len(),
            "captureAuthority":if metadata_only { "actual_source_metadata_scope_receipt" } else { "legacy_expected_hash_gate" },
            "captureMetadataCounters":native_capture::counters(&self.agent, id)?,
            "durableCompletion":true,
        });
        Ok((manifest, sample))
    }

    fn modify_large_file(&mut self) -> Result<()> {
        let file = &mut self.files[0];
        assert_eq!(file.relative, "assets/large-00.bin");
        let path = self.source.join(&file.relative);
        let mut opened = OpenOptions::new().write(true).open(&path)?;
        opened.seek(SeekFrom::Start(0))?;
        opened.write_all(&[0x5a; 4096])?;
        opened.sync_all()?;
        file.hash = noland_cas::blake3_file(&path)?;
        self.fixture_hash_reads += file.size;
        let record = self
            .agent
            .db
            .get_path_by_canonical(path.to_str().unwrap())?
            .unwrap();
        self.agent
            .db
            .mark_dirty(&self.app, Some(record.path_id), false)?;
        self.agent.db.append_app_mutation(&AppMutationRecord::new(
            self.app.clone(),
            path.to_str().unwrap(),
            AppMutationKind::Modify,
        ))?;
        Ok(())
    }

    async fn restore(
        &self,
        manifest: &BundleManifest,
        destination: &Path,
        relative: Option<&str>,
        merge: bool,
    ) -> Result<Value> {
        assert!(
            manifest.tombstones.is_empty(),
            "ordinary fixture approval must not silently acknowledge native tombstones"
        );
        let started = Instant::now();
        let before = self.provider.snapshot();
        let scans = self.agent.metrics.snapshot().reconciliations_total;
        if !destination.exists() {
            fs::create_dir(destination)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
        }
        let mut plan = noland_restore::prepare_restore(
            &self.provider,
            &self.master,
            &self.agent.config.paths,
            &self.app,
            manifest.bundle_id,
            RestoreMode::CompleteApplication,
        )
        .await?;
        // Validate the original authenticated frame before native exact-key
        // projection; a present malformed descriptor must never fall back.
        noland_state_core::native_layout::native_root_layouts(&plan.manifest)?;
        let index = noland_storage::read_pack_index(
            &self.provider,
            &self.master,
            &self.app,
            manifest.bundle_id,
        )
        .await?;
        let available = index
            .iter()
            .map(|entry| entry.pack_id.clone())
            .collect::<BTreeSet<_>>();
        if let Some(relative) = relative {
            // Native-local selection from the authenticated manifest; not caller
            // paths or a fabricated single-file pack. Never widen selection.
            plan.manifest
                .files
                .retain(|file| file.relative_path == relative);
            plan.manifest.tombstones.clear();
            noland_state_core::native_layout::project_native_root_layouts(&mut plan.manifest)?;
            assert_eq!(plan.manifest.files.len(), 1);
        }
        let hashes = plan
            .manifest
            .files
            .iter()
            .flat_map(|file| file.chunks.iter().map(|chunk| chunk.hash.clone()))
            .collect::<BTreeSet<_>>();
        let required = index
            .iter()
            .filter(|entry| hashes.contains(&entry.chunk_hash))
            .map(|entry| entry.pack_id.clone())
            .collect::<BTreeSet<_>>();
        let roots = native_restore_roots(destination, &plan.manifest)?;
        let held = Arc::new(SourcePath::new(destination)?.open_directory()?);
        let pinned = held.metadata()?;
        let identity = (pinned.dev(), pinned.ino());
        let preview = NativeRestorePreview::prepare(
            plan.restore_id,
            &plan.manifest,
            &roots,
            destination,
            identity,
            if merge {
                NativeConflictMode::Merge
            } else {
                NativeConflictMode::CreateOnly
            },
        )?;
        assert!(!preview.has_conflicts());
        let target = destination.to_path_buf();
        let control = NativeRestoreControl::approve(
            preview,
            Arc::new(FixtureRecoveryAuthority(MasterKey::generate())),
            Arc::new(move || {
                let current = SourcePath::new(&target)?.metadata()?;
                let pinned = held.metadata()?;
                if current.is_dir()
                    && !current.is_symlink()
                    && (current.dev(), current.ino()) == identity
                    && (pinned.dev(), pinned.ino()) == identity
                {
                    Ok(())
                } else {
                    Err(StateError::Conflict(
                        "native restore fixture root changed".into(),
                    ))
                }
            }),
        )?;
        let expected_files = plan.manifest.files.clone();
        let plan = plan.into_shared().with_native_control(Arc::new(control));
        let mut last = PipelineProgress::default();
        let report = noland_restore::restore_pipelined(
            &self.provider,
            &self.master,
            &plan,
            &index,
            &roots,
            None,
            None,
            PipelineOptions {
                // One stream makes the ordered/no-readback gate deterministic.
                // Provider/CPU/memory admission remains mandatory and may lower
                // these explicit upper bounds. Limiter parallelism is tested below.
                max_parallel_packs: 1,
                reconstruction_workers: 2,
                buffered_chunks: 2,
                overlap_file_syncs: false,
                ..PipelineOptions::default()
            },
            |progress| {
                last = progress;
                Ok(())
            },
        )
        .await?;
        assert_eq!(report.io.unfinished_files, 0);
        assert_eq!(report.io.unfinished_bytes, 0);
        assert!(report.io.peak_assembly_handles <= 32);
        assert!(report.io.peak_active_hashers <= 128);
        assert!(report.io.peak_unpublished_files <= 256);
        assert!(report.io.peak_unpublished_bytes <= 64 * MIB);
        assert!(report.io.peak_decode_workers <= report.io.effective_parallel_packs);
        assert!(report.io.peak_verification_workers <= report.io.effective_verification_workers);
        assert!(plan.verify_native_completion()?.is_clean_committed(),
            "native restore must authenticate durable completion and reject unknown/plaintext artifacts");
        let completed = report.restore.published_entries + report.restore.reused_entries;
        assert_eq!(completed, expected_files.len());
        let after = self.provider.snapshot();
        let streams = &after.stream_keys[before.stream_keys.len()..];
        let unique = streams.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            streams.len(),
            "never copy/download a pack per file"
        );
        assert_eq!(streams.len(), report.packs_downloaded);
        for key in &unique {
            assert!(required.iter().any(|pack| pack_key(pack) == *key));
        }
        // Independent post-run verification is deliberately separate from the
        // pipeline's readback counter and wall time. It is not a hidden speed win.
        let elapsed = started.elapsed().as_secs_f64();
        let mut verification_bytes = 0u64;
        for file in &expected_files {
            let mapped = roots.resolve(&file.logical_root_parsed().unwrap()).unwrap();
            let path = mapped.join(&file.relative_path);
            let metadata = fs::symlink_metadata(&path)?;
            match file.file_type.as_str() {
                "file" => {
                    assert!(metadata.is_file());
                    assert_eq!(noland_cas::blake3_file(&path)?, file.file_hash);
                    verification_bytes += file.size;
                }
                "directory" => assert!(metadata.is_dir()),
                "symlink" => {
                    assert!(metadata.file_type().is_symlink());
                    assert_eq!(
                        fs::read_link(&path)?.to_str(),
                        file.symlink_target.as_deref()
                    );
                }
                _ => panic!("unsupported fixture manifest kind"),
            }
            assert_eq!(Some(metadata.mode()), file.mode);
            assert_eq!(Some(metadata.uid()), file.uid);
            assert_eq!(Some(metadata.gid()), file.gid);
        }
        Ok(json!({
            "elapsedSeconds":elapsed,
            "bytesRead":report.io.readback_bytes,
            "bytesReadScope":"post-assembly verifier reads only; preview/preflight reads uninstrumented",
            "preflightReadBytes":null, "physicalBytesRead":null,
            "fixtureVerificationBytes":verification_bytes,
            "remoteBytes":after.remote_delta(&before),
            "readback":report.io.readback_bytes,
            "assembledBytes":last.assembled_bytes,
            "verifiedBytes":last.verified_bytes,
            "publishedFiles":report.restore.published_entries,
            "reusedFiles":report.restore.reused_entries,
            "packsDownloaded":report.packs_downloaded,
            "availablePacks":available.len(), "requiredPacks":required.len(),
            "peakBuffers":{
                "assemblyHandles":report.io.peak_assembly_handles,
                "activeHashers":report.io.peak_active_hashers,
                "unpublishedFiles":report.io.peak_unpublished_files,
                "unpublishedBytes":report.io.peak_unpublished_bytes,
                "decodeWorkers":report.io.peak_decode_workers,
                "verificationWorkers":report.io.peak_verification_workers,
                "decoderCeiling":report.io.effective_parallel_packs,
                "verifierCeiling":report.io.effective_verification_workers,
                "queueCeiling":report.io.effective_buffered_chunks,
                "queuePeak":null, "rssPeak":null,
                "estimatedWorkingSetBytes":report.io.estimated_working_set_bytes,
            },
            "io":report.io,
            "fullScans":self.agent.metrics.snapshot().reconciliations_total - scans,
            "durableCompletion":true,
        }))
    }

    async fn refusal_checks(&self) -> Result<(bool, bool)> {
        let relative = self.files.last().unwrap().relative.as_str();
        let stale = self.selection(Some(relative))?;
        let id = self.queue(stale)?;
        // Deliberately no watcher event. The expected payload must fail closed
        // even when its inode/size/mtime are preserved by a same-file rewrite.
        let path = self.source.join(relative);
        let original_time = fs::metadata(&path)?.modified()?;
        let mut file = OpenOptions::new().write(true).open(&path)?;
        file.write_all(b"unapproved-no-event-change")?;
        file.set_times(fs::FileTimes::new().set_modified(original_time))?;
        file.sync_all()?;
        let no_event_clean_refused = self.execute(id).await.is_err();
        assert!(no_event_clean_refused);
        assert_ne!(self.agent.db.get_operation(id)?.unwrap().state, "COMPLETED");
        // Prepare fresh byte evidence, but fail at the visibility marker. Packs
        // and ordinary metadata may exist; an uncommitted revision is not saved.
        let logical = self.agent.native_logical_path(&self.app, &path)?;
        let token = logical.logical_root.as_token();
        let fresh = NativeSelection::parse(&json!({
            "version":1,
            "file_keys":[{"logical_root":token,"relative_path":relative}],
            "roots_fingerprint":self.agent.native_binding_fingerprint(&self.app)?,
            "destination":null,"destination_identity":null,
            "snapshot_identity":"synthetic-fresh-marker-fault",
            "expected_files":[{
                "id":native_file_id(&token, relative),
                "size":fs::metadata(&path)?.len(),"fileHash":noland_cas::blake3_file(&path)?,
            }],
            "coverage":"selected_nodes",
        }))?;
        let id = self.queue(fresh)?;
        let writes_before = self.provider.snapshot().writes.len();
        self.provider
            .fail_bundle_marker
            .store(true, Ordering::Release);
        assert!(self.execute(id).await.is_err());
        assert_ne!(self.agent.db.get_operation(id)?.unwrap().state, "COMPLETED");
        let writes = self.provider.snapshot().writes;
        let incomplete = writes[writes_before..]
            .iter()
            .find(|key| key.starts_with("bundles/") && key.ends_with("/manifest.enc"))
            .expect("actual source ordinary metadata precedes the injected marker fault");
        let prefix = incomplete.strip_suffix("/manifest.enc").unwrap();
        let invisible = !self
            .provider
            .inner
            .root
            .join(prefix)
            .join("COMMITTED")
            .exists();
        assert!(invisible);
        Ok((no_event_clean_refused, invisible))
    }
}

/// A genuine deterministic keyed PRF for this fixture's native recovery journal.
/// The key is independently generated, never the repository key or an OS vault
/// entry. Production recovery authority remains the native vault's responsibility.
struct FixtureRecoveryAuthority(MasterKey);

impl NativeRecoveryAuthority for FixtureRecoveryAuthority {
    fn mac(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        Ok(noland_crypto::pack_key(
            &self.0,
            &format!("native-bench-journal-v1:{}", noland_cas::blake3_hex(bytes)),
        ))
    }
}

/// An isolated native-only sink. Expected hashes are fixture verification data,
/// never sent into metadata-only NativeSelection or used to authorize capture.
struct FixtureCaptureSink {
    scope: NativeCaptureScope,
    nodes: Vec<NativeCaptureNode>,
    hashes: BTreeMap<String, String>,
    master: MasterKey,
    accepted: AtomicBool,
    mutate_after_accept: Option<PathBuf>,
    reuse_epoch: Option<String>,
    mutation: Option<(StateDb, AppId)>,
    replace_root_after_accept: AtomicBool,
    source_root: PathBuf,
    full: Option<Arc<FixtureFullAuthority>>,
    node_metadata: BTreeMap<String, Value>,
}

impl NativeCaptureSink for FixtureCaptureSink {
    fn node_page(
        &self,
        scope: &NativeCaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<NativeCaptureNode>> {
        assert!(scope == &self.scope);
        assert!(limit <= native_capture::NATIVE_CAPTURE_PAGE);
        Ok(self.nodes[offset..offset + limit].to_vec())
    }

    fn reuse_epoch(&self, scope: &NativeCaptureScope) -> Result<Option<String>> {
        assert!(scope == &self.scope);
        Ok(self.reuse_epoch.clone())
    }

    fn full_scope_authority(
        &self,
        scope: &NativeCaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        assert_eq!(scope, &self.scope);
        Ok(self
            .full
            .as_ref()
            .map(|full| full.clone() as Arc<dyn NativeFullScopeAuthority>))
    }

    fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> Result<()> {
        receipt.revalidate()?;
        let evidence = receipt.evidence()?;
        assert_eq!(evidence["workId"], self.scope.work_id);
        assert_eq!(evidence["metadataIdentity"], self.scope.metadata_identity);
        let encoded = evidence["sourceExpectedManifestAuth"]["envelopeHex"]
            .as_str()
            .unwrap();
        assert!(encoded.len() % 2 == 0 && encoded.len() <= 16 * 1024);
        let envelope = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        // Validate real source crypto authentication, not a `{verified:true}`
        // flag or a nonempty, arbitrary JSON object.
        let authenticated: Value = noland_storage::open_metadata(
            &noland_crypto::derive_keys(&self.master).manifest,
            b"quicksave-native-expected-manifest-v1",
            envelope,
        )?;
        assert_eq!(authenticated["scope"]["workId"], self.scope.work_id);
        assert_eq!(
            authenticated["source_snapshot_id"],
            evidence["sourceSnapshotId"]
        );
        assert_eq!(
            authenticated["manifest_hash"],
            evidence["sourceExpectedManifestAuth"]["manifestHash"]
        );
        assert_eq!(
            evidence["sourceExpectedManifestAuth"]["rootLayoutsHash"],
            fixture_digest(&evidence["rootLayouts"])?,
            "the actual source layout must be part of authenticated capture evidence",
        );
        let nodes = evidence["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), self.nodes.len());
        let frozen_nodes = self
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        for node in nodes {
            let id = node["id"].as_str().unwrap();
            let frozen = frozen_nodes[id];
            assert_eq!(node["stamp"], serde_json::to_value(&frozen.stamp)?);
            assert_eq!(node["kind"], frozen.kind);
            match frozen.kind.as_str() {
                "file" => assert_eq!(
                    node["fileHash"].as_str(),
                    self.hashes.get(id).map(String::as_str)
                ),
                "directory" => {
                    assert!(node.get("fileHash").is_none());
                    assert!(node.get("linkTargetHash").is_none());
                    assert_eq!(node["size"], 0);
                }
                "symlink" => {
                    assert!(node.get("fileHash").is_none());
                    assert_eq!(
                        node["linkTargetHash"].as_str(),
                        frozen.link_target_hash.as_deref()
                    );
                    assert_eq!(node["size"], 0);
                }
                _ => panic!("fixture has an unsupported entry kind"),
            }
        }
        self.accepted.store(true, Ordering::Release);
        if let Some(path) = &self.mutate_after_accept {
            // Bytes after stable capture are a later generation. They must not
            // change the old immutable captured payload or be acknowledged by
            // its generation-specific mutation completion.
            let modified = fs::metadata(path)?.modified()?;
            let mut file = OpenOptions::new().write(true).open(path)?;
            file.write_all(b"changed after actual native capture")?;
            file.set_times(fs::FileTimes::new().set_modified(modified))?;
            file.sync_all()?;
            if let Some((db, app)) = &self.mutation {
                let record = db.get_path_by_canonical(path.to_str().unwrap())?.unwrap();
                db.mark_dirty(app, Some(record.path_id), false)?;
                db.append_app_mutation(&AppMutationRecord::new(
                    app.clone(),
                    path.to_str().unwrap(),
                    AppMutationKind::Modify,
                ))?;
            }
        }
        if self.replace_root_after_accept.load(Ordering::Acquire) {
            let root = &self.source_root;
            fs::rename(root, root.with_extension("original-owned-source"))?;
            fs::create_dir(root)?;
        }
        Ok(())
    }
}

fn queue_metadata_capture(
    fixture: &Fixture,
    mutate_after_accept: bool,
) -> Result<(Uuid, Arc<FixtureCaptureSink>)> {
    queue_metadata_capture_selected(fixture, None, mutate_after_accept, None)
}

fn queue_metadata_capture_selected(
    fixture: &Fixture,
    relative: Option<&str>,
    mutate_after_accept: bool,
    reuse_epoch: Option<String>,
) -> Result<(Uuid, Arc<FixtureCaptureSink>)> {
    let operation = Uuid::new_v4();
    let mut nodes = Vec::new();
    let mut hashes = BTreeMap::new();
    let mut node_metadata = BTreeMap::new();
    for file in fixture
        .files
        .iter()
        .filter(|file| relative.is_none_or(|relative| file.relative == relative))
    {
        let path = fixture.source.join(&file.relative);
        let logical = fixture.agent.native_logical_path(&fixture.app, &path)?;
        let token = logical.logical_root.as_token();
        let id = native_file_id(&token, &file.relative);
        let opened = SourcePath::new(&path)?.open_regular()?;
        nodes.push(NativeCaptureNode {
            id: id.clone(),
            root_id: "payload".into(),
            logical_root: token,
            path: file.relative.clone(),
            kind: "file".into(),
            size: file.size,
            stamp: NativeCaptureStamp::from_metadata(&opened.metadata()?)?,
            link_target_hash: None,
        });
        hashes.insert(id, file.hash.clone());
        node_metadata.insert(
            native_file_id(&logical.logical_root.as_token(), &file.relative),
            fixture_node_metadata(&opened.metadata()?),
        );
    }
    let scope = NativeCaptureScope {
        version: 1,
        work_id: Uuid::new_v4().to_string(),
        metadata_identity: noland_cas::blake3_hex(&serde_json::to_vec(&nodes)?),
        node_count: nodes.len(),
        full_scope: None,
    };
    let sink = Arc::new(FixtureCaptureSink {
        scope: scope.clone(),
        nodes,
        hashes,
        master: fixture.master.clone(),
        accepted: AtomicBool::new(false),
        mutate_after_accept: mutate_after_accept
            .then(|| fixture.source.join(&fixture.files[0].relative)),
        reuse_epoch,
        mutation: mutate_after_accept.then(|| (fixture.agent.db.clone(), fixture.app.clone())),
        replace_root_after_accept: AtomicBool::new(false),
        source_root: fixture.source.clone(),
        full: None,
        node_metadata,
    });
    let keys = native_capture::install(
        &fixture.agent,
        operation,
        &fixture.app,
        scope.clone(),
        sink.clone(),
    )?;
    let selection = NativeSelection::parse(&json!({
        "version":1, "file_keys":keys,
        "roots_fingerprint":fixture.agent.native_binding_fingerprint(&fixture.app)?,
        "destination":null,"destination_identity":null,
        "snapshot_identity":scope.metadata_identity,
        "expected_files":null,"capture_scope":scope,
        "coverage":"selected_nodes",
        "software_instance_id":"isolated-metadata-native-instance",
    }))?;
    fixture.queue_as(operation, selection)?;
    Ok((operation, sink))
}

fn queue_directory_link_capture(fixture: &Fixture) -> Result<(Uuid, Arc<FixtureCaptureSink>)> {
    for path in ["Contents", "Contents/Resources", "Contents/Resources/empty"] {
        fs::create_dir_all(fixture.source.join(path))?;
    }
    let link = "Contents/Resources/current.bin";
    std::os::unix::fs::symlink("../../assets/large-00.bin", fixture.source.join(link))?;
    queue_full_capture(fixture, None)
}

fn fixture_digest(value: &Value) -> Result<String> {
    Ok(noland_cas::blake3_hex(&serde_json::to_vec(value)?))
}

/// Raw metadata-domain digest of newly generated test data, matching
/// Tracker::bundle::digest. Never normalize a received/signed grant or field.
fn fixture_metadata_digest(value: &Value) -> Result<String> {
    let locally_computed = fixture_digest(value)?;
    Ok(locally_computed
        .strip_prefix("blake3:")
        .expect("source hash format")
        .to_owned())
}

fn fixture_node_metadata(metadata: &fs::Metadata) -> Value {
    json!({
        "mode":metadata.mode(),"owner":metadata.uid(),"group":metadata.gid(),
        "linkCount":metadata.nlink(),
    })
}

/// Source-isolation test authority only, NOT Tracker/StoreAdapter interoperability
/// coverage. Production cross-boundary tests must retain the real Tracker owner,
/// backed by WorkspaceStore/MemoryVault, and never recreate its signed grants.
/// This native Rust owner is not instantiated by incoming JSON.
struct FixtureFullAuthority {
    evidence: Value,
    key: MasterKey,
    scope_envelope: Vec<u8>,
    baseline_envelope: Option<Vec<u8>>,
    revoked: AtomicBool,
}

impl NativeFullScopeAuthority for FixtureFullAuthority {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(StateError::Conflict(
                "synthetic native full-scope grant revoked".into(),
            ));
        }
        let keys = noland_crypto::derive_keys(&self.key);
        let scope: Value = noland_storage::open_metadata(
            &keys.manifest,
            b"isolated-native-full-scope-v1",
            self.scope_envelope.clone(),
        )?;
        if scope != self.evidence["expectedFullScope"]["scope"]
            || self.evidence["expectedFullScope"]["grant"] != fixture_grant(&self.scope_envelope)
        {
            return Err(StateError::Integrity(
                "fixture full-scope authentication failed".into(),
            ));
        }
        if let Some(envelope) = &self.baseline_envelope {
            let baseline: Value = noland_storage::open_metadata(
                &keys.manifest,
                b"isolated-native-baseline-v1",
                envelope.clone(),
            )?;
            if baseline != self.evidence["baseline"]["scope"]
                || self.evidence["baseline"]["reference"]["grant"] != fixture_grant(envelope)
            {
                return Err(StateError::Integrity(
                    "fixture original baseline authentication failed".into(),
                ));
            }
        } else if self.evidence["baseline"]["kind"] != "none"
            || !self.evidence["baseline"]["reference"].is_null()
        {
            return Err(StateError::Integrity(
                "fixture has a baseline without real authentication".into(),
            ));
        }
        Ok(())
    }
}

fn fixture_grant(envelope: &[u8]) -> Value {
    json!({
        "version":1,"algorithm":"isolated-xchacha20poly1305",
        "envelopeHex":envelope.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    })
}

fn queue_full_capture(
    fixture: &Fixture,
    baseline: Option<(&BundleManifest, &FixtureCaptureSink)>,
) -> Result<(Uuid, Arc<FixtureCaptureSink>)> {
    queue_full_capture_for_ids(
        fixture,
        baseline,
        "isolated-full-native-instance",
        "isolated-full-native-instance",
    )
}

fn queue_full_capture_for_ids(
    fixture: &Fixture,
    baseline: Option<(&BundleManifest, &FixtureCaptureSink)>,
    private_software_id: &str,
    software_instance_id: &str,
) -> Result<(Uuid, Arc<FixtureCaptureSink>)> {
    fn inventory(root: &Path, relative: &str, paths: &mut BTreeSet<String>) -> Result<()> {
        let directory = if relative.is_empty() {
            root.to_path_buf()
        } else {
            root.join(relative)
        };
        for name in noland_snapshot::native_metadata::directory_names(
            &SourcePath::new(&directory)?.open_directory()?,
        )? {
            let leaf = name.to_str().unwrap();
            let child = if relative.is_empty() {
                leaf.into()
            } else {
                format!("{relative}/{leaf}")
            };
            let metadata = SourcePath::new(&root.join(&child))?.metadata()?;
            assert!(paths.len() < MAX_FIXTURE_FILES * 4);
            paths.insert(child.clone());
            if metadata.is_dir() {
                inventory(root, &child, paths)?;
            }
        }
        Ok(())
    }
    let mut paths = BTreeSet::new();
    inventory(&fixture.source, "", &mut paths)?;
    let mut nodes = Vec::new();
    let mut hashes = BTreeMap::new();
    let mut node_metadata = BTreeMap::new();
    for relative in paths {
        let path = fixture.source.join(&relative);
        let logical = fixture.agent.native_logical_path(&fixture.app, &path)?;
        let token = logical.logical_root.as_token();
        let id = native_file_id(&token, &relative);
        let metadata = fs::symlink_metadata(&path)?;
        node_metadata.insert(id.clone(), fixture_node_metadata(&metadata));
        let (kind, size, link_target_hash) = if metadata.is_file() {
            hashes.insert(
                id.clone(),
                fixture
                    .files
                    .iter()
                    .find(|file| file.relative == relative)
                    .unwrap()
                    .hash
                    .clone(),
            );
            ("file", metadata.len(), None)
        } else if metadata.is_dir() {
            ("directory", 0, None)
        } else {
            assert!(metadata.file_type().is_symlink());
            let target = fs::read_link(&path)?;
            let hash = noland_cas::blake3_hex(target.to_str().unwrap().as_bytes());
            (
                "symlink",
                0,
                Some(hash.strip_prefix("blake3:").unwrap().to_owned()),
            )
        };
        nodes.push(NativeCaptureNode {
            id,
            root_id: "payload".into(),
            logical_root: token,
            path: relative,
            kind: kind.into(),
            size,
            stamp: NativeCaptureStamp::from_metadata(&metadata)?,
            link_target_hash,
        });
    }
    let operation = Uuid::new_v4();
    let mut scope = NativeCaptureScope {
        version: 1,
        work_id: Uuid::new_v4().to_string(),
        metadata_identity: fixture_metadata_digest(&json!(nodes))?,
        node_count: nodes.len(),
        full_scope: None,
    };
    let root_metadata = fs::metadata(&fixture.source)?;
    let node_ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let mut deleted_nodes = BTreeMap::new();
    if let Some((_, previous)) = baseline {
        for node in &previous.nodes {
            if !node_ids.contains(&node.id) {
                deleted_nodes.insert(
                    node.id.clone(),
                    json!({
                        "id":node.id,"rootId":node.root_id,"path":node.path,
                        "kind":node.kind,"size":node.size,"stamp":node.stamp,
                        "metadata":previous.node_metadata[&node.id],
                        "fileHash":previous.hashes.get(&node.id).map(|hash|
                            hash.strip_prefix("blake3:").expect("locally generated source content hash")),
                        "linkTargetHash":node.link_target_hash,
                    }),
                );
            }
        }
    }
    let deleted_ids = deleted_nodes.keys().cloned().collect::<Vec<_>>();
    let actual_layouts = fixture
        .agent
        .native_root_layouts(&fixture.app, software_instance_id)?;
    let approved_roots = json!([{
        "id":"payload","path":fixture.source,"role":actual_layouts["roots"][0]["role"],
        "identity":{"device":root_metadata.dev(),"fileId":[root_metadata.ino(),0]},
        "allowedFiles":null,
    }]);
    // Exact field names/shapes from TrackedSoftware::{tracking_scope,
    // baseline_scope} and Tracker::full_scope_evidence, not private index grants.
    let tracking_scope = json!({
        "version":1,"softwareId":private_software_id,"appId":software_instance_id,
        "roots":approved_roots,"sourceIdentity":{"app_id":fixture.app},
    });
    let key = MasterKey::generate();
    let (baseline_evidence, baseline_envelope) = if let Some((_manifest, previous)) = baseline {
        let identity = fixture_metadata_digest(&json!({
            "nodes":previous.nodes,"hashes":previous.hashes,
            "rootStamps":previous.full.as_ref().unwrap().evidence["rootStamps"],
        }))?;
        let scope = json!({
            "version":1,"tracking":tracking_scope,"providerId":"isolated-local-provider",
            "name":"isolated-frozen-baseline","hash":identity,"fullScope":true,
        });
        let envelope = noland_storage::seal_metadata(
            &noland_crypto::derive_keys(&key).manifest,
            b"isolated-native-baseline-v1",
            &scope,
        )?
        .envelope;
        (
            json!({
                "kind":"full","snapshotIdentity":identity,"scope":scope,
                "reference":{"name":"isolated-frozen-baseline","hash":identity,"grant":fixture_grant(&envelope)},
            }),
            Some(envelope),
        )
    } else {
        (
            json!({"kind":"none","snapshotIdentity":null,"reference":null,"scope":null}),
            None,
        )
    };
    let proof = json!({
        "version":1,"workId":scope.work_id,"softwareId":private_software_id,
        "providerId":"isolated-local-provider","generation":1,"metadataIdentity":scope.metadata_identity,
        "trackingScopeHash":fixture_metadata_digest(&tracking_scope)?,
        "rootIds":["payload"],"expectedNodeIdsHash":fixture_metadata_digest(&json!(node_ids))?,
        "deletedNodeIdsHash":fixture_metadata_digest(&json!(deleted_ids))?,
        "baselineKind":baseline_evidence["kind"],"baselineIdentity":baseline_evidence["snapshotIdentity"],
        "snapshotMode":"additive_full_scope","keepsHistory":true,
    });
    let scope_envelope = noland_storage::seal_metadata(
        &noland_crypto::derive_keys(&key).manifest,
        b"isolated-native-full-scope-v1",
        &proof,
    )?
    .envelope;
    let evidence = json!({
        "version":1,"workId":scope.work_id,"softwareId":private_software_id,
        "sourceIdentity":{"app_id":fixture.app},"providerId":"isolated-local-provider",
        "generation":1,"metadataIdentity":scope.metadata_identity,
        "fullScope":true,"completeFileList":true,"keepsVersionHistory":true,
        "coverageScope":"approved_evidenced_roots_only",
        "expectedFullScope":{"scope":proof,"grant":fixture_grant(&scope_envelope)},
        "authorization":{"trackingScope":tracking_scope,"trackingGrant":null,
            "autosaveScope":null,"autosaveGrant":null},
        "roots":approved_roots,
        "rootMetadata":{"payload":fixture_node_metadata(&root_metadata)},
        "rootStamps":{"payload":NativeCaptureStamp::from_metadata(&root_metadata)?},
        "deletedFileIds":deleted_ids,"deletedNodes":deleted_nodes.into_values().collect::<Vec<_>>(),
        "baseline":baseline_evidence,
        "sourceBaseline":baseline.map(|(manifest, _)| json!({
            "sourceSnapshotId":manifest.bundle_id,"manifestHash":noland_cas::blake3_hex(&serde_json::to_vec(manifest).unwrap()),
        })),
    });
    scope.full_scope = Some(NativeFullScopeBinding::from_evidence(&evidence)?);
    let full = Arc::new(FixtureFullAuthority {
        evidence,
        key,
        scope_envelope,
        baseline_envelope,
        revoked: AtomicBool::new(false),
    });
    let sink = Arc::new(FixtureCaptureSink {
        scope: scope.clone(),
        nodes,
        hashes,
        master: fixture.master.clone(),
        accepted: AtomicBool::new(false),
        mutate_after_accept: None,
        reuse_epoch: Some(fixture.reuse_epoch.clone()),
        mutation: None,
        replace_root_after_accept: AtomicBool::new(false),
        source_root: fixture.source.clone(),
        full: Some(full),
        node_metadata,
    });
    let keys = native_capture::install(
        &fixture.agent,
        operation,
        &fixture.app,
        scope.clone(),
        sink.clone(),
    )?;
    let selection = NativeSelection::parse(&json!({
        "version":1,"file_keys":keys,
        "roots_fingerprint":fixture.agent.native_binding_fingerprint(&fixture.app)?,
        "destination":null,"destination_identity":null,"snapshot_identity":scope.metadata_identity,
        "expected_files":null,"capture_scope":scope,"coverage":"full_approved_scope",
        "software_instance_id":software_instance_id,
    }))?;
    fixture.queue_as(operation, selection)?;
    Ok((operation, sink))
}

fn assert_marker_order(provider: &CountedNativeLocalStorage) -> bool {
    let writes = provider.snapshot().writes;
    let mut checked = 0;
    for (position, key) in writes.iter().enumerate() {
        if let Some(prefix) = key
            .strip_suffix("/COMMITTED")
            .filter(|p| p.starts_with("bundles/"))
        {
            for ordinary in ["index.enc", "manifest.enc"] {
                assert!(writes[..position]
                    .iter()
                    .any(|prior| prior == &format!("{prefix}/{ordinary}")));
            }
            checked += 1;
        }
        if key.starts_with("catalog/commits/") && key.ends_with(".COMMITTED") {
            let base = key.strip_suffix(".COMMITTED").unwrap();
            assert!(writes[..position]
                .iter()
                .any(|prior| prior == &format!("{base}.enc")));
        }
    }
    assert!(checked > 0, "the actual metadata marker path was exercised");
    true
}

fn capture_buffers(operation: &OperationRecord) -> Value {
    let pipeline = &operation.detail_json["streaming_pipeline"];
    if !pipeline.is_object() {
        // A genuine fast no-op need not construct any capture/codec worker pool.
        return Value::Null;
    }
    for (peak, limit) in [
        ("peak_codecs", "codec_limit"),
        ("peak_uploads", "upload_limit"),
        ("peak_reserved_count", "reserved_count_limit"),
        ("peak_reserved_bytes", "reserved_byte_limit"),
    ] {
        assert!(
            pipeline[peak].as_u64().expect("source peak counter")
                <= pipeline[limit].as_u64().expect("source admission limit")
        );
    }
    json!({
        "codecs":pipeline["peak_codecs"],"codecCeiling":pipeline["codec_limit"],
        "uploads":pipeline["peak_uploads"],"uploadCeiling":pipeline["upload_limit"],
        "reservedBytes":pipeline["peak_reserved_bytes"],"reservedByteCeiling":pipeline["reserved_byte_limit"],
        "reservedCount":pipeline["peak_reserved_count"],"reservedCountCeiling":pipeline["reserved_count_limit"],
        "readerCeiling":pipeline["reader_limit"],"queueCeiling":pipeline["capture_queue_limit"],
        "preparationWorkspaceLimitBytes":pipeline["preparation_workspace_limit_bytes"],
        "captureReadBytes":pipeline["read_bytes"],"captureDurableBytes":pipeline["durable_bytes"],
        "readerPeak":null,"queuePeak":null,"rssPeak":null,
    })
}

fn opaque_status_probe(agent: &StateAgent) -> Result<Value> {
    let id = Uuid::new_v4();
    let now = Utc::now();
    // This is a DB-only stored-plan stress fixture, not an authorized selection.
    // Allocate/store once; no 250,000-item vectors are created by each poll.
    agent.db.upsert_operation(&OperationRecord {
        operation_id: id,
        kind: "backup".into(),
        app_id: None,
        state: "QUEUED".into(),
        created_at: now,
        updated_at: now,
        last_error: None,
        detail_json: json!({"server_only_plan_fixture":(0..POLL_ROWS).collect::<Vec<_>>() }),
    })?;
    let scans = agent.metrics.snapshot().reconciliations_total;
    let writer_reads = agent.db.contention_snapshot().writer_lock_acquisitions;
    let mut maximum = 0usize;
    for _ in 0..100 {
        let snapshot = agent.db.operation_monitoring_snapshot(id)?.unwrap();
        assert_eq!(snapshot.operation.detail_json, json!({}));
        let output = serde_json::to_vec(&json!({
            "operation":snapshot.operation, "progress":snapshot.progress,
            "packTransfer":snapshot.pack_transfer,
        }))?;
        maximum = maximum.max(output.len());
        assert!(output.len() <= 4096);
    }
    assert_eq!(
        agent.db.contention_snapshot().writer_lock_acquisitions,
        writer_reads
    );
    let full_scans = agent.metrics.snapshot().reconciliations_total - scans;
    assert_eq!(full_scans, 0);
    Ok(json!({
        "storedEntries":POLL_ROWS,"polls":100,"maxPollBytes":maximum,"fullScans":full_scans,
        "scope":"actual source query-only monitoring API; QuickSave IPC adapter still needs separate acceptance",
    }))
}

async fn adaptive_fault_simulation() -> Result<Value> {
    let started = Instant::now();
    let tuning = TransferTuning {
        max_parallel_downloads: 4,
        // Streaming is one connection, not divided by this copyto width.
        rclone_download_streams: 8,
        ..TransferTuning::default()
    };
    let limiter = AdaptiveConcurrency::for_streams(&tuning);
    assert_eq!(limiter.max(), 4);
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let (admitted, mut receiver) = tokio::sync::mpsc::channel(32);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let limiter = Arc::clone(&limiter);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let release = Arc::clone(&release);
        let admitted = admitted.clone();
        workers.spawn(async move {
            let permit = limiter.acquire().await?;
            let count = active.fetch_add(1, Ordering::AcqRel) + 1;
            peak.fetch_max(count, Ordering::Relaxed);
            admitted
                .send(())
                .await
                .map_err(|_| StateError::Storage("fixture closed".into()))?;
            release.acquire().await.unwrap().forget();
            active.fetch_sub(1, Ordering::AcqRel);
            drop(permit);
            Ok::<_, StateError>(())
        });
    }
    drop(admitted);
    for _ in 0..4 {
        receiver
            .recv()
            .await
            .expect("first four admitted simulation jobs");
    }
    let before = limiter.current();
    assert_eq!(limiter.active(), 4);
    limiter.record_error(RemoteErrorClass::RateLimited);
    let after = limiter.current();
    assert_eq!(after, 2);
    // Active work is retained, not falsely cancelled to make the graph prettier.
    assert_eq!(limiter.active(), 4);
    release.add_permits(16);
    while let Some(worker) = workers.join_next().await {
        worker.expect("simulation worker must join")?;
    }
    assert_eq!(limiter.active(), 0);
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(peak.load(Ordering::Relaxed), 4);
    Ok(json!({
        "simulation":true,
        "scope":"real source adaptive limiter + synthetic rate-limit feedback; no provider throughput claim",
        "elapsedSeconds":started.elapsed().as_secs_f64(),
        "maximum":limiter.max(),"peakActive":peak.load(Ordering::Relaxed),
        "beforeRateLimit":before,"afterRateLimit":after,"finalActive":limiter.active(),
    }))
}

async fn workload(bytes: u64, files: usize) -> Result<Value> {
    let started = Instant::now();
    let mut fixture = Fixture::create(bytes, files)?;
    let (first, first_capture) = fixture.capture(None).await?;
    assert_eq!(first.hash.algorithm, "blake3");
    assert_eq!(first.chunking.min, constants::FASTCDC_MIN);
    assert_eq!(first.chunking.avg, constants::FASTCDC_AVG);
    assert_eq!(first.chunking.max, constants::FASTCDC_MAX);
    let index = noland_storage::read_pack_index(
        &fixture.provider,
        &fixture.master,
        &fixture.app,
        first.bundle_id,
    )
    .await?;
    let serialized_index = serde_json::to_value(&index)?;
    let chunk_references = first
        .files
        .iter()
        .map(|file| file.chunks.len())
        .sum::<usize>();
    assert!(
        index.len() < chunk_references,
        "actual pack records must deduplicate cross-file references"
    );
    let mut zstd_used = false;
    for entry in serialized_index.as_array().unwrap() {
        let plaintext = entry["plaintext_len"].as_u64().unwrap();
        let ciphertext = entry["ciphertext_len"].as_u64().unwrap();
        // Exclude only the actual XChaCha20-Poly1305 tag, not record/header
        // bytes. Incompressible data must not expand its stored payload.
        assert!(ciphertext >= 16 && ciphertext - 16 <= plaintext);
        if entry["compression"] == "zstd" {
            zstd_used = true;
            assert!(ciphertext - 16 < plaintext);
        }
    }
    assert!(zstd_used);
    let (_, unchanged_capture) = fixture.capture(None).await?;
    assert_eq!(unchanged_capture["newPacks"], 0);
    assert_eq!(unchanged_capture["remoteBytes"]["packUploaded"], 0);
    fixture.modify_large_file()?;
    let (changed, mut changed_capture) = fixture.capture(None).await?;
    let first_large = first
        .files
        .iter()
        .find(|file| file.relative_path == fixture.files[0].relative)
        .unwrap();
    let changed_large = changed
        .files
        .iter()
        .find(|file| file.relative_path == fixture.files[0].relative)
        .unwrap();
    assert_ne!(first_large.file_hash, changed_large.file_hash);
    let old_chunks = first_large
        .chunks
        .iter()
        .map(|chunk| &chunk.hash)
        .collect::<BTreeSet<_>>();
    let shared = changed_large
        .chunks
        .iter()
        .filter(|chunk| old_chunks.contains(&chunk.hash))
        .count();
    assert!(
        shared > 0,
        "a bounded prefix edit must retain later FastCDC chunks"
    );
    changed_capture["sharedChunkHashes"] = json!(shared);
    assert!(changed_capture["newPacks"].as_u64().unwrap() > 0);
    let selected = fixture.files.last().unwrap().relative.clone();
    let (subset, subset_capture) = fixture.capture(Some(&selected)).await?;
    assert_eq!(subset.files.len(), 1);
    assert_eq!(subset.files[0].relative_path, selected);
    assert_eq!(subset_capture["newPacks"], 0);
    let catalog = noland_storage::load_catalog(&fixture.provider, &fixture.master).await?;
    assert!(catalog.apps[0]
        .bundles
        .iter()
        .any(|bundle| bundle.bundle_id == first.bundle_id));
    assert!(catalog.apps[0]
        .bundles
        .iter()
        .any(|bundle| bundle.bundle_id == changed.bundle_id));
    let destination = fixture._owned.path.join("restored-native");
    let first_restore = fixture.restore(&first, &destination, None, false).await?;
    assert_eq!(first_restore["readback"], 0);
    let unchanged_restore = fixture.restore(&first, &destination, None, true).await?;
    assert_eq!(unchanged_restore["packsDownloaded"], 0);
    let selective_restore = fixture
        .restore(
            &changed,
            &fixture._owned.path.join("selective-native"),
            Some(&selected),
            false,
        )
        .await?;
    assert_eq!(
        selective_restore["packsDownloaded"],
        selective_restore["requiredPacks"]
    );
    assert!(
        selective_restore["requiredPacks"].as_u64().unwrap()
            < selective_restore["availablePacks"].as_u64().unwrap()
    );
    let marker_last = assert_marker_order(&fixture.provider);
    let opaque_plans = opaque_status_probe(&fixture.agent)?;
    let (no_event_clean_refused, failed_marker_invisible) = fixture.refusal_checks().await?;
    let concurrency = adaptive_fault_simulation().await?;
    Ok(json!({
        "schemaVersion":1,"sourceCommit":SOURCE_COMMIT,
        "pipeline":"source-native-local-storage",
        "provider":"isolated_filesystem_fixture","liveProviderBenchmark":false,
        "elapsedSeconds":started.elapsed().as_secs_f64(),
        "fixture":{
            "logicalBytes":bytes,"files":files,"generationBufferBytes":GENERATION_BUFFER,
            "fixtureHashReadBytes":fixture.fixture_hash_reads,
            "scratchAdmissionBytes":bytes * 8 + 256 * MIB,
            "peakDiskBytes":null,
            "captureConsistency":"validated_stable_files_not_app_atomic",
        },
        "phases":{
            "first_capture":first_capture,"unchanged_capture":unchanged_capture,
            "changed_capture":changed_capture,"subset_capture":subset_capture,
            "first_restore":first_restore,"unchanged_restore":unchanged_restore,
            "selective_restore":selective_restore,
        },
        "checks":{
            "zstdNoExpansion":true,"zstdUsed":zstd_used,
            "crossFileDedup":true,
            "markerLast":marker_last,"failedMarkerInvisible":failed_marker_invisible,
            "noEventCleanRefused":no_event_clean_refused,"statusPollBounded":true,
        },
        "opaquePlans":opaque_plans,"adaptiveConcurrency":concurrency,
        "limitations":[
            "No live provider, OS vault, application launch, packaging or cross-platform acceptance",
            "Physical capture/staging reads, restore preview/preflight reads, RSS and queue peaks are not instrumented",
            "Native source files cannot be reused solely because no watcher events arrived",
            "Query-only source DB polling is tested; opaque QuickSave IPC wiring needs adapter acceptance",
            "Stage worker times overlap and must not be summed as operation elapsed time",
        ],
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_capture_retains_guards_and_chunk_reuse_without_clean_event_proof() -> Result<()> {
    let fixture = Fixture::create(4 * MIB, 32)?;
    let (_, first) = fixture.capture_legacy(None).await?;
    let (_, unchanged) = fixture.capture_legacy(None).await?;
    assert_eq!(first["bytesRead"], 4 * MIB);
    assert_eq!(unchanged["newPacks"], 0);
    assert!(unchanged["chunksReused"].as_u64().unwrap() > 0);
    // Do not demand an unsafe no-event shortcut. The Python strict parity gate
    // separately refuses an unoptimized full-revalidation baseline.
    assert!(unchanged["bytesRead"].as_u64().unwrap() <= 4 * MIB);
    assert!(assert_marker_order(&fixture.provider));
    let (no_event, marker) = fixture.refusal_checks().await?;
    assert!(no_event && marker);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_status_projection_and_adaptive_limiter_have_bounded_work() -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let polling = opaque_status_probe(&fixture.agent)?;
    assert!(polling["maxPollBytes"].as_u64().unwrap() <= 4096);
    adaptive_fault_simulation().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_metadata_only_scope_receives_actual_authenticated_capture_before_commit(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, sink) = queue_metadata_capture(&fixture, false)?;
    let manifest = fixture.execute(operation).await?;
    assert!(sink.accepted.load(Ordering::Acquire));
    assert_eq!(manifest.files.len(), fixture.files.len());
    let record = fixture.agent.db.get_operation(operation)?.unwrap();
    let metrics: OperationMetrics = serde_json::from_value(record.detail_json["metrics"].clone())?;
    assert_eq!(
        metrics.bytes_hashed, MIB,
        "exactly the actual source capture hash input"
    );
    assert_eq!(record.state, "COMPLETED");
    assert!(assert_marker_order(&fixture.provider));
    native_capture::verify_prepared(&fixture.agent, operation, &manifest)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_source_change_after_capture_publishes_old_verified_bytes_and_keeps_mutation_pending(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, sink) = queue_metadata_capture(&fixture, true)?;
    let manifest = fixture.execute(operation).await?;
    assert!(
        sink.accepted.load(Ordering::Acquire),
        "real source capture reached its receipt callback"
    );
    assert_eq!(
        fixture.agent.db.get_operation(operation)?.unwrap().state,
        "COMPLETED"
    );
    let original = &fixture.files[0];
    let captured = manifest
        .files
        .iter()
        .find(|file| file.relative_path == original.relative)
        .unwrap();
    assert_eq!(captured.file_hash, original.hash);
    assert_ne!(
        noland_cas::blake3_file(&fixture.source.join(&original.relative))?,
        original.hash
    );
    assert!(
        !fixture
            .agent
            .db
            .pending_app_mutations(&fixture.app, 100)?
            .is_empty(),
        "later writes must not be acknowledged by an older captured generation"
    );
    let report = fixture
        .restore(
            &manifest,
            &fixture._owned.path.join("captured-old-generation"),
            Some(&original.relative),
            false,
        )
        .await?;
    assert_eq!(report["durableCompletion"], true);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_approved_root_replacement_still_blocks_captured_generation_publication(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, sink) = queue_metadata_capture(&fixture, false)?;
    sink.replace_root_after_accept
        .store(true, Ordering::Release);
    assert!(fixture.execute(operation).await.is_err());
    assert!(sink.accepted.load(Ordering::Acquire));
    assert_ne!(
        fixture.agent.db.get_operation(operation)?.unwrap().state,
        "COMPLETED"
    );
    assert!(!fixture
        .provider
        .snapshot()
        .writes
        .iter()
        .any(|key| { key.starts_with("bundles/") && key.ends_with("/COMMITTED") }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_unchanged_reuse_requires_actual_capture_and_same_uncertainty_epoch() -> Result<()> {
    let mut fixture = Fixture::create(MIB, 8)?;
    let (_, first) = fixture.capture(None).await?;
    assert_eq!(first["bytesRead"], MIB);
    let (_, unchanged) = fixture.capture(None).await?;
    assert_eq!(
        unchanged["bytesRead"], 0,
        "actual source proof should avoid a second content pass"
    );
    assert_eq!(unchanged["sourceFilesReused"], fixture.files.len());
    assert_eq!(unchanged["newPacks"], 0);
    // A real uncertainty fence is distinct from a normal source-write event.
    // No bytes changed, but a new epoch must invalidate old source reuse proof.
    fixture.reuse_epoch = format!("isolated-native-fixture-{}:gap-1", Uuid::new_v4());
    fixture.agent.db.mark_dirty(&fixture.app, None, true)?;
    let (_, after_gap) = fixture.capture(None).await?;
    assert_eq!(after_gap["bytesRead"], MIB);
    assert_eq!(after_gap["sourceFilesReused"], 0);
    assert_eq!(
        after_gap["newPacks"], 0,
        "reverification can still deduplicate existing packs"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_source_observer_loss_forces_reconciliation_despite_stale_controller_reuse_epoch(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    fixture.capture(None).await?;
    let (_, unchanged) = fixture.capture(None).await?;
    assert_eq!(unchanged["bytesRead"], 0);
    let before = fixture.agent.observer.loss_generation();
    fixture.agent.observer.signal_loss(
        "synthetic_overflow",
        "isolated native source overflow regression",
    );
    assert!(fixture.agent.observer.loss_generation() > before);
    fixture.agent.db.mark_dirty(&fixture.app, None, true)?;
    // Deliberately retain the old fixture controller epoch. The source's own
    // uncertainty fence must independently prevent its prior proof from reuse.
    let (_, after_loss) = fixture.capture(None).await?;
    assert_eq!(after_loss["bytesRead"], MIB);
    assert_eq!(after_loss["sourceFilesReused"], 0);
    assert!(after_loss["fullScans"].as_u64().unwrap() > 0);
    assert_eq!(
        after_loss["newPacks"], 0,
        "reconciliation/hash verification may still deduplicate existing packs"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_additive_capture_refuses_accidentally_enabled_history_retirement_before_provider_io(
) -> Result<()> {
    let mut fixture = Fixture::create(MIB, 8)?;
    fixture.agent.config.converge_complete_backups = true;
    let (operation, sink) = queue_metadata_capture(&fixture, false)?;
    let error = fixture.execute(operation).await.unwrap_err();
    assert!(error.to_string().contains("additive"));
    assert!(!sink.accepted.load(Ordering::Acquire));
    let io = fixture.provider.snapshot();
    assert!(io.writes.is_empty());
    assert_eq!(io.io.remote_stat_calls, 0);
    assert_eq!(io.io.remote_list_calls, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_full_scope_keeps_actual_directories_and_confined_link_metadata() -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, sink) = queue_directory_link_capture(&fixture)?;
    let manifest = fixture.execute(operation).await?;
    assert!(sink.accepted.load(Ordering::Acquire));
    assert_eq!(
        manifest.files.len(),
        sink.nodes.len(),
        "no structural nodes may be silently dropped"
    );
    let directory = manifest
        .files
        .iter()
        .find(|file| file.relative_path == "Contents/Resources/empty")
        .unwrap();
    assert_eq!(directory.file_type, "directory");
    assert_eq!(directory.size, 0);
    assert!(directory.file_hash.is_empty() && directory.chunks.is_empty());
    let link = manifest
        .files
        .iter()
        .find(|file| file.relative_path == "Contents/Resources/current.bin")
        .unwrap();
    assert_eq!(link.file_type, "symlink");
    assert_eq!(
        link.symlink_target.as_deref(),
        Some("../../assets/large-00.bin")
    );
    assert!(link.chunks.is_empty());
    native_capture::verify_prepared(&fixture.agent, operation, &manifest)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_full_scope_tracker_metadata_digests_are_raw_and_never_rewrite_signed_fields(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, sink) = queue_full_capture(&fixture, None)?;
    // Shape/format regression only. Actual Tracker + StoreAdapter/MemoryVault
    // interop belongs to the parent's cross-crate native bridge fixture.
    let evidence = sink.full.as_ref().unwrap().evidence.clone();
    let original = evidence.clone();
    let binding = NativeFullScopeBinding::from_evidence(&evidence)?;
    assert_eq!(binding.evidence_hash, fixture_metadata_digest(&evidence)?);
    assert_eq!(binding.evidence_hash.len(), 64);
    assert!(!binding.evidence_hash.starts_with("blake3:"));
    assert_eq!(sink.scope.full_scope.as_ref(), Some(&binding));
    assert_eq!(
        evidence, original,
        "header binding must not rewrite an original MAC-signed scope/grant"
    );
    let proof = &evidence["expectedFullScope"]["scope"];
    let ids = sink
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        proof["expectedNodeIdsHash"],
        fixture_metadata_digest(&json!(ids))?
    );
    assert_eq!(
        proof["deletedNodeIdsHash"],
        fixture_metadata_digest(&json!([]))?
    );
    assert_eq!(
        proof["trackingScopeHash"],
        fixture_metadata_digest(&evidence["authorization"]["trackingScope"])?
    );
    for path in [
        "/metadataIdentity",
        "/expectedFullScope/scope/metadataIdentity",
        "/expectedFullScope/scope/trackingScopeHash",
        "/expectedFullScope/scope/expectedNodeIdsHash",
        "/expectedFullScope/scope/deletedNodeIdsHash",
    ] {
        for malformed in [
            format!(
                "blake3:{}",
                evidence.pointer(path).unwrap().as_str().unwrap()
            ),
            "A".repeat(64),
            "0".repeat(63),
            "g".repeat(64),
        ] {
            let mut changed = evidence.clone();
            *changed.pointer_mut(path).unwrap() = json!(malformed);
            let unchanged = changed.clone();
            assert!(
                NativeFullScopeBinding::from_evidence(&changed).is_err(),
                "a signed metadata digest must be exact canonical raw hex: {path}"
            );
            assert_eq!(
                changed, unchanged,
                "rejection must not normalize/re-sign evidence"
            );
        }
    }
    let mut bad_header = sink.scope.clone();
    bad_header.full_scope.as_mut().unwrap().evidence_hash =
        format!("blake3:{}", binding.evidence_hash);
    assert!(
        bad_header.validate().is_err(),
        "source content-hash syntax is not metadata-binding syntax"
    );
    let manifest = fixture.execute(operation).await?;
    assert!(
        manifest
            .files
            .iter()
            .filter(|file| file.file_type == "file")
            .all(|file| file.file_hash.starts_with("blake3:") && file.file_hash.len() == 71),
        "the actual source file-content wire hashes must remain tagged"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_full_scope_separates_private_software_installation_and_canonical_app_through_history(
) -> Result<()> {
    let fixture = Fixture::create_for_app(MIB, 8, AppId("steam:480".into()))?;
    let private_id = "fixture-software";
    let instance = "steam:480@install";
    let (first_id, first_sink) = queue_full_capture_for_ids(&fixture, None, private_id, instance)?;
    let frozen = first_sink.full.as_ref().unwrap().evidence.clone();
    assert_eq!(frozen["softwareId"], private_id);
    assert_eq!(
        frozen["expectedFullScope"]["scope"]["softwareId"],
        private_id
    );
    assert_eq!(
        frozen["authorization"]["trackingScope"]["softwareId"],
        private_id
    );
    assert_eq!(frozen["authorization"]["trackingScope"]["appId"], instance);
    assert_eq!(frozen["sourceIdentity"]["app_id"], "steam:480");
    assert_eq!(
        frozen["expectedFullScope"]["scope"]["trackingScopeHash"],
        fixture_metadata_digest(&frozen["authorization"]["trackingScope"])?
    );
    let first = fixture.execute(first_id).await?;
    assert_eq!(first.app.app_id.as_str(), "steam:480");
    assert_eq!(
        first.environment["quicksave_native"]["software_instance_id"],
        instance
    );
    let layouts = &first.environment["quicksave_native_root_layouts"];
    assert_eq!(layouts["app_id"], "steam:480");
    assert_eq!(layouts["software_instance_id"], instance);
    let canonical_root =
        noland_state_agent::native_host::native_root_token(&fixture.app, "payload");
    assert!(first.files.iter().all(|file| file.logical_root == canonical_root),
        "logical roots must use canonical source ownership, not the private record or installation ID");
    native_capture::verify_prepared(&fixture.agent, first_id, &first)?;
    let committed = noland_storage::read_committed_manifest(
        &fixture.provider,
        &fixture.master,
        &fixture.app,
        first.bundle_id,
    )
    .await?;
    assert_eq!(
        committed.environment["quicksave_native"]["software_instance_id"],
        instance
    );
    fixture
        .restore(
            &committed,
            &fixture._owned.path.join("three-identities-restore"),
            Some(&fixture.files[0].relative),
            false,
        )
        .await?;
    assert_eq!(
        first_sink.full.as_ref().unwrap().evidence,
        frozen,
        "source admission must not rewrite the original signed software/instance scope"
    );
    let before = fixture.provider.snapshot();
    let (second_id, second_sink) =
        queue_full_capture_for_ids(&fixture, Some((&first, &first_sink)), private_id, instance)?;
    let second = fixture.execute(second_id).await?;
    assert_eq!(second.parent_bundle_id, Some(first.bundle_id));
    let metrics: OperationMetrics = serde_json::from_value(
        fixture
            .agent
            .db
            .get_operation(second_id)?
            .unwrap()
            .detail_json["metrics"]
            .clone(),
    )?;
    assert_eq!(
        metrics.bytes_hashed, 0,
        "matching installation history may reuse actual captured file proofs"
    );
    assert_eq!(
        metrics.num_files_skipped_fast_identity,
        fixture.files.len() as u64
    );
    assert_eq!(
        fixture.provider.snapshot().pack_uploads,
        before.pack_uploads
    );
    let removed = fixture.files.last().unwrap().relative.clone();
    fs::remove_file(fixture.source.join(&removed))?;
    let (third_id, third_sink) = queue_full_capture_for_ids(
        &fixture,
        Some((&second, &second_sink)),
        private_id,
        instance,
    )?;
    let third = fixture.execute(third_id).await?;
    assert_eq!(third.parent_bundle_id, Some(second.bundle_id));
    assert_eq!(third.tombstones.len(), 1);
    assert_eq!(third.tombstones[0].relative_path, removed);
    assert_eq!(
        third.environment["quicksave_native"]["software_instance_id"],
        instance
    );
    native_capture::verify_prepared(&fixture.agent, third_id, &third)?;
    let (wrong_id, wrong_sink) = queue_full_capture_for_ids(
        &fixture,
        Some((&third, &third_sink)),
        private_id,
        private_id,
    )?;
    let writes = fixture.provider.snapshot().writes.len();
    assert!(
        fixture.execute(wrong_id).await.is_err(),
        "private software identity must not authorize inheritance as the installation identity"
    );
    assert!(!wrong_sink.accepted.load(Ordering::Acquire));
    assert!(!fixture.provider.snapshot().writes[writes..]
        .iter()
        .any(|key| key.starts_with("bundles/") && key.ends_with("/COMMITTED")));
    assert_eq!(
        fixture.agent.db.latest_commit(&fixture.app)?.unwrap().1,
        third.bundle_id
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_full_scope_legacy_equal_identity_values_still_capture() -> Result<()> {
    let id = "legacy-equal-native-identity";
    let fixture = Fixture::create_for_app(MIB, 8, AppId(id.into()))?;
    let (operation, sink) = queue_full_capture_for_ids(&fixture, None, id, id)?;
    let manifest = fixture.execute(operation).await?;
    assert!(sink.accepted.load(Ordering::Acquire));
    assert_eq!(manifest.app.app_id.as_str(), id);
    assert_eq!(
        manifest.environment["quicksave_native"]["software_instance_id"],
        id
    );
    native_capture::verify_prepared(&fixture.agent, operation, &manifest)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_root_layout_is_actual_canonical_app_structure_not_ui_or_source_path_authority(
) -> Result<()> {
    use noland_state_agent::native_host::NativeRootRole;
    let mut fixture = Fixture::create(MIB, 8)?;
    let app_root = fixture._owned.path.join("Isolated Layout.app");
    fs::rename(&fixture.source, &app_root)?;
    fixture.source = app_root;
    let metadata = SourcePath::new(&fixture.source)?.metadata()?;
    fixture.agent.native_register(
        AppIdentity::new(fixture.app.clone(), "Synthetic Layout"),
        vec![ApprovedNativeRoot {
            id: "payload".into(),
            path: fixture.source.clone(),
            allowed_files: None,
            expected_identity: Some((metadata.dev(), metadata.ino())),
            role: NativeRootRole::Installation,
        }],
    )?;
    let (operation, _) = queue_full_capture(&fixture, None)?;
    let manifest = fixture.execute(operation).await?;
    let layouts = &manifest.environment["quicksave_native_root_layouts"];
    assert_eq!(layouts["version"], 1);
    assert_eq!(layouts["platform"], std::env::consts::OS);
    assert_eq!(
        layouts["app_id"],
        fixture.app.as_str(),
        "root tokens/layouts bind canonical SourceIdentity AppId"
    );
    assert_eq!(
        layouts["software_instance_id"],
        "isolated-full-native-instance"
    );
    assert_eq!(layouts["roots"][0]["leaf_name"], "Isolated Layout.app");
    assert_eq!(layouts["roots"][0]["role"], "installation");
    assert_eq!(layouts["roots"][0]["source_kind"], "directory");
    assert_eq!(layouts["roots"][0]["root_id"], "payload");
    assert!(!serde_json::to_string(layouts)?.contains(fixture._owned.path.to_str().unwrap()));
    fixture
        .agent
        .native_check_publication(operation, &manifest)?;
    let destination = fixture._owned.path.join("restored-layout");
    let roots = native_restore_roots(&destination, &manifest)?;
    let logical =
        LogicalRoot::parse(layouts["roots"][0]["logical_root"].as_str().unwrap()).unwrap();
    assert_eq!(
        roots.resolve(&logical),
        Some(destination.join("Isolated Layout.app"))
    );
    fixture
        .restore(&manifest, &destination, None, false)
        .await?;
    assert!(destination
        .join("Isolated Layout.app")
        .join(&fixture.files[0].relative)
        .is_file());
    let mut forged = manifest.clone();
    forged.environment["quicksave_native_root_layouts"]["roots"][0]["leaf_name"] =
        json!("Forged.app");
    assert!(fixture
        .agent
        .native_check_publication(operation, &forged)
        .is_err());
    assert!(
        native_capture::accept_prepared(&fixture.agent, operation, &forged, &fixture.master)
            .is_err()
    );
    assert!(native_capture::verify_prepared(&fixture.agent, operation, &forged).is_err());
    let (subset, _) = fixture.capture(Some(&fixture.files[0].relative)).await?;
    assert_eq!(subset.mode, BackupMode::Custom);
    assert_eq!(
        subset.environment["quicksave_native"]["coverage"],
        "selected_nodes"
    );
    let catalog = noland_storage::load_catalog(&fixture.provider, &fixture.master).await?;
    assert_eq!(
        catalog.apps[0].latest_complete_bundle_id,
        Some(manifest.bundle_id),
        "a descriptor does not upgrade Custom selection to complete/ready"
    );
    assert_eq!(
        NativeRootRole::parse("installer")?,
        NativeRootRole::Installer
    );
    assert_eq!(NativeRootRole::Installer.as_str(), "installer");
    assert_eq!(
        NativeRootRole::Installer.classification(),
        (
            PersistenceClass::ReconstructableApp,
            SemanticRole::AppContent
        )
    );
    // Neither the synthetic .app nor any installer is executed.
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_full_snapshot_deletes_one_exact_key_additively_and_reuses_remaining_payload(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (first_id, first_sink) = queue_full_capture(&fixture, None)?;
    let first = fixture.execute(first_id).await?;
    let removed = fixture.files.last().unwrap().relative.clone();
    fs::remove_file(fixture.source.join(&removed))?;
    let before = fixture.provider.snapshot();
    let (second_id, second_sink) = queue_full_capture(&fixture, Some((&first, &first_sink)))?;
    let second = fixture.execute(second_id).await?;
    assert!(second_sink.accepted.load(Ordering::Acquire));
    assert_eq!(second.mode, BackupMode::CompleteApplication);
    assert_eq!(second.parent_bundle_id, Some(first.bundle_id));
    assert_eq!(second.tombstones.len(), 1);
    assert_eq!(second.tombstones[0].relative_path, removed);
    assert!(!second
        .files
        .iter()
        .any(|file| file.relative_path == removed));
    assert_eq!(
        fixture.provider.snapshot().pack_uploads,
        before.pack_uploads
    );
    let metrics: OperationMetrics = serde_json::from_value(
        fixture
            .agent
            .db
            .get_operation(second_id)?
            .unwrap()
            .detail_json["metrics"]
            .clone(),
    )?;
    assert_eq!(metrics.bytes_hashed, 0);
    let read = noland_storage::read_committed_manifest(
        &fixture.provider,
        &fixture.master,
        &fixture.app,
        second.bundle_id,
    )
    .await?;
    assert_eq!(read.tombstones.len(), 1);
    native_capture::verify_prepared(&fixture.agent, second_id, &read)?;
    let (third_id, _) = queue_full_capture(&fixture, Some((&second, &second_sink)))?;
    let third = fixture.execute(third_id).await?;
    assert!(
        third.tombstones.is_empty(),
        "only the exact newly frozen deletion list belongs to this generation"
    );
    assert_eq!(
        fixture.provider.snapshot().pack_uploads,
        before.pack_uploads
    );
    let catalog = noland_storage::load_catalog(&fixture.provider, &fixture.master).await?;
    for bundle in [first.bundle_id, second.bundle_id, third.bundle_id] {
        assert!(catalog.apps[0]
            .bundles
            .iter()
            .any(|entry| entry.bundle_id == bundle));
    }
    // The old generation remains fully restorable, including the deleted file.
    fixture
        .restore(
            &first,
            &fixture._owned.path.join("restore-before-one-delete"),
            Some(&removed),
            false,
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_all_deleted_full_snapshot_keeps_authenticated_empty_history_and_no_new_packs(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (first_id, first_sink) = queue_full_capture(&fixture, None)?;
    let first = fixture.execute(first_id).await?;
    let before = fixture.provider.snapshot();
    for node in first_sink
        .nodes
        .iter()
        .filter(|node| node.kind != "directory")
    {
        fs::remove_file(fixture.source.join(&node.path))?;
    }
    let mut directories = first_sink
        .nodes
        .iter()
        .filter(|node| node.kind == "directory")
        .collect::<Vec<_>>();
    directories.sort_by_key(|node| std::cmp::Reverse(node.path.split('/').count()));
    for directory in directories {
        fs::remove_dir(fixture.source.join(&directory.path))?;
    }
    let (empty_id, empty_sink) = queue_full_capture(&fixture, Some((&first, &first_sink)))?;
    assert_eq!(empty_sink.scope.node_count, 0);
    let empty = fixture.execute(empty_id).await?;
    assert!(empty.files.is_empty());
    assert_eq!(empty.tombstones.len(), first.files.len());
    let expected = first
        .files
        .iter()
        .map(|file| native_file_id(&file.logical_root, &file.relative_path))
        .collect::<BTreeSet<_>>();
    let actual = empty
        .tombstones
        .iter()
        .map(|entry| native_file_id(&entry.logical_root, &entry.relative_path))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(
        empty.environment["quicksave_native"]["full_scope"]["rootCaptures"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    native_capture::verify_prepared(&fixture.agent, empty_id, &empty)?;
    let (unchanged_id, _) = queue_full_capture(&fixture, Some((&empty, &empty_sink)))?;
    let unchanged = fixture.execute(unchanged_id).await?;
    assert!(unchanged.files.is_empty() && unchanged.tombstones.is_empty());
    assert_eq!(
        fixture.provider.snapshot().pack_uploads,
        before.pack_uploads
    );
    let catalog = noland_storage::load_catalog(&fixture.provider, &fixture.master).await?;
    for bundle in [first.bundle_id, empty.bundle_id, unchanged.bundle_id] {
        assert!(catalog.apps[0]
            .bundles
            .iter()
            .any(|entry| entry.bundle_id == bundle));
        noland_storage::read_committed_manifest(
            &fixture.provider,
            &fixture.master,
            &fixture.app,
            bundle,
        )
        .await?;
    }
    fixture
        .restore(
            &first,
            &fixture._owned.path.join("restore-before-all-deleted"),
            None,
            false,
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_initial_empty_directory_requires_real_full_root_authority_not_a_placeholder(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    for file in &fixture.files {
        fs::remove_file(fixture.source.join(&file.relative))?;
    }
    for path in ["state/000", "state", "assets"] {
        fs::remove_dir(fixture.source.join(path))?;
    }
    let (operation, sink) = queue_full_capture(&fixture, None)?;
    assert_eq!(sink.scope.node_count, 0);
    let manifest = fixture.execute(operation).await?;
    assert!(manifest.files.is_empty() && manifest.tombstones.is_empty());
    assert!(manifest.parent_bundle_id.is_none());
    assert!(sink.accepted.load(Ordering::Acquire));
    assert_eq!(fixture.provider.snapshot().pack_uploads, 0);
    let roots = manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"]
        .as_array()
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots[0]["stamp"],
        serde_json::to_value(NativeCaptureStamp::from_metadata(&fs::metadata(
            &fixture.source
        )?)?)?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_selected_missing_file_is_not_an_authorized_deletion_plan() -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (first, _) = fixture.capture(None).await?;
    let relative = fixture.files[0].relative.clone();
    let (operation, _) = queue_metadata_capture_selected(&fixture, Some(&relative), false, None)?;
    fs::remove_file(fixture.source.join(&relative))?;
    let writes = fixture.provider.snapshot().writes.len();
    assert!(fixture.execute(operation).await.is_err());
    assert!(!fixture.provider.snapshot().writes[writes..]
        .iter()
        .any(|key| key.starts_with("bundles/") && key.ends_with("/COMMITTED")));
    let parent = noland_storage::read_committed_manifest(
        &fixture.provider,
        &fixture.master,
        &fixture.app,
        first.bundle_id,
    )
    .await?;
    assert!(parent.tombstones.is_empty());
    assert!(parent
        .files
        .iter()
        .any(|file| file.relative_path == relative));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_empty_scope_json_and_revoked_full_authority_fail_closed() -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    assert!(NativeCaptureScope {
        version: 1,
        work_id: "no-authority".into(),
        metadata_identity: "not-an-authority".into(),
        node_count: 0,
        full_scope: None,
    }
    .validate()
    .is_err());
    assert!(NativeSelection::parse(&json!({
        "version":1,"file_keys":[],"roots_fingerprint":fixture.agent.native_binding_fingerprint(&fixture.app)?,
        "coverage":"selected_nodes","snapshot_identity":"empty","expected_files":[],
    })).is_err());
    let forged_scope = NativeCaptureScope {
        version: 1,
        work_id: "forged-empty-full-json".into(),
        metadata_identity: "untrusted-json".into(),
        node_count: 0,
        full_scope: Some(NativeFullScopeBinding {
            version: 1,
            evidence_hash: "0".repeat(64),
            root_count: 1,
            deleted_count: 0,
        }),
    };
    let forged_sink = Arc::new(FixtureCaptureSink {
        scope: forged_scope.clone(),
        nodes: Vec::new(),
        hashes: BTreeMap::new(),
        master: fixture.master.clone(),
        accepted: AtomicBool::new(false),
        mutate_after_accept: None,
        reuse_epoch: None,
        mutation: None,
        replace_root_after_accept: AtomicBool::new(false),
        source_root: fixture.source.clone(),
        full: None,
        node_metadata: BTreeMap::new(),
    });
    assert!(
        native_capture::install(
            &fixture.agent,
            Uuid::new_v4(),
            &fixture.app,
            forged_scope,
            forged_sink,
        )
        .is_err(),
        "a full-scope JSON binding without its native Rust grant owner grants nothing"
    );
    let (operation, sink) = queue_full_capture(&fixture, None)?;
    sink.full
        .as_ref()
        .unwrap()
        .revoked
        .store(true, Ordering::Release);
    assert!(fixture.execute(operation).await.is_err());
    assert!(!sink.accepted.load(Ordering::Acquire));
    assert!(!fixture
        .provider
        .snapshot()
        .writes
        .iter()
        .any(|key| key.ends_with("/COMMITTED")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_unreadable_or_changed_full_scope_directory_cannot_be_omitted_as_empty() -> Result<()>
{
    let fixture = Fixture::create(MIB, 8)?;
    let (operation, _) = queue_full_capture(&fixture, None)?;
    let directory = fixture.source.join("assets");
    let permissions = fs::metadata(&directory)?.permissions();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o000))?;
    let result = fixture.execute(operation).await;
    fs::set_permissions(&directory, permissions)?;
    assert!(result.is_err(),
        "permission-denied enumeration or its changed frozen directory stamp must fail, never omit the root");
    assert!(!fixture
        .provider
        .snapshot()
        .writes
        .iter()
        .any(|key| key.starts_with("bundles/") && key.ends_with("/COMMITTED")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_frozen_deletions_cannot_name_a_different_authenticated_source_baseline(
) -> Result<()> {
    let fixture = Fixture::create(MIB, 8)?;
    let (first_id, first_sink) = queue_full_capture(&fixture, None)?;
    let first = fixture.execute(first_id).await?;
    fs::remove_file(fixture.source.join(&fixture.files[0].relative))?;
    let mut different = first.clone();
    different.bundle_id = Uuid::new_v4();
    let (operation, sink) = queue_full_capture(&fixture, Some((&different, &first_sink)))?;
    let writes = fixture.provider.snapshot().writes.len();
    assert!(fixture.execute(operation).await.is_err());
    assert!(!sink.accepted.load(Ordering::Acquire));
    assert!(!fixture.provider.snapshot().writes[writes..]
        .iter()
        .any(|key| key.starts_with("bundles/") && key.ends_with("/COMMITTED")));
    assert_eq!(
        fixture.agent.db.latest_commit(&fixture.app)?.unwrap().1,
        first.bundle_id
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit isolated benchmark: 64 MiB/1000 files by default; 256 MiB hard maximum"]
async fn native_optimized_pipeline_benchmark() -> Result<()> {
    fn bounded_env(name: &str, default: u64, min: u64, max: u64) -> u64 {
        let value = std::env::var(name).map_or(default, |value| {
            assert!(
                value.bytes().all(|byte| byte.is_ascii_digit()),
                "decimal fixture bounds"
            );
            value.parse::<u64>().expect("bounded fixture number")
        });
        assert!((min..=max).contains(&value), "fixture resource ceiling");
        value
    }
    let mib = bounded_env("QUICKSAVE_NATIVE_BENCH_MIB", 64, 64, 256);
    let files = bounded_env(
        "QUICKSAVE_NATIVE_BENCH_FILES",
        1000,
        32,
        MAX_FIXTURE_FILES as u64,
    );
    let report = workload(mib * MIB, files as usize).await?;
    let report = serde_json::to_string(&report)?;
    assert!(report.len() <= 256 * 1024);
    println!("NATIVE_SHARED_STORAGE_BENCH {report}");
    Ok(())
}
