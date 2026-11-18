// SPDX-License-Identifier: GPL-3.0-only
//! Native streaming composition of No Land's FastCDC, leased CAS, zstd NLPK,
//! adaptive transfer scheduler and authenticated metadata commit protocols.
//! Reference: audited No Land e81238a7536aae201540956ce76981364fd36595.
//!
//! A file is never buffered or copied as a whole. Capture emits sealed CAS waves;
//! a bounded next wave overlaps actual packing/upload. Only a fully verified
//! exact file set may publish a manifest. Orphan immutable packs are not commits.
use super::*;
use noland_cas::{CasLease, ChunkFileReader, ChunkSource, LocalCas};
use noland_crypto::derive_keys;
use noland_pack::{BuiltPack, PackIndexEntry};
use noland_rclone_adapter::WorkerResources;
use noland_state_core::{
    constants::{FASTCDC_MAX, PACK_TARGET},
    BackupMode, ConsistencyKind, ManifestApp, ManifestFile, ManifestSource, PersistenceClass,
    SemanticRole,
};
use noland_storage::{PackUploadSession, RollingUploadWindow};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;

const WAVE_BYTES: u64 = PACK_TARGET;
const MAX_WAVE_CHUNKS: usize = 16_384;
const MAX_WAVES: usize = 200_000;
const FILE_RECEIPT_BATCH: usize = 1024;
const RECEIPT_MAGIC: &[u8; 8] = b"QSWREC1\0";

/// Device authentication protects captured hashes in metadata-only plans:
/// possessing the repository key alone cannot manufacture a native receipt.
pub(super) struct ReceiptDirectory {
    root: SafeRoot,
    authority: NativeOperationAuthority,
}
impl ReceiptDirectory {
    pub(super) fn open(inner: &Inner, path: &Path) -> Result<Self> {
        let authority = inner
            .operation_authority
            .lock()
            .map_err(poison)?
            .clone()
            .context("native durable capture receipts require installed device authority")?;
        Self::with_authority(path, authority)
    }
    fn with_authority(path: &Path, authority: NativeOperationAuthority) -> Result<Self> {
        Ok(Self {
            root: SafeRoot::open(path)?,
            authority,
        })
    }
    fn mac(&self, aad: &[u8], envelope: &[u8]) -> Result<[u8; 32]> {
        let mut message = b"QuickSave Windows prepared receipt v1\0".to_vec();
        message.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        message.extend_from_slice(aad);
        message.extend_from_slice(blake3::hash(envelope).as_bytes());
        (self.authority)(&message)
    }
}
impl std::ops::Deref for ReceiptDirectory {
    type Target = SafeRoot;
    fn deref(&self) -> &Self::Target {
        &self.root
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    operation: Uuid,
    parent: Option<Uuid>,
    inherited: Vec<PackIndexEntry>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaveReceipt {
    operation: Uuid,
    file: usize,
    wave: usize,
    hashes: Vec<(String, u64)>,
    packs: Vec<BuiltPack>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReceipt {
    operation: Uuid,
    index: usize,
    stamp: FileStamp,
    file: ManifestFile,
    waves: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBatch {
    operation: Uuid,
    batch: usize,
    files: Vec<FileReceipt>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    operation: Uuid,
    manifest: BundleManifest,
    index: Vec<PackIndexEntry>,
    packed_bytes: u64,
}
struct Wave {
    file: usize,
    wave: usize,
    hashes: Vec<(String, u64)>,
    sources: Vec<(String, ChunkSource)>,
    lease: Option<Arc<CasLease>>,
    cached: Option<WaveReceipt>,
}
struct SmallBatch {
    owner: Option<usize>,
    wave: Option<WaveBuilder>,
    files: Vec<FileReceipt>,
    reader: ChunkFileReader,
}
impl SmallBatch {
    fn new() -> Self {
        Self {
            owner: None,
            wave: None,
            files: Vec::new(),
            reader: ChunkFileReader::default(),
        }
    }
    fn finish(self, capture: &Capture) -> Result<()> {
        if let (Some(owner), Some(mut wave)) = (self.owner, self.wave) {
            wave.finish(capture, owner, 0)?;
        }
        for file in self.files {
            capture.send_event(Event::File(file))?;
        }
        Ok(())
    }
}
enum Event {
    Wave(Wave),
    File(FileReceipt),
    Failure(anyhow::Error),
}

/// An owned native worker can never be detached by cancellation or an error.
/// The receive side is asynchronous; Drop closes it, then joins real execution.
struct OwnedWorker<T> {
    receive: tokio::sync::oneshot::Receiver<Result<T>>,
    thread: Option<JoinHandle<()>>,
    stop_on_drop: Option<Arc<AtomicBool>>,
}
impl<T: Send + 'static> OwnedWorker<T> {
    fn start(name: &str, work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<Self> {
        let (send, receive) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!("native capture/packing worker panicked"))
                    });
                let _ = send.send(result);
            })?;
        Ok(Self {
            receive,
            thread: Some(thread),
            stop_on_drop: None,
        })
    }
    fn stop_on_drop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop_on_drop = Some(stop);
        self
    }
    async fn finish(mut self) -> Result<T> {
        let result = (&mut self.receive)
            .await
            .context("native worker result unavailable")?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("native worker join failed"))?;
        }
        result
    }
}
impl<T> Drop for OwnedWorker<T> {
    fn drop(&mut self) {
        if let Some(stop) = &self.stop_on_drop {
            stop.store(true, Ordering::Release);
        }
        self.receive.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Capture {
    plan: Arc<FrozenPlan>,
    master: MasterKey,
    directory: Arc<ReceiptDirectory>,
    roots: BTreeMap<String, Arc<SafeRoot>>,
    cas: LocalCas,
    inherited: Arc<BTreeMap<String, PackIndexEntry>>,
    previous: BTreeMap<String, (FileStamp, ManifestFile)>,
    file_batches: Mutex<BTreeMap<usize, Option<Arc<FileBatch>>>>,
    send: mpsc::Sender<Event>,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    check: Check,
}

pub(super) async fn upload(
    inner: &Arc<Inner>,
    job: &Job,
    provider: &CheckedProvider,
) -> Result<()> {
    let Work::Upload {
        app,
        source_identity,
        software_instance_id,
        roots,
        files,
        bundle,
        commit,
        snapshot,
        metadata,
        complete_approved_scope,
        coverage,
        capture_scope,
        full_snapshot,
        ..
    } = &job.plan.work
    else {
        bail!("native capture plan kind mismatch");
    };
    check_roots(roots)?;
    (provider.check)().map_err(source_error)?;
    let path = operation_directory(inner, job.plan.operation, "upload")?;
    let directory = Arc::new(ReceiptDirectory::open(inner, &path)?);
    let master = &job.access.master;
    let prepared: Prepared = match read_document(
        &directory,
        "prepared.enc",
        master,
        job.plan.operation,
    )? {
        Some(prepared) => {
            validate_prepared(&prepared, &job.plan)?;
            prepared
        }
        None => {
            let header: Header = match read_document::<Header>(
                &directory,
                "header.enc",
                master,
                job.plan.operation,
            )? {
                Some(header) => {
                    ensure!(
                        header.operation == job.plan.operation,
                        "native inherited-index operation mismatch"
                    );
                    header
                }
                None => {
                    let catalog = load_catalog(provider, master).await.map_err(source_error)?;
                    let parent = catalog
                        .apps
                        .iter()
                        .find(|candidate| &candidate.app_id == app)
                        .map(|candidate| candidate.latest_bundle_id);
                    let inherited = match parent {
                        Some(parent) => {
                            noland_storage::read_pack_index(provider, master, app, parent)
                                .await
                                .map_err(source_error)?
                        }
                        None => Vec::new(),
                    };
                    ensure!(
                        inherited.len() <= MAX_CHUNKS,
                        "native inherited pack-index bound exceeded"
                    );
                    let header = Header {
                        operation: job.plan.operation,
                        parent,
                        inherited,
                    };
                    write_document(
                        &directory,
                        "header.enc",
                        master,
                        job.plan.operation,
                        &header,
                    )?;
                    header
                }
            };
            let mut inherited: BTreeMap<String, PackIndexEntry> = header
                .inherited
                .iter()
                .map(|entry| (entry.chunk_hash.clone(), entry.clone()))
                .collect::<BTreeMap<_, _>>();
            ensure!(
                inherited.len() == header.inherited.len(),
                "ambiguous inherited native chunk index"
            );
            // Durable operation-local pack receipts are loaded before admitting
            // any new wave. Retry cannot let an earlier dedup-only wave suppress
            // the original failed owner, nor repack acknowledged earlier work.
            for entry in prepared_wave_index(inner, &directory, master, job.plan.operation)? {
                ensure!(
                    inherited.len() < MAX_CHUNKS || inherited.contains_key(&entry.chunk_hash),
                    "native resumed chunk-index bound exceeded"
                );
                inherited.insert(entry.chunk_hash.clone(), entry);
            }
            let inherited = Arc::new(inherited);
            let resources = WorkerResources::detect();
            // Shared aggregate resource policy: FastCDC/compression workspaces,
            // stack and decoder buffers are not each given a whole-machine budget.
            let budget = resources
                .cpu_workers(
                    TransferWorkload::Throughput,
                    3 * FASTCDC_MAX + 2 * 1024 * 1024,
                )
                .clamp(2, 16);
            let capture_workers = (budget / 3).clamp(1, 4).min(files.len());
            let pack_workers = budget
                .saturating_sub(capture_workers)
                .clamp(1, 4)
                .min(provider.transfer_tuning().max_parallel_uploads.max(1));
            let cas_path = inner.paths.cache.join("cas").join("chunks");
            ensure_private_directory(&cas_path)?;
            let cas = LocalCas::new(&cas_path).map_err(source_error)?;
            let mut handles = BTreeMap::new();
            for root in roots {
                let handle = SafeRoot::open(&root.path)?;
                ensure!(
                    handle.identity()? == root.identity,
                    "native root changed before capture"
                );
                handles.insert(root.logical.clone(), Arc::new(handle));
            }
            let (send, mut receive) = mpsc::channel(pack_workers * 2);
            let failed = Arc::new(AtomicBool::new(false));
            let previous: BTreeMap<String, (FileStamp, ManifestFile)> =
                match read_document(&directory, "unchanged.enc", master, job.plan.operation)? {
                    Some(previous) => previous,
                    None => {
                        let previous = previous_files(inner, job, app)?;
                        write_document(
                            &directory,
                            "unchanged.enc",
                            master,
                            job.plan.operation,
                            &previous,
                        )?;
                        previous
                    }
                };
            let capture = Arc::new(Capture {
                plan: Arc::clone(&job.plan),
                master: master.clone(),
                directory: Arc::clone(&directory),
                roots: handles,
                cas,
                inherited: Arc::clone(&inherited),
                previous,
                file_batches: Mutex::new(BTreeMap::new()),
                send,
                stop: Arc::clone(&job.stop),
                failed: Arc::clone(&failed),
                check: Arc::clone(&provider.check),
            });
            let producer = {
                let capture = Arc::clone(&capture);
                OwnedWorker::start("quicksave-win-capture", move || {
                    let next = AtomicUsize::new(0);
                    std::thread::scope(|scope| {
                        let mut workers = Vec::new();
                        for _ in 0..capture_workers {
                            let capture = Arc::clone(&capture);
                            let next = &next;
                            workers.push(scope.spawn(move || {
                                loop {
                                    if capture.stopped() {
                                        break;
                                    }
                                    let index =
                                        next.fetch_add(FILE_RECEIPT_BATCH, Ordering::AcqRel);
                                    let count = match &capture.plan.work {
                                        Work::Upload { files, .. } => files.len(),
                                        _ => 0,
                                    };
                                    if index >= count {
                                        break;
                                    }
                                    if let Err(error) = capture
                                        .batch(index, (index + FILE_RECEIPT_BATCH).min(count))
                                    {
                                        capture.failed.store(true, Ordering::Release);
                                        let _ = capture.send.try_send(Event::Failure(error));
                                        return Err(anyhow::anyhow!(
                                            "native capture worker failed"
                                        ));
                                    }
                                }
                                Ok::<_, anyhow::Error>(())
                            }));
                        }
                        for worker in workers {
                            match worker.join() {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    capture.failed.store(true, Ordering::Release);
                                    return Err(error);
                                }
                                Err(_) => {
                                    capture.failed.store(true, Ordering::Release);
                                    return Err(anyhow::anyhow!("native capture scope panicked"));
                                }
                            }
                        }
                        Ok(())
                    })
                })?
                .stop_on_drop(Arc::clone(&failed))
            };
            // Only worker clones keep event senders alive. Retaining this Arc
            // would make EOF depend on the consumer itself.
            drop(capture);
            let session =
                PackUploadSession::new(provider, Some(&inner.db), Some(job.plan.operation));
            let mut window = RollingUploadWindow::new(
                pack_workers,
                provider
                    .transfer_tuning()
                    .max_bulk_bytes
                    .max(WAVE_BYTES + FASTCDC_MAX)
                    .min((WAVE_BYTES + FASTCDC_MAX) * pack_workers as u64),
            );
            let mut results: Vec<Option<FileReceipt>> = (0..files.len()).map(|_| None).collect();
            let mut ready_waves = vec![0usize; files.len()];
            let mut ready_wave_ids = BTreeSet::new();
            let mut ready_batches = BTreeSet::new();
            let mut captured_files = 0u64;
            let mut index = (*inherited).clone();
            let mut known = inherited.keys().cloned().collect::<BTreeSet<_>>();
            let mut packed_bytes = 0u64;
            let mut wave_count = 0usize;
            let mut first_error = None;
            let mut eof = false;
            inner.progress(
                job.plan.operation,
                "capturing_and_uploading",
                0,
                Some(files.len() as u64),
                "files",
            )?;
            while !eof || !window.is_empty() {
                let room = window.can_push(WAVE_BYTES + FASTCDC_MAX);
                tokio::select! {
                    event = receive.recv(), if !eof && (room || first_error.is_some()) => {
                        match event {
                            None => eof = true,
                            Some(Event::Failure(error)) => {
                                if first_error.is_none() { first_error = Some(error); }
                                failed.store(true, Ordering::Release);
                                receive.close();
                            }
                            Some(Event::File(receipt)) if first_error.is_none() => {
                                if receipt.index >= results.len() || results[receipt.index].is_some() {
                                    first_error = Some(anyhow::anyhow!("duplicate or foreign native captured file receipt"));
                                    failed.store(true, Ordering::Release);
                                    receive.close();
                                } else {
                                    let file_index = receipt.index;
                                    results[file_index] = Some(receipt);
                                    captured_files += 1;
                                    checkpoint_files(&directory, master, job.plan.operation, file_index,
                                        &results, &ready_waves, &mut ready_batches)?;
                                    inner.progress(job.plan.operation, "capturing_and_uploading",
                                        captured_files,
                                        Some(files.len() as u64), "files")?;
                                }
                            }
                            Some(Event::Wave(wave)) if first_error.is_none() => {
                                wave_count += 1;
                                if wave_count > MAX_WAVES {
                                    first_error = Some(anyhow::anyhow!("native streaming capture wave bound exceeded"));
                                    failed.store(true, Ordering::Release);
                                    receive.close();
                                    continue;
                                }
                                let admitted = if let Some(cached) = &wave.cached {
                                    for entry in cached.packs.iter().flat_map(|pack| &pack.entries) {
                                        known.insert(entry.chunk_hash.clone());
                                    }
                                    BTreeSet::new()
                                } else {
                                    wave.hashes.iter().filter(|(hash, _)| known.insert(hash.clone()))
                                        .map(|(hash, _)| hash.clone()).collect::<BTreeSet<_>>()
                                };
                                let master = master.clone();
                                let directory = Arc::clone(&directory);
                                let path = path.clone();
                                let operation = job.plan.operation;
                                let db = inner.db.clone();
                                let check = Arc::clone(&provider.check);
                                let worker = OwnedWorker::start("quicksave-win-pack", move || {
                                    prepare_wave(wave, admitted, &directory, &path, &master, operation, &db, &check)
                                })?;
                                let session = &session;
                                window.push(WAVE_BYTES + FASTCDC_MAX, async move {
                                    let receipt = worker.finish().await.map_err(|_| StateError::Storage("native prepared wave failed".into()))?;
                                    let packs = receipt.packs.iter().map(|pack|
                                        (pack.pack_id.clone(), pack.path.clone())).collect::<Vec<_>>();
                                    session.upload(&packs).await?;
                                    Ok(receipt)
                                }).map_err(source_error)?;
                            }
                            Some(_) => {} // Failure drain: never admit more work.
                        }
                    }
                    result = window.next(), if !window.is_empty() => {
                        match result {
                            Some(Ok(receipt)) => {
                                ensure!(receipt.file < ready_waves.len()
                                    && ready_wave_ids.insert((receipt.file, receipt.wave)),
                                    "duplicate/foreign prepared native wave receipt");
                                ready_waves[receipt.file] += 1;
                                checkpoint_files(&directory, master, job.plan.operation, receipt.file,
                                    &results, &ready_waves, &mut ready_batches)?;
                                for pack in receipt.packs {
                                    packed_bytes = packed_bytes.saturating_add(pack.bytes);
                                    for entry in pack.entries {
                                        ensure!(index.len() < MAX_CHUNKS || index.contains_key(&entry.chunk_hash),
                                            "native prepared pack-index bound exceeded");
                                        index.insert(entry.chunk_hash.clone(), entry);
                                    }
                                }
                            }
                            Some(Err(error)) => {
                                if first_error.is_none() { first_error = Some(source_error(error)); }
                                failed.store(true, Ordering::Release);
                                receive.close();
                            }
                            None => {}
                        }
                    }
                }
            }
            receive.close();
            let producer_result = producer.finish().await;
            if let Some(error) = first_error {
                return Err(error);
            }
            producer_result?;
            let mut files = results
                .into_iter()
                .map(|file| {
                    file.map(|receipt| receipt.file)
                        .context("native capture did not verify every frozen file")
                })
                .collect::<Result<Vec<_>>>()?;
            files.extend(materialize_metadata(roots, metadata)?);
            let required = files
                .iter()
                .flat_map(|f| &f.chunks)
                .map(|chunk| chunk.hash.as_str())
                .collect::<BTreeSet<_>>();
            for file in &files {
                for chunk in &file.chunks {
                    ensure!(
                        index
                            .get(&chunk.hash)
                            .is_some_and(|entry| u64::from(entry.plaintext_len) == chunk.size),
                        "native captured chunk lacks its authenticated pack reference"
                    );
                }
            }
            let index: Vec<PackIndexEntry> = index
                .into_iter()
                .filter_map(|(hash, entry)| required.contains(hash.as_str()).then_some(entry))
                .collect::<Vec<_>>();
            let mut manifest = BundleManifest::new(
                ManifestApp::from(source_identity),
                ManifestSource {
                    instance_id: inner.instance,
                    image_id: "quicksave-native-windows".into(),
                    captured_at: job.plan.created_at,
                },
                if *complete_approved_scope {
                    BackupMode::CompleteApplication
                } else {
                    BackupMode::Custom
                },
            );
            // Only explicit authenticated full_scope coverage becomes a complete
            // approved-scope bundle. Selecting every visible row is not proof.
            manifest.bundle_id = *bundle;
            manifest.commit_id = *commit;
            manifest.parent_bundle_id = header.parent;
            manifest.consistency = ConsistencyKind::BestEffort;
            manifest.files = files;
            let selected_roots = manifest
                .files
                .iter()
                .map(|file| file.logical_root.as_str())
                .collect::<BTreeSet<_>>();
            let source_layouts = native_root_layouts_value(
                app,
                software_instance_id,
                roots,
                if full_snapshot.is_some() {
                    None
                } else {
                    Some(&selected_roots)
                },
            )?;
            manifest.environment = json!({
                "platform":"windows","capture_consistency":"validated_stable_files_not_application_atomic",
                "snapshot_identity":snapshot,"automatic_retirement":false,
                "software_instance_id":software_instance_id,
                "native_identity":"volume_and_128_bit_file_id","keeps_local_copy":true,
                "completeness":if *complete_approved_scope {"complete_approved_scope"} else {"selected_scope"},
                "quicksave_native_root_layouts":source_layouts,
                "native_symlink_directory_hints":metadata.iter().filter_map(|entry|
                    entry.link.as_ref().and_then(|link| link.target_is_directory).map(|directory|
                        (file_id(&entry.root, &entry.relative), directory))).collect::<BTreeMap<_, _>>(),
                "windowsSymlinkMetadata":metadata.iter().filter_map(|entry|
                    entry.link.as_ref().and_then(|link| link.target_is_directory).map(|directory|
                        json!({"logicalRoot":entry.root,"relativePath":entry.relative,
                            "targetIsDirectory":directory}))).collect::<Vec<_>>(),
                "quicksave_native":{
                    "platform":"windows","coverage":coverage,
                    "software_instance_id":software_instance_id,
                    "operation_id":job.plan.operation,
                    "rootsFingerprint":native_roots_fingerprint(app, roots)?,
                    "selection":{"coverage":coverage,"capture_scope":capture_scope,
                        "software_instance_id":software_instance_id,
                        "roots_fingerprint":native_roots_fingerprint(app, roots)?},
                },
            });
            if let Some(full) = full_snapshot {
                full.revalidate_roots(roots)?;
                let parent = match header.parent {
                    Some(parent) => Some(
                        read_committed_manifest(provider, master, app, parent)
                            .await
                            .map_err(source_error)?,
                    ),
                    None => None,
                };
                full.apply_manifest(&mut manifest, parent.as_ref(), roots)?;
            }
            noland_state_core::native_layout::native_root_layouts(&manifest)
                .map_err(source_error)?;
            let prepared = Prepared {
                operation: job.plan.operation,
                manifest,
                index,
                packed_bytes,
            };
            validate_prepared(&prepared, &job.plan)?;
            write_document(
                &directory,
                "prepared.enc",
                master,
                job.plan.operation,
                &prepared,
            )?;
            prepared
        }
    };
    (provider.check)().map_err(source_error)?;
    check_roots(roots)?;
    // No recapture or changed selection on retries. All packs were uploaded
    // before prepared.enc; the source's immutable completion receipts remain the
    // authority for retransmission, not local plaintext or a UI enabled bit.
    let retired = noland_storage::retired_pack_ids(provider, master)
        .await
        .map_err(source_error)?;
    ensure!(
        !prepared
            .index
            .iter()
            .any(|entry| retired.contains(&entry.pack_id)),
        "original frozen revision references explicitly deleted packs"
    );
    verify_referenced_packs(provider, &prepared.index).await?;
    capture::accept(inner, job, &prepared.manifest)?;
    (provider.check)().map_err(source_error)?;
    inner.progress(job.plan.operation, "publishing_manifest", 0, None, "files")?;
    noland_storage::commit_bundle_with_pack_index_for_operation(
        provider,
        master,
        &prepared.manifest,
        &[],
        Some(&prepared.index),
        Some(&inner.db),
        Some(job.plan.operation),
    )
    .await
    .map_err(source_error)?;
    (provider.check)().map_err(source_error)?;
    check_roots(roots)?;
    inner.progress(job.plan.operation, "publishing_catalog", 0, None, "files")?;
    let catalog = noland_storage::update_catalog_with_bundle(
        provider,
        master,
        &prepared.manifest,
        prepared.packed_bytes,
    )
    .await
    .map_err(source_error)?;
    ensure!(
        catalog
            .apps
            .iter()
            .filter(|candidate| &candidate.app_id == app)
            .flat_map(|candidate| &candidate.bundles)
            .any(|candidate| candidate.bundle_id == *bundle && candidate.commit_id == *commit),
        "native committed revision was not verified in the live catalog"
    );
    (provider.check)().map_err(source_error)?;
    check_roots(roots)?;
    completion::record_committed(inner, job, provider, &prepared.manifest).await?;
    inner.progress(
        job.plan.operation,
        "completed",
        prepared.manifest.files.len() as u64,
        Some(prepared.manifest.files.len() as u64),
        "files",
    )
}

impl Capture {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }
    fn send_event(&self, mut event: Event) -> Result<()> {
        loop {
            ensure!(!self.stopped(), "native capture consumer stopped");
            match self.send.try_send(event) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    bail!("native capture consumer closed")
                }
                Err(mpsc::error::TrySendError::Full(pending)) => {
                    event = pending;
                    // Bounded native producer backpressure, interruptible by
                    // failure/shutdown. No blocking_send may outlive its receiver
                    // and deadlock an error-path joined worker.
                    std::thread::park_timeout(Duration::from_millis(5));
                }
            }
        }
    }
    fn batch(&self, start: usize, end: usize) -> Result<()> {
        (self.check)().map_err(source_error)?;
        let mut small = SmallBatch::new();
        for index in start..end {
            self.file(index, &mut small)?;
        }
        small.finish(self)
    }
    fn file(&self, index: usize, small: &mut SmallBatch) -> Result<()> {
        ensure!(!self.stopped(), "native capture stopped");
        let Work::Upload {
            files,
            capture_scope,
            ..
        } = &self.plan.work
        else {
            bail!("native capture kind mismatch");
        };
        let expected = &files[index];
        if let Some(receipt) = self.saved_file(index)? {
            self.check_file_receipt(&receipt, expected, index)?;
            for wave in 0..receipt.waves {
                let saved = self
                    .wave_receipt(index, wave)?
                    .context("verified native file is missing a prepared wave receipt")?;
                self.send_event(Event::Wave(Wave {
                    file: index,
                    wave,
                    hashes: saved.hashes.clone(),
                    sources: Vec::new(),
                    lease: None,
                    cached: Some(saved),
                }))?;
            }
            return self.send_event(Event::File(receipt));
        }
        let root = self
            .roots
            .get(&expected.root)
            .context("native source root missing")?;
        let (mut file, stamp) = root.read_file(&expected.relative)?;
        let native_before =
            noland_snapshot::SourceMetadata::from_file(&file).map_err(source_error)?;
        let native_id = native_before
            .native_identity()
            .context("native source did not supply its full handle identity")?;
        ensure!(
            native_id.volume == stamp.device && native_id.file_id == stamp.file_id,
            "native snapshot/platform 128-bit file identities disagree"
        );
        ensure!(
            stamp == expected.stamp,
            "uncaptured native file changed; start a new frozen revision"
        );
        if let Some((prior_stamp, prior_file)) = self.previous.get(&expected.id) {
            if prior_stamp == &stamp
                && (capture_scope.is_some() || prior_file.file_hash == expected.hash)
                && prior_file.size == expected.size
                && prior_file.chunks.iter().all(|chunk| {
                    self.inherited
                        .get(&chunk.hash)
                        .is_some_and(|entry| u64::from(entry.plaintext_len) == chunk.size)
                })
            {
                root.verify_file(&expected.relative, &stamp)?;
                ensure!(
                    noland_snapshot::same_file_identity(
                        &native_before,
                        &noland_snapshot::SourceMetadata::from_file(&file).map_err(source_error)?
                    ),
                    "native reused file metadata changed"
                );
                let receipt = FileReceipt {
                    operation: self.plan.operation,
                    index,
                    stamp,
                    file: {
                        let mut file = prior_file.clone();
                        let Work::Upload { roots, .. } = &self.plan.work else {
                            unreachable!()
                        };
                        let root = roots
                            .iter()
                            .find(|root| root.logical == expected.root)
                            .context("native reused file root role missing")?;
                        (file.persistence_class, file.semantic_role) = root.role.classification();
                        file
                    },
                    waves: 0,
                };
                // Unchanged-file reuse has actual complete native stamp +
                // tracker hash or same-instance/epoch-qualified capture evidence
                // and authenticated live packs. Watcher silence is not proof.
                return self.send_event(Event::File(receipt));
            }
        }
        if expected.size <= noland_cas::SMALL_FILE_THRESHOLD {
            if small.wave.is_none() {
                small.owner = Some(index);
                small.wave = Some(WaveBuilder::new(self, index, 0)?);
            }
            let wave = small.wave.as_mut().unwrap();
            let result = small
                .reader
                .chunk_open_file(&mut file, |chunk, bytes| {
                    if self.stopped() {
                        return Err(StateError::Conflict(
                            "native small-file capture stopped".into(),
                        ));
                    }
                    wave.add(self, chunk.hash.clone(), chunk.size, bytes)
                        .map_err(native_capture_error)
                })
                .map_err(source_error)?;
            root.verify_file(&expected.relative, &stamp)?;
            ensure!(
                noland_snapshot::same_file_identity(
                    &native_before,
                    &noland_snapshot::SourceMetadata::from_file(&file).map_err(source_error)?
                ),
                "native small-file handle metadata changed"
            );
            ensure!(
                result.size == expected.size
                    && (capture_scope.is_some() || result.file_hash == expected.hash),
                "actual native small-file capture differs from canonical expected evidence"
            );
            let manifest = self.manifest_file(expected, &stamp, result)?;
            small.files.push(FileReceipt {
                operation: self.plan.operation,
                index,
                stamp,
                file: manifest,
                waves: usize::from(small.owner == Some(index)),
            });
            return Ok(());
        }
        let mut wave = 0usize;
        let mut builder = WaveBuilder::new(self, index, wave)?;
        let mut reader = ChunkFileReader::default();
        let mut chunks_seen = 0usize;
        let result = reader
            .chunk_reader(
                (&mut file).take(
                    expected
                        .size
                        .checked_add(1)
                        .context("source size overflow")?,
                ),
                |chunk, bytes| {
                    chunks_seen += 1;
                    if chunks_seen > MAX_CHUNKS {
                        return Err(StateError::Integrity(
                            "native file chunk bound exceeded".into(),
                        ));
                    }
                    if self.stopped() {
                        return Err(StateError::Conflict("native capture stopped".into()));
                    }
                    if builder.bytes > 0
                        && (builder.bytes.saturating_add(chunk.size) > WAVE_BYTES
                            || builder.hashes.len() == MAX_WAVE_CHUNKS)
                    {
                        builder
                            .finish(self, index, wave)
                            .map_err(native_capture_error)?;
                        wave += 1;
                        builder =
                            WaveBuilder::new(self, index, wave).map_err(native_capture_error)?;
                    }
                    builder
                        .add(self, chunk.hash.clone(), chunk.size, bytes)
                        .map_err(native_capture_error)
                },
            )
            .map_err(source_error)?;
        if !builder.hashes.is_empty() {
            builder.finish(self, index, wave)?;
            wave += 1;
        }
        root.verify_file(&expected.relative, &stamp)?;
        ensure!(
            noland_snapshot::same_file_identity(
                &native_before,
                &noland_snapshot::SourceMetadata::from_file(&file).map_err(source_error)?
            ),
            "native large-file handle metadata changed"
        );
        ensure!(
            result.size == expected.size
                && (capture_scope.is_some() || result.file_hash == expected.hash),
            "actual native capture differs from canonical expected file evidence"
        );
        ensure!(
            result.chunks.len() <= MAX_CHUNKS,
            "single file exceeds native chunk-index bound"
        );
        let manifest = self.manifest_file(expected, &stamp, result)?;
        self.send_event(Event::File(FileReceipt {
            operation: self.plan.operation,
            index,
            stamp,
            file: manifest,
            waves: wave,
        }))
    }

    fn manifest_file(
        &self,
        expected: &ExpectedFile,
        stamp: &FileStamp,
        result: noland_cas::ChunkStreamResult,
    ) -> Result<ManifestFile> {
        let mtime = Some(mtime_ns_from_stamp(stamp)?);
        let Work::Upload { roots, .. } = &self.plan.work else {
            unreachable!()
        };
        let approved = roots
            .iter()
            .find(|root| root.logical == expected.root)
            .context("native captured file root role missing")?;
        let (persistence_class, semantic_role) = approved.role.classification();
        Ok(ManifestFile {
            logical_root: expected.root.clone(),
            relative_path: expected.relative.clone(),
            source_path_hint: None,
            file_type: "file".into(),
            size: result.size,
            file_hash: result.file_hash,
            chunks: result.chunks,
            mode: None,
            mtime_ns: mtime,
            uid: None,
            gid: None,
            symlink_target: None,
            persistence_class,
            semantic_role,
            association_confidence: 1.0,
            shared_app_ids: Vec::new(),
        })
    }

    fn wave_receipt(&self, file: usize, wave: usize) -> Result<Option<WaveReceipt>> {
        read_document(
            &self.directory,
            &wave_name(file, wave),
            &self.master,
            self.plan.operation,
        )
    }
    fn saved_file(&self, index: usize) -> Result<Option<FileReceipt>> {
        let batch = index / FILE_RECEIPT_BATCH;
        let mut batches = self.file_batches.lock().map_err(poison)?;
        if !batches.contains_key(&batch) {
            let saved = read_document::<FileBatch>(
                &self.directory,
                &file_batch_name(batch),
                &self.master,
                self.plan.operation,
            )?;
            if let Some(saved) = &saved {
                ensure!(
                    saved.operation == self.plan.operation
                        && saved.batch == batch
                        && !saved.files.is_empty()
                        && saved.files.len() <= FILE_RECEIPT_BATCH,
                    "native stable-file receipt batch binding changed"
                );
            }
            batches.insert(batch, saved.map(Arc::new));
        }
        Ok(batches
            .get(&batch)
            .and_then(|saved| saved.as_ref())
            .and_then(|saved| saved.files.iter().find(|file| file.index == index))
            .cloned())
    }
    fn check_file_receipt(
        &self,
        receipt: &FileReceipt,
        expected: &ExpectedFile,
        index: usize,
    ) -> Result<()> {
        ensure!(
            receipt.operation == self.plan.operation
                && receipt.index == index
                && receipt.stamp == expected.stamp
                && receipt.file.logical_root == expected.root
                && receipt.file.relative_path == expected.relative
                && receipt.file.size == expected.size
                && (matches!(
                    &self.plan.work,
                    Work::Upload {
                        capture_scope: Some(_),
                        ..
                    }
                ) || receipt.file.file_hash == expected.hash)
                && receipt.waves <= MAX_WAVES,
            "native captured file receipt differs from original frozen scope"
        );
        ensure!(
            receipt.file.file_hash == canonical_hash(&receipt.file.file_hash)?,
            "native captured file receipt lacks its actual canonical BLAKE3 hash"
        );
        Ok(())
    }
}

struct WaveBuilder {
    hashes: Vec<(String, u64)>,
    sources: BTreeMap<String, ChunkSource>,
    lease: Option<Arc<CasLease>>,
    cached: Option<WaveReceipt>,
    bytes: u64,
}
impl WaveBuilder {
    fn new(capture: &Capture, file: usize, wave: usize) -> Result<Self> {
        let cached = capture.wave_receipt(file, wave)?;
        if let Some(saved) = &cached {
            ensure!(
                saved.operation == capture.plan.operation
                    && saved.file == file
                    && saved.wave == wave,
                "native prepared wave identity changed"
            );
        }
        Ok(Self {
            hashes: Vec::new(),
            sources: BTreeMap::new(),
            lease: None,
            cached,
            bytes: 0,
        })
    }
    fn add(&mut self, capture: &Capture, hash: String, size: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            size == bytes.len() as u64 && size <= FASTCDC_MAX,
            "native chunk size mismatch"
        );
        if self.cached.is_none()
            && !capture.inherited.contains_key(&hash)
            && !self.sources.contains_key(&hash)
        {
            if self.lease.is_none() {
                let lease = Arc::new(capture.cas.lease().map_err(source_error)?);
                lease.retain_for_retry();
                self.lease = Some(lease);
            }
            let source = self
                .lease
                .as_ref()
                .unwrap()
                .capture_streaming_prehashed(&hash, bytes)
                .map_err(source_error)?
                .source;
            self.sources.insert(hash.clone(), source);
        }
        self.hashes.push((hash, size));
        self.bytes = self
            .bytes
            .checked_add(size)
            .context("native wave size overflow")?;
        Ok(())
    }
    fn finish(&mut self, capture: &Capture, file: usize, wave: usize) -> Result<()> {
        (capture.check)().map_err(source_error)?;
        if let Some(cached) = &self.cached {
            ensure!(
                cached.hashes == self.hashes,
                "retry captured a different original chunk wave"
            );
        }
        if let Some(lease) = &self.lease {
            lease.sync_all().map_err(source_error)?;
        }
        capture.send_event(Event::Wave(Wave {
            file,
            wave,
            hashes: std::mem::take(&mut self.hashes),
            sources: std::mem::take(&mut self.sources).into_iter().collect(),
            lease: self.lease.take(),
            cached: self.cached.take(),
        }))?;
        self.bytes = 0;
        Ok(())
    }
}

fn prepare_wave(
    wave: Wave,
    admitted: BTreeSet<String>,
    directory: &ReceiptDirectory,
    path: &Path,
    master: &MasterKey,
    operation: Uuid,
    db: &StateDb,
    check: &Check,
) -> Result<WaveReceipt> {
    check().map_err(source_error)?;
    if let Some(receipt) = wave.cached {
        ensure!(
            receipt.operation == operation
                && receipt.file == wave.file
                && receipt.wave == wave.wave
                && receipt.hashes == wave.hashes,
            "native wave replay changed original scope"
        );
        for pack in &receipt.packs {
            let remote = noland_state_core::pack_key(&pack.pack_id);
            if !db
                .sync_journal_completed(operation, &remote)
                .map_err(source_error)?
            {
                verify_pack(path, pack, true)?;
            }
        }
        return Ok(receipt);
    }
    let leaf = format!("packs-{:08x}-{:08x}", wave.file, wave.wave);
    directory.create_dir(&leaf)?;
    let pack_path = path.join(&leaf);
    let packs = noland_pack::pack_chunk_files(&pack_path, master, wave.sources, |hash| {
        !admitted.contains(hash)
    })
    .map_err(source_error)?;
    // PackWriter already hashed exactly the emitted ciphertext while writing.
    // Check native confinement/privacy/size now; do not immediately reread an
    // entire freshly built pack merely to compute the same checksum again.
    for pack in &packs {
        verify_pack(path, pack, false)?;
    }
    let receipt = WaveReceipt {
        operation,
        file: wave.file,
        wave: wave.wave,
        hashes: wave.hashes,
        packs,
    };
    write_document(
        directory,
        &wave_name(wave.file, wave.wave),
        master,
        operation,
        &receipt,
    )?;
    let item = format!("native-wave:{}:{}", wave.file, wave.wave);
    db.start_sync_journal_item(
        operation,
        &item,
        noland_state_core::ContentObjectKind::Other,
        noland_state_core::SyncDirection::Upload,
        None,
        None,
        Some(0),
    )
    .map_err(source_error)?;
    db.complete_sync_journal_item(operation, &item, 0)
        .map_err(source_error)?;
    // Prepared ciphertext/index receipt is durable before plaintext staging may
    // be released. This removes only a No Land operation-owned lease, never user
    // source files or history; upload errors retain ciphertext for exact retry.
    if let Some(lease) = wave.lease {
        let lease_path = lease.root().to_owned();
        drop(lease);
        // Use the actual lease's verified CAS ancestor, never a guessed target.
        let actual_cas = lease_path
            .parent()
            .and_then(Path::parent)
            .context("native CAS lease ancestry missing")?;
        LocalCas::new(actual_cas)
            .map_err(source_error)?
            .release_lease(&lease_path)
            .map_err(source_error)?;
    }
    Ok(receipt)
}

fn verify_pack(operation_path: &Path, pack: &BuiltPack, checksum: bool) -> Result<()> {
    ensure!(
        pack.path.starts_with(operation_path)
            && pack.path.extension().and_then(|s| s.to_str()) == Some("pack"),
        "prepared native pack is outside its operation"
    );
    let relative = pack
        .path
        .strip_prefix(operation_path)?
        .to_str()
        .context("native pack path is not Unicode")?
        .replace('\\', "/");
    validate_relative(&relative)?;
    let root = SafeRoot::open(operation_path)?;
    let (mut file, stamp) = root.read_file(&relative)?;
    verify_private_file(&file)?;
    ensure!(
        stamp.size == pack.bytes && pack.bytes <= noland_state_core::constants::PACK_MAX,
        "prepared native pack size changed"
    );
    if checksum {
        let mut digest = blake3::Hasher::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        ensure!(
            pack.checksum == format!("blake3:{}", digest.finalize().to_hex()),
            "prepared native pack checksum changed"
        );
    }
    root.verify_file(&relative, &stamp)
}

fn validate_prepared(prepared: &Prepared, plan: &FrozenPlan) -> Result<()> {
    ensure!(
        prepared.operation == plan.operation && prepared.index.len() <= MAX_CHUNKS,
        "prepared native operation/index binding changed"
    );
    validate_captured_manifest(&prepared.manifest, plan)
}

/// Immutable local/remote manifest validation only; never opens a live source.
pub(super) fn validate_captured_manifest(
    manifest: &BundleManifest,
    plan: &FrozenPlan,
) -> Result<()> {
    let Work::Upload {
        app,
        roots,
        files,
        bundle,
        commit,
        metadata,
        capture_scope,
        source_identity,
        complete_approved_scope,
        software_instance_id,
        coverage,
        full_snapshot,
        ..
    } = &plan.work
    else {
        bail!("prepared native plan kind mismatch")
    };
    ensure!(
        manifest.app.app_id == *app
            && manifest.bundle_id == *bundle
            && manifest.commit_id == *commit
            && manifest.files.len() == files.len().saturating_add(metadata.len())
            && manifest.mode
                == if *complete_approved_scope {
                    BackupMode::CompleteApplication
                } else {
                    BackupMode::Custom
                }
            && manifest.tombstones.len()
                == full_snapshot.as_ref().map_or(0, |full| full.deleted.len())
            && manifest.source.instance_id == plan.instance
            && manifest.source.captured_at == plan.created_at
            && manifest.environment["software_instance_id"] == *software_instance_id
            && manifest.environment["quicksave_native"]["coverage"]
                == serde_json::to_value(coverage)?
            && serde_json::to_value(&manifest.app)?
                == serde_json::to_value(ManifestApp::from(source_identity))?
            && manifest.consistency == ConsistencyKind::BestEffort
            && manifest.environment["capture_consistency"]
                == "validated_stable_files_not_application_atomic",
        "prepared native manifest identity/count changed"
    );
    noland_state_core::native_layout::native_root_layouts(manifest).map_err(source_error)?;
    if let Some(full) = full_snapshot {
        ensure!(
            manifest.environment["quicksave_native"]["full_scope"]["evidenceHash"]
                == full_scope::metadata_digest(&full.evidence)?,
            "prepared native full-scope proof changed"
        );
    }
    let actual = manifest
        .files
        .iter()
        .map(|file| (file_id(&file.logical_root, &file.relative_path), file))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        actual.len() == files.len().saturating_add(metadata.len()),
        "prepared native manifest duplicates files"
    );
    let selected = manifest
        .files
        .iter()
        .map(|file| file.logical_root.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        manifest.environment["quicksave_native_root_layouts"]
            == frozen_root_layouts_value(
                app,
                software_instance_id,
                roots,
                if full_snapshot.is_some() {
                    None
                } else {
                    Some(&selected)
                }
            )?,
        "immutable native root layout differs from the exact original kind/leaf/role scope"
    );
    for file in &manifest.files {
        let root = roots
            .iter()
            .find(|root| root.logical == file.logical_root)
            .context("captured native file has no original approved root")?;
        let (persistence, semantic) = root.role.classification();
        ensure!(file.persistence_class == persistence && file.semantic_role == semantic
            && file.mode.is_none() && file.uid.is_none() && file.gid.is_none(),
            "immutable native classification/ownership differs from original Windows source context");
    }
    for expected in files {
        let file = actual
            .get(&expected.id)
            .context("prepared manifest omitted exact selected file")?;
        let expected_mtime = Some(mtime_ns_from_stamp(&expected.stamp)?);
        ensure!(
            (capture_scope.is_some() || file.file_hash == expected.hash)
                && file.size == expected.size
                && file.file_type == "file"
                && file.mtime_ns == expected_mtime
                && file.mode.is_none()
                && file.symlink_target.is_none()
                && file.uid.is_none()
                && file.gid.is_none(),
            "prepared native payload differs from canonical expected evidence"
        );
        ensure!(
            file.file_hash == canonical_hash(&file.file_hash)?,
            "prepared native payload has a noncanonical BLAKE3 hash"
        );
    }
    for expected in metadata {
        let file = actual
            .get(&file_id(&expected.root, &expected.relative))
            .context("prepared manifest omitted frozen native metadata")?;
        ensure!(
            file.file_type
                == if expected.directory {
                    "directory"
                } else {
                    "symlink"
                }
                && file.symlink_target == expected.link.as_ref().map(|link| link.target.clone())
                && file.uid.is_none()
                && file.gid.is_none(),
            "prepared native metadata changed"
        );
    }
    Ok(())
}

fn materialize_metadata(
    roots: &[RootSpec],
    metadata: &[FrozenMetadata],
) -> Result<Vec<ManifestFile>> {
    let mut files = Vec::with_capacity(metadata.len());
    for entry in metadata {
        let root = roots
            .iter()
            .find(|root| root.logical == entry.root)
            .context("frozen native metadata root disappeared")?;
        let handle = SafeRoot::open(&root.path)?;
        ensure!(
            handle.identity()? == root.identity,
            "native metadata root changed"
        );
        if let Some(link) = &entry.link {
            handle.verify_link(&entry.relative, link)?;
        } else {
            let actual = noland_snapshot::SourcePath::new(&root.path.join(&entry.relative))
                .and_then(|path| path.open_directory())
                .map_err(source_error)?;
            ensure!(
                capture::stamp(&actual)? == entry.stamp,
                "native captured directory identity/metadata changed"
            );
        }
        let (persistence_class, semantic_role) = root.role.classification();
        let target = entry.link.as_ref().map(|link| link.target.clone());
        files.push(ManifestFile {
            logical_root: entry.root.clone(),
            relative_path: entry.relative.clone(),
            source_path_hint: None,
            file_type: if entry.directory {
                "directory"
            } else {
                "symlink"
            }
            .into(),
            size: 0,
            file_hash: noland_cas::blake3_hex(target.as_deref().unwrap_or("").as_bytes()),
            chunks: Vec::new(),
            mode: None,
            mtime_ns: Some(mtime_ns_from_stamp(&entry.stamp)?),
            uid: None,
            gid: None,
            symlink_target: target,
            persistence_class,
            semantic_role,
            association_confidence: 1.0,
            shared_app_ids: Vec::new(),
        });
    }
    Ok(files)
}

pub(super) async fn download(
    inner: &Arc<Inner>,
    job: &Job,
    provider: &CheckedProvider,
) -> Result<()> {
    use noland_restore::{DownloadJournal, PipelineOptions, RestorePlan};
    use noland_state_core::RestoreMode;
    let Work::Download {
        app,
        bundle,
        commit,
        manifest_hash,
        files,
        destination,
        identity,
        ..
    } = &job.plan.work
    else {
        bail!("native restore plan kind mismatch");
    };
    let root = SafeRoot::open(destination)?;
    ensure!(
        &root.identity()? == identity,
        "native restore destination identity changed"
    );
    let mut manifest = read_committed_manifest(provider, &job.access.master, app, *bundle)
        .await
        .map_err(source_error)?;
    ensure!(
        manifest.commit_id == *commit
            && noland_storage::compact_json_hash(&manifest).map_err(source_error)?
                == *manifest_hash,
        "authenticated restore payload changed from original frozen revision"
    );
    restore::select_payload(&mut manifest, files.as_ref())?;
    let control = job.restore.as_ref().context(
        "native restore lost its original frozen control; preview again, never downgrade",
    )?;
    restore::check_frozen_control(&job.plan, control)?;
    let mappings = control.logical_roots().map_err(source_error)?;
    control
        .validate_payload(&manifest, RestoreMode::CompleteApplication)
        .map_err(source_error)?;
    let index = noland_storage::read_pack_index(provider, &job.access.master, app, *bundle)
        .await
        .map_err(source_error)?;
    ensure!(
        index.len() <= MAX_CHUNKS,
        "native restore pack-index bound exceeded"
    );
    restore::install_recorders(inner, job.plan.operation, control)?;
    if let Some(lifecycle) = &job.access.lifecycle {
        let lifecycle = Arc::clone(lifecycle);
        control
            .set_credential_checkpoint(Arc::new(move || {
                lifecycle.checkpoint().map_err(|_| {
                    StateError::Conflict(
                        "native credential checkpoint failed before restore publication".into(),
                    )
                })
            }))
            .map_err(source_error)?;
    }
    let reports = restore::recover_recorded(inner, job.plan.operation, control)?;
    if let Some(report) = reports.last() {
        ensure!(
            report.retained_artifacts.is_empty()
                && report.owned_artifacts_clean
                && report.metadata_only_workspace,
            "native restore recovery retained artifacts; explicit native inspection is required"
        );
        if report.committed {
            return Ok(());
        }
        ensure!(
            report.rolled_back,
            "native restore recovery did not confirm rollback"
        );
    }
    control
        .validate_fresh(&manifest, RestoreMode::CompleteApplication, &mappings)
        .map_err(source_error)?;
    let (attempt, workspace) = restore::new_workspace(inner, job.plan.operation)?;
    let restore = RestorePlan {
        restore_id: attempt,
        staging: workspace,
        pack_cache: inner.paths.cache.join("restore-packs"),
        manifest,
        mode: RestoreMode::CompleteApplication,
    }
    .into_shared()
    .with_native_control(Arc::clone(control));
    let options = PipelineOptions::for_transfer_tuning(
        WorkerResources::detect(),
        TransferWorkload::Throughput,
        &provider.transfer_tuning(),
    );
    noland_restore::restore_pipelined(
        provider,
        &job.access.master,
        &restore,
        &index,
        &mappings,
        Some(&inner.db),
        Some(DownloadJournal {
            db: &inner.db,
            operation_id: job.plan.operation,
        }),
        options,
        |progress| {
            (provider.check)()?;
            inner
                .progress(
                    job.plan.operation,
                    &progress.phase,
                    progress.verified_bytes,
                    Some(progress.total_bytes),
                    "bytes",
                )
                .map_err(native_capture_error)
        },
    )
    .await
    .map_err(source_error)?;
    let completion = restore.verify_native_completion().map_err(source_error)?;
    ensure!(
        completion.is_clean_committed(),
        "native restore completion is not authenticated/clean; retain original recovery artifacts"
    );
    ensure!(
        &root.identity()? == identity,
        "native destination changed after verified restore"
    );
    (provider.check)().map_err(source_error)
}

pub(super) struct DeletionProgressSink<'a> {
    pub inner: &'a Arc<Inner>,
    pub job: &'a Job,
}
impl noland_storage::DeletionObserver for DeletionProgressSink<'_> {
    fn progress(
        &self,
        progress: &noland_storage::DeletionProgress,
    ) -> noland_state_core::Result<()> {
        if self.job.stop.load(Ordering::Acquire) {
            return Err(StateError::Conflict("native deletion cancelled".into()));
        }
        self.inner
            .progress(
                self.job.plan.operation,
                &progress.phase,
                progress.verified_absent_bytes,
                Some(progress.total_bytes),
                "bytes",
            )
            .map_err(native_capture_error)
    }
}

pub(super) fn operation_directory(inner: &Inner, operation: Uuid, kind: &str) -> Result<PathBuf> {
    if kind == "restore" {
        let root = SafeRoot::open(&inner.paths.restore)?;
        let name = operation.to_string();
        root.create_dir(&name)?;
        let path = inner.paths.restore.join(name);
        ensure_private_directory(&path)?;
        return Ok(path);
    }
    let root = SafeRoot::open(&inner.paths.packs)?;
    let name = format!("native-{kind}-{operation}");
    root.create_dir(&name)?;
    let path = inner.paths.packs.join(name);
    ensure_private_directory(&path)?;
    Ok(path)
}

fn wave_name(file: usize, wave: usize) -> String {
    format!("wave-{file:08x}-{wave:08x}.enc")
}
fn file_batch_name(batch: usize) -> String {
    format!("files-{batch:08x}.enc")
}

fn prepared_wave_index(
    inner: &Inner,
    directory: &ReceiptDirectory,
    master: &MasterKey,
    operation: Uuid,
) -> Result<Vec<PackIndexEntry>> {
    let records = inner
        .db
        .list_sync_journal_entries(operation, None)
        .map_err(source_error)?;
    ensure!(
        records.len() <= MAX_WAVES * 4,
        "native operation receipt journal bound exceeded"
    );
    let mut index = Vec::new();
    for record in records {
        let Some(rest) = record.item_key.strip_prefix("native-wave:") else {
            continue;
        };
        let (file, wave) = rest
            .split_once(':')
            .context("invalid native wave journal key")?;
        let file = file.parse::<usize>()?;
        let wave = wave.parse::<usize>()?;
        ensure!(
            file < MAX_FILES && wave <= MAX_WAVES,
            "native wave journal identity bound exceeded"
        );
        let receipt: WaveReceipt =
            read_document(directory, &wave_name(file, wave), master, operation)?
                .context("native prepared-wave journal lost its authenticated receipt")?;
        ensure!(
            receipt.operation == operation && receipt.file == file && receipt.wave == wave,
            "native prepared-wave journal/receipt binding mismatch"
        );
        for pack in receipt.packs {
            ensure!(
                index.len().saturating_add(pack.entries.len()) <= MAX_CHUNKS,
                "native resumed pack-index bound exceeded"
            );
            index.extend(pack.entries);
        }
    }
    Ok(index)
}

fn checkpoint_files(
    directory: &ReceiptDirectory,
    master: &MasterKey,
    operation: Uuid,
    file: usize,
    files: &[Option<FileReceipt>],
    ready_waves: &[usize],
    ready: &mut BTreeSet<usize>,
) -> Result<()> {
    let batch = file / FILE_RECEIPT_BATCH;
    if ready.contains(&batch) {
        return Ok(());
    }
    let start = batch * FILE_RECEIPT_BATCH;
    let end = (start + FILE_RECEIPT_BATCH).min(files.len());
    if !(start..end).all(|index| {
        files[index]
            .as_ref()
            .is_some_and(|receipt| ready_waves[index] == receipt.waves)
    }) {
        return Ok(());
    }
    let name = file_batch_name(batch);
    if read_document::<FileBatch>(directory, &name, master, operation)?.is_none() {
        let batch = FileBatch {
            operation,
            batch,
            files: files[start..end]
                .iter()
                .map(|file| file.as_ref().unwrap().clone())
                .collect(),
        };
        write_document(directory, &name, master, operation, &batch)?;
    }
    ready.insert(batch);
    Ok(())
}

fn previous_files(
    inner: &Inner,
    job: &Job,
    app: &AppId,
) -> Result<BTreeMap<String, (FileStamp, ManifestFile)>> {
    // A small metadata projection finds the last local committed revision; no
    // source-tree enumeration or content hashing is performed for this lookup.
    for operation in inner
        .db
        .recent_matching_operations(Some(app), 16)
        .map_err(source_error)?
    {
        if operation.kind != "backup" || operation.state != "COMPLETED" {
            continue;
        }
        let prior = match inner.read_plan(operation.operation_id, &job.access.master) {
            Ok(prior)
                if prior.provider == job.plan.provider && prior.storage == job.plan.storage =>
            {
                prior
            }
            _ => continue, // Optional authenticated cache hint, not remote authority.
        };
        let Work::Upload {
            files,
            software_instance_id: prior_instance,
            roots: prior_roots,
            reuse_epoch: prior_epoch,
            ..
        } = &prior.work
        else {
            continue;
        };
        let Work::Upload {
            software_instance_id: current_instance,
            roots: current_roots,
            capture_scope,
            reuse_epoch: current_epoch,
            ..
        } = &job.plan.work
        else {
            continue;
        };
        if prior_instance != current_instance || prior_roots != current_roots {
            continue;
        }
        if capture_scope.is_some() && (current_epoch.is_none() || current_epoch != prior_epoch) {
            continue; // Restart/overflow/uncertainty never qualifies a stamp-only reuse.
        }
        let path = inner
            .paths
            .packs
            .join(format!("native-upload-{}", operation.operation_id));
        let directory = match ReceiptDirectory::open(inner, &path) {
            Ok(directory) => directory,
            Err(_) => continue,
        };
        let Some(prepared) = read_document::<Prepared>(
            &directory,
            "prepared.enc",
            &job.access.master,
            operation.operation_id,
        )?
        else {
            continue;
        };
        validate_prepared(&prepared, &prior)?;
        let stamps = files
            .iter()
            .map(|file| (file.id.clone(), file.stamp.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut previous = BTreeMap::new();
        for file in prepared.manifest.files {
            let id = file_id(&file.logical_root, &file.relative_path);
            if let Some(stamp) = stamps.get(&id) {
                previous.insert(id, (stamp.clone(), file));
            }
        }
        return Ok(previous);
    }
    Ok(BTreeMap::new())
}

async fn verify_referenced_packs(
    provider: &dyn SharedStorageProvider,
    index: &[PackIndexEntry],
) -> Result<()> {
    let mut bounds = BTreeMap::<String, u64>::new();
    for entry in index {
        let end = entry
            .offset
            .checked_add(36)
            .and_then(|n| n.checked_add(u64::from(entry.ciphertext_len)))
            .context("native referenced pack bound overflow")?;
        bounds
            .entry(entry.pack_id.clone())
            .and_modify(|bound| *bound = (*bound).max(end))
            .or_insert(end);
    }
    let width = provider
        .transfer_tuning()
        .max_parallel_downloads
        .clamp(1, 8);
    let mut window = RollingUploadWindow::new(width, width as u64);
    let mut pending = bounds.into_iter();
    let mut exhausted = false;
    let mut failure = None;
    loop {
        while failure.is_none() && !exhausted && window.can_push(1) {
            match pending.next() {
                None => exhausted = true,
                Some((pack, minimum)) => window
                    .push(1, async move {
                        let key =
                            noland_storage::RemoteKey::new(noland_state_core::pack_key(&pack));
                        let meta = provider.stat(&key).await?.ok_or_else(|| {
                            StateError::Integrity("referenced immutable pack is missing".into())
                        })?;
                        if meta.key != key
                            || meta.size < minimum
                            || meta.size > noland_state_core::constants::PACK_MAX
                        {
                            return Err(StateError::Integrity(
                                "referenced immutable pack size changed".into(),
                            ));
                        }
                        Ok(())
                    })
                    .map_err(source_error)?,
            }
        }
        match window.next().await {
            None => break,
            Some(Err(error)) if failure.is_none() => failure = Some(source_error(error)),
            _ => {}
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn read_document<T: DeserializeOwned>(
    directory: &ReceiptDirectory,
    name: &str,
    master: &MasterKey,
    operation: Uuid,
) -> Result<Option<T>> {
    let (file, stamp) = match directory.read_file(name) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    verify_private_file(&file)?;
    ensure!(
        stamp.size <= noland_storage::MAX_METADATA_BYTES + 1024 * 1024,
        "native retry receipt exceeds metadata bound"
    );
    let mut bytes = Vec::new();
    file.take(noland_storage::MAX_METADATA_BYTES + 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    directory.verify_file(name, &stamp)?;
    let aad = format!("quicksave-windows-prepared-v1:{operation}:{name}");
    ensure!(
        bytes.len() >= 40 && &bytes[..8] == RECEIPT_MAGIC,
        "native prepared receipt lacks its device-authenticated frame"
    );
    let expected = directory.mac(aad.as_bytes(), &bytes[40..])?;
    ensure!(
        bytes[8..40]
            .iter()
            .zip(expected)
            .fold(0u8, |d, (a, b)| d | (*a ^ b))
            == 0,
        "native prepared receipt device-HMAC authentication failed"
    );
    bytes.drain(..40);
    Ok(Some(
        noland_storage::open_metadata(&derive_keys(master).manifest, aad.as_bytes(), bytes)
            .map_err(source_error)?,
    ))
}

pub(super) fn write_document<T: Serialize>(
    directory: &ReceiptDirectory,
    name: &str,
    master: &MasterKey,
    operation: Uuid,
    document: &T,
) -> Result<()> {
    let aad = format!("quicksave-windows-prepared-v1:{operation}:{name}");
    let bytes =
        noland_storage::seal_metadata(&derive_keys(master).manifest, aad.as_bytes(), document)
            .map_err(source_error)?
            .envelope;
    let mac = directory.mac(aad.as_bytes(), &bytes)?;
    directory.write_new(name, |file| {
        file.write_all(RECEIPT_MAGIC)?;
        file.write_all(&mac)?;
        file.write_all(&bytes)?;
        Ok(())
    })
}

fn native_capture_error(_: anyhow::Error) -> StateError {
    StateError::Integrity(
        "native capture/publication verification failed; private details withheld".into(),
    )
}
