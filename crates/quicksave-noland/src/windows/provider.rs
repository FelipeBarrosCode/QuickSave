// SPDX-License-Identifier: GPL-3.0-only
//! Authorization wrapper, not another storage implementation. All actual wire,
//! transfer scheduling, immutable comparison and checksums remain in No Land.
use async_trait::async_trait;
use bytes::Bytes;
use noland_state_core::{AppId, Result, StateError};
use noland_storage::*;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub(super) type Check = Arc<dyn Fn() -> Result<()> + Send + Sync>;

pub(super) struct CheckedProvider {
    pub inner: RcloneStorage,
    pub check: Check,
    pub read_only: bool,
    pub stream_stop: Arc<AtomicBool>,
    pub lifecycle: Option<Arc<crate::provider_lifecycle::NativeProviderLifecycle>>,
    pub publication: Option<Check>,
}

impl CheckedProvider {
    fn read(&self) -> Result<()> {
        (self.check)()
    }
    fn write(&self) -> Result<()> {
        self.read()?;
        if self.read_only {
            return Err(StateError::Conflict(
                "native provider write grant is read-only".into(),
            ));
        }
        Ok(())
    }
    fn metadata_checkpoint(&self, publication: bool) -> Result<()> {
        self.write()?;
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.checkpoint().map_err(|_| {
                StateError::Conflict(
                    "native-vault token rotation is not durably checkpointed before publication"
                        .into(),
                )
            })?;
        }
        if publication {
            if let Some(check) = &self.publication {
                check()?;
            }
        }
        self.write()
    }
}

#[async_trait]
impl SharedStorageProvider for CheckedProvider {
    async fn health_check(&self) -> Result<Health> {
        self.read()?;
        let value = self.inner.health_check().await?;
        self.read()?;
        Ok(value)
    }
    async fn ensure_root(&self) -> Result<()> {
        self.write()?;
        self.inner.ensure_root().await?;
        self.read()
    }
    async fn stat(&self, key: &RemoteKey) -> Result<Option<RemoteMeta>> {
        self.read()?;
        let value = self.inner.stat(key).await?;
        self.read()?;
        Ok(value)
    }
    async fn upload_immutable(&self, path: &Path, key: &RemoteKey) -> Result<RemoteMeta> {
        let upload = ImmutableUpload::new(path, key.clone());
        let mut values = self
            .upload_immutable_bulk_observed(std::slice::from_ref(&upload), None)
            .await?;
        if values.len() != 1 || values[0].key != *key {
            return Err(StateError::Integrity(
                "native immutable upload completion binding changed".into(),
            ));
        }
        Ok(values.remove(0))
    }
    async fn download(&self, key: &RemoteKey, dest: &Path) -> Result<()> {
        self.download_observed(key, dest, None).await
    }
    async fn read_small(&self, key: &RemoteKey, limit: u64) -> Result<Vec<u8>> {
        self.read()?;
        let value = self.inner.read_small(key, limit).await?;
        self.read()?;
        Ok(value)
    }
    async fn list_prefix(&self, prefix: &RemoteKey) -> Result<Vec<RemoteEntry>> {
        self.read()?;
        let value = self.inner.list_prefix(prefix).await?;
        self.read()?;
        Ok(value)
    }
    async fn put_small_versioned(&self, bytes: Bytes, key: &RemoteKey) -> Result<RemoteMeta> {
        self.metadata_checkpoint(publishes_revision(key))?;
        let value = self.inner.put_small_versioned(bytes, key).await?;
        self.read()?;
        Ok(value)
    }
    async fn put_metadata_batch(&self, batch: &MetadataBatch) -> Result<Vec<RemoteMeta>> {
        let visibility = batch
            .entries()
            .iter()
            .any(|entry| publishes_revision(&entry.key));
        if visibility && (batch.entries().len() != 1 || batch.committed().is_some()) {
            return Err(StateError::Invalid(
                "native visibility metadata must remain a separate final batch".into(),
            ));
        }
        self.metadata_checkpoint(visibility)?;
        // Keep the source's staged parallel ordinary phase. Delegating the whole
        // batch would skip a new authorization check between it and COMMITTED.
        let ordinary = MetadataBatch::new(batch.entries().to_vec());
        let mut written = self.inner.put_metadata_batch(&ordinary).await?;
        self.read()?;
        if let Some(committed) = batch.committed() {
            written.push(
                self.put_small_versioned(committed.bytes.clone(), &committed.key)
                    .await?,
            );
        }
        Ok(written)
    }
    async fn check_full_deletion_support(&self) -> Result<()> {
        self.write()?;
        self.inner.check_full_deletion_support().await
    }
    async fn delete_object(&self, key: &RemoteKey) -> Result<()> {
        self.write()?;
        self.inner.delete_object(key).await?;
        self.read()
    }
    async fn delete_prevalidated(&self, object: &PrevalidatedDeletion) -> Result<()> {
        self.write()?;
        self.inner.delete_prevalidated(object).await?;
        self.read()
    }
    async fn stat_for_deletion(&self, key: &RemoteKey) -> Result<Option<RemoteMeta>> {
        self.read()?;
        self.inner.stat_for_deletion(key).await
    }
    async fn remove_empty_bundle(&self, app: &AppId, bundle: uuid::Uuid) -> Result<()> {
        self.write()?;
        self.inner.remove_empty_bundle(app, bundle).await?;
        self.read()
    }
    async fn upload_immutable_bulk(&self, uploads: &[ImmutableUpload]) -> Result<Vec<RemoteMeta>> {
        self.upload_immutable_bulk_observed(uploads, None).await
    }
    async fn upload_immutable_bulk_observed(
        &self,
        uploads: &[ImmutableUpload],
        observer: Option<&(dyn ImmutableUploadObserver + '_)>,
    ) -> Result<Vec<RemoteMeta>> {
        self.write()?;
        let checked = CheckedUploadObserver {
            inner: observer,
            check: &self.check,
            stop: &self.stream_stop,
        };
        let value = self
            .inner
            .upload_immutable_bulk_observed(uploads, Some(&checked))
            .await?;
        self.read()?;
        Ok(value)
    }
    async fn upload_immutable_bulk_known_observed(
        &self,
        uploads: &[ImmutableUpload],
        known: &RemoteKnownSet,
        observer: Option<&(dyn ImmutableUploadObserver + '_)>,
    ) -> Result<Vec<RemoteMeta>> {
        self.write()?;
        let checked = CheckedUploadObserver {
            inner: observer,
            check: &self.check,
            stop: &self.stream_stop,
        };
        let value = self
            .inner
            .upload_immutable_bulk_known_observed(uploads, known, Some(&checked))
            .await?;
        self.read()?;
        Ok(value)
    }
    async fn download_observed(
        &self,
        key: &RemoteKey,
        dest: &Path,
        observer: Option<&(dyn DownloadObserver + '_)>,
    ) -> Result<()> {
        self.read()?;
        let checked = CheckedDownloadObserver {
            inner: observer,
            check: &self.check,
            stop: &self.stream_stop,
        };
        self.inner
            .download_observed(key, dest, Some(&checked))
            .await?;
        self.read()
    }
    async fn download_stream_observed(
        &self,
        key: &RemoteKey,
        scratch: &Path,
        consumer: &dyn DownloadStreamConsumer,
        observer: Option<&(dyn DownloadObserver + '_)>,
    ) -> Result<()> {
        self.read()?;
        let consumer = CheckedConsumer {
            inner: consumer,
            check: &self.check,
            stop: &self.stream_stop,
        };
        let checked = CheckedDownloadObserver {
            inner: observer,
            check: &self.check,
            stop: &self.stream_stop,
        };
        self.inner
            .download_stream_observed(key, scratch, &consumer, Some(&checked))
            .await?;
        self.read()
    }
    fn supports_streaming_downloads(&self) -> bool {
        self.inner.supports_streaming_downloads()
    }
    fn supports_parallel_upload_groups(&self) -> bool {
        self.inner.supports_parallel_upload_groups()
    }
    fn supports_targeted_uploads(&self) -> bool {
        self.inner.supports_targeted_uploads()
    }
    fn transfer_tuning(&self) -> TransferTuning {
        SharedStorageProvider::transfer_tuning(&self.inner)
    }
    fn deletion_concurrency(&self) -> usize {
        self.inner.deletion_concurrency()
    }
    fn provider_kind(&self) -> Option<ProviderKind> {
        SharedStorageProvider::provider_kind(&self.inner)
    }
    fn capabilities(&self) -> Option<&ProviderCapabilities> {
        SharedStorageProvider::capabilities(&self.inner)
    }
    fn storage_identity(&self) -> Option<ProviderRootIdentity> {
        self.inner.storage_identity()
    }
    fn operation_metrics(&self) -> StorageOperationMetrics {
        self.inner.operation_metrics()
    }
    fn metadata_read_metrics(&self) -> MetadataReadMetrics {
        self.inner.metadata_read_metrics()
    }
}

fn publishes_revision(key: &RemoteKey) -> bool {
    key.as_str() == "catalog/LATEST"
        || key.as_str().ends_with("/COMMITTED")
        || (key.as_str().starts_with("catalog/commits/") && key.as_str().ends_with(".COMMITTED"))
}

fn check_cancelled(stop: &AtomicBool) -> Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(StateError::Conflict(
            "native transfer cancelled; new retries are not authorized".into(),
        ));
    }
    Ok(())
}

struct CheckedUploadObserver<'a> {
    inner: Option<&'a (dyn ImmutableUploadObserver + 'a)>,
    check: &'a Check,
    stop: &'a AtomicBool,
}
impl ImmutableUploadObserver for CheckedUploadObserver<'_> {
    fn transfer_started(&self) -> Result<()> {
        (self.check)()?;
        self.inner.map_or(Ok(()), |inner| inner.transfer_started())
    }
    fn transfer_progress(&self, bytes: u64) -> Result<()> {
        check_cancelled(self.stop)?;
        self.inner
            .map_or(Ok(()), |inner| inner.transfer_progress(bytes))
    }
    fn transfer_diagnostics(&self, diagnostics: &UploadTransferDiagnostics) -> Result<()> {
        check_cancelled(self.stop)?;
        self.inner
            .map_or(Ok(()), |inner| inner.transfer_diagnostics(diagnostics))
    }
    fn completed(
        &self,
        uploads: &[ImmutableUpload],
        completion: ImmutableUploadCompletion,
    ) -> Result<()> {
        (self.check)()?;
        self.inner
            .map_or(Ok(()), |inner| inner.completed(uploads, completion))
    }
}

struct CheckedDownloadObserver<'a> {
    inner: Option<&'a (dyn DownloadObserver + 'a)>,
    check: &'a Check,
    stop: &'a AtomicBool,
}
impl DownloadObserver for CheckedDownloadObserver<'_> {
    fn transfer_started(&self) -> Result<()> {
        (self.check)()?;
        self.inner.map_or(Ok(()), |inner| inner.transfer_started())
    }
    fn transfer_retrying(&self, reason: &str) -> Result<()> {
        (self.check)()?;
        self.inner
            .map_or(Ok(()), |inner| inner.transfer_retrying(reason))
    }
    fn transfer_progress(&self, bytes: u64) -> Result<()> {
        check_cancelled(self.stop)?;
        self.inner
            .map_or(Ok(()), |inner| inner.transfer_progress(bytes))
    }
    fn transfer_progress_with_diagnostics(
        &self,
        bytes: u64,
        diagnostics: &StreamTransferDiagnostics,
    ) -> Result<()> {
        check_cancelled(self.stop)?;
        self.inner.map_or(Ok(()), |inner| {
            inner.transfer_progress_with_diagnostics(bytes, diagnostics)
        })
    }
}

struct CheckedConsumer<'a> {
    inner: &'a dyn DownloadStreamConsumer,
    check: &'a Check,
    stop: &'a AtomicBool,
}
#[async_trait]
impl DownloadStreamConsumer for CheckedConsumer<'_> {
    async fn restart(&self) -> Result<()> {
        (self.check)()?;
        self.inner.restart().await
    }
    async fn write(&self, bytes: &[u8]) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            return Err(StateError::Conflict(
                "native streaming restore cancelled".into(),
            ));
        }
        self.inner.write(bytes).await
    }
    async fn finish(&self) -> Result<()> {
        (self.check)()?;
        self.inner.finish().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_receipt_checks_are_publication_barriers_not_poll_or_chunk_callbacks() {
        for key in [
            "bundles/app/revision/COMMITTED",
            "catalog/commits/revision.COMMITTED",
            "catalog/LATEST",
        ] {
            assert!(publishes_revision(&RemoteKey::new(key)));
        }
        for key in [
            "packs/pack.pack",
            "maintenance/admission",
            "instances/activity",
            "bundles/app/revision/manifest.enc",
        ] {
            assert!(!publishes_revision(&RemoteKey::new(key)));
        }
    }

    #[test]
    fn native_transport_retry_and_completion_recheck_authority_without_per_chunk_io() {
        let allowed = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let check: Check = {
            let allowed = Arc::clone(&allowed);
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::Relaxed);
                if allowed.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(StateError::Conflict(
                        "synthetic native authority revoked".into(),
                    ))
                }
            })
        };
        let stop = AtomicBool::new(false);
        let upload = CheckedUploadObserver {
            inner: None,
            check: &check,
            stop: &stop,
        };
        let download = CheckedDownloadObserver {
            inner: None,
            check: &check,
            stop: &stop,
        };
        upload.transfer_started().unwrap();
        download.transfer_started().unwrap();
        for _ in 0..16 {
            upload.transfer_progress(1).unwrap();
            download.transfer_progress(1).unwrap();
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "progress must not query state/vault per chunk"
        );
        allowed.store(false, Ordering::Release);
        assert!(
            upload.transfer_started().is_err(),
            "a new upload attempt cannot reuse revoked access"
        );
        assert!(upload
            .completed(&[], ImmutableUploadCompletion::Uploaded)
            .is_err());
        assert!(download.transfer_retrying("synthetic retry").is_err());
        stop.store(true, Ordering::Release);
        assert!(upload.transfer_progress(1).is_err());
        assert!(download.transfer_progress(1).is_err());
    }
}
