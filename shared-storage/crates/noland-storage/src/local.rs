use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use noland_state_core::{Result, StateError};

use crate::{
    transfer::local_storage_identity, DownloadObserver, DownloadStreamConsumer, Health,
    ProviderRootIdentity, RemoteEntry, RemoteKey, RemoteMeta, SharedStorageProvider,
};

/// Filesystem-backed provider used by tests and as the local cache layout.
pub struct LocalStorage {
    pub root: PathBuf,
}

impl LocalStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn abs(&self, key: &RemoteKey) -> PathBuf {
        self.root.join(key.as_str())
    }
}

struct UploadTemp(PathBuf);
impl Drop for UploadTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn identical_files(left: &Path, right: &Path) -> Result<bool> {
    use std::io::Read;
    if std::fs::metadata(left)?.len() != std::fs::metadata(right)?.len() {
        return Ok(false);
    }
    #[cfg(windows)]
    let mut left = noland_snapshot::SourcePath::new(left)?.open_regular()?;
    #[cfg(windows)]
    let mut right = noland_snapshot::SourcePath::new(right)?.open_regular()?;
    #[cfg(not(windows))]
    let mut left = std::fs::File::open(left)?;
    #[cfg(not(windows))]
    let mut right = std::fs::File::open(right)?;
    let mut a = [0u8; 64 * 1024];
    let mut b = [0u8; 64 * 1024];
    loop {
        let count = left.read(&mut a)?;
        if count == 0 {
            return Ok(right.read(&mut b[..1])? == 0);
        }
        right.read_exact(&mut b[..count])?;
        if a[..count] != b[..count] {
            return Ok(false);
        }
    }
}

#[async_trait]
impl SharedStorageProvider for LocalStorage {
    async fn remove_empty_bundle(
        &self,
        app: &noland_state_core::AppId,
        bundle: uuid::Uuid,
    ) -> Result<()> {
        let path = self.abs(&RemoteKey::new(noland_state_core::bundle_dir(app, bundle)));
        match noland_snapshot::SourcePath::new(&path)
            .and_then(|source| source.remove_empty_directory())
        {
            Ok(()) => Ok(()),
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
    async fn delete_object(&self, key: &RemoteKey) -> Result<()> {
        crate::deletion::validate_deletable_key(key)?;
        let source = match noland_snapshot::SourcePath::new(&self.abs(key)) {
            Ok(source) => source,
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let metadata = match source.metadata() {
            Ok(metadata) => metadata,
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        source.delete_leaf(&metadata)
    }

    fn supports_targeted_uploads(&self) -> bool {
        true
    }
    async fn health_check(&self) -> Result<Health> {
        Ok(Health {
            ok: true,
            provider: "local".into(),
            detail: self.root.display().to_string(),
        })
    }

    async fn ensure_root(&self) -> Result<()> {
        #[cfg(windows)]
        crate::native_fs::ensure_private_directory(&self.root)?;
        #[cfg(not(windows))]
        std::fs::create_dir_all(&self.root)?;
        for child in [
            "catalog",
            "commits",
            "bundles",
            "objects",
            "packs",
            "checkpoints",
            "instances",
        ] {
            #[cfg(windows)]
            crate::native_fs::ensure_private_directory(&self.root.join(child))?;
            #[cfg(not(windows))]
            std::fs::create_dir_all(self.root.join(child))?;
        }
        Ok(())
    }

    async fn stat(&self, key: &RemoteKey) -> Result<Option<RemoteMeta>> {
        let path = self.abs(key);
        #[cfg(windows)]
        {
            crate::transfer::validate_remote_key(key)?;
            return match noland_snapshot::SourcePath::new(&path)
                .and_then(|source| source.metadata())
            {
                Ok(metadata) if !metadata.is_symlink() => Ok(Some(RemoteMeta {
                    key: key.clone(),
                    size: metadata.len(),
                })),
                Ok(_) => Err(StateError::UnsafePath(
                    "reparse link in local storage inventory".into(),
                )),
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(None)
                }
                Err(error) => Err(error),
            };
        }
        #[cfg(not(windows))]
        {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() {
                return Err(StateError::UnsafePath(
                    "symlink in storage inventory".into(),
                ));
            }
            Ok(Some(RemoteMeta {
                key: key.clone(),
                size: metadata.len(),
            }))
        }
    }

    async fn upload_immutable(&self, local: &Path, key: &RemoteKey) -> Result<RemoteMeta> {
        crate::transfer::validate_remote_key(key)?;
        let dest = self.abs(key);
        #[cfg(windows)]
        {
            let parent = dest.parent().ok_or_else(|| {
                StateError::UnsafePath("local immutable key has no parent".into())
            })?;
            crate::native_fs::ensure_private_directory(parent)?;
            let temporary =
                UploadTemp(dest.with_extension(format!("upload-{}", uuid::Uuid::new_v4())));
            let source = noland_snapshot::SourcePath::new(&temporary.0)?;
            let target = noland_snapshot::SourcePath::new(&dest)?;
            let mut input = noland_snapshot::SourcePath::new(local)?.open_regular()?;
            let before = crate::native_fs::FileState::read(&input)?;
            {
                let mut output = source.open_partial_private(true)?;
                std::io::copy(&mut input, &mut output)?;
                output.sync_all()?;
            }
            if !before.same_file(&input)? {
                return Err(StateError::Conflict(
                    "immutable local source changed during upload".into(),
                ));
            }
            match target.metadata() {
                Ok(_) => {
                    if !identical_files(local, &dest)? {
                        return Err(StateError::Conflict(
                            "immutable local object differs".into(),
                        ));
                    }
                }
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    source.publish_new_to(&target)?
                }
                Err(error) => return Err(error),
            }
            return Ok(RemoteMeta {
                key: key.clone(),
                size: before.len(),
            });
        }
        #[cfg(not(windows))]
        {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temporary =
                UploadTemp(dest.with_extension(format!("upload-{}", uuid::Uuid::new_v4())));
            std::fs::copy(local, &temporary.0)?;
            std::fs::File::open(&temporary.0)?.sync_all()?;
            match std::fs::hard_link(&temporary.0, &dest) {
                Ok(()) => {
                    if let Some(parent) = dest.parent() {
                        std::fs::File::open(parent)?.sync_all()?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !identical_files(local, &dest)? {
                        return Err(StateError::Conflict(format!(
                            "immutable remote object differs: {}",
                            key.as_str()
                        )));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            Ok(RemoteMeta {
                key: key.clone(),
                size: std::fs::metadata(dest)?.len(),
            })
        }
    }

    async fn download(&self, key: &RemoteKey, dest: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            crate::transfer::validate_remote_key(key)?;
            let parent = dest
                .parent()
                .ok_or_else(|| StateError::UnsafePath("local download has no parent".into()))?;
            crate::native_fs::ensure_private_directory(parent)?;
            let mut input = noland_snapshot::SourcePath::new(&self.abs(key))?.open_regular()?;
            let before = crate::native_fs::FileState::read(&input)?;
            let mut output = noland_snapshot::SourcePath::new(dest)?.open_partial_private(true)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            if !before.same_file(&input)? {
                return Err(StateError::Conflict("local download source changed".into()));
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(self.abs(key), dest)?;
            Ok(())
        }
    }

    async fn read_small(&self, key: &RemoteKey, limit: u64) -> Result<Vec<u8>> {
        let bound = crate::fetch::validate_small_read(key, limit)?;
        #[cfg(not(windows))]
        let opened = self
            .root
            .canonicalize()
            .map_err(StateError::from)
            .and_then(|root| crate::fetch::open_metadata_file(&root.join(key.as_str())));
        #[cfg(windows)]
        let opened = crate::fetch::open_metadata_file(&self.abs(key));
        let file = match opened {
            Ok(file) => file,
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(crate::fetch::absent());
            }
            Err(error) => return Err(error),
        };
        crate::fetch::read_file_bounded(file, bound)
    }

    fn supports_streaming_downloads(&self) -> bool {
        true
    }

    async fn download_stream_observed(
        &self,
        key: &RemoteKey,
        _scratch: &Path,
        consumer: &dyn DownloadStreamConsumer,
        observer: Option<&(dyn DownloadObserver + '_)>,
    ) -> Result<()> {
        use std::io::Read;
        consumer.restart().await?;
        if let Some(observer) = observer {
            observer.transfer_started()?;
        }
        #[cfg(windows)]
        let mut source = noland_snapshot::SourcePath::new(&self.abs(key))?.open_regular()?;
        #[cfg(not(windows))]
        let mut source = std::fs::File::open(self.abs(key))?;
        let mut buffer = vec![0; 256 * 1024];
        let mut bytes = 0;
        let mut last = std::time::Instant::now();
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            consumer.write(&buffer[..count]).await?;
            bytes += count as u64;
            if last.elapsed() >= std::time::Duration::from_millis(500) {
                if let Some(observer) = observer {
                    observer.transfer_progress(bytes)?;
                }
                last = std::time::Instant::now();
            }
        }
        if let Some(observer) = observer {
            observer.transfer_progress(bytes)?;
        }
        consumer.finish().await
    }

    async fn list_prefix(&self, prefix: &RemoteKey) -> Result<Vec<RemoteEntry>> {
        let dir = self.abs(prefix);
        let mut out = Vec::new();
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(StateError::UnsafePath(
                    "storage inventory prefix is not a directory".into(),
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(error.into()),
        }
        fn walk(
            base: &Path,
            dir: &Path,
            out: &mut Vec<RemoteEntry>,
            depth: usize,
            path_bytes: &mut usize,
        ) -> Result<()> {
            if depth >= 128 {
                return Err(StateError::Invalid(
                    "local storage inventory exceeds its depth bound".into(),
                ));
            }
            #[cfg(windows)]
            let pinned = noland_snapshot::SourcePath::new(dir)?.open_directory()?;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                *path_bytes = path_bytes.checked_add(rel.len()).ok_or_else(|| {
                    StateError::Invalid("local inventory path budget overflow".into())
                })?;
                if out.len() >= 1_000_000 || *path_bytes > 128 * 1024 * 1024 {
                    return Err(StateError::Invalid(
                        "local storage inventory exceeds its entry/path bound".into(),
                    ));
                }
                #[cfg(not(windows))]
                let kind = entry.file_type()?;
                #[cfg(windows)]
                let kind =
                    noland_snapshot::SourcePath::child(&pinned, entry.file_name())?.metadata()?;
                if kind.is_symlink() {
                    return Err(StateError::UnsafePath(
                        "symlink in storage inventory".into(),
                    ));
                }
                if kind.is_dir() {
                    out.push(RemoteEntry {
                        key: RemoteKey(rel),
                        size: 0,
                        is_prefix: true,
                    });
                    walk(base, &path, out, depth + 1, path_bytes)?;
                } else {
                    out.push(RemoteEntry {
                        key: RemoteKey(rel),
                        size: entry.metadata()?.len(),
                        is_prefix: false,
                    });
                }
            }
            Ok(())
        }
        let mut path_bytes = 0;
        walk(&self.root, &dir, &mut out, 0, &mut path_bytes)?;
        Ok(out)
    }

    async fn put_small_versioned(&self, bytes: Bytes, key: &RemoteKey) -> Result<RemoteMeta> {
        use std::io::Write;
        crate::transfer::validate_remote_key(key)?;
        let dest = self.abs(key);
        #[cfg(windows)]
        {
            let parent = dest.parent().ok_or_else(|| {
                StateError::UnsafePath("versioned local key has no parent".into())
            })?;
            crate::native_fs::ensure_private_directory(parent)?;
            let temporary =
                UploadTemp(dest.with_extension(format!("write-{}", uuid::Uuid::new_v4())));
            let source = noland_snapshot::SourcePath::new(&temporary.0)?;
            let target = noland_snapshot::SourcePath::new(&dest)?;
            {
                let mut output = source.open_partial_private(true)?;
                output.write_all(&bytes)?;
                output.sync_all()?;
            }
            match target.metadata() {
                Ok(_) => {
                    let directory = crate::native_fs::directory_handle(parent)?;
                    crate::native_windows::replace_private_file(
                        &directory,
                        temporary
                            .0
                            .file_name()
                            .and_then(|name| name.to_str())
                            .ok_or_else(|| {
                                StateError::UnsafePath("local temporary leaf is invalid".into())
                            })?,
                        dest.file_name()
                            .and_then(|name| name.to_str())
                            .ok_or_else(|| {
                                StateError::UnsafePath("local target leaf is invalid".into())
                            })?,
                    )?;
                }
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    source.publish_new_to(&target)?
                }
                Err(error) => return Err(error),
            }
            return Ok(RemoteMeta {
                key: key.clone(),
                size: bytes.len() as u64,
            });
        }
        #[cfg(not(windows))]
        {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temporary =
                UploadTemp(dest.with_extension(format!("write-{}", uuid::Uuid::new_v4())));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary.0)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary.0, &dest)?;
            if let Some(parent) = dest.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(RemoteMeta {
                key: key.clone(),
                size: bytes.len() as u64,
            })
        }
    }

    fn storage_identity(&self) -> Option<ProviderRootIdentity> {
        Some(local_storage_identity(&self.root))
    }
}
