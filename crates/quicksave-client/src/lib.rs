//! Local entry points shared by CLI and desktop. Key bytes never reach the UI.
//! There is no remote transport, cloud deletion, or production Noland state access.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use quicksave_content::RepositoryKey;
use quicksave_platform::{FileStamp, SafeRoot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

pub fn engine_limits() -> Value {
    quicksave_engine::limits()
}

pub fn local_repository_supported() -> bool {
    quicksave_engine::local_repository_supported()
}

/// Make an absolute literal path without following symlinks or accepting `..`.
/// The platform adapter subsequently opens all ancestors without following links.
pub fn literal_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("Choose a nonempty path");
    }
    if path.to_str().is_none() {
        bail!("This preview does not support paths with non-Unicode names");
    }
    if path
        .to_str()
        .expect("validated Unicode")
        .chars()
        .any(char::is_control)
    {
        bail!("Approved paths cannot contain control characters");
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => bail!("Parent traversal is not allowed in approved paths"),
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}

fn is_at_or_below(path: &Path, root: &Path) -> bool {
    // Platform adapters also enforce their native case/volume rules before IO.
    #[cfg(windows)]
    {
        let path = path
            .to_str()
            .expect("validated literal path")
            .to_lowercase();
        let root = root
            .to_str()
            .expect("validated literal path")
            .to_lowercase();
        Path::new(&path).starts_with(Path::new(&root))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
}

fn external_key_path(key: &Path, excluded_roots: &[&Path]) -> Result<PathBuf> {
    let key = literal_path(key)?;
    for root in excluded_roots {
        let root = literal_path(root)?;
        if is_at_or_below(&key, &root) {
            bail!("Recovery key must be outside the repository, source, and restore destination");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Compare actual ancestor identities as well: default macOS volumes
            // may spell the same approved directory with different letter case.
            // This is a deny-only check; SafeRoot still establishes IO authority.
            if let Ok(root_identity) = std::fs::metadata(&root) {
                for ancestor in key.parent().into_iter().flat_map(Path::ancestors) {
                    if let Ok(identity) = std::fs::metadata(ancestor) {
                        if identity.dev() == root_identity.dev()
                            && identity.ino() == root_identity.ino()
                        {
                            bail!("Recovery key is inside an approved data root through an alias");
                        }
                    }
                }
            }
        }
    }
    Ok(key)
}

fn key_parent(path: &Path) -> Result<(SafeRoot, String)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Recovery key needs a valid file name")?
        .to_owned();
    let parent = path
        .parent()
        .context("Recovery key needs a parent folder")?;
    Ok((SafeRoot::open(parent)?, name))
}

fn read_key(path: &Path) -> Result<RepositoryKey> {
    Ok(read_key_with_stamp(path)?.0)
}

fn read_key_with_stamp(path: &Path) -> Result<(RepositoryKey, FileStamp)> {
    let (root, name) = key_parent(path)?;
    let (mut file, stamp) = root
        .read_file(&name)
        .context("Cannot open recovery key without following links")?;
    let metadata = file.metadata()?;
    if metadata.len() != 32 {
        bail!("Recovery key must be an external 32-byte QuickSave key file");
    }
    quicksave_platform::verify_private_file(&file)
        .context("Recovery key privacy/ownership/ACL verification failed")?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *bytes)?;
    root.verify_file(&name, &stamp)?;
    Ok((RepositoryKey::from_bytes(*bytes), stamp))
}

pub fn initialize_repository(repository: &Path, key_file: &Path) -> Result<Value> {
    // Native filesystem durability is not acceptance of the legacy local
    // repository format. Refuse before generating/publishing an external key.
    if !local_repository_supported() {
        bail!("legacy local repository initialization is unsupported on this platform");
    }
    let repository = literal_path(repository)?;
    let key_file = external_key_path(key_file, &[&repository])?;
    let (root, name) = key_parent(&key_file)?;
    if repository.try_exists()? {
        let repository_root = SafeRoot::open(&repository)?;
        if root.same_root(&repository_root)? {
            bail!("Recovery key parent aliases the repository; choose a separate folder");
        }
        if !repository_root.entries()?.is_empty() {
            bail!(
                "Initialize only an empty folder; no recovery key or repository data was written"
            );
        }
    }
    let key = RepositoryKey::generate();
    // Publish and durably flush the external key FIRST. On initialization failure
    // it is deliberately retained; never strand a new repository without its key.
    root.write_new(&name, |file| {
        file.write_all(key.as_bytes())?;
        Ok(())
    })
    .context(
        "Recovery key creation could not be confirmed durable. Preserve the file if present; existing files are never overwritten",
    )?;
    let initialized =
        quicksave_engine::initialize_with_key(&repository, &key).with_context(|| {
            format!(
                "Repository initialization failed. Keep the new recovery key at {}",
                key_file.display()
            )
        })?;
    Ok(json!({
        "repository": repository,
        "keyFile": key_file,
        "keySaved": true,
        "result": initialized,
        "warning": "Store a second secure copy of your recovery key. QuickSave cannot recover a lost key."
    }))
}

pub fn backup_folder(repository: &Path, source: &Path, key_file: &Path) -> Result<Value> {
    let repository = literal_path(repository)?;
    let source = literal_path(source)?;
    let key_file = external_key_path(key_file, &[&repository, &source])?;
    let (key, key_stamp) = read_key_with_stamp(&key_file)?;
    quicksave_engine::verify_repository(&repository, &key)?;
    if SafeRoot::open(&repository)?.contains_file_identity(&key_stamp)?
        || SafeRoot::open(&source)?.contains_file_identity(&key_stamp)?
    {
        bail!("Recovery key is included through a native filesystem alias; no capture was started");
    }
    quicksave_engine::backup(&repository, &source, &key)
}

pub fn list_snapshots(repository: &Path, key_file: &Path) -> Result<Value> {
    let repository = literal_path(repository)?;
    let key_file = external_key_path(key_file, &[&repository])?;
    let key = read_key(&key_file)?;
    quicksave_engine::snapshots(&repository, &key)
}

pub fn restore_snapshot(
    repository: &Path,
    snapshot_id: &str,
    destination: &Path,
    key_file: &Path,
) -> Result<Value> {
    let repository = literal_path(repository)?;
    let destination = literal_path(destination)?;
    let key_file = external_key_path(key_file, &[&repository, &destination])?;
    let key = read_key(&key_file)?;
    quicksave_engine::restore(&repository, snapshot_id, &destination, &key)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub id: String,
    pub kind: String,
    pub state: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

struct Inner {
    directory: PathBuf,
    operations: Mutex<BTreeMap<String, Operation>>,
    active: Mutex<Option<String>>,
    active_flag: AtomicBool,
}

/// One foreground desktop mutation at a time. Monitoring is read-only.
/// Owned workers are joined, not abandoned on a normal application shutdown.
/// This is NOT an independently installed login/background service.
pub struct OperationManager {
    inner: Arc<Inner>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl OperationManager {
    pub fn open(directory: &Path) -> Result<Self> {
        quicksave_platform::ensure_private_directory(directory)?;
        let root = SafeRoot::open(directory)?;
        let entries = root.entries()?;
        if entries.len() > 4096 {
            bail!("Operation history exceeds the supported local history bound");
        }
        let mut operations: BTreeMap<String, Operation> = BTreeMap::new();
        for entry in entries {
            if entry.is_directory || !entry.relative_path.ends_with(".json") {
                continue;
            }
            let name = &entry.relative_path;
            let id = name.split('.').next().unwrap_or_default();
            if Uuid::parse_str(id).is_err() {
                continue;
            }
            let (mut file, stamp) = root.read_file(name)?;
            if file.metadata()?.len() > 64 * 1024 {
                bail!("Operation history document exceeds its bound");
            }
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let mut operation: Operation = serde_json::from_slice(&bytes)?;
            root.verify_file(name, &stamp)?;
            if operation.id != id {
                bail!("Operation history identity mismatch");
            }
            let finished = name.ends_with(".finished.json");
            if !finished && operation.state == "running" {
                operation.state = "interrupted".into();
                operation.error = Some(
                    "The previous process ended. No automatic retry was started; inspect the repository before retrying."
                        .into(),
                );
            }
            if finished
                || operations
                    .get(id)
                    .is_none_or(|previous| previous.finished_at.is_none())
            {
                operations.insert(id.to_owned(), operation);
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                directory: directory.to_owned(),
                operations: Mutex::new(operations),
                active: Mutex::new(None),
                active_flag: AtomicBool::new(false),
            }),
            workers: Mutex::new(Vec::new()),
        })
    }

    pub fn active(&self) -> bool {
        self.inner.active_flag.load(Ordering::Acquire)
    }

    pub fn get(&self, id: &str) -> Result<Operation> {
        self.inner
            .operations
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation history unavailable"))?
            .get(id)
            .cloned()
            .context("Unknown operation ID")
    }

    pub fn history(&self) -> Result<Vec<Operation>> {
        let mut values = self
            .inner
            .operations
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation history unavailable"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        Ok(values)
    }

    pub fn submit(
        &self,
        kind: &str,
        work: impl FnOnce() -> Result<Value> + Send + 'static,
    ) -> Result<Operation> {
        let mut active = self
            .inner
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("Operation admission unavailable"))?;
        if active.is_some() {
            bail!("Wait for the active QuickSave operation to finish");
        }
        if self.inner.operations.lock().expect("history lock").len() >= 1024 {
            bail!("Local operation history is full; export/archive it before starting more work");
        }
        let operation = Operation {
            id: Uuid::new_v4().to_string(),
            kind: kind.to_owned(),
            state: "running".into(),
            started_at: Utc::now().to_rfc3339(),
            finished_at: None,
            result: None,
            error: None,
        };
        self.inner.active_flag.store(true, Ordering::Release);
        if let Err(error) = write_history(&self.inner.directory, &operation, false) {
            self.inner.active_flag.store(false, Ordering::Release);
            return Err(error);
        }
        self.inner
            .operations
            .lock()
            .expect("history lock")
            .insert(operation.id.clone(), operation.clone());
        *active = Some(operation.id.clone());
        let weak = Arc::downgrade(&self.inner);
        let mut completion = operation.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("quicksave-{}", operation.kind))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
                match outcome {
                    Ok(Ok(result)) => {
                        completion.state = "completed".into();
                        completion.result = Some(result);
                    }
                    Ok(Err(error)) => {
                        completion.state = "failed".into();
                        completion.error = Some(format!("{error:#}"));
                    }
                    Err(_) => {
                        completion.state = "failed".into();
                        completion.error = Some(
                            "Worker stopped unexpectedly; existing backups were not deleted".into(),
                        );
                    }
                }
                completion.finished_at = Some(Utc::now().to_rfc3339());
                if let Some(inner) = weak.upgrade() {
                    if let Err(error) = write_history(&inner.directory, &completion, true) {
                        completion.state = "failed".into();
                        completion.error = Some(format!(
                            "Operation returned, but its local completion receipt could not be saved: {error:#}. Inspect repository history before retrying."
                        ));
                    }
                    inner
                        .operations
                        .lock()
                        .expect("history lock")
                        .insert(completion.id.clone(), completion);
                    *inner.active.lock().expect("active operation lock") = None;
                    inner.active_flag.store(false, Ordering::Release);
                }
            });
        match spawned {
            Ok(worker) => {
                let mut workers = self.workers.lock().expect("worker lock");
                let mut still_running = Vec::new();
                for worker in workers.drain(..) {
                    if worker.is_finished() {
                        let _ = worker.join();
                    } else {
                        still_running.push(worker);
                    }
                }
                still_running.push(worker);
                *workers = still_running;
            }
            Err(error) => {
                *active = None;
                self.inner.active_flag.store(false, Ordering::Release);
                let mut failed = operation.clone();
                failed.state = "failed".into();
                failed.finished_at = Some(Utc::now().to_rfc3339());
                failed.error = Some(format!("Could not start worker: {error}"));
                write_history(&self.inner.directory, &failed, true)?;
                self.inner
                    .operations
                    .lock()
                    .expect("history lock")
                    .insert(failed.id.clone(), failed);
                return Err(error.into());
            }
        }
        Ok(operation)
    }
}

fn write_history(directory: &Path, operation: &Operation, finished: bool) -> Result<()> {
    let bytes = serde_json::to_vec(operation)?;
    if bytes.len() > 64 * 1024 {
        bail!("Operation receipt exceeds its local bound");
    }
    let suffix = if finished { "finished" } else { "started" };
    let root = SafeRoot::open(directory)?;
    root.write_new(&format!("{}.{suffix}.json", operation.id), |file| {
        file.write_all(&bytes)?;
        Ok(())
    })
}

impl Drop for OperationManager {
    fn drop(&mut self) {
        if let Ok(workers) = self.workers.get_mut() {
            for worker in workers.drain(..) {
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn unsupported_local_initialization_never_creates_keys_or_repository_entries() {
        assert!(!local_repository_supported());
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let repository = temp.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        let key = temp.path().join("recovery.key");
        let error = initialize_repository(&repository, &key).unwrap_err();
        assert!(error.to_string().contains("unsupported"));
        assert!(!key.exists());
        assert!(std::fs::read_dir(&repository).unwrap().next().is_none());
        let absent = temp.path().join("absent-repository");
        assert!(initialize_repository(&absent, &key).is_err());
        assert!(!absent.exists());
        assert!(!key.exists());
    }

    #[cfg(unix)]
    fn private_temp() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("quicksave-client-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap()
    }

    #[test]
    fn key_cannot_live_in_the_repository_or_source() {
        assert!(external_key_path(
            Path::new("/approved/repository/key"),
            &[Path::new("/approved/repository")]
        )
        .is_err());
        assert!(literal_path(Path::new("../escape")).is_err());
        assert!(literal_path(Path::new("misleading\nconfirmation")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn operation_is_joined_and_history_survives_reopen() {
        let temp = private_temp();
        let directory = temp.path().join("history");
        let manager = OperationManager::open(&directory).unwrap();
        let operation = manager
            .submit("test", || Ok(json!({"verified": true})))
            .unwrap();
        drop(manager);
        let reopened = OperationManager::open(&directory).unwrap();
        let finished = reopened.get(&operation.id).unwrap();
        assert_eq!(finished.state, "completed");
        assert!(finished.finished_at.is_some());
        assert_eq!(finished.result.unwrap()["verified"], true);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_mutations_are_refused_without_blocking_status() {
        let temp = private_temp();
        let manager = OperationManager::open(&temp.path().join("history")).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let operation = manager
            .submit("held", move || {
                receiver.recv()?;
                Ok(json!({}))
            })
            .unwrap();
        assert_eq!(manager.get(&operation.id).unwrap().state, "running");
        assert!(manager.submit("second", || Ok(json!({}))).is_err());
        sender.send(()).unwrap();
        drop(manager);
    }

    #[cfg(unix)]
    #[test]
    fn initialization_never_overwrites_an_existing_recovery_file() {
        let temp = private_temp();
        let repository = temp.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        let key = temp.path().join("existing.key");
        std::fs::write(&key, b"existing data must survive").unwrap();
        assert!(initialize_repository(&repository, &key).is_err());
        assert_eq!(std::fs::read(&key).unwrap(), b"existing data must survive");
        assert!(std::fs::read_dir(repository).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn foreign_nonempty_repository_is_refused_before_creating_a_key() {
        let temp = private_temp();
        let repository = temp.path().join("foreign-repository");
        std::fs::create_dir(&repository).unwrap();
        let existing = repository.join("existing-backup");
        std::fs::write(&existing, b"preserve existing repository").unwrap();
        let key = temp.path().join("must-not-be-created.key");
        assert!(initialize_repository(&repository, &key).is_err());
        assert!(!key.exists());
        assert_eq!(
            std::fs::read(existing).unwrap(),
            b"preserve existing repository"
        );
        assert_eq!(std::fs::read_dir(repository).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_identity_check_rejects_case_aliases_for_recovery_keys() {
        let temp = private_temp();
        let source = temp.path().join("SelectedFolder");
        std::fs::create_dir(&source).unwrap();
        let key = source.join("recovery.key");
        assert!(external_key_path(&key, &[&source]).is_err());
        let alias = temp.path().join("selectedfolder");
        if alias.exists() {
            assert!(external_key_path(&key, &[&alias]).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn recovery_key_requires_private_permissions_and_no_hardlink_alias() {
        use std::os::unix::fs::PermissionsExt;
        let temp = private_temp();
        let path = temp.path().join("recovery.key");
        std::fs::write(&path, [0xa5; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key(&path).is_ok());
        std::fs::hard_link(&path, temp.path().join("alias.key")).unwrap();
        assert!(read_key(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_history_is_not_replayed_as_a_new_job() {
        let temp = private_temp();
        let directory = temp.path().join("history");
        quicksave_platform::ensure_private_directory(&directory).unwrap();
        let started = Operation {
            id: Uuid::new_v4().to_string(),
            kind: "backup".into(),
            state: "running".into(),
            started_at: Utc::now().to_rfc3339(),
            finished_at: None,
            result: None,
            error: None,
        };
        write_history(&directory, &started, false).unwrap();
        let manager = OperationManager::open(&directory).unwrap();
        assert_eq!(manager.get(&started.id).unwrap().state, "interrupted");
        assert!(!manager.active());
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1);
    }
}
