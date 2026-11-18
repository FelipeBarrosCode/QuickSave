//! Storage-efficient restore: prioritize, verify, atomically publish, and roll back.

mod download;
mod identity;
#[cfg(unix)]
mod journal;
#[cfg(windows)]
#[path = "windows/legacy_journal.rs"]
mod journal;
#[cfg(unix)]
mod leaf;
#[cfg(windows)]
#[path = "windows/legacy_leaf.rs"]
mod leaf;
mod native;
mod pipeline;
mod planner;
mod prerequisite;
#[cfg(all(test, unix))]
mod safety_tests;
#[cfg(windows)]
mod windows;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use identity::VerifiedIdentity;
#[cfg(test)]
use noland_cas::blake3_file;
use noland_crypto::MasterKey;
use noland_pack::PackIndexEntry;
use noland_snapshot::SnapshotView;
use noland_state_core::*;
use noland_state_db::{RestoredPathAssociationInput, StateDb};
use noland_storage::{read_committed_manifest, SharedStorageProvider};
use uuid::Uuid;

pub use download::{
    download_and_verify_to, planned_pack_download_count, prune_local_pack_cache, DownloadJournal,
    DownloadOptions, DownloadReport, PackCacheGcOptions, PackCacheGcReport,
    DEFAULT_MAX_PARALLEL_PACK_DOWNLOADS,
};
pub use native::{
    recover_native_restore, verify_native_restore_completion, NativeApplicationAssessment,
    NativeAttemptRecorder, NativeCommitRecorder, NativeConflictMode, NativeCredentialCheckpoint,
    NativeEntryKind, NativeEntryObservation, NativeExpectedGate, NativeObjectId,
    NativeReconstructionReport, NativeRecoveryAuthority, NativeRestoreAction,
    NativeRestoreCompletionReceipt, NativeRestoreControl, NativeRestoreEntry, NativeRestorePreview,
    NativeRestoreReadiness, NativeRestoreRecoveryReport, NativeWindowsObservation,
    NativeWindowsSecurity, MAX_NATIVE_RESTORE_METADATA,
};
pub use pipeline::{
    restore_pipelined, PipelineIoMetrics, PipelineOptions, PipelineProgress, PipelineReport,
};
pub use planner::{
    embed_restore_plan, plan_restore_priorities, restore_priority, RestorePlanEntry,
    RestorePriority, RestorePriorityPlan, RestoreTarget, READY_TO_LAUNCH,
};
pub use prerequisite::RestorePrerequisite;

#[derive(Debug, Clone)]
pub struct RestorePlan {
    pub restore_id: Uuid,
    pub staging: PathBuf,
    /// Provider-agnostic immutable pack cache rooted under [`AgentPaths::cache`].
    pub pack_cache: PathBuf,
    pub manifest: BundleManifest,
    pub mode: RestoreMode,
}

/// Immutable restore metadata shared by the async coordinator and owned worker.
/// Moving a fetched plan here avoids cloning a potentially hundreds-of-MiB
/// manifest, and computes the priority ordering just once for the whole restore.
#[derive(Debug, Clone)]
pub struct SharedRestorePlan {
    plan: Arc<RestorePlan>,
    priorities: Arc<RestorePriorityPlan>,
    prerequisites: Arc<Vec<RestorePrerequisite>>,
    native_control: Option<Arc<NativeRestoreControl>>,
}

impl std::ops::Deref for SharedRestorePlan {
    type Target = RestorePlan;

    fn deref(&self) -> &Self::Target {
        &self.plan
    }
}

impl SharedRestorePlan {
    pub fn priority_plan(&self) -> Arc<RestorePriorityPlan> {
        Arc::clone(&self.priorities)
    }

    /// Local launcher metadata is published before the durable restore commit,
    /// without altering the immutable remote manifest or its parent-cache identity.
    pub fn with_prerequisites(mut self, prerequisites: Vec<RestorePrerequisite>) -> Self {
        self.prerequisites = Arc::new(prerequisites);
        self
    }

    /// Native consent is an in-process capability, never deserialized from the
    /// cloud manifest, RPC parameters, or a legacy path-based journal.
    pub fn with_native_control(mut self, control: Arc<NativeRestoreControl>) -> Self {
        self.native_control = Some(control);
        self
    }

    pub fn verify_native_completion(&self) -> Result<NativeRestoreCompletionReceipt> {
        let control = self.native_control.as_ref().ok_or_else(|| {
            StateError::Invalid(
                "completion verification requires the approved native control".into(),
            )
        })?;
        verify_native_restore_completion(&self.staging, Arc::clone(control))
    }
}

impl From<RestorePlan> for SharedRestorePlan {
    fn from(plan: RestorePlan) -> Self {
        let priorities = Arc::new(plan.priority_plan());
        Self {
            plan: Arc::new(plan),
            priorities,
            prerequisites: Arc::new(Vec::new()),
            native_control: None,
        }
    }
}

impl From<&SharedRestorePlan> for SharedRestorePlan {
    fn from(plan: &SharedRestorePlan) -> Self {
        plan.clone()
    }
}

// Preserve the existing borrowed-plan API for compatibility. Large restores
// should pass an owned plan or `&plan.into_shared()` to avoid this legacy copy.
impl From<&RestorePlan> for SharedRestorePlan {
    fn from(plan: &RestorePlan) -> Self {
        plan.clone().into()
    }
}

impl RestorePlan {
    pub fn into_shared(self) -> SharedRestorePlan {
        self.into()
    }

    pub fn priority_plan(&self) -> RestorePriorityPlan {
        plan_restore_priorities(&self.manifest, self.mode)
    }

    /// Removes only this restore's staged pack hardlinks. Cached pack objects are left intact
    /// until the caller explicitly prunes them.
    pub fn release_staged_pack_links(&self) -> Result<usize> {
        #[cfg(windows)]
        return Err(StateError::Invalid(
            "Windows staged cache cleanup requires authenticated native artifact ownership".into(),
        ));
        #[cfg(unix)]
        {
            let packs = self.staging.join("packs");
            let metadata = match fs::symlink_metadata(&packs) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StateError::UnsafePath(format!(
                    "restore pack staging is not a directory: {}",
                    packs.display()
                )));
            }

            let mut released = 0;
            for entry in fs::read_dir(&packs)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    return Err(StateError::UnsafePath(format!(
                        "unexpected directory in restore pack staging: {}",
                        path.display()
                    )));
                }
                fs::remove_file(path)?;
                released += 1;
            }
            fs::remove_dir(packs)?;
            Ok(released)
        }
    }

    /// Removes every unlinked verified pack from the shared restore cache.
    pub fn prune_restore_pack_cache(&self) -> Result<PackCacheGcReport> {
        let report = prune_local_pack_cache(&self.pack_cache, &PackCacheGcOptions::new(0, 0))?;
        if report.packs_after != 0 {
            return Err(StateError::Invalid(format!(
                "{} restore packs remain linked or protected",
                report.packs_after
            )));
        }
        Ok(report)
    }
}

#[cfg(unix)]
struct DirectoryCleanupGuard {
    path: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl DirectoryCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for DirectoryCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub async fn prepare_restore(
    provider: &dyn SharedStorageProvider,
    master: &MasterKey,
    paths: &AgentPaths,
    app_id: &AppId,
    bundle_id: Uuid,
    mode: RestoreMode,
) -> Result<RestorePlan> {
    #[cfg(windows)]
    {
        let _ = (provider, master, paths, app_id, bundle_id, mode);
        return Err(StateError::Invalid("Windows restore preparation requires a native-approved private workspace and typed control".into()));
    }
    #[cfg(unix)]
    {
        let restore_id = Uuid::new_v4();
        let staging = paths.restore_dir(&restore_id.to_string());
        let mut staging_cleanup = DirectoryCleanupGuard::new(staging.clone());
        for child in ["packs", "materialized/.chunks", "pre_restore", "logs"] {
            fs::create_dir_all(staging.join(child))?;
        }
        let manifest = read_committed_manifest(provider, master, app_id, bundle_id).await?;
        staging_cleanup.disarm();
        Ok(RestorePlan {
            restore_id,
            staging,
            pack_cache: paths.cache.join("restore-packs"),
            manifest,
            mode,
        })
    }
}

/// Downloads and verifies all selected restore data.
///
/// This compatibility entry point retains full-completion behavior while using the bounded,
/// cache-aware downloader.
pub async fn download_and_verify(
    provider: &dyn SharedStorageProvider,
    master: &MasterKey,
    plan: &RestorePlan,
    pack_index: &[PackIndexEntry],
) -> Result<()> {
    download_and_verify_to(
        provider,
        master,
        plan,
        pack_index,
        RestoreTarget::Complete,
        DownloadOptions::default(),
        None,
    )
    .await
    .map(|_| ())
}

#[derive(Debug, Default, Clone)]
pub struct RestoreReport {
    pub destinations: Vec<PathBuf>,
    pub published_entries: usize,
    pub reused_entries: usize,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct RestoreCommitMetrics {
    pub prepare_us: u64,
    pub cache_cleanup_us: u64,
    pub journal_us: u64,
    pub database_us: u64,
    pub workspace_cleanup_us: u64,
    pub elapsed_us: u64,
    pub native_cleanup_required: bool,
    pub native_retained_diagnostics: u64,
    pub native_completion: Option<NativeRestoreCompletionReceipt>,
    pub native_reconstruction: Option<NativeReconstructionReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    Active,
    Committed,
    Aborted,
}

#[derive(Debug)]
struct PlannedDestination {
    manifest_index: usize,
    root: PathBuf,
    destination: PathBuf,
    identical: bool,
    verified: Option<VerifiedIdentity>,
    existed: bool,
    prior_identity: Option<VerifiedIdentity>,
}

#[derive(Debug)]
struct PlannedTombstone {
    root: PathBuf,
    destination: PathBuf,
    observation: leaf::Observation,
}

#[derive(Debug, Clone)]
struct SymlinkRollback {
    destination: PathBuf,
    target: PathBuf,
}

const TRANSACTION_JOURNAL_FILE: &str = "restore-transaction.json";
// Older agents must refuse journals requiring intent logs or tombstone guards.
const TRANSACTION_JOURNAL_VERSION: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalState {
    Active,
    Committed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JournalPathMapping {
    source: PathBuf,
    staged: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JournalSymlinkRollback {
    destination: PathBuf,
    target: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JournalTombstoneGuard {
    destination: PathBuf,
    observation: leaf::Observation,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RestoreTransactionJournal {
    version: u32,
    restore_id: Uuid,
    state: JournalState,
    allowed_roots: Vec<PathBuf>,
    rollback_mappings: Vec<JournalPathMapping>,
    prior_symlinks: Vec<JournalSymlinkRollback>,
    created_paths: Vec<PathBuf>,
    created_directories: Vec<PathBuf>,
    partial_paths: Vec<PathBuf>,
    #[serde(default)]
    tombstone_guards: Vec<JournalTombstoneGuard>,
    /// v4 native-only confinement proof. Ordinary source journals stay v3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_boundary: Option<(PathBuf, (u64, u64))>,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreRecoveryReport {
    pub workspaces_scanned: usize,
    pub workspaces_rolled_back: usize,
    pub committed_workspaces_cleaned: usize,
    pub unjournaled_workspaces_cleaned: usize,
    pub failures: Vec<RestoreRecoveryFailure>,
}

#[derive(Debug, Clone)]
pub struct RestoreRecoveryFailure {
    pub workspace: PathBuf,
    pub error: String,
}

/// Owns all filesystem mutations for one restore across every milestone.
///
/// Dropping an active transaction rolls back published paths and removes restore staging. This is
/// required because operation cancellation drops the restore future at an async cancellation point.
pub struct RestoreTransaction<'a> {
    plan: &'a RestorePlan,
    roots: &'a LogicalRootMap,
    db: Option<&'a StateDb>,
    rollback_views: Vec<SnapshotView>,
    symlink_rollbacks: Vec<SymlinkRollback>,
    tombstone_guards: Vec<JournalTombstoneGuard>,
    created_paths: BTreeSet<PathBuf>,
    created_directories: BTreeSet<PathBuf>,
    active_partials: BTreeSet<PathBuf>,
    published_entries: BTreeSet<usize>,
    verified_files: BTreeMap<usize, VerifiedIdentity>,
    // Cache lexical resolution only. Parent safety and file identities are still
    // checked at every mutation and again inside the database commit.
    resolved_roots: BTreeMap<String, PathBuf>,
    index_generation: Option<i64>,
    allowed_roots: BTreeSet<PathBuf>,
    remaining_chunk_refs: BTreeMap<String, usize>,
    chunk_eviction_enabled: bool,
    tombstones_applied: bool,
    state: TransactionState,
    priorities: Arc<RestorePriorityPlan>,
    uses_legacy_pack_cache: bool,
    disk_reservations: Vec<disk::DiskReservation>,
    native: Option<native::NativeTransaction>,
}

impl<'a> RestoreTransaction<'a> {
    pub fn new(plan: &'a RestorePlan, roots: &'a LogicalRootMap, db: Option<&'a StateDb>) -> Self {
        Self::with_priorities(plan, roots, db, Arc::new(plan.priority_plan()), true)
    }

    fn with_priorities(
        plan: &'a RestorePlan,
        roots: &'a LogicalRootMap,
        db: Option<&'a StateDb>,
        priorities: Arc<RestorePriorityPlan>,
        uses_legacy_pack_cache: bool,
    ) -> Self {
        let mut remaining_chunk_refs = BTreeMap::new();
        // Streaming has no decrypted chunk cache to evict. Its placement table
        // and the published-entry check at commit already prove completeness.
        if uses_legacy_pack_cache {
            for entry in &priorities.entries {
                let unique_chunks = plan.manifest.files[entry.manifest_index]
                    .chunks
                    .iter()
                    .map(|chunk| chunk.hash.clone())
                    .collect::<BTreeSet<_>>();
                for hash in unique_chunks {
                    *remaining_chunk_refs.entry(hash).or_insert(0) += 1;
                }
            }
        }
        Self {
            plan,
            roots,
            db,
            rollback_views: Vec::new(),
            symlink_rollbacks: Vec::new(),
            tombstone_guards: Vec::new(),
            created_paths: BTreeSet::new(),
            created_directories: BTreeSet::new(),
            active_partials: BTreeSet::new(),
            published_entries: BTreeSet::new(),
            verified_files: BTreeMap::new(),
            resolved_roots: BTreeMap::new(),
            index_generation: None,
            allowed_roots: BTreeSet::new(),
            remaining_chunk_refs,
            chunk_eviction_enabled: false,
            tombstones_applied: false,
            state: if cfg!(windows) {
                TransactionState::Aborted
            } else {
                TransactionState::Active
            },
            priorities,
            uses_legacy_pack_cache,
            disk_reservations: Vec::new(),
            native: None,
        }
    }

    /// Synchronous counterpart of `SharedRestorePlan::with_native_control`.
    pub fn new_native(
        plan: &'a RestorePlan,
        roots: &'a LogicalRootMap,
        control: Arc<NativeRestoreControl>,
    ) -> Result<Self> {
        let mut transaction = Self::new(plan, roots, None);
        transaction.attach_native(control)?;
        Ok(transaction)
    }

    fn attach_native(&mut self, control: Arc<NativeRestoreControl>) -> Result<()> {
        // Failure while establishing native authentication must never fall back
        // to the legacy Drop/path cleanup branch.
        self.state = TransactionState::Aborted;
        self.native = Some(native::NativeTransaction::begin(
            &self.plan.staging,
            self.plan.restore_id,
            control,
            &self.plan.manifest,
            self.plan.mode,
            self.roots,
        )?);
        self.state = TransactionState::Active;
        Ok(())
    }

    /// Reconstructs and atomically publishes entries through `target` directly at their final
    /// destinations. The transaction retains rollback state until [`Self::commit`].
    pub fn publish_to(&mut self, target: RestoreTarget) -> Result<RestoreReport> {
        #[cfg(windows)]
        if self.native.is_none()
            || self
                .plan
                .manifest
                .files
                .iter()
                .any(|file| !file.chunks.is_empty())
        {
            return Err(StateError::Invalid("Windows restore uses the typed shared streaming pipeline, not legacy plaintext chunk-cache assembly".into()));
        }
        if self.state != TransactionState::Active {
            return Err(StateError::Invalid(
                "restore transaction is not active".into(),
            ));
        }

        self.begin_index_observation()?;
        let (planned, tombstones) = self.preflight(target)?;
        self.prepare_rollback(&planned, &tombstones)?;

        let mut report = RestoreReport::default();
        for planned in planned {
            report.destinations.push(planned.destination.clone());
            if planned.identical {
                if let Some(identity) = planned.verified {
                    self.verified_files.insert(planned.manifest_index, identity);
                }
                self.release_entry_chunks(planned.manifest_index)?;
                self.published_entries.insert(planned.manifest_index);
                // A retry after a crash may find the destination already published while the
                // prior process died before committing its database association.
                report.reused_entries += 1;
                continue;
            }

            let file = &self.plan.manifest.files[planned.manifest_index];
            match file.file_type.as_str() {
                "directory" => {
                    self.create_directory_chain_journaled(&planned.root, &planned.destination)?;
                }
                "symlink" => self.publish_symlink(file, &planned)?,
                "file" => self.publish_file(file, &planned)?,
                other => {
                    return Err(StateError::UnsafePath(format!(
                        "unsupported file type '{other}'"
                    )));
                }
            }
            self.release_entry_chunks(planned.manifest_index)?;
            self.published_entries.insert(planned.manifest_index);
            report.published_entries += 1;
        }

        if target == RestoreTarget::Complete && !self.tombstones_applied {
            if let Some(native) = &mut self.native {
                native.apply_tombstones()?;
            } else {
                for tombstone in tombstones {
                    tombstone.apply()?;
                }
            }
            self.tombstones_applied = true;
        }

        Ok(report)
    }

    /// Enables chunk eviction after the complete download has populated every chunk needed by the
    /// selected restore mode. Chunks whose only files were already published are removed now;
    /// remaining chunks are removed as their final referencing file is published.
    pub fn enable_chunk_eviction(&mut self) -> Result<usize> {
        if self.state != TransactionState::Active {
            return Err(StateError::Invalid(
                "restore transaction is not active".into(),
            ));
        }
        self.chunk_eviction_enabled = true;
        let zero_reference = self
            .remaining_chunk_refs
            .iter()
            .filter(|(_, references)| **references == 0)
            .map(|(hash, _)| hash.clone())
            .collect::<Vec<_>>();
        let mut evicted = 0;
        for hash in zero_reference {
            if self.evict_chunk(&hash)? {
                evicted += 1;
            }
        }
        Ok(evicted)
    }

    pub fn remaining_chunk_references(&self, hash: &str) -> usize {
        self.remaining_chunk_refs.get(hash).copied().unwrap_or(0)
    }

    pub fn release_staged_pack_links(&self) -> Result<usize> {
        self.plan.release_staged_pack_links()
    }

    pub fn prune_restore_pack_cache(&self) -> Result<PackCacheGcReport> {
        self.plan.prune_restore_pack_cache()
    }

    fn begin_index_observation(&mut self) -> Result<()> {
        if self.index_generation.is_none() {
            if let Some(db) = self.db {
                self.index_generation =
                    Some(db.capture_generation(&self.plan.manifest.app.app_id)?);
            }
        }
        Ok(())
    }

    /// Persists deferred associations and removes all restore-local staging and rollback data.
    pub fn commit(self) -> Result<()> {
        self.commit_with_metrics().map(|_| ())
    }

    pub fn commit_with_metrics(mut self) -> Result<RestoreCommitMetrics> {
        let started = Instant::now();
        let mut metrics = RestoreCommitMetrics::default();
        if self.state != TransactionState::Active {
            return Err(StateError::Invalid(
                "restore transaction is not active".into(),
            ));
        }

        if self.published_entries.len() != self.priorities.entries.len()
            || (!self.plan.manifest.tombstones.is_empty() && !self.tombstones_applied)
            || self
                .remaining_chunk_refs
                .values()
                .any(|references| *references != 0)
        {
            return Err(StateError::Invalid(
                "cannot commit restore before every selected file is published".into(),
            ));
        }
        if let Some(native) = &mut self.native {
            let report = native.commit()?;
            metrics.native_cleanup_required = !report.retained_artifacts.is_empty();
            metrics.native_retained_diagnostics = report.retained_artifacts.len() as u64;
            metrics.native_completion = report.completion;
            metrics.native_reconstruction = report.reconstruction;
            self.state = TransactionState::Committed;
            // Native audit journals and any unowned internal artifacts are not
            // swept through a mutable workspace string.
            metrics.elapsed_us = pipeline::elapsed_us(started);
            return Ok(metrics);
        }
        #[cfg(windows)]
        return Err(StateError::Conflict(
            "Windows commit requires typed native authority".into(),
        ));
        #[cfg(unix)]
        {
            let now = chrono::Utc::now();
            let mut associations = Vec::new();
            let mut states = Vec::new();
            if self.db.is_some() {
                associations.reserve(self.published_entries.len());
                states.reserve(self.verified_files.len());
                for &index in &self.published_entries {
                    let file = &self.plan.manifest.files[index];
                    let root = &self.resolved_roots[&file.logical_root];
                    let destination = join_validated(root, &file.relative_path)?;
                    let canonical = destination.to_string_lossy().into_owned();
                    associations.push(RestoredPathAssociationInput {
                        canonical_path: canonical.clone(),
                        persistence_class: file.persistence_class,
                        semantic_role: file.semantic_role,
                    });
                    let Some(&identity) = self.verified_files.get(&index) else {
                        continue;
                    };
                    let logical = self
                        .roots
                        .classify(&destination)
                        .unwrap_or(LogicalPath::new(
                            file.logical_root_parsed()
                                .ok_or_else(|| StateError::UnsafePath(file.logical_root.clone()))?,
                            &file.relative_path,
                        ));
                    states.push(FileStateRecord {
                        app_id: self.plan.manifest.app.app_id.clone(),
                        logical_root: logical.logical_root.as_token(),
                        relative_path: logical.relative_path,
                        canonical_path: Some(canonical),
                        file_type: FileType::File,
                        size: identity.size,
                        mtime_ns: identity.mtime_ns,
                        inode: Some(identity.inode),
                        mount_id: Some(identity.device),
                        mode: Some(identity.mode),
                        content_hash: Some(file.file_hash.clone()),
                        trust: FileStateTrust::Trusted,
                        last_seen_at: now,
                        last_hashed_at: Some(now),
                    });
                }
            }

            // Borrow the strings required by the existing DB API instead of retaining
            // another full set of canonical strings and destination PathBufs.
            let guards = self
                .published_entries
                .iter()
                .zip(&associations)
                .filter_map(|(&index, association)| {
                    self.verified_files.get(&index).map(|&identity| {
                        let root =
                            &self.resolved_roots[&self.plan.manifest.files[index].logical_root];
                        (
                            association.canonical_path.as_str(),
                            (root.as_path(), identity),
                        )
                    })
                })
                .collect::<BTreeMap<_, _>>();
            metrics.prepare_us = pipeline::elapsed_us(started);

            let cache_started = Instant::now();
            self.release_staged_pack_links()?;
            if self.uses_legacy_pack_cache {
                self.prune_restore_pack_cache()?;
            }
            metrics.cache_cleanup_us = pipeline::elapsed_us(cache_started);

            // Persist the filesystem commit decision before the SQLite commit. A crash after SQLite
            // commits can never leave an active journal that startup recovery would roll back.
            let journal_started = Instant::now();
            self.persist_journal(JournalState::Committed)?;
            metrics.journal_us = pipeline::elapsed_us(journal_started);
            self.state = TransactionState::Committed;

            if let Some(db) = self.db {
                let database_started = Instant::now();
                let result = db.commit_restored_paths(
                    &self.plan.manifest.app.app_id,
                    &associations,
                    &states,
                    self.index_generation,
                    |state| {
                        state
                            .canonical_path
                            .as_deref()
                            .and_then(|path| guards.get(path))
                            .is_some_and(|(root, identity)| {
                                let destination = Path::new(
                                    state.canonical_path.as_deref().expect("guarded path"),
                                );
                                validate_parent_chain(root, destination).is_ok()
                                    && identity.matches_path(destination)
                            })
                    },
                );
                metrics.database_us = pipeline::elapsed_us(database_started);
                tracing::debug!(
                    database_commit_us = metrics.database_us,
                    "restore database commit finished"
                );
                if let Err(database_error) = result {
                    // A returned database error is rollback-safe only after the durable journal has
                    // been re-armed. If that write fails, retain the committed decision and destinations.
                    if let Err(journal_error) = self.persist_journal(JournalState::Active) {
                        return Err(StateError::Invalid(format!(
                        "database publication failed: {database_error}; restore remains committed because the rollback journal could not be re-armed: {journal_error}"
                    )));
                    }
                    self.state = TransactionState::Active;
                    return Err(database_error);
                }
            }

            let cleanup_started = Instant::now();
            if self.plan.staging.exists() {
                // The durable decision and database transaction have committed.
                // Cleanup failure is recoverable at startup, not a failed restore
                // whose trusted state could misleadingly appear to have survived.
                if let Err(error) = remove_directory_tree_durable(&self.plan.staging) {
                    tracing::warn!(%error, restore_id = %self.plan.restore_id, "committed restore workspace cleanup deferred");
                }
            }
            metrics.workspace_cleanup_us = pipeline::elapsed_us(cleanup_started);
            metrics.elapsed_us = pipeline::elapsed_us(started);
            Ok(metrics)
        }
    }

    /// Reverts every path changed by this restore and removes staging after rollback succeeds.
    pub fn abort(&mut self) -> Result<()> {
        #[cfg(windows)]
        if self.native.is_none() {
            return Err(StateError::Conflict(
                "Windows rollback cannot use an unsigned legacy transaction".into(),
            ));
        }
        if self.state != TransactionState::Active {
            return Ok(());
        }
        if let Some(native) = &mut self.native {
            let result = native.abort().map(|_| ());
            self.state = TransactionState::Aborted;
            return result;
        }
        #[cfg(windows)]
        {
            self.state = TransactionState::Aborted;
            return Err(StateError::Conflict(
                "Windows rollback requires explicit authenticated native recovery".into(),
            ));
        }
        #[cfg(unix)]
        {
            if native_boundary(self.plan)?.is_some() {
                self.state = TransactionState::Aborted;
                return Err(StateError::Conflict(
                    "native restore has no authenticated recovery authority; artifacts retained"
                        .into(),
                ));
            }

            let journal = self.journal_snapshot(JournalState::Active)?;
            let mut first_error = None;
            record_cleanup_error(self.persist_journal(JournalState::Active), &mut first_error);
            record_cleanup_error(
                rollback_from_journal(&self.plan.staging, &journal),
                &mut first_error,
            );
            record_cleanup_error(
                self.release_staged_pack_links().map(|_| ()),
                &mut first_error,
            );
            if self.uses_legacy_pack_cache {
                record_cleanup_error(
                    self.prune_restore_pack_cache().map(|_| ()),
                    &mut first_error,
                );
            }

            if let Some(error) = first_error {
                return Err(error);
            }
            self.state = TransactionState::Aborted;
            if self.plan.staging.exists() {
                remove_directory_tree_durable(&self.plan.staging)?;
            }
            Ok(())
        }
    }

    fn preflight(
        &mut self,
        target: RestoreTarget,
    ) -> Result<(Vec<PlannedDestination>, Vec<PlannedTombstone>)> {
        #[cfg(windows)]
        if self.native.is_none() {
            return Err(StateError::Conflict(
                "Windows restore requires an approved typed plan and recovery authority".into(),
            ));
        }
        if self.native.is_none() && native_boundary(self.plan)?.is_some() {
            return Err(StateError::Conflict(
                "native restore requires an approved typed plan and recovery authority".into(),
            ));
        }
        self.preflight_observed(target, |_| Ok(()))
    }

    fn preflight_observed(
        &mut self,
        target: RestoreTarget,
        mut on_checked: impl FnMut(u64) -> Result<()>,
    ) -> Result<(Vec<PlannedDestination>, Vec<PlannedTombstone>)> {
        #[cfg(windows)]
        if self.native.is_none() {
            return Err(StateError::Conflict(
                "Windows restore requires an approved typed plan and recovery authority".into(),
            ));
        }
        if self.native.is_none() && native_boundary(self.plan)?.is_some() {
            return Err(StateError::Conflict(
                "native restore requires an approved typed plan and recovery authority".into(),
            ));
        }
        let priority_plan = &self.priorities;
        let mut destinations = BTreeSet::new();
        let mut planned = Vec::new();
        for (checked, entry) in priority_plan.entries_for(target).enumerate() {
            if checked % 256 == 0 {
                on_checked(checked as u64)?;
            }
            if self.published_entries.contains(&entry.manifest_index) {
                continue;
            }
            let file = &self.plan.manifest.files[entry.manifest_index];
            let root = match self.resolved_roots.get(&file.logical_root) {
                Some(root) => root.clone(),
                None => {
                    let (root, _) = resolve_destination(self.roots, file)?;
                    self.resolved_roots
                        .insert(file.logical_root.clone(), root.clone());
                    root
                }
            };
            let destination = join_validated(&root, &file.relative_path)?;
            if !destinations.insert(destination.clone()) {
                return Err(StateError::Invalid(format!(
                    "multiple manifest entries resolve to {}",
                    destination.display()
                )));
            }
            validate_parent_chain(&root, &destination)?;
            let metadata = symlink_metadata_if_present(&destination)?;
            if self.native.is_none() && native_no_overwrite(self.plan) && metadata.is_some() {
                return Err(StateError::Conflict(
                    "native download refuses an existing destination file".into(),
                ));
            }
            let native_action = self
                .native
                .as_ref()
                .map(|native| native.approved_action(&file.logical_root, &file.relative_path))
                .transpose()?;
            let verified =
                if file.file_type == "file" && native_action == Some(NativeRestoreAction::Reuse) {
                    metadata
                        .as_ref()
                        .map(|_| VerifiedIdentity::from_path(&destination))
                        .transpose()?
                } else if file.file_type == "file" && self.native.is_none() {
                    identity::verify_existing(&destination, file, metadata.as_ref())?
                } else {
                    None
                };
            let identical = if let Some(action) = native_action {
                action == NativeRestoreAction::Reuse
            } else {
                match file.file_type.as_str() {
                    "file" => verified.is_some(),
                    "directory" => metadata.as_ref().is_some_and(|value| value.is_dir()),
                    "symlink" => {
                        let target = file
                            .symlink_target
                            .as_deref()
                            .ok_or_else(|| StateError::Invalid("symlink missing target".into()))?;
                        validate_symlink_target_within_root(&file.relative_path, target)?;
                        fs::read_link(&destination)
                            .map(|existing| existing == Path::new(target))
                            .unwrap_or(false)
                    }
                    other => {
                        return Err(StateError::UnsafePath(format!(
                            "unsupported file type '{other}'"
                        )));
                    }
                }
            };
            if let Some(metadata) = &metadata {
                let incompatible = match file.file_type.as_str() {
                    "directory" => !metadata.is_dir(),
                    "file" | "symlink" => metadata.is_dir(),
                    _ => false,
                };
                if incompatible {
                    return Err(StateError::Invalid(format!(
                        "cannot atomically replace incompatible destination {}",
                        destination.display()
                    )));
                }
            }
            let prior_identity = metadata
                .as_ref()
                .map(|_| VerifiedIdentity::from_path(&destination))
                .transpose()?;
            planned.push(PlannedDestination {
                manifest_index: entry.manifest_index,
                root,
                destination,
                identical,
                verified,
                existed: metadata.is_some(),
                prior_identity,
            });
        }

        let mut tombstones = Vec::new();
        on_checked(planned.len() as u64)?;
        if self.native.is_none() && target == RestoreTarget::Complete && !self.tombstones_applied {
            for tombstone in &self.plan.manifest.tombstones {
                validate_relative_path(&tombstone.relative_path)?;
                let Some(logical) = LogicalRoot::parse(&tombstone.logical_root) else {
                    return Err(StateError::UnsafePath(tombstone.logical_root.clone()));
                };
                let Some(root) = self.roots.resolve(&logical) else {
                    continue;
                };
                let root = canonicalize_root_if_present(root)?;
                let destination = join_validated(&root, &tombstone.relative_path)?;
                validate_parent_chain(&root, &destination)?;
                if !destinations.insert(destination.clone()) {
                    return Err(StateError::Invalid(format!(
                        "manifest entry and tombstone both resolve to {}",
                        destination.display()
                    )));
                }
                let observation = leaf::observe(&destination)?;
                if observation
                    .identity
                    .is_some_and(|identity| identity.is_directory())
                {
                    continue;
                }
                tombstones.push(PlannedTombstone {
                    root,
                    destination,
                    observation,
                });
            }
        }
        Ok((planned, tombstones))
    }

    fn prepare_rollback(
        &mut self,
        planned: &[PlannedDestination],
        tombstones: &[PlannedTombstone],
    ) -> Result<()> {
        if self.native.is_some() {
            // Native rollback moves exact approved inodes into same-volume
            // slots at publication. No path-based snapshot mappings or legacy
            // intent logs are authoritative for this branch.
            let mut requests = planned
                .iter()
                .filter(|entry| !entry.identical)
                .filter_map(|entry| {
                    let file = &self.plan.manifest.files[entry.manifest_index];
                    (file.file_type == "file")
                        .then(|| (entry.destination.clone(), file.size.saturating_add(4096)))
                })
                .collect::<Vec<_>>();
            let rollback_bytes = planned
                .iter()
                .filter(|entry| !entry.identical)
                .filter_map(|entry| entry.prior_identity)
                .filter(|identity| !identity.is_directory())
                .try_fold(0u64, |total, identity| {
                    total
                        .checked_add(identity.size)
                        .and_then(|total| total.checked_add(4096))
                        .ok_or_else(|| {
                            StateError::Invalid("native rollback disk reservation overflow".into())
                        })
                })?;
            requests.push((self.plan.staging.clone(), rollback_bytes));
            self.disk_reservations
                .push(disk::DiskReservation::reserve(&requests)?);
            self.native
                .as_mut()
                .expect("native branch")
                .capture_originals()?;
            return Ok(());
        }
        self.prepare_rollback_observed(planned, tombstones, |_| Ok(()))
    }

    fn prepare_rollback_observed(
        &mut self,
        planned: &[PlannedDestination],
        tombstones: &[PlannedTombstone],
        on_file: impl FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        if self.native.is_some() {
            return self.prepare_rollback(planned, tombstones);
        }
        #[cfg(windows)]
        {
            let _ = (planned, tombstones, on_file);
            return Err(StateError::Conflict(
                "Windows rollback capture requires typed native handles".into(),
            ));
        }
        #[cfg(unix)]
        {
            self.allowed_roots
                .extend(planned.iter().map(|planned| planned.root.clone()));
            self.allowed_roots
                .extend(tombstones.iter().map(|tombstone| tombstone.root.clone()));
            let mut regular_files = Vec::new();
            let mut symlinks = Vec::new();
            let mut requests = BTreeMap::<PathBuf, u64>::new();
            for entry in planned.iter().filter(|entry| !entry.identical) {
                let file = &self.plan.manifest.files[entry.manifest_index];
                if file.file_type == "file" {
                    *requests
                        .entry(
                            entry
                                .destination
                                .parent()
                                .unwrap_or(&entry.root)
                                .to_path_buf(),
                        )
                        .or_default() += file.size.saturating_add(4096);
                }
            }
            let mut rollback_bytes = 0u64;
            let mut recovery_peaks = BTreeMap::<u64, (PathBuf, u64)>::new();
            for (destination, expected) in planned
                .iter()
                .filter(|planned| !planned.identical)
                .map(|planned| (&planned.destination, planned.prior_identity))
                .chain(
                    tombstones
                        .iter()
                        .map(|tombstone| (&tombstone.destination, tombstone.observation.identity)),
                )
            {
                let metadata = symlink_metadata_if_present(destination)?;
                if metadata.as_ref().map(VerifiedIdentity::from_metadata) != expected {
                    return Err(StateError::Integrity(
                        "restore destination changed before rollback capture".into(),
                    ));
                }
                let Some(metadata) = metadata else {
                    continue;
                };
                if metadata.file_type().is_symlink() {
                    symlinks.push(SymlinkRollback {
                        destination: destination.clone(),
                        target: fs::read_link(destination)?,
                    });
                } else if metadata.is_file() {
                    rollback_bytes = rollback_bytes
                        .saturating_add(metadata.len())
                        .saturating_add(4096);
                    let peak = recovery_peaks
                        .entry(metadata.dev())
                        .or_insert((destination.clone(), 0));
                    peak.1 = peak.1.max(metadata.len());
                    regular_files.push(destination.clone());
                }
            }
            // Recovery atomically replaces one old file at a time. Reserve that
            // largest temporary too, even when the rollback snapshot used CoW.
            for (path, bytes) in recovery_peaks.into_values() {
                *requests.entry(path).or_default() += bytes;
            }
            *requests.entry(self.plan.staging.clone()).or_default() += rollback_bytes;
            self.disk_reservations.push(disk::DiskReservation::reserve(
                &requests.into_iter().collect::<Vec<_>>(),
            )?);
            if !regular_files.is_empty() {
                let rollback_root = self.plan.staging.join("pre_restore");
                let view = noland_snapshot::create_view_observed(
                    &rollback_root,
                    &regular_files,
                    false,
                    on_file,
                )?;
                validate_rollback_view(&view, &regular_files)?;
                // A copy may be internally stable yet newer than preflight, or an
                // earlier source may change while a later source is being copied.
                for entry in planned.iter().filter(|entry| !entry.identical) {
                    validate_parent_chain(&entry.root, &entry.destination)?;
                    if symlink_metadata_if_present(&entry.destination)?
                        .as_ref()
                        .map(VerifiedIdentity::from_metadata)
                        != entry.prior_identity
                    {
                        return Err(StateError::Integrity(
                            "restore destination changed during rollback capture".into(),
                        ));
                    }
                }
                for tombstone in tombstones {
                    tombstone.validate()?;
                }
                sync_snapshot_view(&rollback_root, &view)?;
                self.rollback_views.push(view);
            }
            self.symlink_rollbacks.extend(symlinks);
            self.tombstone_guards
                .extend(tombstones.iter().map(|tombstone| JournalTombstoneGuard {
                    destination: tombstone.destination.clone(),
                    observation: tombstone.observation,
                }));
            self.persist_journal(JournalState::Active)
        }
    }

    #[cfg(unix)]
    fn journal_snapshot(&self, state: JournalState) -> Result<RestoreTransactionJournal> {
        let boundary = native_boundary(self.plan)?;
        Ok(RestoreTransactionJournal {
            version: if boundary.is_some() {
                TRANSACTION_JOURNAL_VERSION
            } else {
                3
            },
            restore_id: self.plan.restore_id,
            state,
            allowed_roots: self.allowed_roots.iter().cloned().collect(),
            rollback_mappings: self
                .rollback_views
                .iter()
                .flat_map(|view| &view.mappings)
                .map(|mapping| JournalPathMapping {
                    source: mapping.source.clone(),
                    staged: mapping.staged.clone(),
                })
                .collect(),
            prior_symlinks: self
                .symlink_rollbacks
                .iter()
                .map(|rollback| JournalSymlinkRollback {
                    destination: rollback.destination.clone(),
                    target: rollback.target.clone(),
                })
                .collect(),
            created_paths: self.created_paths.iter().cloned().collect(),
            created_directories: self.created_directories.iter().cloned().collect(),
            partial_paths: self.active_partials.iter().cloned().collect(),
            tombstone_guards: self.tombstone_guards.clone(),
            native_boundary: boundary,
        })
    }

    fn persist_journal(&self, state: JournalState) -> Result<()> {
        if self.native.is_some() {
            return Err(StateError::Integrity(
                "legacy journal cannot represent native restore authority".into(),
            ));
        }
        #[cfg(windows)]
        {
            let _ = state;
            return Err(StateError::Conflict(
                "Windows cannot persist unsigned legacy restore cleanup authority".into(),
            ));
        }
        #[cfg(unix)]
        {
            persist_transaction_journal(&self.plan.staging, &self.journal_snapshot(state)?)?;
            journal::checkpoint(&self.plan.staging)
        }
    }

    fn create_directory_chain_journaled(&mut self, root: &Path, destination: &Path) -> Result<()> {
        if let Some(native) = &mut self.native {
            return native.create_directories(destination);
        }
        #[cfg(windows)]
        {
            let _ = (root, destination);
            return Err(StateError::Conflict(
                "Windows directory creation requires typed native control".into(),
            ));
        }
        #[cfg(unix)]
        {
            let native = native_boundary(self.plan)?;
            for directory in missing_directory_chain(root, destination)? {
                if let Some((boundary, identity)) = &native {
                    noland_snapshot::SourcePath::new_beneath(&directory, boundary, *identity)?
                        .create_private_directory()?;
                }
                // A logical root may not exist yet, so creating it can also require ancestors outside
                // the root itself. Journal each such directory as an allowed rollback boundary before
                // creating it.
                self.allowed_roots.insert(directory.clone());
                self.created_directories.insert(directory.clone());
                journal::append(
                    &self.plan.staging,
                    &[journal::Intent::Directory(directory.clone())],
                )?;
                if native.is_none() {
                    fs::create_dir(&directory)?;
                }
                sync_parent_directory(&directory)?;
            }
            Ok(())
        }
    }

    fn track_partial(&mut self, partial: &Path) -> Result<()> {
        if self.native.is_some() {
            return Err(StateError::Integrity(
                "native partial ownership requires the actual created handle".into(),
            ));
        }
        if self.active_partials.insert(partial.to_path_buf()) {
            journal::append(
                &self.plan.staging,
                &[journal::Intent::Partial(partial.into())],
            )?;
        }
        Ok(())
    }

    fn clear_partial(&mut self, partial: &Path) -> Result<()> {
        self.active_partials.remove(partial);
        // The durable intent may outlive the partial. Recovery removal is idempotent;
        // no completion record or whole-journal rewrite is needed for every file.
        Ok(())
    }

    fn track_created_path(&mut self, path: &Path) -> Result<()> {
        if self.native.is_some() {
            return Err(StateError::Integrity(
                "native created ownership is recorded before guarded publication".into(),
            ));
        }
        if self.created_paths.insert(path.to_path_buf()) {
            journal::append(&self.plan.staging, &[journal::Intent::Created(path.into())])?;
        }
        Ok(())
    }

    fn release_entry_chunks(&mut self, manifest_index: usize) -> Result<()> {
        if !self.uses_legacy_pack_cache {
            return Ok(());
        }
        let unique_chunks = self.plan.manifest.files[manifest_index]
            .chunks
            .iter()
            .map(|chunk| chunk.hash.clone())
            .collect::<BTreeSet<_>>();
        for hash in unique_chunks {
            let references = self.remaining_chunk_refs.get_mut(&hash).ok_or_else(|| {
                StateError::Invalid(format!("missing restore chunk reference count for {hash}"))
            })?;
            if *references == 0 {
                return Err(StateError::Invalid(format!(
                    "restore chunk reference count underflow for {hash}"
                )));
            }
            *references -= 1;
            if self.chunk_eviction_enabled && *references == 0 {
                self.evict_chunk(&hash)?;
            }
        }
        Ok(())
    }

    fn evict_chunk(&self, hash: &str) -> Result<bool> {
        #[cfg(windows)]
        return Err(StateError::Invalid(
            "Windows plaintext cache eviction lacks authenticated artifact ownership".into(),
        ));
        #[cfg(unix)]
        {
            let path = restore_chunk_path(self.plan, hash)?;
            match fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
    }

    fn publish_file(&mut self, file: &ManifestFile, planned: &PlannedDestination) -> Result<()> {
        let parent = planned.destination.parent().ok_or_else(|| {
            StateError::UnsafePath(format!(
                "destination has no parent: {}",
                planned.destination.display()
            ))
        })?;
        self.create_directory_chain_journaled(&planned.root, parent)?;
        validate_parent_chain(&planned.root, &planned.destination)?;

        let partial = destination_partial_path(&planned.destination, self.plan.restore_id)?;
        if self.native.is_none() && !native_no_overwrite(self.plan) {
            self.track_partial(&partial)?;
            remove_recovery_leaf(&partial)?;
        }
        let mut output = if let Some(native) = &self.native {
            native.open_partial(&partial)?
        } else {
            #[cfg(windows)]
            return Err(StateError::Conflict(
                "Windows file assembly requires typed native filesystem authority".into(),
            ));
            #[cfg(unix)]
            {
                if let Some((boundary, identity)) = native_boundary(self.plan)? {
                    noland_snapshot::SourcePath::new_beneath(&partial, &boundary, identity)?
                        .open_partial_private(true)?
                } else {
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&partial)?
                }
            }
        };
        if let Some(native) = &mut self.native {
            native.own_partial(&partial, &output)?;
            native.flush_intents()?;
        } else if native_no_overwrite(self.plan) {
            self.track_partial(&partial)?;
        }
        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;
        let mut buffer = vec![0u8; 256 * 1024];
        for chunk in &file.chunks {
            let chunk_path = restore_chunk_path(self.plan, &chunk.hash)?;
            let mut input = fs::File::open(chunk_path)?;
            use std::io::Read;
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                output.write_all(&buffer[..count])?;
                hasher.update(&buffer[..count]);
                written = written.saturating_add(count as u64);
            }
        }
        output.flush()?;

        let size = written;
        if size != file.size {
            return Err(StateError::Integrity(format!(
                "file size mismatch for {}: expected {}, got {size}",
                file.relative_path, file.size
            )));
        }
        if format!("blake3:{}", hasher.finalize().to_hex()) != file.file_hash {
            return Err(StateError::Integrity(format!(
                "file hash mismatch for {}",
                file.relative_path
            )));
        }
        apply_file_metadata(&output, file)?;
        output.sync_all()?;
        let verified = VerifiedIdentity::from_file(&output)?;
        drop(output);
        validate_parent_chain(&planned.root, &planned.destination)?;
        if !verified.matches_path(&partial) {
            return Err(StateError::Integrity(
                "restore partial changed before publication".into(),
            ));
        }
        if let Some(native) = &mut self.native {
            native.checkpoint_publication()?;
            native.prepare_publication(&partial, &planned.destination)?;
            native.flush_intents()?;
            native.execute_publication(&planned.destination)?;
            native.flush_namespace()?;
        } else {
            #[cfg(windows)]
            return Err(StateError::Conflict(
                "Windows publication requires typed native filesystem authority".into(),
            ));
            #[cfg(unix)]
            {
                if native_no_overwrite(self.plan) {
                    // linkat is create-new, unlike rename which could clobber a
                    // leaf raced into place after preflight.
                    leaf::publish_new(
                        &partial,
                        &planned.destination,
                        native_boundary(self.plan)?.as_ref(),
                    )?;
                    self.track_created_path(&planned.destination)?;
                } else {
                    if !planned.existed {
                        self.track_created_path(&planned.destination)?;
                    }
                    fs::rename(&partial, &planned.destination)?;
                }
            }
        }
        let published_identity = VerifiedIdentity::from_path(&planned.destination)?;
        if !published_identity.is_regular() || !verified.matches_after_rename(published_identity) {
            return Err(StateError::Integrity(
                "restored file changed during publication".into(),
            ));
        }
        sync_parent_directory(&planned.destination)?;
        if !published_identity.matches_path(&planned.destination) {
            return Err(StateError::Integrity(
                "restored file changed during publication".into(),
            ));
        }
        self.verified_files
            .insert(planned.manifest_index, published_identity);
        if let Some(native) = &mut self.native {
            native.record_publication_receipt(&planned.destination)?;
            native.flush_intents()?;
        }
        self.clear_partial(&partial)?;
        Ok(())
    }

    fn publish_symlink(&mut self, file: &ManifestFile, planned: &PlannedDestination) -> Result<()> {
        if let Some(native) = &mut self.native {
            return native.publish_symlink(file, &planned.destination);
        }
        #[cfg(windows)]
        return Err(StateError::Conflict(
            "Windows link publication requires typed native authority and link kind".into(),
        ));
        #[cfg(unix)]
        {
            let target = file
                .symlink_target
                .as_deref()
                .ok_or_else(|| StateError::Invalid("symlink missing target".into()))?;
            validate_symlink_target_within_root(&file.relative_path, target)?;
            let parent = planned.destination.parent().ok_or_else(|| {
                StateError::UnsafePath(format!(
                    "destination has no parent: {}",
                    planned.destination.display()
                ))
            })?;
            self.create_directory_chain_journaled(&planned.root, parent)?;
            validate_parent_chain(&planned.root, &planned.destination)?;
            let partial = destination_partial_path(&planned.destination, self.plan.restore_id)?;
            self.track_partial(&partial)?;
            remove_recovery_leaf(&partial)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &partial)?;
            if !planned.existed {
                self.track_created_path(&planned.destination)?;
            }
            fs::rename(&partial, &planned.destination)?;
            sync_parent_directory(&planned.destination)?;
            self.clear_partial(&partial)?;
            Ok(())
        }
    }
}

impl Drop for RestoreTransaction<'_> {
    fn drop(&mut self) {
        if self.state == TransactionState::Active {
            let _ = self.abort();
        }
    }
}

/// Recovers restore workspaces left by a process crash. Active journals are rolled back;
/// committed journals and workspaces created before the first destination mutation are cleaned.
/// A workspace is retained when its journal is invalid or any rollback step fails.
pub fn recover_interrupted_restores(paths: &AgentPaths) -> Result<RestoreRecoveryReport> {
    #[cfg(windows)]
    {
        let _ = paths;
        return Err(StateError::Conflict("Windows restore recovery is explicit, consent-bound and device authenticated; automatic legacy replay is unsupported".into()));
    }
    #[cfg(unix)]
    {
        let mut report = RestoreRecoveryReport::default();
        let metadata = match fs::symlink_metadata(&paths.restore) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StateError::UnsafePath(format!(
                "restore workspace root is not a directory: {}",
                paths.restore.display()
            )));
        }
        let entries = fs::read_dir(&paths.restore)?;
        let mut workspaces = entries
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        workspaces.sort();

        for workspace in workspaces {
            report.workspaces_scanned += 1;
            let result = recover_restore_workspace(&workspace);
            match result {
                Ok(WorkspaceRecovery::RolledBack) => report.workspaces_rolled_back += 1,
                Ok(WorkspaceRecovery::CommittedCleaned) => report.committed_workspaces_cleaned += 1,
                Ok(WorkspaceRecovery::UnjournaledCleaned) => {
                    report.unjournaled_workspaces_cleaned += 1
                }
                Err(error) => report.failures.push(RestoreRecoveryFailure {
                    workspace,
                    error: error.to_string(),
                }),
            }
        }

        // Removing successful workspaces releases their staged hardlinks. Zero-budget pruning then
        // removes all packs not still protected by a failed recovery workspace.
        let _ = prune_local_pack_cache(
            &paths.cache.join("restore-packs"),
            &PackCacheGcOptions::new(0, 0),
        );
        Ok(report)
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum WorkspaceRecovery {
    RolledBack,
    CommittedCleaned,
    UnjournaledCleaned,
}

#[cfg(unix)]
fn recover_restore_workspace(workspace: &Path) -> Result<WorkspaceRecovery> {
    let metadata = fs::symlink_metadata(workspace)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StateError::UnsafePath(format!(
            "restore workspace is not a directory: {}",
            workspace.display()
        )));
    }
    if native::is_native_workspace(workspace) {
        return Err(StateError::Conflict(
            "native restore workspace requires its device-authenticated frozen recovery control; retained without path replay".into(),
        ));
    }
    let journal_path = workspace.join(TRANSACTION_JOURNAL_FILE);
    let journal_metadata = match fs::symlink_metadata(&journal_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            remove_directory_tree_durable(workspace)?;
            return Ok(WorkspaceRecovery::UnjournaledCleaned);
        }
        Err(error) => return Err(error.into()),
    };
    if !journal_metadata.is_file() || journal_metadata.file_type().is_symlink() {
        return Err(StateError::UnsafePath(format!(
            "restore transaction journal is not a regular file: {}",
            journal_path.display()
        )));
    }
    let journal = journal::read(workspace)?;
    if workspace
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| Uuid::parse_str(name).ok())
        != Some(journal.restore_id)
    {
        return Err(StateError::Invalid(format!(
            "restore transaction journal ID does not match workspace {}",
            workspace.display()
        )));
    }
    validate_recovery_journal(workspace, &journal)?;
    match journal.state {
        JournalState::Committed => {
            remove_directory_tree_durable(workspace)?;
            Ok(WorkspaceRecovery::CommittedCleaned)
        }
        JournalState::Active => {
            rollback_from_journal(workspace, &journal)?;
            remove_directory_tree_durable(workspace)?;
            Ok(WorkspaceRecovery::RolledBack)
        }
    }
}

#[cfg(unix)]
fn persist_transaction_journal(
    workspace: &Path,
    journal: &RestoreTransactionJournal,
) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (workspace, journal);
        return Err(StateError::Conflict(
            "Windows cannot persist an unsigned legacy restore cleanup grant".into(),
        ));
    }
    #[cfg(unix)]
    {
        fs::create_dir_all(workspace)?;
        let workspace_metadata = fs::symlink_metadata(workspace)?;
        if workspace_metadata.file_type().is_symlink() || !workspace_metadata.is_dir() {
            return Err(StateError::UnsafePath(format!(
                "restore workspace is not a directory: {}",
                workspace.display()
            )));
        }
        let path = workspace.join(TRANSACTION_JOURNAL_FILE);
        let temporary = workspace.join(format!("{TRANSACTION_JOURNAL_FILE}.partial"));
        if let Some(metadata) = symlink_metadata_if_present(&temporary)? {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                return Err(StateError::UnsafePath(format!(
                    "restore transaction journal temporary path is a directory: {}",
                    temporary.display()
                )));
            }
            fs::remove_file(&temporary)?;
        }
        let bytes = serde_json::to_vec_pretty(journal)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        fs::File::open(workspace)?.sync_all()?;
        // fsync(workspace) persists its children, not the workspace's own name.
        // Include every ancestor: prepare_restore/create_view may have just created
        // the restore root or state root as well. This precedes all destination writes.
        for parent in fs::canonicalize(workspace)?.ancestors().skip(1) {
            let directory = fs::File::open(parent)?;
            // An existing mount boundary cannot have been created by this restore.
            // In particular, do not fsync macOS's read-only system-volume ancestors.
            if directory.metadata()?.dev() != workspace_metadata.dev() {
                break;
            }
            directory.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_rollback_view(view: &SnapshotView, sources: &[PathBuf]) -> Result<()> {
    if view.consistency != ConsistencyKind::Snapshot
        || view.mappings.len() != sources.len()
        || view
            .mappings
            .iter()
            .zip(sources)
            .any(|(mapping, source)| &mapping.source != source)
    {
        return Err(StateError::Integrity(
            "restore requires a complete stable rollback snapshot".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_snapshot_view(rollback_root: &Path, view: &SnapshotView) -> Result<()> {
    let mut directories = BTreeSet::new();
    directories.insert(rollback_root.to_path_buf());
    for mapping in &view.mappings {
        let relative = mapping.staged.strip_prefix(rollback_root).map_err(|_| {
            StateError::UnsafePath(format!(
                "rollback artifact escapes restore staging: {}",
                mapping.staged.display()
            ))
        })?;
        if relative.as_os_str().is_empty() {
            return Err(StateError::UnsafePath(format!(
                "invalid rollback artifact path: {}",
                mapping.staged.display()
            )));
        }
        let metadata = fs::symlink_metadata(&mapping.staged)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(StateError::UnsafePath(format!(
                "rollback artifact is not a regular file: {}",
                mapping.staged.display()
            )));
        }
        fs::File::open(&mapping.staged)?.sync_all()?;

        let mut directory = mapping.staged.parent();
        while let Some(path) = directory {
            directories.insert(path.to_path_buf());
            if path == rollback_root {
                break;
            }
            directory = path.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_recovery_journal(workspace: &Path, journal: &RestoreTransactionJournal) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (workspace, journal);
        return Err(StateError::Conflict(
            "Windows legacy restore journals are not native recovery authority".into(),
        ));
    }
    #[cfg(unix)]
    {
        if !(1..=TRANSACTION_JOURNAL_VERSION).contains(&journal.version) {
            return Err(StateError::Invalid(format!(
                "unsupported restore transaction journal version {}",
                journal.version
            )));
        }
        validate_absolute_journal_path(workspace, "restore workspace")?;
        if let Some((boundary, identity)) = &journal.native_boundary {
            validate_absolute_journal_path(boundary, "native recovery boundary")?;
            let observed = noland_snapshot::SourcePath::new(boundary)?.metadata()?;
            if !observed.is_dir()
                || observed.is_symlink()
                || (observed.dev(), observed.ino()) != *identity
                || !journal.rollback_mappings.is_empty()
                || !journal.prior_symlinks.is_empty()
                || !journal.tombstone_guards.is_empty()
            {
                return Err(StateError::Conflict(
                    "native restore recovery boundary changed; preserving recovery artifacts"
                        .into(),
                ));
            }
        }
        for root in &journal.allowed_roots {
            validate_absolute_journal_path(root, "journaled logical root")?;
        }
        let rollback_root = workspace.join("pre_restore");
        for mapping in &journal.rollback_mappings {
            validate_recovery_destination(journal, &mapping.source)?;
            validate_absolute_journal_path(&mapping.staged, "rollback artifact")?;
            let relative = mapping.staged.strip_prefix(&rollback_root).map_err(|_| {
                StateError::UnsafePath(format!(
                    "rollback artifact escapes restore workspace: {}",
                    mapping.staged.display()
                ))
            })?;
            if relative.as_os_str().is_empty()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(StateError::UnsafePath(format!(
                    "invalid rollback artifact path: {}",
                    mapping.staged.display()
                )));
            }
            validate_parent_chain(workspace, &mapping.staged)?;
        }
        for rollback in &journal.prior_symlinks {
            validate_recovery_destination(journal, &rollback.destination)?;
        }
        for guard in &journal.tombstone_guards {
            validate_recovery_destination(journal, &guard.destination)?;
        }
        for path in journal
            .created_paths
            .iter()
            .chain(&journal.created_directories)
            .chain(&journal.partial_paths)
        {
            validate_recovery_destination(journal, path)?;
        }
        Ok(())
    }
}

fn validate_absolute_journal_path(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(StateError::UnsafePath(format!(
            "{description} is not a normalized absolute path: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_recovery_destination(
    journal: &RestoreTransactionJournal,
    destination: &Path,
) -> Result<()> {
    validate_absolute_journal_path(destination, "recovery destination")?;
    if let Some((boundary, identity)) = &journal.native_boundary {
        if !destination.starts_with(boundary) || destination == boundary {
            return Err(StateError::UnsafePath(
                "native recovery escaped its approved boundary".into(),
            ));
        }
        match noland_snapshot::SourcePath::new_beneath(destination, boundary, *identity) {
            Ok(_) => {}
            Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let root = journal
        .allowed_roots
        .iter()
        .filter(|root| destination.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or_else(|| {
            StateError::UnsafePath(format!(
                "recovery destination is outside journaled logical roots: {}",
                destination.display()
            ))
        })?;
    validate_parent_chain(root, destination)
}

#[cfg(unix)]
fn rollback_from_journal(workspace: &Path, journal: &RestoreTransactionJournal) -> Result<()> {
    if journal.native_boundary.is_some() {
        return Err(StateError::Conflict("native restore artifacts require explicit identity-verified cleanup; automatic path-based rollback is disabled".into()));
    }
    validate_recovery_journal(workspace, journal)?;
    for guard in &journal.tombstone_guards {
        validate_tombstone_recovery(journal, guard)?;
    }
    let mut first_error = None;
    for partial in &journal.partial_paths {
        record_cleanup_error(
            remove_native_or_source_recovery_leaf(journal, partial),
            &mut first_error,
        );
    }
    for path in journal.created_paths.iter().rev() {
        record_cleanup_error(
            remove_native_or_source_recovery_leaf(journal, path),
            &mut first_error,
        );
    }
    for mapping in journal.rollback_mappings.iter().rev() {
        record_cleanup_error(restore_regular_mapping(journal, mapping), &mut first_error);
    }
    for rollback in journal.prior_symlinks.iter().rev() {
        record_cleanup_error(restore_prior_symlink(journal, rollback), &mut first_error);
    }
    let mut directories = journal.created_directories.clone();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if let Some((boundary, identity)) = &journal.native_boundary {
            let result = noland_snapshot::SourcePath::new_beneath(&directory, boundary, *identity)
                .and_then(|source| source.remove_empty_directory());
            match result {
                Ok(()) => {}
                Err(StateError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => record_cleanup_error(Err(error), &mut first_error),
            }
            continue;
        }
        match fs::remove_dir(&directory) {
            Ok(()) => record_cleanup_error(sync_parent_directory(&directory), &mut first_error),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                record_cleanup_error(sync_existing_ancestor(&directory), &mut first_error);
            }
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => record_cleanup_error(Err(error.into()), &mut first_error),
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(unix)]
fn remove_native_or_source_recovery_leaf(
    journal: &RestoreTransactionJournal,
    path: &Path,
) -> Result<()> {
    let Some((boundary, identity)) = &journal.native_boundary else {
        return remove_recovery_leaf_durable(path);
    };
    let result = (|| {
        let source = noland_snapshot::SourcePath::new_beneath(path, boundary, *identity)?;
        let metadata = source.metadata()?;
        source.delete_leaf(&metadata)
    })();
    match result {
        Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(unix)]
fn validate_tombstone_recovery(
    journal: &RestoreTransactionJournal,
    guard: &JournalTombstoneGuard,
) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (journal, guard);
        return Err(StateError::Conflict(
            "Windows tombstone recovery requires authenticated native ownership".into(),
        ));
    }
    #[cfg(unix)]
    {
        let current = leaf::observe(&guard.destination)?;
        if guard.observation.same_parent(current) {
            if current.identity.is_none() || current.identity == guard.observation.identity {
                return Ok(());
            }
            // Recovery itself installs a new inode. Accept already-restored bytes
            // on a repeated pass, while refusing to overwrite a swapped-in leaf.
            if let Some(mapping) = journal
                .rollback_mappings
                .iter()
                .find(|mapping| mapping.source == guard.destination)
            {
                let staged = fs::symlink_metadata(&mapping.staged)?;
                let metadata = symlink_metadata_if_present(&guard.destination)?;
                if identity::verify_contents(
                    &guard.destination,
                    &noland_cas::blake3_file(&mapping.staged)?,
                    staged.len(),
                    Some(staged.mode()),
                    metadata.as_ref(),
                )?
                .is_some()
                {
                    return Ok(());
                }
            } else if let Some(rollback) = journal
                .prior_symlinks
                .iter()
                .find(|rollback| rollback.destination == guard.destination)
            {
                if fs::read_link(&guard.destination).is_ok_and(|target| target == rollback.target)
                    && leaf::observe(&guard.destination)? == current
                {
                    return Ok(());
                }
            }
        }
        Err(StateError::UnsafePath(
            "tombstone replacement prevents safe rollback; retaining recovery workspace".into(),
        ))
    }
}

#[cfg(unix)]
fn restore_regular_mapping(
    journal: &RestoreTransactionJournal,
    mapping: &JournalPathMapping,
) -> Result<()> {
    let metadata = fs::symlink_metadata(&mapping.staged).map_err(|error| {
        StateError::Invalid(format!(
            "rollback artifact {} is unavailable: {error}",
            mapping.staged.display()
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(StateError::UnsafePath(format!(
            "unsupported rollback artifact type: {}",
            mapping.staged.display()
        )));
    }
    validate_recovery_destination(journal, &mapping.source)?;
    require_destination_parent(&mapping.source)?;
    ensure_recovery_leaf_replaceable(&mapping.source)?;

    let partial = rollback_partial_path(&mapping.source, journal.restore_id)?;
    validate_recovery_destination(journal, &partial)?;
    remove_recovery_leaf(&partial)?;
    fs::copy(&mapping.staged, &partial)?;
    fs::File::open(&partial)?.sync_all()?;
    fs::rename(&partial, &mapping.source)?;
    sync_parent_directory(&mapping.source)
}

#[cfg(unix)]
fn restore_prior_symlink(
    journal: &RestoreTransactionJournal,
    rollback: &JournalSymlinkRollback,
) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (journal, rollback);
        return Err(StateError::Conflict(
            "Windows legacy symlink reconstruction has no authenticated native link kind".into(),
        ));
    }
    #[cfg(unix)]
    {
        validate_recovery_destination(journal, &rollback.destination)?;
        require_destination_parent(&rollback.destination)?;
        ensure_recovery_leaf_replaceable(&rollback.destination)?;

        let partial = rollback_partial_path(&rollback.destination, journal.restore_id)?;
        validate_recovery_destination(journal, &partial)?;
        remove_recovery_leaf(&partial)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&rollback.target, &partial)?;
        fs::rename(&partial, &rollback.destination)?;
        sync_parent_directory(&rollback.destination)
    }
}

fn resolve_destination(roots: &LogicalRootMap, file: &ManifestFile) -> Result<(PathBuf, PathBuf)> {
    validate_relative_path(&file.relative_path)?;
    let logical = file
        .logical_root_parsed()
        .ok_or_else(|| StateError::UnsafePath(file.logical_root.clone()))?;
    let root = roots
        .resolve(&logical)
        .ok_or_else(|| StateError::NotFound(format!("logical root {}", file.logical_root)))?;
    let root = canonicalize_root_if_present(root)?;
    let destination = join_validated(&root, &file.relative_path)?;
    Ok((root, destination))
}

fn canonicalize_root_if_present(root: PathBuf) -> Result<PathBuf> {
    let mut ancestor = root.as_path();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                // canonicalize follows ancestor symlinks and would turn an
                // attacker-controlled alias into accepted restore authority.
                let source = noland_snapshot::SourcePath::new(ancestor)?;
                if metadata.file_type().is_symlink() || !source.metadata()?.is_dir() {
                    return Err(StateError::UnsafePath(
                        "restore root traverses a symlink or non-directory".into(),
                    ));
                }
                return Ok(root);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    StateError::UnsafePath(format!(
                        "logical root has no existing ancestor: {}",
                        root.display()
                    ))
                })?;
                missing.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    StateError::UnsafePath(format!(
                        "logical root has no existing ancestor: {}",
                        root.display()
                    ))
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn native_no_overwrite(plan: &RestorePlan) -> bool {
    plan.manifest.environment["quicksave_native_download"]["no_overwrite"].as_bool() == Some(true)
}

fn native_boundary(plan: &RestorePlan) -> Result<Option<(PathBuf, (u64, u64))>> {
    #[cfg(windows)]
    {
        let _ = plan;
        return Err(StateError::Conflict(
            "Windows native boundaries cannot use truncated Unix inode approvals".into(),
        ));
    }
    #[cfg(unix)]
    {
        if plan
            .manifest
            .environment
            .get("quicksave_native_download")
            .is_none()
        {
            return Ok(None);
        }
        let value = &plan.manifest.environment["quicksave_native_download"];
        let boundary = value["destination"]
            .as_str()
            .ok_or_else(|| StateError::Invalid("native restore boundary missing".into()))?;
        let identity: (u64, u64) = serde_json::from_value(value["identity"].clone())?;
        Ok(Some((PathBuf::from(boundary), identity)))
    }
}

fn validate_parent_chain(root: &Path, destination: &Path) -> Result<()> {
    validate_directory_component(root)?;
    if destination == root {
        return Ok(());
    }
    let parent = destination.parent().ok_or_else(|| {
        StateError::UnsafePath(format!(
            "destination has no parent: {}",
            destination.display()
        ))
    })?;
    let relative = parent.strip_prefix(root).map_err(|_| {
        StateError::UnsafePath(format!(
            "destination {} escapes {}",
            destination.display(),
            root.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if !validate_directory_component(&current)? {
            break;
        }
    }
    Ok(())
}

fn validate_directory_component(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StateError::UnsafePath(format!(
            "destination parent is a symlink: {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(StateError::Invalid(format!(
            "destination parent is not a directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn missing_directory_chain(root: &Path, destination: &Path) -> Result<Vec<PathBuf>> {
    destination.strip_prefix(root).map_err(|_| {
        StateError::UnsafePath(format!(
            "destination {} escapes {}",
            destination.display(),
            root.display()
        ))
    })?;

    let mut missing = Vec::new();
    let mut current = destination.to_path_buf();
    loop {
        match symlink_metadata_if_present(&current)? {
            Some(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::UnsafePath(format!(
                    "destination directory is a symlink: {}",
                    current.display()
                )));
            }
            Some(metadata) if metadata.is_dir() => break,
            Some(_) => {
                return Err(StateError::Invalid(format!(
                    "destination parent is not a directory: {}",
                    current.display()
                )));
            }
            None => missing.push(current.clone()),
        }
        current = current
            .parent()
            .ok_or_else(|| {
                StateError::UnsafePath(format!(
                    "destination has no existing ancestor: {}",
                    destination.display()
                ))
            })?
            .to_path_buf();
    }

    missing.reverse();
    Ok(missing)
}

fn restore_chunk_path(plan: &RestorePlan, hash: &str) -> Result<PathBuf> {
    let token = hash.trim_start_matches("blake3:");
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StateError::Integrity(format!(
            "invalid restore chunk hash {hash}"
        )));
    }
    Ok(plan.staging.join("materialized/.chunks").join(token))
}

fn destination_partial_path(destination: &Path, restore_id: Uuid) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let leaf = destination
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or_else(|| {
                StateError::UnsafePath("Windows restore destination has no Unicode leaf".into())
            })?;
        // A valid 255-byte source basename must not become an invalid native
        // partial just because an operation suffix was appended to that name.
        let hash = blake3::hash(leaf.as_bytes()).to_hex();
        return Ok(destination.with_file_name(format!(".noland-{restore_id}-{hash}.partial")));
    }
    #[cfg(unix)]
    destination_auxiliary_path(destination, format!(".noland-{restore_id}.partial"))
}

#[cfg(unix)]
fn rollback_partial_path(destination: &Path, restore_id: Uuid) -> Result<PathBuf> {
    destination_auxiliary_path(
        destination,
        format!(".noland-{restore_id}.rollback.partial"),
    )
}

fn destination_auxiliary_path(destination: &Path, suffix: String) -> Result<PathBuf> {
    let file_name = destination.file_name().ok_or_else(|| {
        StateError::UnsafePath(format!(
            "destination has no filename: {}",
            destination.display()
        ))
    })?;
    let mut auxiliary_name = OsString::from(file_name);
    auxiliary_name.push(suffix);
    Ok(destination.with_file_name(auxiliary_name))
}

fn symlink_metadata_if_present(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn require_destination_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        StateError::UnsafePath(format!("destination has no parent: {}", path.display()))
    })?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StateError::UnsafePath(format!(
            "destination parent is a symlink: {}",
            parent.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(StateError::Invalid(format!(
            "destination parent is not a directory: {}",
            parent.display()
        ))),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn ensure_recovery_leaf_replaceable(path: &Path) -> Result<()> {
    if symlink_metadata_if_present(path)?
        .as_ref()
        .is_some_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        return Err(StateError::UnsafePath(format!(
            "recovery expected a file or symlink but found a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn remove_recovery_leaf(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = path;
        return Err(StateError::Conflict(
            "Windows path-only restore cleanup is not authorized".into(),
        ));
    }
    #[cfg(unix)]
    {
        let Some(metadata) = symlink_metadata_if_present(path)? else {
            return Ok(());
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            return Err(StateError::UnsafePath(format!(
                "recovery expected a file or symlink but found a directory: {}",
                path.display()
            )));
        }
        fs::remove_file(path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn remove_recovery_leaf_durable(path: &Path) -> Result<()> {
    remove_recovery_leaf(path)?;
    sync_existing_ancestor(path)
}

// On a second recovery pass a previously removed parent may itself be absent.
// Flush the surviving ancestry instead of making successful rollback non-idempotent.
#[cfg(unix)]
fn sync_existing_ancestor(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        if validate_directory_component(parent)? {
            fs::File::open(parent)?.sync_all()?;
            break;
        }
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::UnsafePath(format!("path has no parent: {}", path.display())))?;
    let directory = noland_snapshot::SourcePath::new(parent)?.open_directory()?;
    noland_snapshot::native_metadata::flush_directory(&directory)?;
    Ok(())
}

/// Apply only metadata represented by the authenticated manifest, on the actual
/// opened output handle. Failure is explicit (including unavailable ownership
/// privileges); Windows never pretends that Unix chmod/chown succeeded.
fn apply_file_metadata(output: &fs::File, file: &ManifestFile) -> Result<()> {
    apply_file_metadata_fields(output, file.mode, file.mtime_ns, file.uid, file.gid)
}

fn apply_file_metadata_fields(
    output: &fs::File,
    mode: Option<u32>,
    mtime_ns: Option<i64>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let metadata = output.metadata()?;
        let change_uid = uid.filter(|uid| *uid != metadata.uid());
        let change_gid = gid.filter(|gid| *gid != metadata.gid());
        if change_uid.is_some() || change_gid.is_some() {
            if unsafe {
                libc::fchown(
                    output.as_raw_fd(),
                    change_uid.unwrap_or(u32::MAX),
                    change_gid.unwrap_or(u32::MAX),
                )
            } != 0
            {
                return Err(StateError::Io(std::io::Error::last_os_error()));
            }
        }
        if let Some(mode) = mode {
            if output.metadata()?.mode() & 0o7777 != mode & 0o7777 {
                output.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
            }
        }
        if let Some(nanos) = mtime_ns {
            let modified = if nanos >= 0 {
                std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(nanos as u64))
            } else {
                std::time::UNIX_EPOCH
                    .checked_sub(std::time::Duration::from_nanos(nanos.unsigned_abs()))
            }
            .ok_or_else(|| {
                StateError::Invalid("restore mtime is not representable natively".into())
            })?;
            if output.metadata()?.modified()? != modified {
                output.set_times(fs::FileTimes::new().set_modified(modified))?;
            }
            if output.metadata()?.modified()? != modified {
                return Err(StateError::Invalid(
                    "restore mtime is not exactly representable by this native filesystem".into(),
                ));
            }
        }
        let applied = output.metadata()?;
        if mode.is_some_and(|mode| applied.mode() & 0o7777 != mode & 0o7777)
            || uid.is_some_and(|uid| applied.uid() != uid)
            || gid.is_some_and(|gid| applied.gid() != gid)
        {
            return Err(StateError::Invalid(
                "native filesystem did not preserve the approved mode/ownership metadata".into(),
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        noland_snapshot::native_metadata::apply_file_metadata(output, mode, mtime_ns, uid, gid)
    }
}

#[cfg(unix)]
fn remove_directory_tree_durable(path: &Path) -> Result<()> {
    fs::remove_dir_all(path)?;
    sync_parent_directory(path)
}

#[cfg(unix)]
fn record_cleanup_error(result: Result<()>, first_error: &mut Option<StateError>) {
    if let Err(error) = result {
        if first_error.is_none() {
            *first_error = Some(error);
        }
    }
}

pub(crate) fn include_file(mode: RestoreMode, file: &ManifestFile) -> bool {
    match mode {
        RestoreMode::CompleteApplication | RestoreMode::Custom => true,
        RestoreMode::PersonalState => {
            matches!(
                file.persistence_class,
                PersistenceClass::PersistentState | PersistenceClass::SharedState
            ) || file.semantic_role == SemanticRole::UserState
                || file.semantic_role == SemanticRole::Secret
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use chrono::Utc;
    use noland_pack::pack_chunks;
    use noland_storage::LocalStorage;

    use super::*;

    #[test]
    fn rejects_traversal_entries() {
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("ok/file").is_ok());
    }

    #[test]
    fn priority_plan_is_tiered_and_deterministic() {
        let mut manifest = test_manifest(vec![
            test_file(
                "z-cache",
                PersistenceClass::PersistentState,
                SemanticRole::Cache,
                b"cache",
            ),
            test_file(
                "b-user",
                PersistenceClass::PersistentState,
                SemanticRole::UserState,
                b"user",
            ),
            test_file(
                "a-runtime",
                PersistenceClass::SharedState,
                SemanticRole::SharedRuntime,
                b"runtime",
            ),
            test_file(
                "c-unknown",
                PersistenceClass::SharedState,
                SemanticRole::Unknown,
                b"soon",
            ),
        ]);
        let first = plan_restore_priorities(&manifest, RestoreMode::CompleteApplication);
        let order = first
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.priority,
                    manifest.files[entry.manifest_index].relative_path.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                (RestorePriority::Prerequisite, "a-runtime".to_string()),
                (RestorePriority::Critical, "b-user".to_string()),
                (RestorePriority::Soon, "c-unknown".to_string()),
                (RestorePriority::Background, "z-cache".to_string()),
            ]
        );

        manifest.files.reverse();
        let second = plan_restore_priorities(&manifest, RestoreMode::CompleteApplication);
        let second_order = second
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.priority,
                    manifest.files[entry.manifest_index].relative_path.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(order, second_order);
    }

    #[test]
    fn ready_to_launch_publishes_only_critical_tiers() {
        let root = test_dir("ready");
        let critical = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let background = test_file(
            "game/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"cache",
        );
        let manifest = test_manifest(vec![background.clone(), critical.clone()]);
        let plan = test_plan(&root, manifest);
        seed_chunks(&plan, &[&critical, &background]);
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let mut transaction = RestoreTransaction::new(&plan, &roots, None);

        let ready = transaction.publish_to(READY_TO_LAUNCH).unwrap();
        assert_eq!(ready.published_entries, 1);
        assert_eq!(
            fs::read(home.join(".local/share/game/save.dat")).unwrap(),
            b"save"
        );
        assert!(!home.join(".local/share/game/cache.bin").exists());
        assert!(!plan.staging.join("materialized/tree").exists());

        let complete = transaction.publish_to(RestoreTarget::Complete).unwrap();
        assert_eq!(complete.published_entries, 1);
        assert_eq!(
            fs::read(home.join(".local/share/game/cache.bin")).unwrap(),
            b"cache"
        );
        transaction.commit().unwrap();
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_recovery_uses_durable_journal_for_files_symlinks_directories_and_partials() {
        let root = test_dir("crash-recovery");
        let paths = AgentPaths::from_roots(root.join("state"), root.join("run"));
        paths.ensure_dirs().unwrap();
        let replaced = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let created = test_file(
            "new/deep/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"cache",
        );
        let mut symlink = test_file(
            "game/current-link",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"",
        );
        symlink.file_type = "symlink".into();
        symlink.chunks.clear();
        symlink.symlink_target = Some("new-target".into());
        let plan = crash_test_plan(
            &paths,
            test_manifest(vec![replaced.clone(), created.clone(), symlink]),
        );
        for (file, bytes) in [
            (&replaced, b"save".as_slice()),
            (&created, b"cache".as_slice()),
        ] {
            fs::write(
                restore_chunk_path(&plan, &file.chunks[0].hash).unwrap(),
                bytes,
            )
            .unwrap();
        }
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let replaced_path = home.join(".local/share/game/save.dat");
        let created_path = home.join(".local/share/new/deep/cache.bin");
        let symlink_path = home.join(".local/share/game/current-link");
        fs::create_dir_all(replaced_path.parent().unwrap()).unwrap();
        fs::write(&replaced_path, b"old-save").unwrap();
        std::os::unix::fs::symlink("old-target", &symlink_path).unwrap();

        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        let canonical_deep = fs::canonicalize(home.join(".local/share/new/deep")).unwrap();
        let partial =
            destination_partial_path(&canonical_deep.join("interrupted.bin"), plan.restore_id)
                .unwrap();
        transaction.track_partial(&partial).unwrap();
        fs::write(&partial, b"incomplete").unwrap();
        let journal = journal::read(&plan.staging).unwrap();
        assert!(!journal.rollback_mappings.is_empty());
        assert!(!journal.prior_symlinks.is_empty());
        let canonical_created_path = fs::canonicalize(&created_path).unwrap();
        assert!(journal.created_paths.contains(&canonical_created_path));
        assert!(journal
            .created_directories
            .iter()
            .any(|path| path.ends_with("new/deep")));
        assert!(journal.partial_paths.contains(&partial));
        assert!(!plan
            .staging
            .join(format!("{TRANSACTION_JOURNAL_FILE}.partial"))
            .exists());
        std::mem::forget(transaction);

        let report = recover_interrupted_restores(&paths).unwrap();

        assert_eq!(report.workspaces_rolled_back, 1);
        assert!(report.failures.is_empty());
        assert_eq!(fs::read(&replaced_path).unwrap(), b"old-save");
        assert!(!created_path.exists());
        assert_eq!(
            fs::read_link(&symlink_path).unwrap(),
            PathBuf::from("old-target")
        );
        assert!(!partial.exists());
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_recovery_removes_new_logical_root_ancestor_directories() {
        let root = test_dir("crash-new-logical-root");
        let paths = AgentPaths::from_roots(root.join("state"), root.join("run"));
        paths.ensure_dirs().unwrap();
        let file = test_file(
            "new/deep/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"cache",
        );
        let plan = crash_test_plan(&paths, test_manifest(vec![file.clone()]));
        fs::write(
            restore_chunk_path(&plan, &file.chunks[0].hash).unwrap(),
            b"cache",
        )
        .unwrap();
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/new/deep/cache.bin");

        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"cache");
        assert!(plan.staging.join(TRANSACTION_JOURNAL_FILE).exists());
        std::mem::forget(transaction);

        let report = recover_interrupted_restores(&paths).unwrap();

        assert_eq!(report.workspaces_rolled_back, 1);
        assert!(report.failures.is_empty());
        assert!(!destination.exists());
        assert!(!home.exists());
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_recovery_cleans_committed_workspace_without_reverting_destination() {
        let root = test_dir("crash-after-commit-marker");
        let paths = AgentPaths::from_roots(root.join("state"), root.join("run"));
        paths.ensure_dirs().unwrap();
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let plan = crash_test_plan(&paths, test_manifest(vec![file.clone()]));
        fs::write(
            restore_chunk_path(&plan, &file.chunks[0].hash).unwrap(),
            b"save",
        )
        .unwrap();
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/game/save.dat");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"old-save").unwrap();

        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        transaction
            .persist_journal(JournalState::Committed)
            .unwrap();
        transaction.state = TransactionState::Committed;
        std::mem::forget(transaction);

        let report = recover_interrupted_restores(&paths).unwrap();

        assert_eq!(report.committed_workspaces_cleaned, 1);
        assert!(report.failures.is_empty());
        assert_eq!(fs::read(destination).unwrap(), b"save");
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn database_failure_rearms_journal_and_rolls_back_published_destination() {
        let root = test_dir("database-failure-rollback");
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let plan = test_plan(&root, test_manifest(vec![file.clone()]));
        seed_chunks(&plan, &[&file]);
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/game/save.dat");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"old-save").unwrap();
        let db = StateDb::open_in_memory().unwrap();

        let mut transaction = RestoreTransaction::new(&plan, &roots, Some(&db));
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"save");

        let error = transaction.commit().unwrap_err();

        assert!(matches!(error, StateError::Database(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"old-save");
        assert!(!plan.staging.exists());
        assert!(db
            .get_path_by_canonical(&destination.to_string_lossy())
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_recovery_retains_workspace_when_rollback_artifact_is_missing() {
        let root = test_dir("crash-recovery-failure");
        let paths = AgentPaths::from_roots(root.join("state"), root.join("run"));
        paths.ensure_dirs().unwrap();
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let plan = crash_test_plan(&paths, test_manifest(vec![file.clone()]));
        fs::write(
            restore_chunk_path(&plan, &file.chunks[0].hash).unwrap(),
            b"save",
        )
        .unwrap();
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/game/save.dat");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"old-save").unwrap();

        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        let staged = transaction.rollback_views[0].mappings[0].staged.clone();
        fs::remove_file(staged).unwrap();
        std::mem::forget(transaction);

        let report = recover_interrupted_restores(&paths).unwrap();

        assert_eq!(report.failures.len(), 1);
        assert!(plan.staging.exists());
        assert!(plan.staging.join(TRANSACTION_JOURNAL_FILE).exists());
        assert_eq!(fs::read(destination).unwrap(), b"save");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn chunk_eviction_waits_for_enable_and_final_file_reference() {
        let root = test_dir("chunk-refs");
        let exclusive_ready = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let shared_ready = test_file(
            "game/shared-ready.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"shared",
        );
        let shared_background = test_file(
            "game/shared-background.dat",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"shared",
        );
        let exclusive_hash = exclusive_ready.chunks[0].hash.clone();
        let shared_hash = shared_ready.chunks[0].hash.clone();
        assert_eq!(shared_background.chunks[0].hash, shared_hash);
        let plan = test_plan(
            &root,
            test_manifest(vec![shared_background, exclusive_ready, shared_ready]),
        );
        fs::write(restore_chunk_path(&plan, &exclusive_hash).unwrap(), b"save").unwrap();
        fs::write(restore_chunk_path(&plan, &shared_hash).unwrap(), b"shared").unwrap();
        let roots = LogicalRootMap::from_home(root.join("home"));
        let mut transaction = RestoreTransaction::new(&plan, &roots, None);

        assert_eq!(transaction.remaining_chunk_references(&exclusive_hash), 1);
        assert_eq!(transaction.remaining_chunk_references(&shared_hash), 2);
        transaction
            .publish_to(RestoreTarget::ReadyToLaunch)
            .unwrap();
        assert_eq!(transaction.remaining_chunk_references(&exclusive_hash), 0);
        assert_eq!(transaction.remaining_chunk_references(&shared_hash), 1);
        assert!(restore_chunk_path(&plan, &exclusive_hash).unwrap().exists());
        assert!(restore_chunk_path(&plan, &shared_hash).unwrap().exists());

        assert_eq!(transaction.enable_chunk_eviction().unwrap(), 1);
        assert!(!restore_chunk_path(&plan, &exclusive_hash).unwrap().exists());
        assert!(restore_chunk_path(&plan, &shared_hash).unwrap().exists());

        transaction.publish_to(RestoreTarget::Complete).unwrap();
        assert_eq!(transaction.remaining_chunk_references(&shared_hash), 0);
        assert!(!restore_chunk_path(&plan, &shared_hash).unwrap().exists());
        assert_eq!(
            fs::read(root.join("home/.local/share/game/shared-background.dat")).unwrap(),
            b"shared"
        );
        transaction.commit().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn chunk_reference_counts_include_only_entries_selected_by_restore_mode() {
        let root = test_dir("chunk-mode");
        let personal = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let background = test_file(
            "game/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"cache",
        );
        let personal_hash = personal.chunks[0].hash.clone();
        let background_hash = background.chunks[0].hash.clone();
        let mut plan = test_plan(&root, test_manifest(vec![personal, background]));
        plan.mode = RestoreMode::PersonalState;
        let roots = LogicalRootMap::from_home(root.join("home"));
        let transaction = RestoreTransaction::new(&plan, &roots, None);

        assert_eq!(transaction.remaining_chunk_references(&personal_hash), 1);
        assert_eq!(transaction.remaining_chunk_references(&background_hash), 0);
        drop(transaction);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identical_target_skips_snapshot_and_rewrite() {
        let root = test_dir("identical-target");
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let plan = test_plan(&root, test_manifest(vec![file]));
        let home = root.join("home");
        let target = home.join(".local/share/game/save.dat");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"save").unwrap();
        let before = fs::metadata(&target).unwrap().modified().unwrap();

        let roots = LogicalRootMap::from_home(&home);
        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        let report = transaction.publish_to(RestoreTarget::Complete).unwrap();

        assert_eq!(report.reused_entries, 1);
        assert_eq!(report.published_entries, 0);
        assert_eq!(fs::read(&target).unwrap(), b"save");
        assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), before);
        assert!(fs::read_dir(plan.staging.join("pre_restore"))
            .unwrap()
            .next()
            .is_none());
        transaction.commit().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn published_target_is_reused_when_chunks_are_gone() {
        let root = test_dir("materialize-resume");
        let payload = [vec![b'a'; 1024 * 1024], vec![b'b'; 1024 * 1024]].concat();
        let mut file = test_file(
            "game/large.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            &payload,
        );
        file.chunks = vec![
            ChunkRef {
                hash: noland_cas::blake3_hex(&payload[..1024 * 1024]),
                size: 1024 * 1024,
            },
            ChunkRef {
                hash: noland_cas::blake3_hex(&payload[1024 * 1024..]),
                size: 1024 * 1024,
            },
        ];
        let manifest = test_manifest(vec![file.clone()]);
        let plan = test_plan(&root, manifest.clone());
        seed_chunks(&plan, &[&file]);
        let roots = LogicalRootMap::from_home(root.join("home"));

        let mut transaction = RestoreTransaction::new(&plan, &roots, None);
        transaction.publish_to(RestoreTarget::Complete).unwrap();
        transaction.commit().unwrap();

        let retry_plan = test_plan(&root.join("retry"), manifest);
        fs::remove_dir_all(retry_plan.staging.join("materialized/.chunks")).unwrap();
        let mut retry = RestoreTransaction::new(&retry_plan, &roots, None);
        let report = retry.publish_to(RestoreTarget::Complete).unwrap();

        let destination = root.join("home/.local/share/game/large.dat");
        assert_eq!(report.published_entries, 0);
        assert_eq!(report.reused_entries, 1);
        assert_eq!(
            fs::metadata(&destination).unwrap().len(),
            payload.len() as u64
        );
        assert_eq!(
            blake3_file(&destination).unwrap(),
            noland_cas::blake3_hex(&payload)
        );
        assert!(!retry_plan.staging.join("materialized/tree").exists());
        retry.commit().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dropping_active_transaction_rolls_back_replaced_and_created_files() {
        let root = test_dir("drop-rollback");
        let replaced = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let created = test_file(
            "game/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            b"cache",
        );
        let plan = test_plan(
            &root,
            test_manifest(vec![replaced.clone(), created.clone()]),
        );
        seed_chunks(&plan, &[&replaced, &created]);
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let replaced_path = home.join(".local/share/game/save.dat");
        let created_path = home.join(".local/share/game/cache.bin");
        fs::create_dir_all(replaced_path.parent().unwrap()).unwrap();
        fs::write(&replaced_path, b"old-save").unwrap();
        let cached_pack = plan.pack_cache.join("aa/aa-cancelled.pack");
        fs::create_dir_all(cached_pack.parent().unwrap()).unwrap();
        fs::write(&cached_pack, b"cached pack").unwrap();
        let staged_pack = plan.staging.join("packs/aa-cancelled.pack");
        fs::hard_link(&cached_pack, &staged_pack).unwrap();

        {
            let mut transaction = RestoreTransaction::new(&plan, &roots, None);
            transaction.publish_to(RestoreTarget::Complete).unwrap();
            assert_eq!(fs::read(&replaced_path).unwrap(), b"save");
            assert_eq!(fs::read(&created_path).unwrap(), b"cache");
        }

        assert_eq!(fs::read(&replaced_path).unwrap(), b"old-save");
        assert!(!created_path.exists());
        assert!(!plan.staging.exists());
        assert!(!cached_pack.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_reconstruction_keeps_old_destination_and_removes_partial() {
        let root = test_dir("corrupt-atomic");
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            b"save",
        );
        let plan = test_plan(&root, test_manifest(vec![file.clone()]));
        seed_chunks(&plan, &[&file]);
        let chunk = &file.chunks[0];
        fs::write(
            plan.staging
                .join("materialized/.chunks")
                .join(chunk.hash.trim_start_matches("blake3:")),
            b"evil",
        )
        .unwrap();
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/game/save.dat");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"old-save").unwrap();
        let partial = destination_partial_path(&destination, plan.restore_id).unwrap();

        {
            let mut transaction = RestoreTransaction::new(&plan, &roots, None);
            assert!(transaction.publish_to(RestoreTarget::Complete).is_err());
        }

        assert_eq!(fs::read(&destination).unwrap(), b"old-save");
        assert!(!partial.exists());
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn abort_restores_complete_phase_tombstone() {
        let root = test_dir("tombstone-rollback");
        let mut manifest = test_manifest(Vec::new());
        manifest.tombstones.push(ManifestTombstone {
            logical_root: "$XDG_DATA_HOME".into(),
            relative_path: "game/deleted.dat".into(),
            reason: "deleted at source".into(),
        });
        let plan = test_plan(&root, manifest);
        let home = root.join("home");
        let roots = LogicalRootMap::from_home(&home);
        let destination = home.join(".local/share/game/deleted.dat");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"keep-on-abort").unwrap();

        {
            let mut transaction = RestoreTransaction::new(&plan, &roots, None);
            transaction.publish_to(RestoreTarget::Complete).unwrap();
            assert!(!destination.exists());
        }

        assert_eq!(fs::read(&destination).unwrap(), b"keep-on-abort");
        assert!(!plan.staging.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_pack_release_unlinks_staging_before_full_cache_prune() {
        let root = test_dir("release-staged-pack");
        let plan = test_plan(&root, test_manifest(Vec::new()));
        let pack_id = "aa-release";
        let cached_pack = plan.pack_cache.join("aa").join(format!("{pack_id}.pack"));
        fs::create_dir_all(cached_pack.parent().unwrap()).unwrap();
        fs::write(&cached_pack, b"verified pack").unwrap();
        let staged_pack = plan.staging.join("packs").join(format!("{pack_id}.pack"));
        fs::hard_link(&cached_pack, &staged_pack).unwrap();
        let roots = LogicalRootMap::from_home(root.join("home"));
        let transaction = RestoreTransaction::new(&plan, &roots, None);

        assert_eq!(transaction.release_staged_pack_links().unwrap(), 1);
        assert!(!staged_pack.exists());
        assert!(cached_pack.exists());
        let report = transaction.prune_restore_pack_cache().unwrap();
        assert_eq!(report.packs_pruned, 1);
        assert_eq!(report.packs_after, 0);
        assert!(!cached_pack.exists());
        transaction.commit().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn downloaded_pack_cache_is_reused_after_remote_disappears() {
        let root = test_dir("pack-cache");
        let remote = root.join("remote");
        let built = root.join("built");
        let master = MasterKey::generate();
        let payload = b"portable-state".to_vec();
        let background_payload = b"rebuildable-cache".to_vec();
        let hash = noland_cas::blake3_hex(&payload);
        let background_hash = noland_cas::blake3_hex(&background_payload);
        let packs = pack_chunks(
            &built,
            &master,
            vec![
                (hash.clone(), payload.clone()),
                (background_hash.clone(), background_payload.clone()),
            ],
            |_| false,
        )
        .unwrap();
        let pack = &packs[0];
        let remote_pack = remote.join(noland_state_core::pack_key(&pack.pack_id));
        fs::create_dir_all(remote_pack.parent().unwrap()).unwrap();
        fs::copy(&pack.path, &remote_pack).unwrap();

        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            &payload,
        );
        let background = test_file(
            "game/cache.bin",
            PersistenceClass::Ephemeral,
            SemanticRole::Cache,
            &background_payload,
        );
        let manifest = test_manifest(vec![background, file]);
        let first = test_plan(&root.join("first"), manifest.clone());
        let storage = LocalStorage::new(&remote);
        let first_report = block_on(download_and_verify_to(
            &storage,
            &master,
            &first,
            &pack.entries,
            READY_TO_LAUNCH,
            DownloadOptions {
                max_parallel_packs: 2,
            },
            None,
        ))
        .unwrap();
        assert_eq!(first_report.packs_downloaded, 1);
        assert_eq!(first_report.chunks_extracted, 1);
        assert!(!first
            .staging
            .join("materialized/.chunks")
            .join(background_hash.trim_start_matches("blake3:"))
            .exists());

        fs::remove_file(remote_pack).unwrap();
        let mut second = test_plan(&root.join("second"), manifest);
        second.pack_cache = first.pack_cache.clone();
        let second_report = block_on(download_and_verify_to(
            &storage,
            &master,
            &second,
            &pack.entries,
            RestoreTarget::Complete,
            DownloadOptions::default(),
            None,
        ))
        .unwrap();
        assert_eq!(second_report.packs_downloaded, 0);
        assert_eq!(second_report.packs_reused, 1);
        assert_eq!(second_report.chunks_extracted, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn planned_pack_count_excludes_irrelevant_and_locally_satisfied_packs() {
        let root = test_dir("planned-pack-count");
        let master = MasterKey::generate();
        let needed_payload = b"needed-state".to_vec();
        let irrelevant_payload = b"old-parent-state".to_vec();
        let needed_hash = noland_cas::blake3_hex(&needed_payload);
        let irrelevant_hash = noland_cas::blake3_hex(&irrelevant_payload);
        let needed_pack = pack_chunks(
            &root.join("needed-pack"),
            &master,
            vec![(needed_hash.clone(), needed_payload.clone())],
            |_| false,
        )
        .unwrap()
        .remove(0);
        let irrelevant_pack = pack_chunks(
            &root.join("irrelevant-pack"),
            &master,
            vec![(irrelevant_hash, irrelevant_payload)],
            |_| false,
        )
        .unwrap()
        .remove(0);
        let mut index = needed_pack.entries;
        index.extend(irrelevant_pack.entries);
        let file = test_file(
            "game/save.dat",
            PersistenceClass::PersistentState,
            SemanticRole::UserState,
            &needed_payload,
        );
        let plan = test_plan(&root, test_manifest(vec![file]));

        assert_eq!(
            planned_pack_download_count(&plan, &index, RestoreTarget::Complete).unwrap(),
            1
        );
        let chunk = plan
            .staging
            .join("materialized/.chunks")
            .join(needed_hash.trim_start_matches("blake3:"));
        fs::write(chunk, needed_payload).unwrap();
        assert_eq!(
            planned_pack_download_count(&plan, &index, RestoreTarget::Complete).unwrap(),
            0
        );
        let _ = fs::remove_dir_all(root);
    }

    pub(super) fn test_manifest(files: Vec<ManifestFile>) -> BundleManifest {
        let mut manifest = BundleManifest::new(
            ManifestApp {
                app_id: AppId::desktop("restore-test"),
                display_name: "Restore Test".into(),
                aliases: Vec::new(),
                desktop_entry_id: None,
                steam_app_id: None,
                launcher: None,
                canonical_executable: None,
                icon_path: None,
            },
            ManifestSource {
                instance_id: Uuid::new_v4(),
                image_id: "test".into(),
                captured_at: Utc::now(),
            },
            BackupMode::CompleteApplication,
        );
        manifest.files = files;
        manifest
    }

    pub(super) fn test_file(
        path: &str,
        persistence_class: PersistenceClass,
        semantic_role: SemanticRole,
        payload: &[u8],
    ) -> ManifestFile {
        let hash = noland_cas::blake3_hex(payload);
        ManifestFile {
            logical_root: "$XDG_DATA_HOME".into(),
            relative_path: path.into(),
            source_path_hint: None,
            file_type: "file".into(),
            size: payload.len() as u64,
            file_hash: hash.clone(),
            chunks: vec![ChunkRef {
                hash,
                size: payload.len() as u64,
            }],
            mode: None,
            mtime_ns: None,
            uid: None,
            gid: None,
            symlink_target: None,
            persistence_class,
            semantic_role,
            association_confidence: 1.0,
            shared_app_ids: Vec::new(),
        }
    }

    pub(super) fn crash_test_plan(paths: &AgentPaths, manifest: BundleManifest) -> RestorePlan {
        let restore_id = Uuid::new_v4();
        let staging = paths.restore_dir(&restore_id.to_string());
        for child in ["packs", "materialized/.chunks", "pre_restore"] {
            fs::create_dir_all(staging.join(child)).unwrap();
        }
        RestorePlan {
            restore_id,
            staging,
            pack_cache: paths.cache.join("restore-packs"),
            manifest,
            mode: RestoreMode::CompleteApplication,
        }
    }

    pub(super) fn test_plan(root: &Path, manifest: BundleManifest) -> RestorePlan {
        let staging = root.join("restore");
        for child in ["packs", "materialized/.chunks", "pre_restore"] {
            fs::create_dir_all(staging.join(child)).unwrap();
        }
        RestorePlan {
            restore_id: Uuid::new_v4(),
            staging,
            pack_cache: root.join("cache/restore-packs"),
            manifest,
            mode: RestoreMode::CompleteApplication,
        }
    }

    fn seed_chunks(plan: &RestorePlan, files: &[&ManifestFile]) {
        for file in files {
            let payload = match file.relative_path.as_str() {
                "game/save.dat" => b"save".to_vec(),
                "game/cache.bin" => b"cache".to_vec(),
                "game/large.dat" => [vec![b'a'; 1024 * 1024], vec![b'b'; 1024 * 1024]].concat(),
                other => panic!("no test payload for {other}"),
            };
            let mut offset = 0;
            for chunk in &file.chunks {
                let end = offset + chunk.size as usize;
                let bytes = &payload[offset..end];
                assert_eq!(chunk.hash, noland_cas::blake3_hex(bytes));
                fs::write(
                    plan.staging
                        .join("materialized/.chunks")
                        .join(chunk.hash.trim_start_matches("blake3:")),
                    bytes,
                )
                .unwrap();
                offset = end;
            }
            assert_eq!(offset, payload.len());
        }
    }

    pub(super) fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("noland-restore-{label}-{}", Uuid::new_v4()))
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    pub(super) fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
