// SPDX-License-Identifier: GPL-3.0-only
//! Native, explicitly authorized, read-only source tracking.
//!
//! Original QuickSave code. Watcher events are hints, never confirmation of a
//! cloud upload. The injected service owns all cloud writes and native consent.
#![forbid(unsafe_code)]

mod approval;
mod bundle;
mod diagnostics;
mod metadata_index;
mod model;
mod native;
mod receipt;
mod scan;
pub mod scheduler;
mod trackingresume;

pub use metadata_index::{MetadataIndexRevisionChanged, NativeMetadataIndex};
pub use model::{
    file_id, ApprovedRoot, RootIdentity, TrackedSoftware, TrackingClock, TrackingPolicy,
};
use model::{
    validate_id, validate_name, ApprovedRoot as Root, Snapshot, MAX_FILES, MAX_PAGE, MAX_ROOTS,
    MAX_SELECTION, MAX_SOFTWARE,
};
pub use receipt::NativeCaptureReceipt;
use scheduler::Scheduler;
pub use trackingresume::NativeFrozenWork;

use anyhow::{bail, ensure, Context, Result};

/// Denial-only marker supplied by a native store, not renderer input. A spent
/// explicit refresh can renew a pristine metadata-only enrollment after fully
/// revalidating its unchanged roots under the current native policy.
#[derive(Debug)]
pub struct DeferredLegacyAuthority;
impl std::fmt::Display for DeferredLegacyAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The prior local approval is deferred. Explicit credential import is required unless an unchanged, never-captured metadata scope can be reapproved.")
    }
}
impl std::error::Error for DeferredLegacyAuthority {}
/// A synchronous metadata projection raced a workspace write. Not a denial,
/// grant, or worker/publication retry; the caller must discard the whole DTO.
#[derive(Debug)]
pub struct TrackingProjectionChanged;
impl std::fmt::Display for TrackingProjectionChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tracking metadata projection changed; discard this read")
    }
}
impl std::error::Error for TrackingProjectionChanged {}
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{sync_channel, SyncSender},
        Arc, Mutex, MutexGuard, RwLock,
    },
    thread::JoinHandle,
    time::Instant,
};

/// Authenticated persistence adapter. Implement with WorkspaceStore's native
/// vault HMAC device key and persistent revocation, NEVER a JSON boolean.
///
/// Mutation entry points on Tracker are backend-only, already-native-consented.
/// `issue_grant` must not be made available directly to an untrusted webview.
pub trait TrackingStore: Send + Sync + 'static {
    fn load_records(&self) -> Result<Vec<Value>>;
    fn save_record(&self, record: &Value) -> Result<()>;
    /// Native boundary readback, never called per node/chunk. Stores can
    /// override this with one bounded state view instead of a whole list read.
    fn read_record(&self, software_id: &str) -> Result<Option<Value>> {
        let records = self.load_records()?;
        model::bounded_serialized(&records, 128 * 1024 * 1024)?;
        ensure!(
            records.len() <= MAX_SOFTWARE,
            "too many native tracking records"
        );
        Ok(records
            .into_iter()
            .find(|record| record["id"].as_str() == Some(software_id)))
    }
    fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value>;
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool>;
    fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()>;
    fn provider_writable(&self, provider_id: &str) -> Result<bool>;
    /// Override with a metadata-only existence check to allow selecting an
    /// imported read-only/disconnected provider without granting writes.
    fn provider_known(&self, provider_id: &str) -> Result<bool> {
        self.provider_writable(provider_id)
    }
}

pub type Enqueue = Arc<dyn Fn(Value) -> Result<()> + Send + Sync>;
/// The native worker is owned by Tracker, not detached or tied to UI visibility.
pub type NativeTracker = Tracker;

pub struct Tracker {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) struct Shared {
    store: Arc<dyn TrackingStore>,
    enqueue: Enqueue,
    policy: TrackingPolicy,
    apps: Mutex<BTreeMap<String, Runtime>>,
    routes: RwLock<Vec<native::WatchRoute>>,
    wake: SyncSender<native::Hint>,
    stop: AtomicBool,
    reconfigure: AtomicBool,
    uncertainty_epoch: AtomicU64,
    index_entries: AtomicUsize,
    baseline_entries: AtomicUsize,
    index_path_bytes: AtomicUsize,
    baseline_path_bytes: AtomicUsize,
    frozen_indices: Mutex<metadata_index::FrozenIndices>,
    frozen_frames: Mutex<trackingresume::FrameQuota>,
    io: scan::IoCounters,
    instance_nonce: String,
    watch_reset_requested: AtomicU64,
    watch_reset_confirmed: AtomicU64,
    origin: Instant,
}

struct Runtime {
    // Runtime uncertainty is not consent revocation. Only an explicit scan may
    // clear it after checking current authority; polling must never resume work.
    authorization_paused: bool,
    record: TrackedSoftware,
    scheduler: Scheduler,
    baseline: Option<Arc<Snapshot>>,
    current: Option<Arc<Snapshot>>,
    pending: Option<Pending>,
    event_epoch: Arc<AtomicU64>,
    force_hash: bool,
    watch_ok: bool,
    index_identity: Option<String>,
    observation_event_epoch: u64,
    observation_uncertainty_epoch: u64,
    policy_pending: bool,
}

struct Pending {
    work_id: String,
    generation: u64,
    captured: Arc<Snapshot>,
    selected: BTreeSet<String>,
    full_scope: bool,
    event_epoch: u64,
    uncertainty_epoch: u64,
    scope: Value,
    receipt: Option<Arc<dyn NativeCaptureReceipt>>,
    receipt_evidence: Option<Value>,
    source_expected_manifest_auth: Option<Value>,
    awaiting_receipt: bool,
    frozen_metadata_identity: String,
    full_scope_proof: Option<Value>,
    source_pins: Vec<scan::PinnedRoot>,
    automatic: bool,
    deleted: Vec<String>,
    immutable_prepared_capture: bool,
    frozen_authorization: Value,
    frozen_baseline: Option<Arc<Snapshot>>,
    frozen_baseline_reference: Option<model::BaselineReference>,
    frozen_baseline_scope: Option<Value>,
    frozen_baseline_full_scope: bool,
    unknown_generation: u64,
    original_frame: Option<Arc<trackingresume::FrozenFrame>>,
    recovered: bool,
}

impl Tracker {
    pub fn open(
        store: Arc<dyn TrackingStore>,
        enqueue: Enqueue,
        policy: TrackingPolicy,
    ) -> Result<Self> {
        Self::open_impl(store, enqueue, policy, true)
    }

    fn open_impl(
        store: Arc<dyn TrackingStore>,
        enqueue: Enqueue,
        policy: TrackingPolicy,
        start_worker: bool,
    ) -> Result<Self> {
        ensure!(
            cfg!(any(target_os = "macos", target_os = "linux", windows)),
            "automatic tracking needs an implemented native root-anchor/required-metadata adapter for this platform"
        );
        policy.validate()?;
        quicksave_platform::ensure_private_directory(&policy.data_dir)?;
        quicksave_platform::ensure_private_directory(&policy.baseline_dir())?;
        quicksave_platform::ensure_private_directory(&policy.bundle_dir())?;
        let records = store.load_records()?;
        model::bounded_serialized(&records, 128 * 1024 * 1024)?;
        ensure!(
            records.len() <= MAX_SOFTWARE,
            "too many tracked software records"
        );
        let mut apps = BTreeMap::new();
        let mut baseline_entries = 0_usize;
        let mut index_entries = 0_usize;
        let mut baseline_path_bytes = 0_usize;
        let mut index_path_bytes = 0_usize;
        let mut frame_quota = trackingresume::FrameQuota::default();
        for value in records {
            model::bounded_json(&value, 3 * 1024 * 1024)?;
            let mut record: TrackedSoftware = serde_json::from_value(value)?;
            record.validate()?;
            if let Some(reference) = &record.pending_work {
                if trackingresume::verify_reference(store.as_ref(), reference).is_ok() {
                    frame_quota.install(&record.id, reference)?;
                }
            }
            let mut scheduler = Scheduler::new(
                record.dirty_generation,
                record.last_confirmed_uploaded_generation,
                0,
            )?;
            let tracking_check = store
                .verify_grant("tracking", &record.tracking_scope(), &record.tracking_grant)
                .and_then(|valid| {
                    if valid {
                        if let Some(enrollment) = &record.auto_enrollment {
                            enrollment.verify_record(&record, store.as_ref(), &policy)?;
                        }
                    }
                    Ok(valid)
                });
            let mut authorization_paused = record.authorization_pending || tracking_check.is_err();
            let tracking_valid = matches!(tracking_check, Ok(true));
            let mut policy_pending = false;
            if record.pending_work.is_some() {
                record.unknown_generation = record
                    .unknown_generation
                    .checked_add(1)
                    .context("native restart unknown generation exhausted")?;
                scheduler.hint(0)?;
            }
            let baseline = if tracking_valid && !authorization_paused {
                for root in &record.roots {
                    let check = scan::PinnedRoot::open(root).and_then(|pinned| {
                        scan::check_policy(&root.path, &policy, root.allowed_files.is_some())?;
                        pinned.check()
                    });
                    if let Err(error) = check {
                        policy_pending = true;
                        scheduler.failed(0);
                        if error.downcast_ref::<scan::AuthorityChanged>().is_some() {
                            scheduler.revoke();
                            record.autosave = false;
                            record.error = Some(
                                "Approved root identity changed; approve the roots again.".into(),
                            );
                        } else {
                            record.error = Some("An approved root is unavailable or excluded; reconciliation will retry.".into());
                        }
                    }
                }
                match scan::load_baseline(&record, store.as_ref(), &policy) {
                    Ok(baseline) => baseline.map(Arc::new),
                    Err(_) => {
                        // Fail closed: missing/corrupt baseline is not a clean source.
                        authorization_paused = true;
                        scheduler.revoke();
                        record.error = Some(
                            "Confirmed baseline is unavailable; reconciliation is required.".into(),
                        );
                        None
                    }
                }
            } else {
                scheduler.revoke();
                if authorization_paused {
                    record.error = Some("Native approval is temporarily unavailable; explicit verification and reconciliation are required.".into());
                } else {
                    record.autosave = false;
                    record.error = Some(
                        "Tracking approval is invalid or revoked; approve these roots again."
                            .into(),
                    );
                }
                None
            };
            if record.autosave {
                match record.autosave_grant.as_ref().map_or(Ok(false), |grant| {
                    store.verify_grant("autosave", &record.autosave_scope(), grant)
                }) {
                    Ok(true) => {}
                    Ok(false) => {
                        record.autosave = false;
                        record.autosave_grant = None;
                        record.error = Some("Autosave approval is invalid or revoked.".into());
                    }
                    Err(_) => {
                        authorization_paused = true;
                        scheduler.revoke();
                        record.error = Some("Native approval is temporarily unavailable; explicit verification and reconciliation are required.".into());
                    }
                }
            }
            record.dirty = true;
            record.status = if scheduler.paused {
                "error"
            } else {
                "checking"
            }
            .into();
            baseline_entries = baseline_entries
                .checked_add(baseline.as_ref().map_or(0, |s| s.nodes.len()))
                .context("baseline entry count overflow")?;
            ensure!(
                baseline_entries <= MAX_FILES,
                "workspace baselines exceed the global entry bound"
            );
            baseline_path_bytes = baseline_path_bytes
                .checked_add(
                    baseline
                        .as_ref()
                        .map(|s| s.path_bytes())
                        .transpose()?
                        .unwrap_or(0),
                )
                .context("workspace baseline path count overflow")?;
            ensure!(
                baseline_path_bytes <= model::MAX_PATH_BYTES,
                "workspace baseline path memory exceeds bounded limit"
            );
            // An unavailable historical proof quarantines the entire current
            // index, even if the tracking grant itself is presently valid.
            // Only explicit recovery may reload retained private references.
            let current = if tracking_valid && !authorization_paused {
                match bundle::load_index(&record, store.as_ref(), &policy) {
                    Ok(snapshot) => snapshot.map(Arc::new),
                    Err(_) => {
                        authorization_paused = true;
                        scheduler.revoke();
                        record.error = Some("Authenticated bundle index is unavailable; native reconciliation is required.".into());
                        None
                    }
                }
            } else {
                None
            };
            if current.is_none() && !authorization_paused {
                record.tracked = false;
            }
            if let Some(source) = current.as_ref().and(record.bundle_index_source.as_ref()) {
                record.file_count = Some(source.file_count);
                record.logical_bytes = Some(source.logical_bytes);
            }
            index_entries = index_entries
                .checked_add(current.as_ref().map_or(0, |s| s.nodes.len()))
                .context("workspace bundle index count overflow")?;
            ensure!(
                index_entries <= MAX_FILES,
                "workspace indexes exceed the global entry bound"
            );
            index_path_bytes = index_path_bytes
                .checked_add(
                    current
                        .as_ref()
                        .map(|s| s.path_bytes())
                        .transpose()?
                        .unwrap_or(0),
                )
                .context("workspace index path count overflow")?;
            ensure!(
                index_path_bytes <= model::MAX_PATH_BYTES,
                "workspace index path memory exceeds bounded limit"
            );
            let index_identity =
                current
                    .as_ref()
                    .map(|s| s.identity())
                    .transpose()?
                    .map(|identity| {
                        blake3::hash(format!("{}:{identity}", record.id).as_bytes())
                            .to_hex()
                            .to_string()
                    });
            let id = record.id.clone();
            if authorization_paused && !record.authorization_pending {
                record.unknown_generation = record
                    .unknown_generation
                    .checked_add(1)
                    .context("native authorization gap generation exhausted")?;
            }
            record.authorization_pending = authorization_paused;
            if authorization_paused {
                scheduler.revoke();
                // Failure to persist cannot unpause this running instance.
                // Source operations remain denied; a later explicit retry
                // must durably clear the denial latch before work can proceed.
                let _ = store.save_record(&serde_json::to_value(&record)?);
            }
            if record.pending_work.is_some() && tracking_valid {
                // A restart cannot reuse the original zero-valued event/unknown
                // partition. Persist the checked unknown transition before any
                // native source recovery admission/readback.
                record.dirty_generation = scheduler.dirty_generation;
                store.save_record(&serde_json::to_value(&record)?)?;
            }
            let runtime = Runtime {
                authorization_paused,
                record,
                scheduler,
                baseline,
                current,
                pending: None,
                event_epoch: Arc::new(AtomicU64::new(0)),
                force_hash: true,
                watch_ok: false,
                index_identity,
                observation_event_epoch: 0,
                observation_uncertainty_epoch: 0,
                policy_pending,
            };
            ensure!(
                apps.insert(id, runtime).is_none(),
                "duplicate tracked software ID"
            );
        }
        let (wake, receiver) = sync_channel(native::QUEUE_CAPACITY);
        let shared = Arc::new(Shared {
            store,
            enqueue,
            policy,
            apps: Mutex::new(apps),
            routes: RwLock::new(Vec::new()),
            wake,
            stop: AtomicBool::new(false),
            reconfigure: AtomicBool::new(true),
            uncertainty_epoch: AtomicU64::new(0),
            index_entries: AtomicUsize::new(index_entries),
            baseline_entries: AtomicUsize::new(baseline_entries),
            index_path_bytes: AtomicUsize::new(index_path_bytes),
            baseline_path_bytes: AtomicUsize::new(baseline_path_bytes),
            frozen_indices: Mutex::new(metadata_index::FrozenIndices::default()),
            frozen_frames: Mutex::new(frame_quota),
            io: scan::IoCounters::default(),
            instance_nonce: uuid::Uuid::new_v4().to_string(),
            watch_reset_requested: AtomicU64::new(0),
            watch_reset_confirmed: AtomicU64::new(0),
            origin: Instant::now(),
        });
        let worker = if start_worker {
            Some(native::start(shared.clone(), receiver)?)
        } else {
            None // Private deterministic test constructor; public open always starts notify.
        };
        Ok(Self {
            shared,
            worker: Mutex::new(worker),
        })
    }

    pub fn software(&self) -> Result<Vec<Value>> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let mut values = Vec::with_capacity(apps.len());
        for app in apps.values_mut() {
            if self.shared.validate_tracking(app).is_ok() {
                let _ = self.shared.validate_autosave(app);
            }
            sync_record(app);
            let mut value = app.record.sanitized();
            value["metadataStale"] = json!(app.authorization_paused || app.scheduler.paused);
            value["authorizationPending"] = json!(app.authorization_paused);
            if app.authorization_paused {
                value["tracked"] = json!(false);
                value["fileCount"] = Value::Null;
                value["logicalBytes"] = Value::Null;
                value["roots"] = json!([]);
                value["bundle"] = Value::Null;
            }
            values.push(value);
        }
        Ok(values)
    }

    /// Caller must have obtained native confirmation for these exact paths.
    pub fn approve_software(&self, input: &Value) -> Result<Value> {
        self.approve_software_impl(input, None, None)
    }

    fn approve_software_impl(
        &self,
        input: &Value,
        expected_previous_scope: Option<&Value>,
        prepared: Option<&approval::PreparedPaths>,
    ) -> Result<Value> {
        self.shared.check_running()?;
        model::bounded_json(input, 16 * 1024 * 1024)?;
        let owned_prepared = if prepared.is_none() {
            approval::PreparedPaths::from_input(input)?
        } else {
            None
        };
        let prepared = prepared.or(owned_prepared.as_ref());
        let name = input
            .get("name")
            .and_then(Value::as_str)
            .context("software name is required")?;
        validate_name(name)?;
        let app_id = optional_string(input, "appId")?;
        let provider_id = optional_string(input, "providerId")?;
        if let Some(provider) = &provider_id {
            validate_id(provider)?;
            ensure!(
                self.shared.store.provider_known(provider)?,
                "provider is unknown or unavailable for selection"
            );
        }
        if let Some(app_id) = &app_id {
            validate_id(app_id)?;
        }
        let roots_input = input
            .get("roots")
            .and_then(Value::as_array)
            .context("approved roots are required")?;
        ensure!(
            !roots_input.is_empty() && roots_input.len() <= MAX_ROOTS,
            "invalid root count"
        );
        let supplied_id = input
            .get("softwareId")
            .or_else(|| input.get("id"))
            .and_then(Value::as_str);
        if let Some(id) = supplied_id {
            validate_id(id)?;
        }
        let id = supplied_id
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut apps = self.shared.apps()?;
        if let Some(expected) = expected_previous_scope {
            ensure!(
                apps.get(&id)
                    .is_some_and(|old| &old.record.autosave_scope() == expected),
                "software authority changed while approving selected files"
            );
        }
        ensure!(
            apps.contains_key(&id) || apps.len() < MAX_SOFTWARE,
            "software limit reached"
        );
        if let Some(old) = apps.get(&id) {
            ensure!(
                old.pending.is_none(),
                "finish/cancel the active upload before changing roots"
            );
        }
        let old_roots = apps
            .get(&id)
            .map(|old| old.record.roots.as_slice())
            .unwrap_or(&[]);
        let retained_roots = if let Some(old) = apps.get(&id) {
            if self.shared.store.verify_grant(
                "tracking",
                &old.record.tracking_scope(),
                &old.record.tracking_grant,
            )? {
                old_roots
            } else {
                &[]
            }
        } else {
            &[]
        };
        let mut roots = Vec::with_capacity(roots_input.len());
        let mut identities = BTreeSet::new();
        for value in roots_input {
            let path = value
                .get("path")
                .and_then(Value::as_str)
                .context("root path is required")?;
            let path = PathBuf::from(path);
            let identity = scan::approve_root_identity(
                &path,
                &self.shared.policy,
                value.get("allowedFiles").is_some(),
            )?;
            ensure!(
                identities.insert((identity.device, identity.file_id)),
                "duplicate/aliased approved roots"
            );
            let role = value
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("manual")
                .to_owned();
            // add_files supplies an internal validated allowlist; this API also
            // accepts it for exact native-consented parent-directory scopes.
            let allowed_files = if let Some(leaves) = value.get("allowedFiles") {
                let leaves = leaves.as_array().context("allowedFiles must be an array")?;
                ensure!(
                    !leaves.is_empty() && leaves.len() <= 4096,
                    "invalid leaf count"
                );
                let mut set = BTreeSet::new();
                for leaf in leaves {
                    let leaf = leaf.as_str().context("invalid manual file leaf")?;
                    ensure!(set.insert(leaf.to_owned()), "duplicate manual file leaf");
                }
                Some(set)
            } else {
                None
            };
            let same = old_roots
                .iter()
                .find(|r| r.path == path && r.identity == identity);
            let root_id = if let Some(requested) = value.get("id").and_then(Value::as_str) {
                validate_id(requested)?;
                ensure!(
                    same.is_some_and(|root| root.id == requested),
                    "an existing root ID cannot be rebound to another native root"
                );
                requested.to_owned()
            } else {
                same.map(|r| r.id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
            };
            let root = Root {
                id: root_id,
                path,
                role,
                identity,
                allowed_files,
                source: value.get("source").cloned(),
            };
            root.validate()?;
            if let Some(leaves) = &root.allowed_files {
                let pinned = scan::PinnedRoot::open(&root)?;
                for leaf in leaves {
                    // Approval of an individual file cannot silently become
                    // approval of a nonexistent name or a directory.
                    pinned.safe.file_metadata(leaf)?;
                }
                pinned.check()?;
            }
            roots.push(root);
        }
        if let Some(prepared) = prepared {
            // Compare our freshly pinned native IDs/file stamps to the handles
            // the parent pinned AFTER consent, before any grant/state mutation.
            prepared.roots(&roots, retained_roots)?;
            prepared.verify()?;
        }
        let old = apps.get(&id);
        let dirty_generation = old
            .map(|r| r.scheduler.dirty_generation)
            .unwrap_or(0)
            .checked_add(1)
            .context("generation exhausted")?;
        let confirmed = old
            .map(|r| r.scheduler.last_confirmed_uploaded_generation)
            .unwrap_or(0);
        let mut record = TrackedSoftware {
            authorization_pending: false,
            id: id.clone(),
            app_id,
            source_identity: input
                .get("sourceIdentity")
                .filter(|value| !value.is_null())
                .cloned(),
            name: name.to_owned(),
            tracked: false,
            provider_id,
            autosave: false,
            dirty: true,
            status: "checking".into(),
            last_saved_at: None,
            file_count: None,
            logical_bytes: None,
            error: None,
            roots,
            dirty_generation,
            unknown_generation: old.map_or(0, |old| old.record.unknown_generation),
            last_confirmed_uploaded_generation: confirmed,
            tracking_grant: Value::Null,
            autosave_grant: None,
            baseline: None,
            baseline_full_scope: false,
            bundle_index_source: None,
            previous_bundle_manifest: old.and_then(|old| {
                old.record
                    .bundle_index_source
                    .as_ref()
                    .map(|source| source.certificate(&old.record))
            }),
            auto_enrollment: None,
            app_running: old.and_then(|old| old.record.app_running),
            capture_receipt: None,
            pending_work: None,
        };
        record.validate()?;
        if let Some(old) = old {
            if old.record.autosave_grant.is_some() {
                self.shared
                    .store
                    .revoke_grant("autosave", &old.record.autosave_scope())?;
            }
            self.shared
                .store
                .revoke_grant("tracking", &old.record.tracking_scope())?;
        }
        if let Some(prepared) = prepared {
            prepared.verify()?;
        }
        record.tracking_grant = self
            .shared
            .store
            .issue_grant("tracking", &record.tracking_scope())?;
        ensure!(
            self.shared.store.verify_grant(
                "tracking",
                &record.tracking_scope(),
                &record.tracking_grant
            )?,
            "store did not issue a verifiable native tracking grant"
        );
        if let Some(prepared) = prepared {
            prepared.verify()?;
        }
        self.shared
            .store
            .save_record(&serde_json::to_value(&record)?)?;
        let result = record.sanitized();
        let runtime = Runtime {
            authorization_paused: false,
            scheduler: Scheduler::new(dirty_generation, confirmed, self.shared.now())?,
            record,
            baseline: None,
            current: None,
            pending: None,
            event_epoch: Arc::new(AtomicU64::new(0)),
            force_hash: true,
            watch_ok: false,
            index_identity: None,
            observation_event_epoch: 0,
            observation_uncertainty_epoch: 0,
            policy_pending: false,
        };
        if let Some(previous) = apps.insert(id, runtime) {
            self.shared.index_path_bytes.fetch_sub(
                previous
                    .current
                    .as_ref()
                    .map(|s| s.path_bytes())
                    .transpose()?
                    .unwrap_or(0),
                Ordering::AcqRel,
            );
            self.shared.baseline_path_bytes.fetch_sub(
                previous
                    .baseline
                    .as_ref()
                    .map(|s| s.path_bytes())
                    .transpose()?
                    .unwrap_or(0),
                Ordering::AcqRel,
            );
            self.shared.index_entries.fetch_sub(
                previous.current.as_ref().map_or(0, |s| s.nodes.len()),
                Ordering::AcqRel,
            );
            self.shared.baseline_entries.fetch_sub(
                previous.baseline.as_ref().map_or(0, |s| s.nodes.len()),
                Ordering::AcqRel,
            );
        }
        self.shared.reconfigure.store(true, Ordering::Release);
        self.shared.wake();
        Ok(result)
    }

    /// Pin parent directories but never grant their other children.
    pub fn add_files(&self, input: &Value) -> Result<Value> {
        self.shared.check_running()?;
        model::bounded_json(input, 16 * 1024 * 1024)?;
        let prepared = approval::PreparedPaths::from_input(input)?;
        let paths = input
            .get("paths")
            .and_then(Value::as_array)
            .context("file paths are required")?;
        ensure!(
            !paths.is_empty() && paths.len() <= 4096,
            "invalid manual file count"
        );
        let mut grouped: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
        let mut requested = BTreeSet::new();
        for path in paths {
            let path = Path::new(path.as_str().context("invalid manual file path")?);
            model::validate_absolute(path)?;
            ensure!(
                requested.insert(path.to_owned()),
                "duplicate selected file path"
            );
            let parent = path.parent().context("file has no parent")?;
            let leaf = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("file leaf is not UTF-8")?;
            model::validate_relative(leaf)?;
            ensure!(
                !model::is_secret_component(leaf),
                "key material is excluded"
            );
            ensure!(
                grouped
                    .entry(parent.to_owned())
                    .or_default()
                    .insert(leaf.to_owned()),
                "duplicate manual file"
            );
        }
        ensure!(
            grouped.len() <= MAX_ROOTS,
            "too many manual parent directories"
        );
        // An existing software's non-manual roots and manual selections are
        // preserved exactly; new siblings are included only by this consent.
        let mut roots = Vec::new();
        let software_id = input
            .get("softwareId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut app_id = json!(format!(
            "quicksave.manual.{}",
            blake3::hash(software_id.as_bytes()).to_hex(),
        ));
        let mut expected_previous_scope = None;
        let mut source_identity = Value::Null;
        let mut name = input
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Selected files")
            .to_owned();
        let mut provider = input.get("providerId").cloned().unwrap_or(Value::Null);
        if let Some(id) = input.get("softwareId").and_then(Value::as_str) {
            let mut apps = self.shared.apps()?;
            let old = apps.get_mut(id).context("unknown tracked software")?;
            self.shared.validate_tracking(old)?;
            ensure!(
                !old.scheduler.paused,
                "previous tracking approval is invalid or revoked"
            );
            expected_previous_scope = Some(old.record.autosave_scope());
            source_identity = json!(old.record.source_identity);
            if old.record.app_id.is_some() {
                app_id = json!(old.record.app_id);
            }
            if let Some(prepared) = &prepared {
                prepared.files(&requested, &old.record.roots)?;
            }
            name = input
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&old.record.name)
                .to_owned();
            if provider.is_null() {
                provider = json!(old.record.provider_id);
            }
            for old_root in &old.record.roots {
                if let Some(leaves) = &old_root.allowed_files {
                    grouped
                        .entry(old_root.path.clone())
                        .or_default()
                        .extend(leaves.iter().cloned());
                } else {
                    roots.push(json!({
                        "id": old_root.id, "path": old_root.path, "role": old_root.role,
                        "source": old_root.source
                    }));
                }
            }
        } else if let Some(prepared) = &prepared {
            prepared.files(&requested, &[])?;
        }
        for (path, leaves) in grouped {
            roots.push(json!({"path": path, "role": "manual", "allowedFiles": leaves}));
        }
        let mut request = json!({
            "softwareId": software_id, "name": name,
            "providerId": provider, "roots": roots, "appId": app_id,
            "sourceIdentity": source_identity,
        });
        if let Some(proofs) = input.get("_approvedPaths") {
            // Preserve the original parent proofs through the internal root
            // approval; never manufacture directory consent from a file pick.
            request["_approvedPaths"] = proofs.clone();
        }
        self.approve_software_impl(
            &request,
            expected_previous_scope.as_ref(),
            prepared.as_ref(),
        )
    }

    /// Changing a provider invalidates its old autosave grant and cloud baseline.
    pub fn set_provider(&self, software_id: &str, provider_id: Option<&str>) -> Result<Value> {
        self.shared.check_running()?;
        if let Some(id) = provider_id {
            validate_id(id)?;
            ensure!(
                self.shared.store.provider_known(id)?,
                "provider is unknown or unavailable for selection"
            );
        }
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.validate_tracking(app)?;
        ensure!(!app.scheduler.paused, "tracking approval must be renewed");
        if app.record.provider_id.as_deref() == provider_id {
            return Ok(app.record.sanitized());
        }
        self.shared.revoke_autosave(app)?;
        app.record.provider_id = provider_id.map(str::to_owned);
        app.record.baseline = None;
        app.record.baseline_full_scope = false;
        self.shared.baseline_path_bytes.fetch_sub(
            app.baseline
                .as_ref()
                .map(|s| s.path_bytes())
                .transpose()?
                .unwrap_or(0),
            Ordering::AcqRel,
        );
        self.shared.baseline_entries.fetch_sub(
            app.baseline.as_ref().map_or(0, |s| s.nodes.len()),
            Ordering::AcqRel,
        );
        app.baseline = None;
        app.record.last_saved_at = None;
        app.scheduler.hint(self.shared.now())?;
        app.scheduler.content_dirty = true;
        app.force_hash = true;
        self.shared.persist(app)?;
        self.shared.wake();
        Ok(app.record.sanitized())
    }

    /// Backend-only: `enabled` is a request, NEVER the source of write authority.
    pub fn configure_autosave(
        &self,
        software_id: &str,
        provider_id: &str,
        enabled: bool,
    ) -> Result<Value> {
        self.shared.check_running()?;
        validate_id(provider_id)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.validate_tracking(app)?;
        ensure!(!app.scheduler.paused, "tracking approval must be renewed");
        ensure!(
            app.record.provider_id.as_deref() == Some(provider_id),
            "provider selection changed; select and approve the provider first"
        );
        self.shared.revoke_autosave(app)?;
        if enabled {
            ensure!(
                self.shared.store.provider_writable(provider_id)?,
                "provider is disconnected or read-only"
            );
            for root in &app.record.roots {
                scan::PinnedRoot::open(root)?.check()?;
            }
            let scope = app.record.autosave_scope();
            let grant = self.shared.store.issue_grant("autosave", &scope)?;
            ensure!(
                self.shared.store.verify_grant("autosave", &scope, &grant)?,
                "store did not issue a verifiable native autosave grant"
            );
            app.record.autosave_grant = Some(grant);
            app.record.autosave = true;
            app.scheduler.resume(self.shared.now());
            app.force_hash = true;
        }
        app.record.error = None;
        self.shared.persist(app)?;
        self.shared.wake();
        Ok(app.record.sanitized())
    }

    /// Explicit scan, not an upload confirmation. Uses a bounded streaming hash.
    pub fn scan(&self, software_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.verify_paused_authority(app)?;
        let result = self.shared.reconcile(app, true);
        if result.is_err() && app.record.authorization_pending {
            let _ = self.shared.pause_authorization(app);
        }
        result?;
        Ok(json!({
            "software": app.record.sanitized(),
            "captureSource": self.shared.capture_source(app)?
        }))
    }

    /// A bounded explicit metadata refresh, never a content scan for UI polling.
    pub fn scan_metadata(&self, software_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.verify_paused_authority(app)?;
        let result = self.shared.reconcile_mode(app, false, false);
        if result.is_err() && app.record.authorization_pending {
            let _ = self.shared.pause_authorization(app);
        }
        result?;
        Ok(json!({"software": app.record.sanitized(),
            "captureSource": self.shared.capture_source(app)?}))
    }

    pub fn performance_counters(&self) -> Value {
        self.shared.io.value()
    }

    /// Native recovery only: the caller compares its signed frozen authority
    /// revision first and drains its source owner. Root availability is NOT an
    /// authorization requirement for making a genuine signed scope less clean.
    /// No source handle, listing, capture, hash, or grant mutation occurs here.
    pub fn mark_unknown_dirty(&self, software_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        validate_id(software_id)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        app.record.validate()?;
        let scope = app.record.tracking_scope();
        ensure!(
            self.shared
                .store
                .verify_grant("tracking", &scope, &app.record.tracking_grant)?,
            "unknown-state recovery requires genuine signed tracking authority"
        );
        if let Some(enrollment) = &app.record.auto_enrollment {
            // Authentication/evidence only. Deliberately NOT revalidate_native:
            // a missing/replaced root must not prevent a safe dirty transition.
            enrollment.verify_record(
                &app.record,
                self.shared.store.as_ref(),
                &self.shared.policy,
            )?;
        }
        let dirty = app
            .scheduler
            .dirty_generation
            .checked_add(1)
            .context("native dirty generation exhausted")?;
        let unknown = app
            .record
            .unknown_generation
            .checked_add(1)
            .context("native unknown generation exhausted")?;
        let scope_hash = bundle::digest(&scope)?;
        let grant_hash = bundle::digest(&app.record.tracking_grant)?;
        app.event_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("native source event epoch exhausted"))?;
        app.scheduler.hint(self.shared.now())?;
        ensure!(
            app.scheduler.dirty_generation == dirty,
            "native dirty counter changed unexpectedly"
        );
        app.scheduler.require_reconcile();
        app.scheduler.content_dirty = true;
        app.record.unknown_generation = unknown;
        app.force_hash = true;
        self.shared.persist(app)?;
        let value = json!({
            "softwareId": app.record.id, "dirty": app.record.dirty,
            "dirtyGeneration": app.record.dirty_generation, "unknownGeneration": unknown,
            "lastConfirmedUploadedGeneration": app.record.last_confirmed_uploaded_generation,
            "reconciliationRequired": true, "status": app.record.status,
            "trackingScopeHash": scope_hash, "trackingGrantHash": grant_hash,
            "pendingWorkId": app.pending.as_ref().map(|pending| &pending.work_id),
            "authorityUnchanged": true, "keepsVersionHistory": true,
        });
        model::bounded_json(&value, 16 * 1024)?;
        self.shared.wake();
        Ok(value)
    }

    /// Native-service-only exact root authority, never a webview DTO.
    pub fn root_authority(&self, software_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "tracking approval is invalid or revoked"
        );
        for root in &app.record.roots {
            scan::PinnedRoot::open(root)?.check()?;
        }
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.revalidate_native(self.shared.store.as_ref(), &self.shared.policy)?;
        }
        Ok(json!({
            "id": app.record.id, "softwareId": app.record.id, "appId": app.record.app_id,
            "sourceIdentity": app.record.source_identity,
            "name": app.record.name, "providerId": app.record.provider_id,
            "roots": app.record.roots.iter().map(scan::root_request).collect::<Vec<_>>(),
            "scope": app.record.tracking_scope(), "grant": app.record.tracking_grant
        }))
    }

    /// Snapshot-bound, bounded, lazy UI page. Stale cursors fail rather than
    /// duplicate/drop entries or accidentally select another software's files.
    pub fn file_listing(
        &self,
        software_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Value> {
        self.shared.check_running()?;
        ensure!(
            limit > 0 && limit <= MAX_PAGE,
            "file page limit must be 1..=500"
        );
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        self.shared.validate_tracking(app)?;
        ensure!(!app.scheduler.paused, "tracking root approval is revoked");
        let current = app
            .current
            .as_ref()
            .context("file scan is pending; request scan and retry")?;
        let identity = app
            .index_identity
            .as_deref()
            .context("file index is unavailable")?;
        let offset = if let Some(cursor) = cursor {
            ensure!(cursor.len() <= 1024, "oversized file cursor");
            let (prefix, offset) = cursor.rsplit_once(':').context("invalid file cursor")?;
            ensure!(
                prefix == identity,
                "file listing changed; restart pagination"
            );
            offset
                .parse::<usize>()
                .context("invalid file page offset")?
        } else {
            0
        };
        let mut files = Vec::with_capacity(limit);
        let empty = Snapshot::default();
        let baseline = app.baseline.as_deref().unwrap_or(&empty);
        // Merge current and baseline iterators without constructing a second
        // 186k-item UI tree. Missing baseline items are stable-ID tombstones.
        let mut left = current.nodes.iter().peekable();
        let mut right = baseline.nodes.iter().peekable();
        let mut index = 0_usize;
        let mut has_more = false;
        loop {
            let item = match (left.peek(), right.peek()) {
                (None, None) => break,
                (Some((l, _)), Some((r, _))) if l == r => {
                    let (id, node) = left.next().unwrap();
                    right.next();
                    (
                        node,
                        if baseline.nodes.get(id) == Some(node) {
                            "saved"
                        } else {
                            "changed"
                        },
                    )
                }
                (Some((l, _)), Some((r, _))) if l > r => (right.next().unwrap().1, "deleted"),
                (Some(_), _) => (left.next().unwrap().1, "new"),
                (_, Some(_)) => (right.next().unwrap().1, "deleted"),
            };
            if index >= offset {
                if files.len() == limit {
                    has_more = true;
                    break;
                }
                files.push(item.0.item(item.1));
            }
            index = index.checked_add(1).context("file index overflow")?;
        }
        ensure!(offset <= index, "file cursor exceeds this snapshot");
        Ok(json!({
            "files": files,
            "nextCursor": if has_more { Some(format!("{identity}:{}", offset + limit)) } else { None }
        }))
    }

    /// Register a manually authorized upload, preserving one-flight-per-app.
    pub fn begin_upload(
        &self,
        software_id: &str,
        provider_id: &str,
        file_ids: Option<&[String]>,
    ) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        ensure!(
            app.pending.is_none(),
            "an upload is already in flight for this software"
        );
        self.shared.reconcile(app, true)?;
        self.shared
            .prepare_upload(app, provider_id, file_ids, false)
    }

    /// Freeze native IDs/stamps without reading file contents. The actual
    /// source engine must return a NativeCaptureReceipt before publication.
    pub fn prepare_upload_scope(
        &self,
        software_id: &str,
        provider_id: &str,
        file_ids: Option<&[String]>,
    ) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown tracked software")?;
        ensure!(
            app.pending.is_none(),
            "an upload is already in flight for this software"
        );
        self.shared.reconcile_mode(app, false, false)?;
        self.shared
            .prepare_upload_mode(app, provider_id, file_ids, false, true)
    }

    /// Service calls this only for durable success of this exact authenticated
    /// work and generation. Failed/partial engine operations pass false.
    pub fn complete_upload(&self, work_id: &str, generation: u64, success: bool) -> Result<Value> {
        self.shared.check_running()?;
        self.shared.complete_upload(work_id, generation, success)
    }

    /// Recheck a queued autosave request immediately before service admission.
    /// No credentials are read and no new authority is issued.
    pub fn verify_autosave_work(&self, request: &Value) -> Result<Value> {
        self.shared.check_running()?;
        let software = request
            .get("softwareId")
            .and_then(Value::as_str)
            .context("autosave software ID is missing")?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software)
            .context("unknown autosave software")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "tracking approval is invalid or revoked"
        );
        ensure!(
            self.shared.validate_autosave(app)?,
            "autosave grant is invalid or revoked"
        );
        let pending = app
            .pending
            .as_ref()
            .context("autosave work is no longer pending")?;
        ensure!(
            pending.immutable_prepared_capture || app.watch_ok,
            "native autosave watchers require reconciliation"
        );
        ensure!(
            pending.automatic
                && request.get("workId").and_then(Value::as_str) == Some(pending.work_id.as_str())
                && request.get("generation").and_then(Value::as_u64) == Some(pending.generation)
                && request.get("automatic").and_then(Value::as_bool) == Some(true),
            "queued autosave does not match its original work/generation"
        );
        ensure!(
            pending.scope == app.record.autosave_scope(),
            "queued autosave scope changed"
        );
        ensure!(
            request["providerId"] == json!(app.record.provider_id)
                && request["roots"]
                    == json!(app
                        .record
                        .roots
                        .iter()
                        .map(scan::root_request)
                        .collect::<Vec<_>>()),
            "queued autosave root/provider selection changed"
        );
        if request["captureSource"]["stage"] == "awaiting_native_capture_receipt" {
            receipt::validate_metadata_work(request, pending)?;
        } else {
            validate_work_files(request, &pending.selected, &pending.captured)?;
        }
        ensure!(
            request["captureSource"]["snapshotIdentity"] == json!(pending.frozen_metadata_identity),
            "queued capture proof changed"
        );
        ensure!(
            request["captureSource"]["changedDirty"] == true
                && request["captureSource"]["dirtyGeneration"] == pending.generation
                && request["captureSource"]["keepsLocalCopy"] == true
                && request["captureSource"]["consistency"]
                    == "validated_stable_files_not_application_atomic",
            "queued source capture policy changed"
        );
        let deleted = request["deletedFileIds"]
            .as_array()
            .context("queued omission IDs are missing")?;
        ensure!(
            deleted.len() == pending.deleted.len()
                && deleted
                    .iter()
                    .zip(&pending.deleted)
                    .all(|(given, expected)| given.as_str() == Some(expected.as_str())),
            "queued tombstone selection changed"
        );
        ensure!(
            pending.immutable_prepared_capture
                || (app.event_epoch.load(Ordering::Acquire) == pending.event_epoch
                    && app.record.unknown_generation == pending.unknown_generation
                    && self.shared.uncertainty_epoch.load(Ordering::Acquire)
                        == pending.uncertainty_epoch),
            "source events require a new stable capture before this autosave"
        );
        let provider = app
            .record
            .provider_id
            .as_deref()
            .context("autosave provider is missing")?;
        ensure!(
            self.shared.store.provider_writable(provider)?,
            "autosave provider is not writable"
        );
        for root in &app.record.roots {
            scan::PinnedRoot::open(root)?.check()?;
        }
        ensure!(
            request["captureSource"]["expectedFullScope"] == json!(pending.full_scope_proof),
            "queued full/partial snapshot scope proof changed"
        );
        if let Some(proof) = &pending.full_scope_proof {
            ensure!(
                self.shared.store.verify_grant(
                    "tracking_full_capture",
                    &proof["scope"],
                    &proof["grant"]
                )?,
                "queued full-scope capture authority is invalid or revoked"
            );
        }
        Ok(json!({"verified": true, "workId": pending.work_id, "generation": pending.generation}))
    }

    /// Signals stop, releases native notify handles, then joins the owned worker.
    pub fn shutdown(&self) -> Result<()> {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake();
        let mut slot = self
            .worker
            .lock()
            .map_err(|_| anyhow::anyhow!("worker owner lock poisoned"))?;
        if let Some(worker) = slot.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("native tracking worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        // There is no detached thread on normal destruction. A poisoned lock is
        // recovered only to release/join owned native resources, not trust state.
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake();
        let slot = self
            .worker
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(worker) = slot.take() {
            let _ = worker.join();
        }
    }
}

impl Shared {
    fn now(&self) -> u64 {
        self.policy.clock.as_ref().map_or_else(
            || self.origin.elapsed().as_millis().min(u64::MAX as u128) as u64,
            |clock| clock.now_millis(),
        )
    }

    fn check_running(&self) -> Result<()> {
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "native tracker is shut down"
        );
        Ok(())
    }

    fn apps(&self) -> Result<MutexGuard<'_, BTreeMap<String, Runtime>>> {
        self.apps
            .lock()
            .map_err(|_| anyhow::anyhow!("tracking state lock poisoned"))
    }

    fn wake(&self) {
        let _ = self.wake.try_send(native::Hint::Wake);
    }

    fn uncertain(&self, reset_watch: bool) {
        match self
            .uncertainty_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            }) {
            Ok(previous) => {
                if reset_watch {
                    self.watch_reset_requested
                        .fetch_max(previous + 1, Ordering::AcqRel);
                }
            }
            Err(_) => self.stop.store(true, Ordering::Release),
        }
        self.wake();
    }

    fn validate_tracking(&self, app: &mut Runtime) -> Result<()> {
        // Polling cached DTOs does not scan sources, but known hint/gap epochs
        // must immediately prevent a stale "clean" UI before the worker drains
        // its bounded queue.
        if app.event_epoch.load(Ordering::Acquire) != app.observation_event_epoch
            || self.uncertainty_epoch.load(Ordering::Acquire) != app.observation_uncertainty_epoch
        {
            app.scheduler.require_reconcile();
        }
        if self.uncertainty_epoch.load(Ordering::Acquire) != app.observation_uncertainty_epoch {
            app.force_hash = true;
        }
        let verification = self
            .store
            .verify_grant(
                "tracking",
                &app.record.tracking_scope(),
                &app.record.tracking_grant,
            )
            .and_then(|valid| {
                if valid {
                    if let Some(enrollment) = &app.record.auto_enrollment {
                        enrollment.verify_record(&app.record, self.store.as_ref(), &self.policy)?;
                    }
                }
                Ok(valid)
            });
        let valid = match verification {
            Ok(valid) => valid,
            Err(error) => {
                if error.is::<TrackingProjectionChanged>() {
                    return Err(error);
                }
                self.pause_authorization(app)?;
                if error.is::<DeferredLegacyAuthority>() {
                    return Err(error);
                }
                bail!(
                    "native tracking authority is unavailable; explicit verification is required"
                );
            }
        };
        if !valid {
            let had_watch = !app.scheduler.paused || app.watch_ok;
            app.scheduler.revoke();
            app.record.autosave = false;
            app.record.tracked = false;
            app.record.autosave_grant = None;
            app.watch_ok = false;
            app.record.error =
                Some("Tracking approval was revoked; approve the roots again.".into());
            if had_watch {
                self.reconfigure.store(true, Ordering::Release);
            }
            sync_record(app);
        }
        ensure!(
            !app.authorization_paused,
            "native tracking authority requires explicit verification"
        );
        Ok(())
    }

    fn pause_authorization(&self, app: &mut Runtime) -> Result<()> {
        if app.authorization_paused {
            sync_record(app);
            return Ok(());
        }
        app.authorization_paused = true;
        app.record.authorization_pending = true;
        app.scheduler.revoke();
        app.force_hash = true;
        app.watch_ok = false;
        app.record.error = Some("Native approval is temporarily unavailable; explicit verification and reconciliation are required.".into());
        self.reconfigure.store(true, Ordering::Release);
        sync_record(app);
        // Exhaustion must leave the denial latch raised, not an authorized DTO.
        app.record.unknown_generation = app
            .record
            .unknown_generation
            .checked_add(1)
            .context("native authorization gap generation exhausted")?;
        self.store.save_record(&serde_json::to_value(&app.record)?)
    }

    fn verify_paused_authority(&self, app: &mut Runtime) -> Result<()> {
        if !app.authorization_paused {
            return Ok(());
        }
        // Keep the latch set on every error, including errors in autosave proof.
        ensure!(
            self.store.verify_grant(
                "tracking",
                &app.record.tracking_scope(),
                &app.record.tracking_grant
            )?,
            "tracking approval is revoked"
        );
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.verify_record(&app.record, self.store.as_ref(), &self.policy)?;
        }
        if app.record.autosave {
            let grant = app
                .record
                .autosave_grant
                .as_ref()
                .context("autosave approval is missing")?;
            ensure!(
                self.store
                    .verify_grant("autosave", &app.record.autosave_scope(), grant)?,
                "autosave approval is revoked"
            );
        }
        // Startup during a vault outage deliberately did not load these. Restore
        // them under the original bounds before any scan may compare/delete.
        if app.baseline.is_none() && app.record.baseline.is_some() {
            let baseline = scan::load_baseline(&app.record, self.store.as_ref(), &self.policy)?
                .context("confirmed baseline is unavailable")?;
            let entries = self
                .baseline_entries
                .load(Ordering::Acquire)
                .checked_add(baseline.nodes.len())
                .context("baseline entry count overflow")?;
            let paths = self
                .baseline_path_bytes
                .load(Ordering::Acquire)
                .checked_add(baseline.path_bytes()?)
                .context("baseline path count overflow")?;
            ensure!(
                entries <= MAX_FILES && paths <= model::MAX_PATH_BYTES,
                "workspace baseline exceeds bounded limits"
            );
            self.baseline_entries.store(entries, Ordering::Release);
            self.baseline_path_bytes.store(paths, Ordering::Release);
            app.baseline = Some(Arc::new(baseline));
        }
        if app.current.is_none() && app.record.bundle_index_source.is_some() {
            let current = bundle::load_index(&app.record, self.store.as_ref(), &self.policy)?
                .context("authenticated bundle index is unavailable")?;
            self.replace_current(app, Arc::new(current))?;
        }
        // The persistent denial latch remains raised until the explicit
        // reconciliation has completed and its new index is ready to persist.
        app.authorization_paused = false;
        app.scheduler.resume(self.now());
        app.force_hash = true;
        app.record.error = None;
        self.reconfigure.store(true, Ordering::Release);
        Ok(())
    }

    fn validate_autosave(&self, app: &mut Runtime) -> Result<bool> {
        ensure!(
            !app.authorization_paused,
            "native approval requires explicit verification"
        );
        if !app.record.autosave {
            return Ok(false);
        }
        let verification = app
            .record
            .autosave_grant
            .as_ref()
            .map_or(Ok(false), |grant| {
                self.store
                    .verify_grant("autosave", &app.record.autosave_scope(), grant)
            });
        let valid = match verification {
            Ok(valid) => valid,
            Err(_) => {
                self.pause_authorization(app)?;
                bail!(
                    "native autosave authority is unavailable; explicit verification is required"
                );
            }
        };
        if !valid {
            app.record.autosave = false;
            app.record.autosave_grant = None;
            app.record.error =
                Some("Autosave approval was revoked; enable it again with native consent.".into());
            self.persist(app)?;
        }
        Ok(valid)
    }

    fn revoke_autosave(&self, app: &mut Runtime) -> Result<()> {
        // Revocation happens before the unsigned settings mutation.
        if app.record.autosave_grant.is_some() {
            self.store
                .revoke_grant("autosave", &app.record.autosave_scope())?;
        }
        app.record.autosave = false;
        app.record.autosave_grant = None;
        Ok(())
    }

    fn persist(&self, app: &mut Runtime) -> Result<()> {
        sync_record(app);
        if let Err(error) = self.store.save_record(&serde_json::to_value(&app.record)?) {
            app.scheduler.revoke();
            app.record.autosave = false;
            app.record.error =
                Some("Tracking state could not be persisted; automatic writes are paused.".into());
            app.record.tracked = false;
            sync_record(app);
            return Err(error).context("persist native tracking record");
        }
        Ok(())
    }

    fn reconcile(&self, app: &mut Runtime, force_hash: bool) -> Result<()> {
        self.reconcile_mode(app, force_hash, true)
    }

    fn reconcile_mode(
        &self,
        app: &mut Runtime,
        force_hash: bool,
        hash_content: bool,
    ) -> Result<()> {
        self.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "tracking approval is paused or revoked"
        );
        let event_before = app.event_epoch.load(Ordering::Acquire);
        let uncertainty_before = self.uncertainty_epoch.load(Ordering::Acquire);
        let capture: Result<Snapshot> = (|| {
            if app.policy_pending {
                for root in &app.record.roots {
                    let pinned = scan::PinnedRoot::open(root)?;
                    scan::check_policy(&root.path, &self.policy, root.allowed_files.is_some())?;
                    pinned.check()?;
                }
                app.policy_pending = false;
            }
            if let Some(enrollment) = &app.record.auto_enrollment {
                enrollment.revalidate_native(self.store.as_ref(), &self.policy)?;
            }
            let change_proof_valid = app.watch_ok
                && self.watch_reset_requested.load(Ordering::Acquire)
                    <= self.watch_reset_confirmed.load(Ordering::Acquire)
                && !app.force_hash
                && uncertainty_before == app.observation_uncertainty_epoch
                && app.current.as_ref().is_some_and(|previous| {
                    scan::can_reuse_content_cache(&app.record.roots, previous).unwrap_or(false)
                });
            let snapshot = scan::capture_index(
                &app.record.roots,
                app.current.as_deref(),
                force_hash || app.force_hash || !change_proof_valid,
                hash_content,
                &self.policy,
                &self.stop,
                &self.io,
            )?;
            ensure!(
                !snapshot.nodes.is_empty()
                    || !snapshot.root_metadata.is_empty()
                    || app.record.bundle_index_source.is_some(),
                "selected files disappeared before a real initial index was materialized"
            );
            Ok(snapshot)
        })();
        match capture {
            Ok(snapshot) => {
                let changed = app.current.as_deref() != Some(&snapshot);
                let dirty = app
                    .record
                    .auto_enrollment
                    .as_ref()
                    .is_some_and(bundle::AutoEnrollment::has_failed_roots)
                    || !app.record.baseline_full_scope
                    || !snapshot.content_verified()
                    || app.baseline.as_deref() != Some(&snapshot);
                let identity = snapshot.identity()?;
                let counts = snapshot.counts()?;
                let indexed = self.index_total_after(app, &snapshot).and_then(|_| {
                    bundle::write_index(&snapshot, &app.record, self.store.as_ref(), &self.policy)
                });
                let source = match indexed {
                    Ok(source) => source,
                    Err(error) => {
                        app.scheduler.failed(self.now());
                        app.force_hash = true;
                        app.record.error = Some("Real native index could not be persisted within its resource/authority bounds; reconciliation is pending.".into());
                        self.persist(app)?;
                        return Err(error);
                    }
                };
                if let Err(error) = self.replace_current(app, Arc::new(snapshot)) {
                    app.scheduler.failed(self.now());
                    app.force_hash = true;
                    app.record.error = Some("Workspace file index exceeds the bounded limit; approve a narrower source scope.".into());
                    self.persist(app)?;
                    return Err(error);
                }
                // Scope/software binds a page cursor even for identical trees.
                app.index_identity = Some(
                    blake3::hash(format!("{}:{identity}", app.record.id).as_bytes())
                        .to_hex()
                        .to_string(),
                );
                app.scheduler.observed(dirty, changed)?;
                app.observation_event_epoch = event_before;
                app.observation_uncertainty_epoch = uncertainty_before;
                if hash_content {
                    app.force_hash = false;
                }
                app.record.file_count = Some(counts.0);
                app.record.logical_bytes = Some(counts.1);
                app.record.bundle_index_source = Some(source);
                app.record.previous_bundle_manifest = None;
                app.record.tracked = true;
                app.record.error = app
                    .record
                    .auto_enrollment
                    .as_ref()
                    .and_then(bundle::AutoEnrollment::root_failure_message);
                if app.event_epoch.load(Ordering::Acquire) != event_before
                    || self.uncertainty_epoch.load(Ordering::Acquire) != uncertainty_before
                {
                    app.scheduler.hint(self.now())?;
                    app.force_hash = true;
                }
                if app.record.authorization_pending {
                    app.record.authorization_pending = false;
                    sync_record(app);
                    if let Err(error) = self.store.save_record(&serde_json::to_value(&app.record)?)
                    {
                        app.record.authorization_pending = true;
                        let _ = self.pause_authorization(app);
                        return Err(error).context("persist explicitly reconciled authority");
                    }
                } else {
                    self.persist(app)?;
                }
                Ok(())
            }
            Err(error) => {
                app.scheduler.failed(self.now());
                app.force_hash = true;
                if error.downcast_ref::<scan::AuthorityChanged>().is_some() {
                    let _ = self.revoke_autosave(app);
                    app.scheduler.revoke();
                    app.watch_ok = false;
                    self.reconfigure.store(true, Ordering::Release);
                    app.record.error =
                        Some("Approved root identity changed; native approval is required.".into());
                } else {
                    app.record.error = Some(diagnostics::bounded_message(format_args!(
                        "Source is unavailable, unsafe, or changing; reconciliation will retry. {}",
                        diagnostics::message(&error)
                    )));
                }
                self.persist(app)?;
                Err(error)
            }
        }
    }

    fn capture_source(&self, app: &Runtime) -> Result<Value> {
        Ok(json!({
            "changedDirty": app.scheduler.content_dirty || app.scheduler.needs_reconcile,
            "dirtyGeneration": app.scheduler.dirty_generation,
            "unknownGeneration": app.record.unknown_generation,
            "lastConfirmedUploadedGeneration": app.scheduler.last_confirmed_uploaded_generation,
            "baselineKind": if app.baseline.is_none() { "none" }
                else if app.record.baseline_full_scope { "full" } else { "partial" },
            "snapshotIdentity": app.current.as_ref().map(|s| s.identity()).transpose()?,
            "consistency": "validated_stable_files_not_application_atomic",
            "keepsLocalCopy": true
            ,"contentState": if app.current.as_ref().is_some_and(|s| s.content_verified()) {
                "content_verified"
            } else { "metadata_indexed_unknown_content" },
            "payloadReadability": "not_established",
            "fullScopeCaptureBlocked": app.record.auto_enrollment.as_ref()
                .is_some_and(bundle::AutoEnrollment::has_failed_roots)
        }))
    }

    fn replace_current(&self, app: &mut Runtime, snapshot: Arc<Snapshot>) -> Result<()> {
        let total = self.index_total_after(app, &snapshot)?;
        let paths = self.index_paths_after(app, &snapshot)?;
        let identity = snapshot.identity()?;
        app.index_identity = Some(
            blake3::hash(format!("{}:{identity}", app.record.id).as_bytes())
                .to_hex()
                .to_string(),
        );
        self.index_entries.store(total, Ordering::Release);
        self.index_path_bytes.store(paths, Ordering::Release);
        app.current = Some(snapshot);
        Ok(())
    }

    fn index_total_after(&self, app: &Runtime, snapshot: &Snapshot) -> Result<usize> {
        self.index_paths_after(app, snapshot)?;
        let previous = app.current.as_ref().map_or(0, |s| s.nodes.len());
        let total = self
            .index_entries
            .load(Ordering::Acquire)
            .checked_sub(previous)
            .context("invalid workspace index accounting")?
            .checked_add(snapshot.nodes.len())
            .context("workspace index count overflow")?;
        ensure!(
            total <= MAX_FILES,
            "workspace index exceeds the global bounded entry limit"
        );
        Ok(total)
    }

    fn index_paths_after(&self, app: &Runtime, snapshot: &Snapshot) -> Result<usize> {
        let previous = app
            .current
            .as_ref()
            .map(|s| s.path_bytes())
            .transpose()?
            .unwrap_or(0);
        let total = self
            .index_path_bytes
            .load(Ordering::Acquire)
            .checked_sub(previous)
            .and_then(|bytes| bytes.checked_add(snapshot.path_bytes().ok()?))
            .context("invalid workspace index path accounting")?;
        ensure!(
            total <= model::MAX_PATH_BYTES,
            "workspace index exceeds the global native path/link memory bound"
        );
        Ok(total)
    }

    fn prepare_upload(
        &self,
        app: &mut Runtime,
        provider_id: &str,
        file_ids: Option<&[String]>,
        automatic: bool,
    ) -> Result<Value> {
        self.prepare_upload_mode(app, provider_id, file_ids, automatic, false)
    }

    fn prepare_upload_mode(
        &self,
        app: &mut Runtime,
        provider_id: &str,
        file_ids: Option<&[String]>,
        automatic: bool,
        awaiting_receipt: bool,
    ) -> Result<Value> {
        self.validate_tracking(app)?;
        ensure!(!app.scheduler.paused, "tracking root approval is revoked");
        ensure!(
            app.record.provider_id.as_deref() == Some(provider_id),
            "upload provider differs from the approved saved selection"
        );
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.revalidate_native(self.store.as_ref(), &self.policy)?;
        }
        ensure!(
            self.store.provider_writable(provider_id)?,
            "provider is offline, disconnected, or read-only"
        );
        if automatic {
            ensure!(
                self.validate_autosave(app)?,
                "persistent autosave grant is invalid"
            );
            ensure!(app.watch_ok, "native root watchers are not active");
        }
        ensure!(app.pending.is_none(), "an upload is already in flight");
        ensure!(
            app.record.pending_work.is_none(),
            "original durable native work requires recovery before creating new work"
        );
        ensure!(
            app.event_epoch.load(Ordering::Acquire) == app.observation_event_epoch
                && self.uncertainty_epoch.load(Ordering::Acquire)
                    == app.observation_uncertainty_epoch,
            "source events require reconciliation before upload admission"
        );
        let captured = app
            .current
            .as_ref()
            .context("source scan is required")?
            .clone();
        let empty = Snapshot::default();
        let baseline = app.baseline.as_deref().unwrap_or(&empty);
        let full_scope = file_ids.is_none();
        ensure!(!full_scope || !app.record.auto_enrollment.as_ref()
            .is_some_and(bundle::AutoEnrollment::has_failed_roots),
            "a discovered native root scope remains unresolved; repair/reindex it before a full-scope save/head, or explicitly select a custom partial capture");
        let selected: BTreeSet<String> = if let Some(ids) = file_ids {
            ensure!(
                !ids.is_empty() && ids.len() <= MAX_SELECTION,
                "invalid file selection size"
            );
            let set: BTreeSet<_> = ids.iter().cloned().collect();
            ensure!(set.len() == ids.len(), "duplicate selected file ID");
            for id in &set {
                ensure!(
                    captured.nodes.contains_key(id) || baseline.nodes.contains_key(id),
                    "selected file ID is outside this software's approved scope"
                );
            }
            set
        } else {
            captured
                .nodes
                .keys()
                .chain(baseline.nodes.keys())
                .cloned()
                .collect()
        };
        let deleted: Vec<_> = selected
            .iter()
            .filter(|id| !captured.nodes.contains_key(*id))
            .cloned()
            .collect();
        ensure!(
            deleted.is_empty() || self.policy.supports_deletion_snapshots,
            "deleted files require additive tombstone snapshot support; no data is deleted"
        );
        ensure!(deleted.is_empty() || full_scope,
            "deleted nodes require an authenticated full-root omission snapshot, not selected siblings");
        ensure!(
            selected.len() <= MAX_FILES,
            "selected snapshot exceeds metadata bound"
        );
        ensure!(
            !captured.nodes.is_empty() || (full_scope && self.policy.supports_metadata_snapshots),
            "empty-directory snapshots are unsupported by this native writer"
        );
        ensure!(
            self.policy.supports_metadata_snapshots
                || captured
                    .nodes
                    .values()
                    .all(|node| { !node.directory && node.link.is_none() }),
            "native writer lacks verified directory/link snapshot support"
        );
        let evidence = if awaiting_receipt {
            None
        } else {
            Some(expected_files(&selected, &captured)?)
        };
        ensure!(
            awaiting_receipt
                || self.policy.supports_metadata_snapshots
                || evidence
                    .as_ref()
                    .is_some_and(|files| files.as_array().is_some_and(|files| !files.is_empty())),
            "empty or tombstone-only capture is unsupported"
        );
        let exact_ids: Vec<_> = selected
            .iter()
            .filter(|id| captured.nodes.contains_key(*id))
            .cloned()
            .collect();
        let mut capture_source = self.capture_source(app)?;
        let work_id = uuid::Uuid::new_v4().to_string();
        let generation = app.scheduler.dirty_generation;
        let scope = app.record.autosave_scope(); // Binds provider even for manual work.
        let source_pins = app
            .record
            .roots
            .iter()
            .map(scan::PinnedRoot::open)
            .collect::<Result<Vec<_>>>()?;
        for pin in &source_pins {
            pin.check()?;
        }
        let frozen_metadata_identity = captured.identity()?;
        let full_scope_proof = if full_scope {
            let proof_scope = json!({
                "version": 1, "workId": work_id, "softwareId": app.record.id,
                "providerId": provider_id, "generation": generation,
                "trackingScopeHash": bundle::digest(&app.record.tracking_scope())?,
                "metadataIdentity": frozen_metadata_identity,
                "rootIds": app.record.roots.iter().map(|root| &root.id).collect::<Vec<_>>(),
                "expectedNodeIdsHash": bundle::digest(&json!(exact_ids))?,
                "deletedNodeIdsHash": bundle::digest(&json!(deleted))?,
                "baselineKind": if app.baseline.is_none() { "none" }
                    else if app.record.baseline_full_scope { "full" } else { "partial" },
                "baselineIdentity": app.baseline.as_ref().map(|s| s.identity()).transpose()?,
                "snapshotMode": "additive_full_scope", "keepsHistory": true,
            });
            let grant = self
                .store
                .issue_grant("tracking_full_capture", &proof_scope)?;
            ensure!(
                self.store
                    .verify_grant("tracking_full_capture", &proof_scope, &grant)?,
                "full capture scope could not be authenticated"
            );
            Some(json!({"scope": proof_scope, "grant": grant}))
        } else {
            None
        };
        capture_source["expectedFullScope"] = json!(full_scope_proof);
        capture_source["selectionKind"] = json!(if full_scope {
            "full_scope"
        } else {
            "selected_nodes"
        });
        capture_source["snapshotIdentity"] = json!(frozen_metadata_identity);
        capture_source["stage"] = json!(if awaiting_receipt {
            "awaiting_native_capture_receipt"
        } else {
            "content_frozen"
        });
        if let Some(evidence) = evidence {
            capture_source["expectedFiles"] = evidence;
        } else {
            capture_source["metadataSelection"] = json!({
                "workId": work_id, "metadataIdentity": frozen_metadata_identity,
                "nodeCount": exact_ids.len(), "source": "tracker_native_index",
            });
        }
        let request = json!({
            "workId": work_id, "softwareId": app.record.id, "appId": app.record.app_id,
            "sourceIdentity": app.record.source_identity,
            "name": app.record.name, "providerId": provider_id, "generation": generation,
            "fileIds": exact_ids,
            "deletedFileIds": deleted, "automatic": automatic,
            "roots": app.record.roots.iter().map(scan::root_request).collect::<Vec<_>>(),
            "captureSource": capture_source,
            "authorization": {
                "trackingScope": app.record.tracking_scope(),
                "trackingGrant": app.record.tracking_grant,
                "autosaveScope": if automatic { Some(app.record.autosave_scope()) } else { None },
                "autosaveGrant": if automatic { app.record.autosave_grant.clone() } else { None },
            }
        });
        model::bounded_serialized(&request, 512 * 1024 * 1024)?;
        let flight = app.scheduler.begin(work_id.clone(), self.now())?;
        app.pending = Some(Pending {
            work_id,
            generation: flight.generation,
            captured,
            selected,
            full_scope,
            event_epoch: app.event_epoch.load(Ordering::Acquire),
            uncertainty_epoch: self.uncertainty_epoch.load(Ordering::Acquire),
            scope,
            receipt: None,
            receipt_evidence: None,
            source_expected_manifest_auth: None,
            awaiting_receipt,
            frozen_metadata_identity,
            full_scope_proof,
            source_pins,
            automatic,
            deleted,
            immutable_prepared_capture: false,
            frozen_authorization: request["authorization"].clone(),
            frozen_baseline: app.baseline.clone(),
            frozen_baseline_reference: app.record.baseline.clone(),
            frozen_baseline_scope: app
                .record
                .baseline
                .as_ref()
                .map(|reference| app.record.baseline_scope(&reference.name, &reference.hash)),
            frozen_baseline_full_scope: app.record.baseline_full_scope,
            unknown_generation: app.record.unknown_generation,
            original_frame: None,
            recovered: false,
        });
        if awaiting_receipt {
            if let Err(error) = trackingresume::persist_initial(self, app, &request) {
                app.pending = None;
                app.scheduler.flight = None;
                return Err(error).context("persist original native work before source admission");
            }
        }
        if let Err(error) = self.persist(app) {
            // No callback may run if the original in-flight plan wasn't durable.
            app.pending = None;
            app.scheduler.flight = None;
            return Err(error);
        }
        if awaiting_receipt {
            trackingresume::readback_reference(self.store.as_ref(), &app.record)?;
            self.frozen_frames
                .lock()
                .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
                .install(&app.record.id, app.record.pending_work.as_ref().unwrap())?;
        }
        Ok(request)
    }

    fn complete_upload(&self, work_id: &str, generation: u64, success: bool) -> Result<Value> {
        let mut apps = self.apps()?;
        let app = apps
            .values_mut()
            .find(|app| app.pending.as_ref().is_some_and(|p| p.work_id == work_id))
            .context("unknown upload work ID")?;
        let pending = app.pending.as_ref().unwrap();
        ensure!(
            pending.generation == generation,
            "completion generation does not match original upload"
        );
        self.validate_tracking(app)?;
        if app.pending.as_ref().unwrap().recovered {
            return trackingresume::complete_recovered(self, app, work_id, generation, success);
        }
        let same_scope = app.pending.as_ref().unwrap().scope == app.record.autosave_scope();
        let mut confirmed = false;
        let receipt_backed = app.pending.as_ref().unwrap().receipt.is_some();
        if success && same_scope && !app.scheduler.paused {
            // Real engine capture receipts avoid a second content pass. Legacy
            // callers retain conservative rehashing; metadata alone is never a
            // substitute for the owned native source publication proof.
            let pending = app.pending.as_ref().unwrap();
            let captured_after = if pending.awaiting_receipt {
                Err(anyhow::anyhow!(
                    "actual native source capture receipt is required"
                ))
            } else if receipt_backed {
                receipt::verify_pending_receipt(self, app, pending).and_then(|()| {
                    scan::capture_index(
                        &app.record.roots,
                        Some(&pending.captured),
                        false,
                        false,
                        &self.policy,
                        &self.stop,
                        &self.io,
                    )
                })
            } else {
                scan::capture_index(
                    &app.record.roots,
                    None,
                    true,
                    true,
                    &self.policy,
                    &self.stop,
                    &self.io,
                )
            };
            if let Ok(after) = captured_after {
                let pending = app.pending.as_ref().unwrap();
                let epochs_match = app.event_epoch.load(Ordering::Acquire) == pending.event_epoch
                    && app.record.unknown_generation == pending.unknown_generation
                    && self.uncertainty_epoch.load(Ordering::Acquire) == pending.uncertainty_epoch;
                let selected_stable = pending
                    .selected
                    .iter()
                    .all(|id| after.nodes.get(id) == pending.captured.nodes.get(id));
                if epochs_match && selected_stable && self.index_total_after(app, &after).is_ok() {
                    let mut baseline = app.baseline.as_deref().cloned().unwrap_or_default();
                    baseline.content_captured = true;
                    if pending.full_scope {
                        baseline = (*pending.captured).clone();
                    } else {
                        for id in &pending.selected {
                            if let Some(node) = pending.captured.nodes.get(id) {
                                baseline.nodes.insert(id.clone(), node.clone());
                            } else {
                                // Only metadata tombstones are advanced. This
                                // never removes a local file or a cloud object.
                                baseline.nodes.remove(id);
                            }
                        }
                    }
                    let baseline_total = self
                        .baseline_entries
                        .load(Ordering::Acquire)
                        .checked_sub(app.baseline.as_ref().map_or(0, |s| s.nodes.len()))
                        .and_then(|total| total.checked_add(baseline.nodes.len()))
                        .context("invalid baseline entry accounting")?;
                    let baseline_paths = self
                        .baseline_path_bytes
                        .load(Ordering::Acquire)
                        .checked_sub(
                            app.baseline
                                .as_ref()
                                .map(|s| s.path_bytes())
                                .transpose()?
                                .unwrap_or(0),
                        )
                        .and_then(|bytes| bytes.checked_add(baseline.path_bytes().ok()?))
                        .context("invalid baseline path accounting")?;
                    if baseline_total > MAX_FILES
                        || baseline_paths > model::MAX_PATH_BYTES
                        || baseline.identity().is_err()
                    {
                        // The engine may have succeeded, but an unpersistable
                        // tracking baseline must never clear dirtiness or hold
                        // a terminal engine operation in flight forever.
                        app.scheduler
                            .complete(work_id, generation, false, false, self.now())?;
                        app.pending = None;
                        app.force_hash = true;
                        app.record.error = Some("Confirmed tracking metadata exceeds the bounded workspace limit; approve narrower roots.".into());
                        self.persist(app)?;
                        return Ok(json!({
                            "workId": work_id, "generation": generation, "sourceConfirmed": false,
                            "reconciliationRequired": true, "software": app.record.sanitized()
                        }));
                    }
                    let mut next = app.record.clone();
                    next.baseline_full_scope = pending.full_scope || app.record.baseline_full_scope;
                    let reference =
                        scan::save_baseline(&baseline, &next, self.store.as_ref(), &self.policy)?;
                    // Publish the reference durably before trusting it in memory.
                    next.baseline = Some(reference.clone());
                    next.bundle_index_source = Some(bundle::write_index(
                        &after,
                        &next,
                        self.store.as_ref(),
                        &self.policy,
                    )?);
                    self.store.save_record(&serde_json::to_value(&next)?)?;
                    app.record = next;
                    app.baseline = Some(Arc::new(baseline));
                    self.baseline_entries
                        .store(baseline_total, Ordering::Release);
                    self.baseline_path_bytes
                        .store(baseline_paths, Ordering::Release);
                    self.replace_current(app, Arc::new(after))?;
                    confirmed = true;
                }
            }
        }
        let pending = app.pending.as_ref().unwrap();
        let fully_confirmed = confirmed
            && !app
                .record
                .auto_enrollment
                .as_ref()
                .is_some_and(bundle::AutoEnrollment::has_failed_roots)
            && app.record.baseline_full_scope
            && app.current.as_deref() == app.baseline.as_deref();
        app.scheduler.complete(
            &pending.work_id,
            generation,
            confirmed,
            fully_confirmed,
            self.now(),
        )?;
        let metadata_only_cancel = !success
            && app.pending.as_ref().is_some_and(|pending| {
                pending.awaiting_receipt
                    && pending.receipt.is_none()
                    && pending.receipt_evidence.is_none()
            });
        if (success && confirmed) || metadata_only_cancel {
            // An explicit drained failure before receipt acceptance retires only
            // metadata preparation authority. Prepared/uncertain captured work
            // remains recoverable; no failure is promoted to Saved.
            trackingresume::retire_reference(self, app)?;
        }
        app.pending = None;
        app.force_hash = !(confirmed && receipt_backed);
        if confirmed && fully_confirmed {
            app.record.last_saved_at = Some(chrono::Utc::now().to_rfc3339());
        }
        if success && !confirmed {
            app.record.error = Some(
                "An immutable version was uploaded, but newer or uncertain local changes remain pending."
                    .into(),
            );
        }
        // Reconciliation remains required even when the comparison above matched.
        // Queued hints, changes during upload, and other unselected dirt remain.
        self.persist(app)?;
        self.wake();
        Ok(json!({
            "workId": work_id, "generation": generation, "sourceConfirmed": confirmed,
            "reconciliationRequired": true, "software": app.record.sanitized()
        }))
    }
}

fn sync_record(app: &mut Runtime) {
    app.record.dirty_generation = app.scheduler.dirty_generation;
    app.record.last_confirmed_uploaded_generation =
        app.scheduler.last_confirmed_uploaded_generation;
    app.record.dirty = app.scheduler.content_dirty || app.scheduler.needs_reconcile;
    app.record.status = if app.authorization_paused {
        "needs_authorization"
    } else if app.scheduler.paused {
        "error"
    } else if app.pending.is_some() {
        "uploading"
    } else if app.record.error.is_some() {
        "error"
    } else if app.scheduler.needs_reconcile {
        "checking"
    } else if app.scheduler.content_dirty {
        "needs_backup"
    } else {
        "saved"
    }
    .into();
}

fn optional_string(value: &Value, name: &str) -> Result<Option<String>> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(string)) => Ok(Some(string.clone())),
        _ => bail!("{name} must be a string"),
    }
}

fn expected_files(selected: &BTreeSet<String>, captured: &Snapshot) -> Result<Value> {
    let mut files = Vec::with_capacity(selected.len());
    for id in selected {
        let Some(node) = captured.nodes.get(id) else {
            continue;
        };
        files.push(expected_node(id, node)?);
    }
    Ok(json!(files))
}

fn expected_node(id: &str, node: &model::Node) -> Result<Value> {
    if node.directory {
        Ok(json!({"id": id, "kind": "directory", "size": 0}))
    } else if let Some(link) = &node.link {
        Ok(json!({
            "id": id, "kind": "symlink", "size": 0,
            "linkTargetHash": blake3::hash(link.target.as_bytes()).to_hex().to_string(),
        }))
    } else {
        let hash = node
            .hash
            .as_ref()
            .context("captured file has no content hash")?;
        Ok(json!({"id": id, "fileHash": hash, "size": node.size}))
    }
}

fn validate_work_files(
    request: &Value,
    selected: &BTreeSet<String>,
    captured: &Snapshot,
) -> Result<()> {
    let ids = request["fileIds"]
        .as_array()
        .context("queued work lacks exact file IDs")?;
    let files = request["captureSource"]["expectedFiles"]
        .as_array()
        .context("queued work lacks expected native file evidence")?;
    let count = selected
        .iter()
        .filter(|id| captured.nodes.contains_key(*id))
        .count();
    ensure!(
        ids.len() == count && files.len() == count,
        "queued exact file set changed"
    );
    let selected = selected
        .iter()
        .filter_map(|id| captured.nodes.get(id).map(|node| (id, node)));
    for ((id, node), (given_id, file)) in selected.zip(ids.iter().zip(files)) {
        ensure!(
            given_id.as_str() == Some(id.as_str()) && file == &expected_node(id, node)?,
            "queued expected file contents or logical identity changed"
        );
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;
