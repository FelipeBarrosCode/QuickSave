// SPDX-License-Identifier: GPL-3.0-only
//! Owned native observation admission and Tracker bridge. Native Rust only:
//! never dispatch this module with renderer records, paths, booleans or grants.
//!
//! Parent wiring: keep Option<ObservationSession> in the native tracking owner;
//! call start_if_enabled only after native policy activation/materialization,
//! use enabled=false in isolated development, and shutdown BEFORE Tracker.
//! A changed materialized root/executable set requires joined replacement.
use anyhow::{anyhow, ensure, Context, Result};
#[cfg(unix)]
use quicksave_noland::observation_control::{NativeIndexOwner, NativeIndexScope};
use quicksave_observation::{
    integration::{ObservationContext, TrackerBundleBinding},
    native, EvidenceSource, ExecutionState, GapReason, NativeFileIdentity, ObservationEngine,
    ObservationLimits, ObservationScope, ObservationSnapshot, ObservationWatermark,
    ObservationWorker, ScopeConsent, ScopeRequest, WorkerConfig,
};
use quicksave_state::WorkspaceStore;
use quicksave_tracking::{Tracker, TrackingPolicy};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

const MAX_APPS: usize = 4096;
const MAX_ROOTS: usize = 4096;
const MAX_AUTHORITY_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 256;
const MAX_EXCLUSIONS: usize = 256;

/// Native immutable evidence plus the actual installation->source-ID mappings.
/// The sink must remain bounded, must not reenter joined shutdown, and may record
/// APP_USES_PATH/loss facts, never infer ownership or expand a root grant.
/// This contains native path proofs and must NEVER be returned through IPC.
pub(super) type SourceGraphSink =
    Arc<dyn Fn(Arc<ObservationSnapshot>, Arc<[TrackerBundleBinding]>) -> Result<()> + Send + Sync>;

pub(super) struct ObservationSession {
    worker: Option<ObservationWorker>,
    shared: Arc<Shared>,
    store: Option<WorkspaceStore>,
}

/// Alias for native owners which prefer manager naming. There is one bounded
/// process worker across all successfully bound materialized applications.
pub(super) type ObservationManager = ObservationSession;

struct Shared {
    stopping: AtomicBool,
    revoked: AtomicBool,
    admission_valid: AtomicBool,
    state: Mutex<Progress>,
}

struct Progress {
    state: &'static str,
    indexed: usize,
    inspected: usize,
    bound: usize,
    roots: usize,
    protected_files: usize,
    unconfirmed: usize,
    emitted: u64,
    callback_failures: u64,
    diagnostics: Vec<Value>,
    diagnostic_keys: BTreeSet<(String, String)>,
    omitted: u64,
    graph_bound: bool,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            state: "disabled",
            indexed: 0,
            inspected: 0,
            bound: 0,
            roots: 0,
            protected_files: 0,
            unconfirmed: 0,
            emitted: 0,
            callback_failures: 0,
            diagnostics: Vec::new(),
            diagnostic_keys: BTreeSet::new(),
            omitted: 0,
            graph_bound: false,
        }
    }
}

impl Shared {
    fn new(state: &'static str, graph_bound: bool) -> Arc<Self> {
        Arc::new(Self {
            stopping: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            admission_valid: AtomicBool::new(false),
            state: Mutex::new(Progress {
                state,
                graph_bound,
                ..Progress::default()
            }),
        })
    }
    fn diagnostic(&self, software: Option<&str>, code: &'static str) -> Result<()> {
        let software = software.unwrap_or("");
        ensure!(
            software.len() <= 512,
            "observation diagnostic ID exceeds bound"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?;
        let key = (software.to_owned(), code.to_owned());
        if state.diagnostic_keys.contains(&key) {
            return Ok(());
        }
        if state.diagnostics.len() == MAX_DIAGNOSTICS {
            state.omitted = state.omitted.saturating_add(1);
            return Ok(());
        }
        state.diagnostic_keys.insert(key);
        state.diagnostics.push(json!({
            "softwareId": if software.is_empty() { Value::Null } else { json!(software) },
            "code":code, "unconfirmed":true, "trackingAuthorityGranted":false,
        }));
        Ok(())
    }
}

#[derive(Clone)]
struct TrackingAuthority {
    scope: Value,
    grant: Value,
}

struct Consent {
    store: WorkspaceStore,
    shared: Arc<Shared>,
    expected_request_hash: String,
    policy_scope: Value,
    policy_grant: Value,
    tracking: Vec<TrackingAuthority>,
}

impl ScopeConsent for Consent {
    fn verify(&self, request: &ScopeRequest) -> Result<bool> {
        let result = self.verify_current(request);
        self.shared
            .admission_valid
            .store(result.as_ref().is_ok_and(|valid| *valid), Ordering::Release);
        result
    }
}

impl Consent {
    fn verify_current(&self, request: &ScopeRequest) -> Result<bool> {
        if self.shared.stopping.load(Ordering::Acquire)
            || self.shared.revoked.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        if request.fingerprint()? != self.expected_request_hash {
            return Ok(false);
        }
        // No worker-wide/UI-projection cache. A fresh bounded read exists for
        // this one admission, and each MAC still checks its persistent native
        // nonce. This avoids one whole-state read per app or per open FD.
        let current = self.store.app_tracking_policy()?;
        if current.as_ref().is_none_or(|policy| {
            policy["policyScope"] != self.policy_scope || policy["policyGrant"] != self.policy_grant
        }) {
            self.shared.revoked.store(true, Ordering::Release);
            return Ok(false);
        }
        let view = self.store.read_snapshot()?;
        if !view.verify_grant(
            "app_tracking_policy",
            &self.policy_scope,
            &self.policy_grant,
        )? {
            self.shared.revoked.store(true, Ordering::Release);
            return Ok(false);
        }
        for authority in &self.tracking {
            if !view.verify_grant("tracking", &authority.scope, &authority.grant)? {
                self.shared.revoked.store(true, Ordering::Release);
                return Ok(false);
            }
        }
        // A concurrent state mutation is uncertainty, not authority to reuse
        // this view for a later poll/publication. No callback can publish clean.
        view.is_current()
    }
}

impl ObservationSession {
    /// Preferred native composition when the source engine has already
    /// registered the actual records. Source index import is an explicit parent
    /// materialization action, never a side effect of this worker/status path.
    #[cfg(unix)]
    pub(super) fn start_with_source_engine(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        protected_native_files: Vec<NativeFileIdentity>,
        engine: Arc<quicksave_noland::NativeEngine>,
    ) -> Result<Self> {
        let sink = native_source_graph_sink(
            store.clone(),
            tracker.clone(),
            engine,
            protected_native_files.clone(),
        )?;
        Self::start_with_protected_files(
            store,
            tracker,
            policy,
            excluded_paths,
            protected_native_files,
            Some(sink),
        )
    }

    /// Explicitly inert: does not read settings/vaults, start watchers, determine
    /// a user, or construct an ambient process source.
    pub(super) fn disabled() -> Self {
        Self {
            worker: None,
            shared: Shared::new("disabled", false),
            store: None,
        }
    }

    /// Native policy owner only. No provider/default-provider access is needed.
    /// Unit tests cannot take this ambient source path.
    pub(super) fn start(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
    ) -> Result<Self> {
        Self::start_with_graph(store, tracker, policy, excluded_paths, None)
    }

    pub(super) fn start_if_enabled(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        enabled: bool,
    ) -> Result<Self> {
        if !enabled {
            return Ok(Self::disabled());
        }
        Self::start(store, tracker, policy, excluded_paths)
    }

    pub(super) fn start_with_graph(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        sink: Option<SourceGraphSink>,
    ) -> Result<Self> {
        Self::start_with_protected_files(store, tracker, policy, excluded_paths, vec![], sink)
    }

    /// Pass native IDs from the owner's ALREADY PINNED marker/key handles.
    /// This observer must not open excluded secrets just to discover their IDs.
    /// Names/paths alone cannot reject a hard-link alias with a different name.
    pub(super) fn start_with_protected_files(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        excluded_native_files: Vec<NativeFileIdentity>,
        sink: Option<SourceGraphSink>,
    ) -> Result<Self> {
        #[cfg(test)]
        {
            let _ = (
                store,
                tracker,
                policy,
                excluded_paths,
                excluded_native_files,
                sink,
            );
            anyhow::bail!(
                "ambient process observation is forbidden in tests; inject an evidence source"
            );
        }
        #[cfg(not(test))]
        Self::start_internal(
            store,
            tracker,
            policy,
            excluded_paths,
            excluded_native_files,
            None,
            sink,
            native::native_user_id,
            quicksave_observation::native_source,
            WorkerConfig::default(),
        )
    }

    #[cfg(test)]
    fn start_injected<F>(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        uid: u32,
        source: F,
        worker_config: WorkerConfig,
        sink: Option<SourceGraphSink>,
    ) -> Result<Self>
    where
        F: FnOnce(&ObservationScope) -> Result<Box<dyn EvidenceSource>>,
    {
        Self::start_internal(
            store,
            tracker,
            policy,
            excluded_paths,
            vec![],
            Some(uid),
            sink,
            || anyhow::bail!("injected observation must not query the ambient user"),
            source,
            worker_config,
        )
    }

    /// Synchronous owned startup, called on the parent's native blocking worker.
    /// A factory is invoked only AFTER current policy/grants and exact roots are
    /// verified. This is also the non-ambient injection seam used by unit tests.
    #[allow(clippy::too_many_arguments)]
    fn start_internal<U, F>(
        store: WorkspaceStore,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        excluded_paths: Vec<PathBuf>,
        excluded_native_files: Vec<NativeFileIdentity>,
        injected_uid: Option<u32>,
        sink: Option<SourceGraphSink>,
        user: U,
        source: F,
        worker_config: WorkerConfig,
    ) -> Result<Self>
    where
        U: FnOnce() -> Result<u32>,
        F: FnOnce(&ObservationScope) -> Result<Box<dyn EvidenceSource>>,
    {
        // A missing/off policy must not unlock a device key just to display idle
        // state. Even an enabled plaintext setting is not the following grant.
        let document = store.document()?;
        ensure!(
            document
                .settings
                .app_tracking
                .as_ref()
                .is_some_and(|policy| policy.policy_scope.enabled),
            "explicit native app tracking policy is not enabled"
        );
        drop(document);
        ensure!(
            policy.excluded_paths.len() <= MAX_EXCLUSIONS
                && excluded_paths.len() <= MAX_EXCLUSIONS
                && excluded_native_files.len() <= MAX_EXCLUSIONS,
            "native observation protection input exceeds bounds"
        );
        let global = store
            .app_tracking_policy()?
            .context("native app tracking policy is invalid or revoked")?;
        let policy_scope = global["policyScope"].clone();
        let policy_grant = global["policyGrant"].clone();
        ensure!(
            store.verify_grant("app_tracking_policy", &policy_scope, &policy_grant)?,
            "native observer policy admission failed"
        );
        let uid = match injected_uid {
            Some(uid) => uid,
            None => user()?,
        };
        let shared = Shared::new("preparing", sink.is_some());
        let mut session = Self {
            worker: None,
            shared: shared.clone(),
            store: Some(store.clone()),
        };
        let mut request = ScopeRequest::new(
            format!("native-observation:{}", uuid::Uuid::new_v4()),
            uid,
            vec![],
            vec![],
        );
        let mut exclusions: BTreeSet<PathBuf> = policy
            .excluded_paths
            .into_iter()
            .chain(excluded_paths)
            .collect();
        for value in policy_scope["excludedPaths"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let path = PathBuf::from(
                value
                    .as_str()
                    .context("native policy exclusion is invalid")?,
            );
            ensure!(
                path.is_absolute(),
                "native policy exclusion must be absolute"
            );
            exclusions.insert(path);
        }
        ensure!(
            exclusions.len() <= MAX_EXCLUSIONS,
            "too many protected native observation paths"
        );
        request.excluded_paths = exclusions.into_iter().collect();
        request.excluded_native_files = excluded_native_files
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?
            .protected_files = request.excluded_native_files.len();
        let bundles = tracker.bundles()?;
        ensure!(
            bundles.len() <= MAX_APPS,
            "materialized observation app count exceeds 4096"
        );
        shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?
            .indexed = bundles.len();
        let mut bindings = Vec::new();
        let mut authorities = Vec::new();
        let mut authority_bytes = 0usize;
        let mut app_ids = BTreeSet::new();
        let mut executables = BTreeSet::new();
        for bundle in bundles {
            let software = bundle["id"]
                .as_str()
                .context("materialized bundle ID missing")?;
            ensure!(
                !software.is_empty() && software.len() <= 512,
                "invalid materialized bundle ID"
            );
            shared
                .state
                .lock()
                .map_err(|_| anyhow!("observation progress lock failed"))?
                .inspected += 1;
            let prepared = (|| -> Result<Option<(TrackerBundleBinding, TrackingAuthority)>> {
                let record = tracker.bundle_record(software)?;
                let authority = tracker.root_authority(software)?;
                if record.pointer("/autoEnrollment/policyScope") != Some(&policy_scope)
                    || record.pointer("/autoEnrollment/policyGrant") != Some(&policy_grant)
                {
                    return Ok(None);
                }
                let Some(path) = record
                    .pointer("/sourceIdentity/canonical_executable")
                    .and_then(Value::as_str)
                else {
                    return Ok(None);
                };
                let executable = Path::new(path);
                ensure!(
                    executable.is_absolute() && path.len() <= 4096,
                    "native executable path is invalid"
                );
                ensure!(
                    !request
                        .excluded_paths
                        .iter()
                        .any(|excluded| executable.starts_with(excluded)),
                    "native executable is protected"
                );
                let verifier = |kind: &str, scope: &Value, grant: &Value| {
                    store.verify_grant(kind, scope, grant)
                };
                let binding = TrackerBundleBinding::from_native_records(
                    &record, &authority, executable, &verifier,
                )?;
                ensure!(
                    !request
                        .excluded_native_files
                        .contains(&NativeFileIdentity::from(
                            &binding.application().executable_stamp
                        )),
                    "native executable aliases a protected marker or private key"
                );
                let auth = TrackingAuthority {
                    scope: authority["scope"].clone(),
                    grant: authority["grant"].clone(),
                };
                Ok(Some((binding, auth)))
            })();
            let (binding, authority) = match prepared {
                Ok(Some(prepared)) => prepared,
                Ok(None) => {
                    shared.diagnostic(
                        Some(software),
                        "canonical_executable_or_current_policy_unconfirmed",
                    )?;
                    shared
                        .state
                        .lock()
                        .map_err(|_| anyhow!("observation progress lock failed"))?
                        .unconfirmed += 1;
                    continue;
                }
                Err(_) => {
                    shared.diagnostic(Some(software), "materialized_native_binding_unavailable")?;
                    shared
                        .state
                        .lock()
                        .map_err(|_| anyhow!("observation progress lock failed"))?
                        .unconfirmed += 1;
                    continue;
                }
            };
            // Ambiguous images are not attributed by title or basename. Fail the
            // whole observer rather than arbitrarily choosing the first app.
            if !app_ids.insert(binding.app_id().to_owned())
                || !executables.insert(binding.application().executable.clone())
            {
                return session.unavailable("ambiguous_native_bindings", Some(software));
            }
            let bytes = serde_json::to_vec(&authority.scope)?
                .len()
                .checked_add(serde_json::to_vec(&authority.grant)?.len())
                .context("native authority size overflow")?;
            authority_bytes = authority_bytes
                .checked_add(bytes)
                .context("native authority size overflow")?;
            if authority_bytes > MAX_AUTHORITY_BYTES {
                return session.unavailable("native_authority_memory_limit", Some(software));
            }
            let new_roots = binding
                .roots()
                .iter()
                .filter(|root| !request.roots.iter().any(|old| old.id == root.id))
                .count();
            if request.roots.len().saturating_add(new_roots) > MAX_ROOTS {
                return session.unavailable("global_observation_root_limit_4096", Some(software));
            }
            if binding.append_to_scope(&mut request).is_err() {
                return session.unavailable("exact_scope_collision_or_limit", Some(software));
            }
            authorities.push(authority);
            bindings.push(binding);
            let mut progress = shared
                .state
                .lock()
                .map_err(|_| anyhow!("observation progress lock failed"))?;
            progress.bound = bindings.len();
            progress.roots = request.roots.len();
        }
        if bindings.is_empty() {
            return session.unavailable("no_confirmed_native_executable", None);
        }
        let request_hash = match request.fingerprint() {
            Ok(hash) => hash,
            Err(_) => return session.unavailable("observation_scope_byte_limit", None),
        };
        // Exact derived request + the real current policy and tracking MACs.
        // This native-only constructor accepts no incoming request, so there
        // is no separate root grant or per-session vault registry growth.
        let callback_policy_scope = policy_scope.clone();
        let callback_policy_grant = policy_grant.clone();
        let consent: Arc<dyn ScopeConsent> = Arc::new(Consent {
            store: store.clone(),
            shared: shared.clone(),
            expected_request_hash: request_hash,
            policy_scope,
            policy_grant,
            tracking: authorities,
        });
        let limits = ObservationLimits {
            max_roots: MAX_ROOTS,
            max_applications: MAX_APPS,
            max_poll_interval_ms: 60_000,
            ..ObservationLimits::default()
        };
        let scope = match ObservationScope::approve_with_limits(request, consent, &limits) {
            Ok(scope) => scope,
            Err(_) => {
                return session
                    .unavailable("native_scope_identity_permission_or_handle_limit", None)
            }
        };
        let context = scope.context();
        let source = match source(&scope) {
            Ok(source) => source,
            Err(_) => return session.unavailable("native_process_source_unavailable", None),
        };
        let engine = ObservationEngine::new(scope, source, limits)?;
        let bindings: Arc<[TrackerBundleBinding]> = bindings.into();
        let by_app: BTreeMap<_, _> = bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| (binding.app_id().to_owned(), index))
            .collect();
        let callback_shared = shared.clone();
        let callback = Arc::new(move |snapshot: Arc<ObservationSnapshot>| {
            process_snapshot(
                &store,
                &tracker,
                &bindings,
                &by_app,
                &context,
                &callback_policy_scope,
                &callback_policy_grant,
                &callback_shared,
                snapshot,
                sink.as_ref(),
            )
        });
        let worker = match ObservationWorker::start(engine, worker_config, callback) {
            Ok(worker) => worker,
            Err(_) => return session.unavailable("native_observation_worker_unavailable", None),
        };
        session.worker = Some(worker);
        shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?
            .state = "observing_incomplete";
        Ok(session)
    }

    fn unavailable(self, code: &'static str, software: Option<&str>) -> Result<Self> {
        self.shared.diagnostic(software, code)?;
        self.shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?
            .state = code;
        Ok(self)
    }

    /// Cached, bounded, path/grant-free metadata. No Tracker scan, store/vault
    /// read, process probe or file inventory is performed by a UI/status query.
    pub(super) fn status(&self) -> Result<Value> {
        let progress = self
            .shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?;
        let snapshot = self
            .worker
            .as_ref()
            .map(ObservationWorker::snapshot)
            .transpose()?;
        let watermark = self.watermark();
        let running = watermark
            .as_ref()
            .is_some_and(|watermark| !watermark.stopped);
        let revoked = self.shared.revoked.load(Ordering::Acquire);
        let admission_valid = self.shared.admission_valid.load(Ordering::Acquire);
        let admitted = self.worker.is_some()
            && admission_valid
            && !revoked
            && !self.shared.stopping.load(Ordering::Acquire);
        let mut status = json!({
            "enabled":admitted, "running":running, "state":progress.state,
            "policyAuthority":if self.store.is_none() {"not_checked"} else if revoked {"revoked_or_replaced"} else if !admission_valid {"last_poll_not_admitted"} else {"last_native_verification_succeeded"},
            "completeness":"unknown", "applicationAtomic":false,
            "observationsAreHints":true, "clean":false, "cloudWrite":false,
            "indexedBundles":progress.indexed, "inspectedBundles":progress.inspected,
            "preparedBindings":progress.bound,
            "boundBundles":if self.worker.is_some() {progress.bound} else {0},
            "unboundBundles":progress.indexed.saturating_sub(if self.worker.is_some() {progress.bound} else {0}),
            "observedBundles":0,
            "unconfirmedBundles":progress.unconfirmed,
            "unprocessedBundles":progress.indexed.saturating_sub(progress.inspected),
            "preparedLogicalRoots":progress.roots,
            "logicalRoots":if self.worker.is_some() {progress.roots} else {0},
            "emittedHints":progress.emitted,
            "callbackFailures":progress.callback_failures,
            "diagnostics":progress.diagnostics, "omittedDiagnostics":progress.omitted,
            "limits":{"applications":MAX_APPS,"logicalRoots":MAX_ROOTS,
                "authorityBytes":MAX_AUTHORITY_BYTES,"diagnostics":MAX_DIAGNOSTICS,
                "selectedLeaves":16384,"scopePathBytes":16*1024*1024,"serializedScopeBytes":64*1024*1024},
            "sourceGraphBridge":if !progress.graph_bound {"not_bound"} else if self.worker.is_some() {"callback_bound"} else {"configured_inactive"},
            "trackerGapInvalidation":"unavailable_no_public_overflow_api",
            "gapDelivery":"authenticated_change_hint_with_unknown_reasons",
            "protectedFileIdentities":"native_owner_supplied_only",
            "protectedNativeFileCount":progress.protected_files,
            "incomplete":true,
        });
        if let Some(snapshot) = snapshot {
            status["observedBundles"] = json!(snapshot
                .applications
                .iter()
                .filter(|app| app.registered_identity
                    && (app
                        .active_sessions
                        .iter()
                        .any(|session| session.currently_observed)
                        || !app.ended_sessions.is_empty()))
                .count());
            status["pollEpoch"] = json!(snapshot.epoch);
            status["uncertaintyEpoch"] = json!(snapshot.uncertainty_epoch);
            status["lastPollMs"] = json!(snapshot.observed_at_ms);
            status["source"] = serde_json::to_value(&snapshot.source)?;
            status["unknownReasons"] = serde_json::to_value(&snapshot.gaps)?;
            status["runningProcessesObserved"] = json!(snapshot
                .applications
                .iter()
                .filter(
                    |app| app.registered_identity && app.execution_state == ExecutionState::Running
                )
                .map(|app| app
                    .active_sessions
                    .iter()
                    .filter(|session| session.currently_observed)
                    .count())
                .sum::<usize>());
            status["openFileEvidence"] = json!(snapshot.files.len());
            status["unconfirmedProcesses"] = json!(snapshot
                .applications
                .iter()
                .filter(|app| !app.registered_identity)
                .map(|app| app
                    .active_sessions
                    .iter()
                    .filter(|session| session.currently_observed)
                    .count())
                .sum::<usize>());
            status["pendingAssociationReview"] = json!(snapshot
                .applications
                .iter()
                .filter(|app| !app.registered_identity)
                .map(|app| app.root_candidates.len())
                .sum::<usize>());
        }
        if let Some(watermark) = watermark {
            status["pendingLoss"] = json!(watermark.pending_loss);
            if watermark.stopped {
                status["observedBundles"] = json!(0);
                status["runningProcessesObserved"] = json!(0);
                status["unconfirmedProcesses"] = json!(0);
                status["openFileEvidence"] = json!(0);
            }
        }
        if revoked {
            status["state"] = json!("policy_revoked");
        }
        Ok(status)
    }

    /// Stops callback admission and joins/drains the sole native worker. No app data,
    /// provider, tracking policy, saved version or index is removed.
    pub(super) fn shutdown(&self) -> Result<()> {
        self.shared.stopping.store(true, Ordering::Release);
        if let Some(worker) = &self.worker {
            worker.shutdown()?;
        }
        self.shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?
            .state = "stopped";
        Ok(())
    }

    /// Native capture-fence input, never a saved/clean proof or UI authority.
    pub(super) fn watermark(&self) -> Option<ObservationWatermark> {
        let mut watermark = self.worker.as_ref()?.watermark();
        if self.shared.stopping.load(Ordering::Acquire)
            || self.shared.revoked.load(Ordering::Acquire)
            || !self.shared.admission_valid.load(Ordering::Acquire)
        {
            watermark.pending_loss = true;
        }
        Some(watermark)
    }

    pub(super) fn request_reconcile(&self) -> Result<()> {
        self.worker
            .as_ref()
            .context("native observation is inactive")?
            .request_reconcile()
    }
}

impl Drop for ObservationSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn process_snapshot(
    store: &WorkspaceStore,
    tracker: &Tracker,
    bindings: &Arc<[TrackerBundleBinding]>,
    by_app: &BTreeMap<String, usize>,
    context: &ObservationContext,
    policy_scope: &Value,
    policy_grant: &Value,
    shared: &Shared,
    snapshot: Arc<ObservationSnapshot>,
    sink: Option<&SourceGraphSink>,
) -> Result<()> {
    if shared.stopping.load(Ordering::Acquire) || shared.revoked.load(Ordering::Acquire) {
        return Ok(());
    }
    let current = store.app_tracking_policy()?;
    if current.as_ref().is_none_or(|current| {
        &current["policyScope"] != policy_scope || &current["policyGrant"] != policy_grant
    }) {
        shared.revoked.store(true, Ordering::Release);
        shared.diagnostic(None, "native_policy_revoked_or_replaced")?;
        return Ok(());
    }
    let mut failed = false;
    let unknown: Vec<_> = snapshot.gaps.iter().map(|gap| gap.reason).collect();
    for app in snapshot
        .applications
        .iter()
        .filter(|app| app.registered_identity && !app.capture_triggers.is_empty())
    {
        let Some(index) = by_app.get(&app.app_id) else {
            continue;
        };
        let binding = &bindings[*index];
        let result = (|| -> Result<()> {
            let record = tracker.bundle_record(binding.software_id())?;
            let authority = tracker.root_authority(binding.software_id())?;
            let verify =
                |kind: &str, scope: &Value, grant: &Value| store.verify_grant(kind, scope, grant);
            binding.validate_current(&record, &authority, &verify)?;
            if shared.stopping.load(Ordering::Acquire) || shared.revoked.load(Ordering::Acquire) {
                return Ok(());
            }
            let event = if let Some(hint) = binding.hint(&snapshot, context)? {
                let grant = store.issue_grant("tracking_observation", hint.scope())?;
                let mut event = hint.into_event(grant);
                event["nativeObservation"]["unknownReasons"] = serde_json::to_value(&unknown)?;
                event
            } else {
                // A real observer gap is evidence of uncertainty even when no
                // process survived long enough for a generation proof. Do not
                // fabricate app_open/app_close or a session-generation hash.
                if !snapshot.gaps.iter().any(|gap| actionable_gap(gap.reason)) {
                    return Ok(());
                }
                let roots: BTreeSet<_> =
                    binding.roots().iter().map(|root| root.id.clone()).collect();
                let scope = json!({"version":1,"softwareId":binding.software_id(),"appId":binding.app_id(),
                    "kind":"change_hint","rootIds":roots,
                    "trackingScopeHash":blake3::hash(&serde_json::to_vec(&authority["scope"])?).to_hex().to_string()});
                let grant = store.issue_grant("tracking_observation", &scope)?;
                json!({"softwareId":binding.software_id(),"appId":binding.app_id(),"kind":"change_hint",
                    "rootIds":roots,"scope":scope,"grant":grant,
                    "nativeObservation":{"epoch":snapshot.epoch,"kind":"observation_gap",
                        "processGeneration":null,"unknownReasons":unknown,"completeness":"unknown",
                        "clean":false,"applicationAtomic":false,"requiresReconciliation":true}})
            };
            let admitted = tracker.observe_application(&event)?;
            ensure!(
                admitted["reconciliationRequired"] == true && admitted["cloudWrite"] == false,
                "native tracking did not admit an uncertainty hint"
            );
            let mut progress = shared
                .state
                .lock()
                .map_err(|_| anyhow!("observation progress lock failed"))?;
            progress.emitted = progress.emitted.saturating_add(1);
            Ok(())
        })();
        if result.is_err() {
            failed = true;
            shared.diagnostic(
                Some(binding.software_id()),
                "native_observation_binding_changed_or_delivery_failed",
            )?;
        }
    }
    if !failed && !shared.stopping.load(Ordering::Acquire) {
        if let Some(sink) = sink {
            if sink(snapshot, bindings.clone()).is_err() {
                failed = true;
                shared.diagnostic(None, "source_graph_bridge_failed")?;
            }
        }
    }
    if failed {
        let mut progress = shared
            .state
            .lock()
            .map_err(|_| anyhow!("observation progress lock failed"))?;
        progress.callback_failures = progress.callback_failures.saturating_add(1);
        anyhow::bail!("native observation delivery is uncertain; reconciliation is required");
    }
    Ok(())
}

fn actionable_gap(reason: GapReason) -> bool {
    !matches!(
        reason,
        GapReason::PollingCannotObserveShortLivedOpens | GapReason::PollingCannotObserveExecAndBack
    )
}

/// Authenticated, bounded actual No Land DB sink. The source bridge independently
/// verifies current policy/tracking MACs, native registration and exact paths.
/// No runtime/preflight, provider, capture, index walk, content hash or Linux
/// collector is requested here. Windows source graph admission is not claimed.
#[cfg(unix)]
pub(super) fn native_source_graph_sink(
    store: WorkspaceStore,
    tracker: Arc<Tracker>,
    engine: Arc<quicksave_noland::NativeEngine>,
    protected_native_files: Vec<NativeFileIdentity>,
) -> Result<SourceGraphSink> {
    ensure!(
        protected_native_files.len() <= MAX_EXCLUSIONS,
        "source graph native protection bound exceeded"
    );
    let observer = uuid::Uuid::new_v4();
    let protected = serde_json::to_value(protected_native_files)?;
    Ok(Arc::new(move |snapshot, bindings| {
        for app in snapshot
            .applications
            .iter()
            .filter(|app| app.registered_identity)
        {
            let Some(binding) = bindings
                .iter()
                .find(|binding| binding.app_id() == app.app_id)
            else {
                continue;
            };
            let hints: Vec<_> = snapshot
                .unattributed_root_hints
                .iter()
                .filter(|id| binding.roots().iter().any(|root| &root.id == *id))
                .collect();
            if app.capture_triggers.is_empty() && hints.is_empty() {
                continue;
            }
            let record = tracker.bundle_record(binding.software_id())?;
            let authority = tracker.root_authority(binding.software_id())?;
            binding.validate_current(
                &record,
                &authority,
                &|kind: &str, scope: &Value, grant: &Value| store.verify_grant(kind, scope, grant),
            )?;
            let sessions: Vec<_> = app
                .active_sessions
                .iter()
                .map(|session| (session, false))
                .chain(app.ended_sessions.iter().map(|session| (session, true)))
                .collect();
            let scope_fingerprint = sessions
                .first()
                .map(|(session, _)| session.process.scope_fingerprint());
            let processes: Vec<Value> = sessions.iter().map(|(session,ended)|json!({
                "id":session.id,"proof":session.process,"current":session.currently_observed,
                "ended":ended,"nativeReason":format!("{:?}",session.boundary),
            })).collect();
            let files: Vec<_> = snapshot
                .files
                .iter()
                .filter(|file| file.process().app_id() == binding.app_id())
                .collect();
            let app_gaps: Vec<_> = snapshot
                .gaps
                .iter()
                .filter(|gap| {
                    gap.root_id
                        .as_deref()
                        .is_none_or(|id| binding.roots().iter().any(|root| root.id == id))
                })
                .collect();
            let mut gaps = serde_json::to_value(app_gaps)?
                .as_array()
                .context("native source gaps unavailable")?
                .clone();
            for root in hints {
                gaps.push(json!({"reason":"approved_unattributed_root_hint","root_id":root}));
            }
            ensure!(gaps.len() <= 128, "native source graph gap bound exceeded");
            let pages = files.len().max(1).div_ceil(256);
            for page in 0..pages {
                let start = (page * 256).min(files.len());
                let end = (start + 256).min(files.len());
                let observation = json!({
                    "version":1,"observerId":observer,"epoch":snapshot.epoch,"page":page,
                    "finalPage":page+1 == pages,"observedAtMs":snapshot.observed_at_ms,
                    "scopeFingerprint":scope_fingerprint,"source":snapshot.source,
                    "processes":processes,"files":files[start..end],"gaps":gaps,
                    "protectedNativeFiles":protected,"completeness":"unknown","clean":false,"applicationAtomic":false,
                });
                let scope = quicksave_noland::NativeEngine::native_observation_scope(
                    &record,
                    &authority,
                    &observation,
                )?;
                let grant = store.issue_grant("source_native_observation", &scope)?;
                let admitted = engine.native_observe_application(json!({
                    "record":record,"rootAuthority":authority,"observation":observation,"scope":scope,"grant":grant,
                }))?;
                ensure!(
                    admitted["requiresReconciliation"] == true
                        && admitted["coverageTrusted"] == false
                        && admitted["cloudWrite"] == false
                        && admitted["appId"] == binding.source_app_id()
                        && admitted["softwareInstanceId"] == binding.app_id()
                        && admitted["nativeFileUseFacts"].as_u64() == Some((end - start) as u64),
                    "actual native source DB did not acknowledge the uncertainty facts"
                );
            }
        }
        Ok(())
    }))
}

/// Private adapters close over the actual frozen Tracker owner; no JSON caller
/// can install these callbacks or substitute UI file listings for native stamps.
#[cfg(unix)]
struct SourceMetadataIndexOwner {
    store: WorkspaceStore,
    tracker: Arc<Tracker>,
    scope: NativeIndexScope,
    protected: Vec<(u64, [u64; 2])>,
    frozen: Arc<quicksave_tracking::NativeMetadataIndex>,
}

#[cfg(unix)]
impl NativeIndexOwner for SourceMetadataIndexOwner {
    fn root_authority(&self, scope: &NativeIndexScope) -> Result<Value> {
        self.verify_current(scope)?;
        self.tracker.root_authority(&scope.software_id)
    }

    fn verify_current(&self, scope: &NativeIndexScope) -> Result<()> {
        ensure!(
            scope == &self.scope,
            "native source requested a different frozen metadata scope"
        );
        self.frozen.revalidate()?;
        let record = self.tracker.bundle_record(&scope.software_id)?;
        ensure!(
            record["appId"] == scope.instance_id
                && record["sourceIdentity"]["app_id"] == scope.app_id
                && record["bundleIndexSource"]["revisionId"] == scope.revision_id
                && record["bundleIndexSource"]["snapshotIdentity"] == scope.snapshot_identity
                && record["bundleIndexSource"]["trackingScopeHash"] == scope.tracking_scope_hash,
            "actual native Tracker index identity/revision changed"
        );
        let current = self
            .store
            .app_tracking_policy()?
            .context("native source index policy is absent or revoked")?;
        ensure!(
            current["policyScope"] == record["autoEnrollment"]["policyScope"]
                && current["policyGrant"] == record["autoEnrollment"]["policyGrant"],
            "native source index policy changed"
        );
        let authority = self.tracker.root_authority(&scope.software_id)?;
        ensure!(
            self.store
                .verify_grant("tracking", &authority["scope"], &authority["grant"])?,
            "native source index tracking MAC is revoked"
        );
        Ok(())
    }

    fn protected_file_ids(&self) -> Result<Vec<(u64, [u64; 2])>> {
        Ok(self.protected.clone())
    }

    fn node_page(
        &self,
        scope: &NativeIndexScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<quicksave_noland::capture_control::FrozenCaptureNode>> {
        ensure!(
            scope == &self.scope && limit > 0 && limit <= 256 && offset <= scope.node_count,
            "native source metadata page exceeds its frozen scope"
        );
        let page = self.frozen.node_page(offset, limit)?;
        ensure!(
            page["revisionId"] == scope.revision_id
                && page["metadataIdentity"] == scope.snapshot_identity
                && page["nodeCount"].as_u64() == Some(scope.node_count as u64)
                && page["offset"].as_u64() == Some(offset as u64)
                && page["metadataOnly"] == true
                && page["fileStateTrust"] == "VERIFY_REQUIRED"
                && page["reconciliationRequired"] == true
                && page["saved"] == false,
            "actual frozen native Tracker page changed identity or trust"
        );
        let rows = page["nodes"]
            .as_array()
            .context("actual frozen native nodes are unavailable")?;
        ensure!(
            rows.len() <= limit,
            "actual frozen native node count exceeds page bound"
        );
        let nodes = rows
            .iter()
            .map(
                |node| -> Result<quicksave_noland::capture_control::FrozenCaptureNode> {
                    let text = |key: &str, bound: usize| -> Result<String> {
                        let text = node[key]
                            .as_str()
                            .context("actual frozen native node field is missing")?;
                        ensure!(
                            !text.is_empty()
                                && text.len() <= bound
                                && !text.chars().any(char::is_control),
                            "actual frozen native node field exceeds bounds"
                        );
                        Ok(text.into())
                    };
                    ensure!(
                        node.get("fileHash").is_none(),
                        "metadata import cannot accept a predicted content hash"
                    );
                    let root = text("rootId", 512)?;
                    Ok(quicksave_noland::capture_control::FrozenCaptureNode {
                        id: text("id", 512)?,
                        root_id: root.clone(),
                        logical_root: quicksave_noland::native_capture_root_token(
                            &scope.app_id,
                            &root,
                        )?,
                        path: text("path", 4096)?,
                        kind: text("kind", 32)?,
                        size: node["size"]
                            .as_u64()
                            .context("actual native metadata node size is missing")?,
                        stamp: serde_json::from_value(node["stamp"].clone()).context(
                            "actual native metadata node requires its full original stamp",
                        )?,
                        link_target_hash: node
                            .get("linkTargetHash")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    })
                },
            )
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            nodes.len() <= limit && nodes.len() <= scope.node_count.saturating_sub(offset),
            "actual native Tracker metadata page exceeds its frozen count"
        );
        Ok(nodes)
    }
}

/// Explicit native materialization, never a status/file-list poll. Register and
/// import each exact instance before switching capture bindings to the next.
#[cfg(unix)]
pub(super) fn materialize_source_indices(
    store: WorkspaceStore,
    tracker: Arc<Tracker>,
    engine: Arc<quicksave_noland::NativeEngine>,
    protected_native_files: Vec<NativeFileIdentity>,
) -> Result<Value> {
    ensure!(
        protected_native_files.len() <= MAX_EXCLUSIONS,
        "native metadata protection bound exceeded"
    );
    let document = store.document()?;
    ensure!(
        document
            .settings
            .app_tracking
            .as_ref()
            .is_some_and(|policy| policy.policy_scope.enabled),
        "native metadata import requires explicit enabled app tracking policy"
    );
    drop(document);
    let policy = store
        .app_tracking_policy()?
        .context("native metadata import policy is invalid or revoked")?;
    ensure!(
        store.verify_grant(
            "app_tracking_policy",
            &policy["policyScope"],
            &policy["policyGrant"]
        )?,
        "native metadata import policy MAC is invalid"
    );
    let bundles = tracker.bundles()?;
    ensure!(
        bundles.len() <= MAX_APPS,
        "native metadata app count exceeds bound"
    );
    let indexed = bundles.len();
    let mut summaries = Vec::new();
    let mut diagnostics = Vec::new();
    let mut omitted = 0usize;
    let mut canonical = BTreeSet::new();
    let mut imported_nodes = 0u64;
    for bundle in bundles {
        let software = bundle["id"]
            .as_str()
            .context("actual native bundle ID is missing")?;
        ensure!(
            !software.is_empty()
                && software.len() <= 512
                && !software.chars().any(char::is_control),
            "actual native bundle ID exceeds bound"
        );
        let result = (|| -> Result<Value> {
            let record = tracker.bundle_record(software)?;
            let scope = source_index_scope(&record)?;
            let authority = tracker.root_authority(software)?;
            ensure!(
                record["autoEnrollment"]["policyScope"] == policy["policyScope"]
                    && record["autoEnrollment"]["policyGrant"] == policy["policyGrant"]
                    && store.verify_grant("tracking", &authority["scope"], &authority["grant"])?,
                "native index instance/current policy authority changed"
            );
            // Drop our obsolete read lease, not data, history or root authority,
            // before asking Tracker to charge its current bounded native owner.
            engine.native_release_index_owner(software)?;
            let frozen = tracker.freeze_metadata_index(software)?;
            let header = frozen.header()?;
            ensure!(
                header["version"] == 1
                    && header["softwareId"] == scope.software_id
                    && header["appId"] == scope.app_id
                    && header["instanceId"] == scope.instance_id
                    && header["revisionId"] == scope.revision_id
                    && header["snapshotIdentity"] == scope.snapshot_identity
                    && header["trackingScopeHash"] == scope.tracking_scope_hash
                    && header["nodeCount"].as_u64() == Some(scope.node_count as u64)
                    && header["metadataOnly"] == true
                    && header["fileStateTrust"] == "VERIFY_REQUIRED"
                    && header["reconciliationRequired"] == true
                    && header["coverageTrusted"] == false
                    && header["complete"] == false
                    && header["saved"] == false
                    && header["cloudWrite"] == false,
                "actual frozen index header does not match exact native instance/trust"
            );
            let owner = Arc::new(SourceMetadataIndexOwner {
                store: store.clone(),
                tracker: tracker.clone(),
                scope: scope.clone(),
                frozen,
                protected: protected_native_files
                    .iter()
                    .map(|id| (id.device, id.file_id))
                    .collect(),
            });
            owner.verify_current(&scope)?;
            engine.register_materialized(&record)?;
            let imported = engine.native_materialize_index(record, owner)?;
            ensure!(
                imported["softwareId"] == scope.software_id
                    && imported["sourceAppId"] == scope.app_id
                    && imported["softwareInstanceId"] == scope.instance_id
                    && imported["revisionId"] == scope.revision_id
                    && imported["sourceIndexedNodes"].as_u64() == Some(scope.node_count as u64)
                    && imported["sourceIndexMaterialized"] == true
                    && imported["metadataOnly"] == true
                    && imported["fileStateTrust"] == "VERIFY_REQUIRED"
                    && imported["coverageTrusted"] == false
                    && imported["complete"] == false
                    && imported["saved"] == false
                    && imported["cloudWrite"] == false,
                "actual source DB did not acknowledge frozen metadata import"
            );
            Ok(imported)
        })();
        match result {
            Ok(summary) => {
                canonical.insert(
                    summary["sourceAppId"]
                        .as_str()
                        .context("actual source app acknowledgment missing")?
                        .to_owned(),
                );
                imported_nodes = imported_nodes
                    .checked_add(
                        summary["sourceIndexedNodes"]
                            .as_u64()
                            .context("actual source index node acknowledgment missing")?,
                    )
                    .context("native source node count overflow")?;
                summaries.push(summary);
            }
            Err(_) => {
                if diagnostics.len() < MAX_DIAGNOSTICS {
                    diagnostics.push(json!({"softwareId":software,"code":"native_source_index_unavailable_or_changed",
                        "sourceIndexMaterialized":false,"requiresReconciliation":true}));
                } else {
                    omitted += 1;
                }
            }
        }
    }
    Ok(
        json!({"indexedBundles":indexed,"sourceIndexedInstances":summaries.len(),
        "sourceCanonicalApps":canonical.len(),"sourceIndexedNodes":imported_nodes,
        "instances":summaries,"diagnostics":diagnostics,"omittedDiagnostics":omitted,
        "incomplete":!diagnostics.is_empty() || omitted > 0,
        "fileStateTrust":"VERIFY_REQUIRED","coverageTrusted":false,"complete":false,"saved":false,"cloudWrite":false}),
    )
}

#[cfg(unix)]
fn source_index_scope(record: &Value) -> Result<NativeIndexScope> {
    let index = &record["bundleIndexSource"];
    let text = |value: &Value| -> Result<String> {
        let text = value
            .as_str()
            .context("actual native index identity is missing")?;
        ensure!(
            !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control),
            "actual native index identity exceeds bounds"
        );
        Ok(text.to_owned())
    };
    let count = ["fileCount", "directoryCount", "symlinkCount"]
        .into_iter()
        .try_fold(0usize, |count, key| -> Result<usize> {
            count
                .checked_add(usize::try_from(
                    index[key]
                        .as_u64()
                        .context("actual native index count is missing")?,
                )?)
                .context("actual native index count overflow")
        })?;
    ensure!(
        count <= 250_000,
        "actual native index exceeds the Tracker/source node bound"
    );
    Ok(NativeIndexScope {
        software_id: text(&record["id"])?,
        app_id: text(&record["sourceIdentity"]["app_id"])?,
        instance_id: text(&record["appId"])?,
        revision_id: text(&index["revisionId"])?,
        snapshot_identity: text(&index["snapshotIdentity"])?,
        tracking_scope_hash: text(&index["trackingScopeHash"])?,
        node_count: count,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use quicksave_observation::{
        CapabilityState, DescriptorSample, ImageIdentityBinding, NativeFileIdentity, PollingSource,
        ProbeListing, ProcessDescriptor, ProcessGeneration, ProcessProbe, SourceCapabilities,
        SourceKind,
    };
    use quicksave_platform::{FileStamp, SafeRoot};
    use quicksave_state::MemoryVault;
    use quicksave_tracking::TrackingStore;
    use std::{
        fs,
        sync::{
            atomic::AtomicUsize,
            mpsc::{sync_channel, Receiver, SyncSender},
        },
        time::{Duration, Instant},
    };

    // Only temporary local files and MemoryVault. Records remain in this
    // injected Tracker store; all grants still use the real WorkspaceStore MAC
    // and persistent (in-memory vault) nonce implementation.
    struct TestTrackingStore {
        store: WorkspaceStore,
        records: Mutex<BTreeMap<String, Value>>,
        observation_scopes: Mutex<Vec<Value>>,
        accepted_observations: Mutex<Vec<Value>>,
        initial_audit: SyncSender<String>,
    }
    impl TrackingStore for TestTrackingStore {
        fn load_records(&self) -> Result<Vec<Value>> {
            Ok(Vec::new())
        }
        fn save_record(&self, value: &Value) -> Result<()> {
            self.records
                .lock()
                .unwrap()
                .insert(value["id"].as_str().unwrap().into(), value.clone());
            // Observe the real startup metadata audit, not a fabricated clean
            // transition. Notification is bounded/nonblocking while Tracker may
            // hold its own state lock. Fixture-only, never a production guard.
            if std::thread::current().name() == Some("quicksave-tracking")
                && value["status"] == "needs_backup"
                && value["dirty"] == true
                && value["bundleIndexSource"]["contentState"] == "metadata_indexed"
            {
                if let Some(software) = value["id"].as_str() {
                    let _ = self.initial_audit.try_send(software.to_owned());
                }
            }
            Ok(())
        }
        fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
            if kind == "tracking_observation" {
                self.observation_scopes.lock().unwrap().push(scope.clone());
            }
            self.store.issue_grant(kind, scope)
        }
        fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
            let valid = self.store.verify_grant(kind, scope, grant)?;
            if valid && kind == "tracking_observation" {
                self.accepted_observations
                    .lock()
                    .unwrap()
                    .push(scope.clone());
            }
            Ok(valid)
        }
        fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
            self.store.revoke_grant(kind, scope)
        }
        fn provider_writable(&self, _: &str) -> Result<bool> {
            Ok(false)
        }
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        store: WorkspaceStore,
        vault: Arc<MemoryVault>,
        tracking: Arc<TestTrackingStore>,
        tracker: Arc<Tracker>,
        policy: TrackingPolicy,
        app: PathBuf,
        executable: PathBuf,
        file: PathBuf,
        software: String,
        app_id: String,
        initial_audit: Mutex<Receiver<String>>,
    }

    fn stamp(path: &Path) -> FileStamp {
        SafeRoot::open(path.parent().unwrap())
            .unwrap()
            .read_file(path.file_name().unwrap().to_str().unwrap())
            .unwrap()
            .1
    }
    fn digest(value: &Value) -> String {
        blake3::hash(&serde_json::to_vec(value).unwrap())
            .to_hex()
            .to_string()
    }

    impl Fixture {
        fn new(with_policy: bool, known_executable: bool, file_only: bool) -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let temp = tempfile::tempdir_in(base).unwrap();
            let applications = temp.path().join("Applications");
            let app = applications.join("Synthetic");
            fs::create_dir_all(&app).unwrap();
            let executable = app.join("game.bin");
            let file = app.join("slot.dat");
            fs::write(&executable, b"synthetic image never executed").unwrap();
            fs::write(&file, b"synthetic saved file never read by the observer").unwrap();
            let data = temp.path().join("state");
            let vault = Arc::new(MemoryVault::default());
            let store = WorkspaceStore::open_with_vault(&data, vault.clone()).unwrap();
            let mut policy = TrackingPolicy::new(&data);
            policy.supports_metadata_snapshots = true;
            policy.excluded_paths.push(data.clone());
            // Keep periodic audits outside these bounded unit-test windows.
            // The initial mandatory audit still runs and remains observable.
            policy.audit_interval = Duration::from_secs(60 * 60);
            let (initial_audit_tx, initial_audit_rx) = sync_channel(1);
            let tracking = Arc::new(TestTrackingStore {
                store: store.clone(),
                records: Mutex::new(BTreeMap::new()),
                observation_scopes: Mutex::new(Vec::new()),
                accepted_observations: Mutex::new(Vec::new()),
                initial_audit: initial_audit_tx,
            });
            let tracker = Arc::new(
                Tracker::open(tracking.clone(), Arc::new(|_| Ok(())), policy.clone()).unwrap(),
            );
            let app_id = "steam:480@native-fixture-install".to_owned();
            let mut software = String::new();
            if with_policy {
                let root = SafeRoot::open(&applications).unwrap().identity().unwrap();
                let scope = json!({
                    "version":1,"policyId":"fixture-native-policy","rolePolicyVersion":1,
                    "source":"verified_native_discovery","enabled":true,
                    "baseDirectories":[{"id":"fixture-base","path":applications,"identity":root,
                        "allowedRoles":["runtime"],"ownershipRules":["native_executable_handle"]}],
                    "appIdentityPolicy":{"allowedAppIds":[app_id],"allowNewVerifiedApps":false,
                        "allowedEvidenceKinds":["native_executable_handle"],"allowNativeInstallationOnly":false},
                    "excludedPaths":[data],
                });
                let grant = store.issue_grant("app_tracking_policy", &scope).unwrap();
                store
                    .set_app_tracking_policy(&json!({"policyScope":scope,"policyGrant":grant}))
                    .unwrap();
                let evidence =
                    json!([{"kind":"native_executable_handle","identifier":"fixture-runtime"}]);
                let native = if file_only {
                    let stamp = stamp(&executable);
                    json!({"platform":"unix","kind":"regular_file","device":stamp.device,"inode":stamp.file_id[0]})
                } else {
                    let identity = SafeRoot::open(&app).unwrap().identity().unwrap();
                    json!({"platform":"unix","kind":"directory","device":identity.device,"inode":identity.file_id[0]})
                };
                let candidate = json!({
                    "appId":app_id,"productId":"steam:480","displayName":"Synthetic",
                    "sourceIdentity":{"app_id":"steam:480","steam_app_id":480,"display_name":"Synthetic",
                        "canonical_executable":if known_executable {json!(executable)} else {Value::Null},
                        "desktop_entry_id":null,"launcher":"steam","aliases":[],"identity_confidence":1.0,"icon_path":null},
                    "identityEvidence":evidence,"rootsComplete":false,"unresolvedRoots":[],"unresolvedReasons":[],
                    "sourceRoots":[{"rootId":"fixture-runtime","path":if file_only {json!(executable)} else {json!(app)},
                        "classification":"runtime","roles":["runtime"],"status":"verified_candidate",
                        "nativeIdentity":native,"evidence":evidence,"ownership":"exact_native_runtime"}],
                });
                let candidates = json!([candidate]);
                let discovery = json!({"version":1,"source":"verified_native_discovery",
                    "policyHash":digest(&scope),"candidatesHash":digest(&candidates)});
                let discovery_grant = store.issue_grant("bundle_discovery", &discovery).unwrap();
                let authority = json!({"policyScope":scope,"policyGrant":grant,
                    "discoveryScope":discovery,"discoveryGrant":discovery_grant});
                let output = tracker
                    .materialize_bundles(candidates.as_array().unwrap(), &authority)
                    .unwrap();
                software = output["bundles"][0]["id"]
                    .as_str()
                    .expect("actual materialized fixture bundle")
                    .into();
            }
            Self {
                _temp: temp,
                store,
                vault,
                tracking,
                tracker,
                policy,
                app,
                executable,
                file,
                software,
                app_id,
                initial_audit: Mutex::new(initial_audit_rx),
            }
        }

        fn wait_for_initial_metadata_audit(&self) {
            let software = self
                .initial_audit
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect(
                    "real initial Tracker metadata audit did not finish within the fixture bound",
                );
            assert_eq!(software, self.software);
            let record = self.tracker.bundle_record(&software).unwrap();
            assert_eq!(record["status"], "needs_backup");
            assert_eq!(record["dirty"], true);
            assert_eq!(
                record["bundleIndexSource"]["contentState"],
                "metadata_indexed"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.tracker.shutdown();
        }
    }

    struct InjectedProcesses {
        process: ProcessDescriptor,
        file: DescriptorSample,
        running: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
        on_first_process: Option<Box<dyn FnMut() -> Result<()> + Send>>,
    }
    impl ProcessProbe for InjectedProcesses {
        fn capabilities(&self) -> SourceCapabilities {
            SourceCapabilities {
                source: SourceKind::InjectedFixture,
                state: CapabilityState::Available,
                process_generations: true,
                executable_stamps: true,
                running_image_native_identity: true,
                native_open_file_identity: true,
                bundle_identifier_verification: false,
                complete_lifecycle_stream: false,
                complete_file_stream: false,
                reason: "Injected temporary native observation fixture; no OS process enumeration.",
            }
        }
        fn processes(&mut self, _: &ObservationScope, _: usize) -> Result<ProbeListing<u32>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(ProbeListing {
                items: if self.running.load(Ordering::Acquire) {
                    vec![41]
                } else {
                    vec![]
                },
                complete: true,
            })
        }
        fn process(&mut self, _: &ObservationScope, _: u32) -> Result<Option<ProcessDescriptor>> {
            if let Some(mut hook) = self.on_first_process.take() {
                hook()?;
            }
            Ok(Some(self.process.clone()))
        }
        fn descriptors(&mut self, _: u32, _: usize) -> Result<ProbeListing<u64>> {
            Ok(ProbeListing {
                items: vec![7],
                complete: true,
            })
        }
        fn descriptor(
            &mut self,
            _: &ObservationScope,
            _: u32,
            _: u64,
        ) -> Result<Option<DescriptorSample>> {
            Ok(Some(self.file.clone()))
        }
    }

    fn config() -> WorkerConfig {
        WorkerConfig {
            poll_interval: Duration::from_millis(10),
            idle_poll_interval: Duration::from_millis(100),
            queue_capacity: 8,
            watch_roots: false,
        }
    }

    const LIFECYCLE_EVENT_LIMIT: usize = 64;

    /// Consume only fixture notifications, not the worker's native evidence.
    /// Older legitimate frames may already be queued when a reconcile is
    /// requested. Neither each received frame nor a stale matching state can
    /// extend the absolute deadline or satisfy the requested epoch fence.
    fn wait_for_execution_state(
        receiver: &Receiver<(u64, ExecutionState)>,
        expected: ExecutionState,
        after_epoch: u64,
        deadline: Instant,
        event_limit: usize,
    ) -> Result<(u64, usize)> {
        ensure!(
            event_limit > 0 && event_limit <= LIFECYCLE_EVENT_LIMIT,
            "invalid fixture lifecycle event bound"
        );
        for received in 1..=event_limit {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("fixture lifecycle absolute deadline expired")?;
            let (epoch, state) = receiver
                .recv_timeout(remaining)
                .context("fixture lifecycle notification timed out or disconnected")?;
            ensure!(
                Instant::now() <= deadline,
                "fixture lifecycle absolute deadline expired"
            );
            if epoch > after_epoch && state == expected {
                return Ok((epoch, received));
            }
        }
        anyhow::bail!("fixture lifecycle event bound exceeded before the requested state/epoch");
    }

    #[test]
    fn lifecycle_wait_drains_queued_running_and_stale_terminal_notifications() {
        let (tx, rx) = sync_channel(4);
        tx.try_send((1, ExecutionState::NotObservedRunning))
            .unwrap();
        tx.try_send((2, ExecutionState::Running)).unwrap();
        tx.try_send((3, ExecutionState::Running)).unwrap();
        tx.try_send((4, ExecutionState::NotObservedRunning))
            .unwrap();
        let (epoch, received) = wait_for_execution_state(
            &rx,
            ExecutionState::NotObservedRunning,
            2,
            Instant::now() + Duration::from_secs(10),
            4,
        )
        .unwrap();
        assert_eq!((epoch, received), (4, 4));
    }

    #[test]
    fn lifecycle_wait_cannot_extend_its_deadline_or_event_budget() {
        let (tx, rx) = sync_channel(3);
        tx.try_send((1, ExecutionState::Running)).unwrap();
        tx.try_send((2, ExecutionState::Running)).unwrap();
        tx.try_send((3, ExecutionState::NotObservedRunning))
            .unwrap();
        let error = wait_for_execution_state(
            &rx,
            ExecutionState::NotObservedRunning,
            0,
            Instant::now() + Duration::from_secs(10),
            2,
        )
        .unwrap_err();
        assert!(error.to_string().contains("event bound"));
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let error =
            wait_for_execution_state(&rx, ExecutionState::NotObservedRunning, 0, expired, 1)
                .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        // The expired wait did not silently accept or remove a matching frame.
        assert_eq!(
            rx.try_recv().unwrap(),
            (3, ExecutionState::NotObservedRunning)
        );
    }

    #[test]
    fn disabled_and_status_paths_do_not_read_a_vault_or_construct_process_sources() {
        let fixture = Fixture::new(false, false, false);
        let before = fixture.vault.access_log().unwrap();
        let session = ObservationSession::start_if_enabled(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            false,
        )
        .unwrap();
        for _ in 0..5 {
            assert_eq!(session.status().unwrap()["running"], false);
            assert_eq!(session.status().unwrap()["enabled"], false);
        }
        session.shutdown().unwrap();
        assert_eq!(fixture.vault.access_log().unwrap(), before);
        assert!(ObservationSession::start(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![]
        )
        .is_err()); // cfg(test) forbids ambient startup
    }

    #[test]
    fn real_frozen_index_owner_preserves_exact_file_selection_and_full_change_stamps() {
        let fixture = Fixture::new(true, true, true);
        fixture.wait_for_initial_metadata_audit();
        let record = fixture.tracker.bundle_record(&fixture.software).unwrap();
        let scope = source_index_scope(&record).unwrap();
        let owner = SourceMetadataIndexOwner {
            store: fixture.store.clone(),
            tracker: fixture.tracker.clone(),
            scope: scope.clone(),
            protected: vec![],
            frozen: fixture
                .tracker
                .freeze_metadata_index(&fixture.software)
                .unwrap(),
        };
        let before = fixture.tracker.performance_counters();
        let page = owner.node_page(&scope, 0, 256).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].path, "game.bin");
        let actual_stamp: FileStamp =
            serde_json::from_value(serde_json::to_value(&page[0].stamp).unwrap()).unwrap();
        assert_eq!(actual_stamp, stamp(&fixture.executable));
        owner.verify_current(&scope).unwrap();
        assert!(owner
            .node_page(&scope, scope.node_count, 1)
            .unwrap()
            .is_empty());
        assert_eq!(fixture.tracker.performance_counters(), before);
    }

    #[test]
    fn explicit_source_import_uses_actual_native_owner_and_never_hashes_content() {
        let fixture = Fixture::new(true, true, false);
        let home = fixture._temp.path().join("source-home");
        fs::create_dir(&home).unwrap();
        let engine = Arc::new(
            quicksave_noland::NativeEngine::open(&fixture._temp.path().join("state"), &home)
                .unwrap()
                .with_workspace(fixture.store.clone())
                .unwrap(),
        );
        fixture.wait_for_initial_metadata_audit();
        let before = fixture.tracker.performance_counters();
        let result = materialize_source_indices(
            fixture.store.clone(),
            fixture.tracker.clone(),
            engine.clone(),
            vec![],
        )
        .unwrap();
        assert_eq!(result["sourceIndexedInstances"], 1);
        assert_eq!(result["sourceCanonicalApps"], 1);
        assert_eq!(result["sourceIndexedNodes"], 2);
        assert_eq!(result["incomplete"], false);
        assert_eq!(result["fileStateTrust"], "VERIFY_REQUIRED");
        assert_eq!(result["complete"], false);
        assert_eq!(result["saved"], false);
        assert_eq!(result["cloudWrite"], false);
        assert_eq!(
            engine.native_observation_status(&fixture.software).unwrap()["sourceIndexMaterialized"],
            true
        );
        assert_eq!(
            fixture.tracker.performance_counters(),
            before,
            "the first explicit import must only read the frozen metadata index"
        );
        let again = materialize_source_indices(
            fixture.store.clone(),
            fixture.tracker.clone(),
            engine,
            vec![],
        )
        .unwrap();
        assert_eq!(again["sourceIndexedInstances"], 1);
        assert_eq!(
            fixture.tracker.performance_counters(),
            before,
            "explicit reimport must not add a Tracker tree walk, metadata refresh, or content read"
        );
    }

    #[test]
    fn no_native_policy_means_no_vault_unlock_or_injected_source_admission() {
        let fixture = Fixture::new(false, false, false);
        let before = fixture.vault.access_log().unwrap();
        let admitted = Arc::new(AtomicUsize::new(0));
        let count = admitted.clone();
        let result = ObservationSession::start_injected(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            501,
            move |_| {
                count.fetch_add(1, Ordering::AcqRel);
                anyhow::bail!("must not construct source");
            },
            config(),
            None,
        );
        assert!(result.is_err());
        assert_eq!(admitted.load(Ordering::Acquire), 0);
        assert_eq!(fixture.vault.access_log().unwrap(), before);
    }

    #[test]
    fn unknown_executable_remains_a_diagnostic_without_any_process_source() {
        let fixture = Fixture::new(true, false, false);
        let admitted = Arc::new(AtomicUsize::new(0));
        let count = admitted.clone();
        let session = ObservationSession::start_injected(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            501,
            move |_| {
                count.fetch_add(1, Ordering::AcqRel);
                anyhow::bail!("unknown image must not start a source");
            },
            config(),
            None,
        )
        .unwrap();
        let status = session.status().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["unconfirmedBundles"], 1);
        assert_eq!(status["observedBundles"], 0);
        assert_eq!(admitted.load(Ordering::Acquire), 0);
        assert!(!status.to_string().contains(fixture.app.to_str().unwrap()));
        session.shutdown().unwrap();
    }

    #[test]
    fn actual_materialized_instance_ids_sign_hints_and_selected_files_never_expand() {
        let fixture = Fixture::new(true, true, true);
        let running = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let live = running.clone();
        let observed = calls.clone();
        let file = DescriptorSample {
            path: fixture.file.clone(),
            identity: NativeFileIdentity::from(&stamp(&fixture.file)),
        };
        let expected = fixture.app_id.clone();
        let (tx, rx) = sync_channel(LIFECYCLE_EVENT_LIMIT);
        let sink: SourceGraphSink = Arc::new(move |snapshot, bindings| {
            assert_eq!(bindings[0].app_id(), expected);
            assert_eq!(bindings[0].source_app_id(), "steam:480");
            assert_eq!(snapshot.files.len(), 0); // unselected slot.dat is not parent permission
            let _ = tx.try_send((snapshot.epoch, snapshot.applications[0].execution_state));
            Ok(())
        });
        let session = ObservationSession::start_injected(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            501,
            move |scope| {
                let app = &scope.native_applications()[0];
                assert_eq!(
                    scope.roots().next().unwrap().allowed_files,
                    Some(BTreeSet::from(["game.bin".to_owned()]))
                );
                let process = ProcessDescriptor {
                    generation: ProcessGeneration {
                        pid: 41,
                        uid: 501,
                        start: [9, 1],
                        namespace: [1, 1],
                    },
                    executable: app.executable.clone(),
                    executable_identity: NativeFileIdentity::from(&app.executable_stamp),
                    image_binding: ImageIdentityBinding::MappedImageNativeFile,
                    bundle_identifier: None,
                };
                Ok(Box::new(PollingSource::new(InjectedProcesses {
                    process,
                    file,
                    running: live,
                    calls: observed,
                    on_first_process: None,
                })) as Box<dyn EvidenceSource>)
            },
            config(),
            Some(sink),
        )
        .unwrap();
        let (running_epoch, _) = wait_for_execution_state(
            &rx,
            ExecutionState::Running,
            0,
            Instant::now() + Duration::from_secs(10),
            LIFECYCLE_EVENT_LIMIT,
        )
        .unwrap();
        let record = fixture.tracker.bundle_record(&fixture.software).unwrap();
        assert_eq!(record["appId"], fixture.app_id);
        assert_eq!(record["appRunning"], true);
        assert_eq!(record["roots"][0]["allowedFiles"], json!(["game.bin"]));
        let status = session.status().unwrap();
        assert!(status["emittedHints"].as_u64().unwrap() >= 1);
        assert_eq!(status["completeness"], "unknown");
        assert_eq!(status["clean"], false);
        assert!(!status
            .to_string()
            .contains(fixture.executable.to_str().unwrap()));
        let after_epoch = session.worker.as_ref().unwrap().snapshot().unwrap().epoch;
        assert!(after_epoch >= running_epoch);
        let deadline = Instant::now() + Duration::from_secs(10);
        running.store(false, Ordering::Release);
        session.request_reconcile().unwrap();
        let (closed_epoch, _) = wait_for_execution_state(
            &rx,
            ExecutionState::NotObservedRunning,
            after_epoch,
            deadline,
            LIFECYCLE_EVENT_LIMIT,
        )
        .unwrap();
        assert!(closed_epoch > after_epoch);
        session.shutdown().unwrap();
        let joined_count = calls.load(Ordering::Acquire);
        assert_eq!(session.status().unwrap()["running"], false);
        assert_eq!(calls.load(Ordering::Acquire), joined_count);
        assert_eq!(
            fixture.tracker.bundle_record(&fixture.software).unwrap()["appRunning"],
            false
        );
        assert!(
            fixture
                .tracking
                .observation_scopes
                .lock()
                .unwrap()
                .is_empty(),
            "native owner, not TrackingStore::issue_grant, signs observation scopes"
        );
        let accepted = fixture.tracking.accepted_observations.lock().unwrap();
        assert!(!accepted.is_empty());
        assert!(accepted
            .iter()
            .all(|scope| scope["appId"] == fixture.app_id));
    }

    #[test]
    fn protected_native_id_cannot_be_rebound_as_a_harmless_executable_name() {
        let fixture = Fixture::new(true, true, true);
        let admitted = Arc::new(AtomicUsize::new(0));
        let count = admitted.clone();
        let protected = NativeFileIdentity::from(&stamp(&fixture.executable));
        let session = ObservationSession::start_internal(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            vec![protected],
            Some(501),
            None,
            || anyhow::bail!("must not query the ambient user"),
            move |_| {
                count.fetch_add(1, Ordering::AcqRel);
                anyhow::bail!("protected image must not start a source")
            },
            config(),
        )
        .unwrap();
        let status = session.status().unwrap();
        assert_eq!(status["running"], false);
        assert_eq!(status["unconfirmedBundles"], 1);
        assert_eq!(status["protectedNativeFileCount"], 1);
        assert_eq!(admitted.load(Ordering::Acquire), 0);
        assert!(fixture
            .tracking
            .accepted_observations
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn native_policy_revoked_during_injected_poll_discards_all_proofs_and_signatures() {
        let fixture = Fixture::new(true, true, false);
        let record = fixture.tracker.bundle_record(&fixture.software).unwrap();
        let authority = fixture.tracker.root_authority(&fixture.software).unwrap();
        let verifier = |kind: &str, scope: &Value, grant: &Value| {
            fixture.store.verify_grant(kind, scope, grant)
        };
        let binding = TrackerBundleBinding::from_native_records(
            &record,
            &authority,
            &fixture.executable,
            &verifier,
        )
        .unwrap();
        let mut request = ScopeRequest::new("mid-poll-revocation", 501, vec![], vec![]);
        binding.append_to_scope(&mut request).unwrap();
        let policy = fixture.store.app_tracking_policy().unwrap().unwrap();
        let shared = Shared::new("fixture", false);
        let consent: Arc<dyn ScopeConsent> = Arc::new(Consent {
            store: fixture.store.clone(),
            shared: shared.clone(),
            expected_request_hash: request.fingerprint().unwrap(),
            policy_scope: policy["policyScope"].clone(),
            policy_grant: policy["policyGrant"].clone(),
            tracking: vec![TrackingAuthority {
                scope: authority["scope"].clone(),
                grant: authority["grant"].clone(),
            }],
        });
        let scope = ObservationScope::approve(request, consent).unwrap();
        let context = scope.context();
        let app = &scope.native_applications()[0];
        let process = ProcessDescriptor {
            generation: ProcessGeneration {
                pid: 41,
                uid: 501,
                start: [9, 1],
                namespace: [1, 1],
            },
            executable: app.executable.clone(),
            executable_identity: NativeFileIdentity::from(&app.executable_stamp),
            image_binding: ImageIdentityBinding::MappedImageNativeFile,
            bundle_identifier: None,
        };
        let store = fixture.store.clone();
        let probe = InjectedProcesses {
            process,
            file: DescriptorSample {
                path: fixture.file.clone(),
                identity: NativeFileIdentity::from(&stamp(&fixture.file)),
            },
            running: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            on_first_process: Some(Box::new(move || store.clear_app_tracking_policy())),
        };
        let mut engine = ObservationEngine::new(
            scope,
            Box::new(PollingSource::new(probe)),
            ObservationLimits::default(),
        )
        .unwrap();
        let snapshot = engine.reconcile(100).unwrap();
        assert!(snapshot.files.is_empty());
        assert!(snapshot
            .applications
            .iter()
            .all(|app| app.active_sessions.is_empty()));
        assert!(snapshot
            .gaps
            .iter()
            .any(|gap| gap.reason == GapReason::ConsentRevoked));
        assert!(shared.revoked.load(Ordering::Acquire));
        assert!(!shared.admission_valid.load(Ordering::Acquire));
        let by_app = BTreeMap::from([(binding.app_id().to_owned(), 0)]);
        process_snapshot(
            &fixture.store,
            &fixture.tracker,
            &Arc::from(vec![binding]),
            &by_app,
            &context,
            &policy["policyScope"],
            &policy["policyGrant"],
            &shared,
            snapshot,
            None,
        )
        .unwrap();
        assert!(fixture
            .tracking
            .accepted_observations
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_real_source_gap_signs_only_unknown_change_hints_never_fake_lifecycle() {
        let fixture = Fixture::new(true, true, false);
        let (tx, rx) = sync_channel(2);
        let sink: SourceGraphSink = Arc::new(move |snapshot, _| {
            assert!(snapshot
                .applications
                .iter()
                .all(|app| app.active_sessions.is_empty()));
            assert!(snapshot
                .gaps
                .iter()
                .any(|gap| gap.reason == GapReason::SourcePermissionDenied));
            let _ = tx.try_send(());
            Ok(())
        });
        let session = ObservationSession::start_injected(
            fixture.store.clone(),
            fixture.tracker.clone(),
            fixture.policy.clone(),
            vec![],
            501,
            |_| {
                Ok(Box::new(native::UnavailableSource::new(
                    SourceKind::InjectedFixture,
                    CapabilityState::NeedsNativePermission,
                    "injected source denial",
                )) as Box<dyn EvidenceSource>)
            },
            config(),
            Some(sink),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        session.shutdown().unwrap();
        let accepted = fixture.tracking.accepted_observations.lock().unwrap();
        assert!(!accepted.is_empty());
        assert!(accepted
            .iter()
            .all(|scope| scope["kind"] == "change_hint" && scope["appId"] == fixture.app_id));
        assert!(fixture.tracker.bundle_record(&fixture.software).unwrap()["appRunning"].is_null());
        assert_eq!(session.status().unwrap()["clean"], false);
    }

    #[test]
    fn global_limits_are_explicit_not_the_old_sixty_four_root_cutoff() {
        assert_eq!(MAX_ROOTS, 4096);
        assert_eq!(MAX_APPS, 4096);
        let limits = ObservationLimits {
            max_roots: MAX_ROOTS,
            max_applications: MAX_APPS,
            ..ObservationLimits::default()
        };
        limits.validate().unwrap();
    }
}
