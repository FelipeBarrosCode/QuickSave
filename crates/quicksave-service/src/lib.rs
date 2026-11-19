// SPDX-License-Identifier: GPL-3.0-only
//! Native-authorized software/provider workspace orchestration.
//!
//! The desktop gateway owns one-use exact approval tickets. This crate must
//! never be exposed as an unprotected IPC dispatcher. There is no JSON
//! `"approved": true` escape hatch. Original QuickSave code; no copied engine
//! formats, cryptography, remote provisioning or No Land state migration.
#![forbid(unsafe_code)]

mod batch;
mod batch_adapter;
mod boundary;
#[cfg(any(unix, windows))]
mod capture;
mod catalog;
mod enrollment;
pub mod interfaces;
mod native;
mod native_plans;
mod oauth;
mod observation;
pub mod operations;
mod provider_control;
mod root_guard;
mod workspace_restore;
pub use oauth::open_oauth_browser;

use anyhow::{anyhow, bail, ensure, Result};
use boundary as dto;
use interfaces::{
    Enqueue, PublishGuard, ServiceDiscovery, ServiceEngine, ServiceOAuth, ServiceStore,
    ServiceTracking, SourceGuard, UnavailableOAuth,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use uuid::Uuid;

const AUTOSAVE_QUEUE: usize = 16;
const PREVIEW_LIMIT: usize = 32;
const PREVIEW_LIFETIME: Duration = Duration::from_secs(10 * 60);

#[derive(Default)]
struct Lifetime {
    outstanding: AtomicUsize,
    active: AtomicUsize,
    queued: AtomicUsize,
    queued_bytes: AtomicUsize,
    admitted: AtomicBool,
    stopping: AtomicBool,
    finalization_blocked: AtomicBool,
    changed: tokio::sync::Notify,
    shutdown_complete: AtomicBool,
}

struct Active {
    lifetime: Arc<Lifetime>,
    admitted: bool,
}
impl Active {
    fn acquire(lifetime: &Arc<Lifetime>, admitted: bool) -> Result<Self> {
        ensure!(
            !lifetime.stopping.load(Ordering::SeqCst),
            "The workspace is shutting down"
        );
        ensure!(
            !lifetime.finalization_blocked.load(Ordering::Acquire),
            "A native operation needs durable finalization; keep QuickSave open"
        );
        if admitted {
            ensure!(
                lifetime
                    .admitted
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok(),
                "A storage operation is already active; retry after it completes"
            );
        }
        lifetime.outstanding.fetch_add(1, Ordering::SeqCst);
        lifetime.active.fetch_add(1, Ordering::SeqCst);
        let guard = Self {
            lifetime: lifetime.clone(),
            admitted,
        };
        ensure!(
            !lifetime.stopping.load(Ordering::SeqCst),
            "The workspace is shutting down"
        );
        Ok(guard)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        if self.admitted {
            self.lifetime.admitted.store(false, Ordering::Release);
        }
        self.lifetime.active.fetch_sub(1, Ordering::SeqCst);
        self.lifetime.outstanding.fetch_sub(1, Ordering::SeqCst);
        self.lifetime.changed.notify_waiters();
    }
}

struct OperationGuard {
    active: Active,
    finalized: bool,
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        // Panic/abort after the task starts is an unknown finalization state.
        if !self.finalized {
            self.active
                .lifetime
                .finalization_blocked
                .store(true, Ordering::Release);
        }
    }
}

#[derive(Clone)]
struct RetryPlan {
    action: String,
    params: Value,
    captured: Option<Value>,
    scope: String,
}

struct Operation {
    activity: Value,
    native_id: Option<String>,
    cancelled: bool,
    retry: Option<RetryPlan>,
}

#[derive(Clone)]
struct Preview {
    provider_id: String,
    summary: Value,
    created: Instant,
}

#[derive(Clone)]
struct RestorePreview {
    params: Value,
    summary: Value,
    created: Instant,
}

struct PublicationPayload {
    params: Value,
    scope: String,
    work: Value,
    pin: Arc<dyn SourceGuard>,
}
struct PublicationLease(Arc<Mutex<Option<PublicationPayload>>>);
impl Drop for PublicationLease {
    fn drop(&mut self) {
        // The native engine may retain its callback for a later exact retry.
        // Release large work evidence and pinned handles after this attempt;
        // retry must install a fresh authenticated callback, never reuse it.
        if let Ok(mut payload) = self.0.lock() {
            payload.take();
        }
    }
}

enum QueueItem {
    Work(Value, usize),
    Barrier(oneshot::Sender<()>),
}

struct Queue {
    sender: mpsc::Sender<QueueItem>,
    receiver: mpsc::Receiver<QueueItem>,
    lifetime: Arc<Lifetime>,
}
impl Queue {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(AUTOSAVE_QUEUE);
        Self {
            sender,
            receiver,
            lifetime: Arc::new(Lifetime::default()),
        }
    }
    fn enqueue(&self) -> Enqueue {
        enqueue(self.sender.clone(), self.lifetime.clone())
    }
}

fn enqueue(sender: mpsc::Sender<QueueItem>, lifetime: Arc<Lifetime>) -> Enqueue {
    Arc::new(move |request| {
        // This callback executes on the watcher worker. Never call the engine,
        // store or tracker here, and never block waiting for queue capacity.
        let bytes = dto::bounded_size(&request, dto::MAX_WORK_BYTES)?;
        ensure!(
            !lifetime.stopping.load(Ordering::SeqCst),
            "The autosave worker is stopping"
        );
        let mut current = lifetime.queued_bytes.load(Ordering::SeqCst);
        // A watcher callback never waits for queue capacity. Contention and
        // budget exhaustion both retain the caller's reconciliation obligation.
        let mut reserved = false;
        for _ in 0..64 {
            let next = current.checked_add(bytes).filter(|total| *total <= dto::MAX_WORK_BYTES)
                .ok_or_else(|| anyhow!("The bounded autosave queue byte budget is busy; reconciliation remains pending"))?;
            match lifetime.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    reserved = true;
                    break;
                }
                Err(observed) => current = observed,
            }
        }
        ensure!(
            reserved,
            "The bounded autosave queue byte budget is busy; reconciliation remains pending"
        );
        lifetime.outstanding.fetch_add(1, Ordering::SeqCst);
        lifetime.queued.fetch_add(1, Ordering::SeqCst);
        if lifetime.stopping.load(Ordering::SeqCst) {
            lifetime.queued.fetch_sub(1, Ordering::SeqCst);
            lifetime.outstanding.fetch_sub(1, Ordering::SeqCst);
            lifetime.queued_bytes.fetch_sub(bytes, Ordering::SeqCst);
            bail!("The autosave worker is stopping");
        }
        match sender.try_send(QueueItem::Work(request, bytes)) {
            Ok(()) => Ok(()),
            Err(_) => {
                lifetime.queued.fetch_sub(1, Ordering::SeqCst);
                lifetime.outstanding.fetch_sub(1, Ordering::SeqCst);
                lifetime.queued_bytes.fetch_sub(bytes, Ordering::SeqCst);
                bail!("The bounded autosave queue is busy; reconciliation remains pending")
            }
        }
    })
}

pub struct WorkspaceService {
    store: Arc<dyn ServiceStore>,
    engine: Arc<dyn ServiceEngine>,
    tracking: Arc<dyn ServiceTracking>,
    discovery: Arc<dyn ServiceDiscovery>,
    oauth: Arc<dyn ServiceOAuth>,
    lifetime: Arc<Lifetime>,
    queue_sender: mpsc::Sender<QueueItem>,
    queue_stop: Mutex<Option<oneshot::Sender<()>>>,
    queue_worker: Mutex<Option<JoinHandle<()>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    operations: Mutex<BTreeMap<String, Operation>>,
    previews: Mutex<BTreeMap<String, Preview>>,
    restore_previews: Mutex<BTreeMap<String, RestorePreview>>,
    app_tracking: Mutex<Value>,
    tracking_authorization_issues: Mutex<Vec<Value>>,
    history_initialization_failed: AtomicBool,
    healthy: Mutex<BTreeMap<String, String>>,
    catalog: catalog::CatalogCache,
    batch: tokio::sync::OnceCell<Arc<batch::NativeBatchRuntime>>,
    weak: Weak<Self>,
}

impl WorkspaceService {
    /// Opens only QuickSave's private state/engine directories. The native
    /// credential vault is lazy; empty/new workspaces do not read it.
    pub async fn open(data_dir: &Path, home: &Path) -> Result<Arc<Self>> {
        native::open(data_dir, home, false).await
    }

    /// Development fixture boundary: no real credential vault or No Land finder
    /// locations. Not an IPC option and never selected from browser parameters.
    pub async fn open_isolated(data_dir: &Path, home: &Path) -> Result<Arc<Self>> {
        native::open(data_dir, home, true).await
    }

    /// Explicit synthetic vault injection shared with an isolated native host.
    /// Never used by production open; does not access the operating-system vault.
    pub async fn open_isolated_with_vault(
        data_dir: &Path,
        home: &Path,
        vault: Arc<dyn quicksave_state::CredentialVault>,
    ) -> Result<Arc<Self>> {
        native::open_with_vault(data_dir, home, true, Some(vault)).await
    }

    /// Isolated integration constructor. These injected implementations are the
    /// only implementations used by this crate's tests.
    pub fn with_components(
        store: Arc<dyn ServiceStore>,
        engine: Arc<dyn ServiceEngine>,
        tracking: Arc<dyn ServiceTracking>,
        discovery: Arc<dyn ServiceDiscovery>,
    ) -> Result<Arc<Self>> {
        Self::assemble(
            store,
            engine,
            tracking,
            discovery,
            Arc::new(UnavailableOAuth),
            Queue::new(),
        )
    }

    pub fn with_oauth_components(
        store: Arc<dyn ServiceStore>,
        engine: Arc<dyn ServiceEngine>,
        tracking: Arc<dyn ServiceTracking>,
        discovery: Arc<dyn ServiceDiscovery>,
        oauth: Arc<dyn ServiceOAuth>,
    ) -> Result<Arc<Self>> {
        Self::assemble(store, engine, tracking, discovery, oauth, Queue::new())
    }

    fn assemble(
        store: Arc<dyn ServiceStore>,
        engine: Arc<dyn ServiceEngine>,
        tracking: Arc<dyn ServiceTracking>,
        discovery: Arc<dyn ServiceDiscovery>,
        oauth: Arc<dyn ServiceOAuth>,
        queue: Queue,
    ) -> Result<Arc<Self>> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow!("A native asynchronous runtime is required"))?;
        let (stop, stop_rx) = oneshot::channel();
        let Queue {
            sender,
            receiver,
            lifetime,
        } = queue;
        let service = Arc::new_cyclic(|weak| Self {
            store,
            engine,
            tracking,
            discovery,
            oauth,
            lifetime,
            queue_sender: sender,
            queue_stop: Mutex::new(Some(stop)),
            queue_worker: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            operations: Mutex::new(BTreeMap::new()),
            previews: Mutex::new(BTreeMap::new()),
            restore_previews: Mutex::new(BTreeMap::new()),
            tracking_authorization_issues: Mutex::new(Vec::new()),
            history_initialization_failed: AtomicBool::new(false),
            app_tracking: Mutex::new(
                json!({"enabled":false,"state":"disabled","scanning":false,"canRefresh":false,"diagnostics":[]}),
            ),
            healthy: Mutex::new(BTreeMap::new()),
            catalog: catalog::CatalogCache::new(),
            batch: tokio::sync::OnceCell::new(),
            weak: weak.clone(),
        });
        let weak = Arc::downgrade(&service);
        let worker = tokio::spawn(Self::autosave_worker(weak, receiver, stop_rx));
        *service
            .queue_worker
            .lock()
            .map_err(|_| anyhow!("Workspace worker lock failed"))? = Some(worker);
        Ok(service)
    }

    pub fn autosave_enqueue(&self) -> Enqueue {
        enqueue(self.queue_sender.clone(), self.lifetime.clone())
    }

    /// GUI-close safe: atomics only, no filesystem/vault/network work, no mutex.
    pub fn shutdown_blocked(&self) -> bool {
        self.lifetime.outstanding.load(Ordering::SeqCst) != 0
            || self.lifetime.finalization_blocked.load(Ordering::Acquire)
    }

    pub async fn shutdown(&self) -> Result<()> {
        if self.lifetime.shutdown_complete.load(Ordering::Acquire) {
            return Ok(());
        }
        self.lifetime.stopping.store(true, Ordering::SeqCst);
        if self.shutdown_blocked() {
            self.lifetime.stopping.store(false, Ordering::SeqCst);
            bail!("Native work or durable finalization is still active; keep QuickSave open");
        }
        // Drain/recheck the queue handoff before stopping the tracker, because
        // a rejected queued work item still needs its durable failure release.
        let (ack, received) = oneshot::channel();
        self.queue_sender
            .send(QueueItem::Barrier(ack))
            .await
            .map_err(|_| anyhow!("The autosave shutdown barrier is unavailable"))?;
        received
            .await
            .map_err(|_| anyhow!("The autosave shutdown barrier failed"))?;
        if self.shutdown_blocked() {
            self.lifetime.stopping.store(false, Ordering::SeqCst);
            bail!("Autosave work raced shutdown; keep QuickSave open and retry after finalization");
        }
        let result = self.join_workers().await;
        if result.is_err() {
            self.lifetime
                .finalization_blocked
                .store(true, Ordering::Release);
        } else {
            self.lifetime
                .shutdown_complete
                .store(true, Ordering::Release);
        }
        result
    }

    async fn join_workers(&self) -> Result<()> {
        let tracking = self.tracking.clone();
        tokio::task::spawn_blocking(move || tracking.shutdown())
            .await
            .map_err(|_| anyhow!("The tracking worker could not be joined"))?
            .map_err(|_| anyhow!("The tracking worker could not shut down safely"))?;
        if let Some(stop) = self
            .queue_stop
            .lock()
            .map_err(|_| anyhow!("Workspace worker lock failed"))?
            .take()
        {
            let _ = stop.send(());
        }
        let worker = self
            .queue_worker
            .lock()
            .map_err(|_| anyhow!("Workspace worker lock failed"))?
            .take();
        if let Some(worker) = worker {
            worker
                .await
                .map_err(|_| anyhow!("The autosave worker could not be joined"))?;
        }
        let tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .map_err(|_| anyhow!("Workspace task lock failed"))?,
        );
        for task in tasks {
            task.await
                .map_err(|_| anyhow!("A native operation worker could not be joined"))?;
        }
        self.engine.shutdown().await.map_err(|_| {
            anyhow!("Native storage owners or credential finalization are not drained")
        })?;
        Ok(())
    }

    fn snapshot(&self) -> Result<Value> {
        let snapshot = self
            .store
            .snapshot()
            .map_err(|_| anyhow!("QuickSave state could not be read safely"))?;
        dto::bounded(&snapshot, 32 * 1024 * 1024)?;
        ensure!(
            snapshot["providers"].is_array() && snapshot["software"].is_array(),
            "QuickSave state is unavailable"
        );
        Ok(snapshot)
    }

    async fn engine_call(
        &self,
        method: &str,
        access: Option<quicksave_state::ProviderAccess>,
        input: Value,
    ) -> Result<Value> {
        let output = self
            .engine
            .call(method, access, input)
            .await
            .map_err(|error| anyhow!(dto::engine_error(&error)))?;
        dto::bounded(
            &output,
            if method == "catalog" {
                catalog::MAX_CATALOG_DOCUMENT_BYTES
            } else {
                dto::MAX_OUTPUT_BYTES
            },
        )?;
        Ok(output)
    }

    async fn tracking_call(&self, method: &str, input: Value) -> Result<Value> {
        let tracking = self.tracking.clone();
        let method = method.to_owned();
        tokio::task::spawn_blocking(move || tracking.call(&method, &input)).await
            .map_err(|_| anyhow!("The native tracking worker failed"))?
            .map_err(|_| anyhow!("Native source identity, signed authority or reconciliation could not be verified"))
    }

    async fn access(
        &self,
        provider_id: &str,
        operation_id: &str,
        write: bool,
    ) -> Result<quicksave_state::ProviderAccess> {
        let store = self.store.clone();
        let id = provider_id.to_owned();
        let op = operation_id.to_owned();
        let access = tokio::task::spawn_blocking(move || store.provider_access(&id, &op))
            .await
            .map_err(|_| anyhow!("The native credential worker failed"))?
            .map_err(|_| anyhow!("Native provider access is unavailable"))?;
        ensure!(
            access.provider_id == provider_id,
            "Native provider access scope mismatch"
        );
        ensure!(!write || !access.read_only, "This imported provider is read-only; explicitly enable uploads with native consent first");
        Ok(access)
    }

    fn strong(&self) -> Result<Arc<Self>> {
        self.weak
            .upgrade()
            .ok_or_else(|| anyhow!("The workspace has shut down"))
    }

    fn batch_runtime(&self) -> Result<Arc<batch::NativeBatchRuntime>> {
        self.batch.get().cloned().ok_or_else(|| {
            anyhow!("Authenticated native all-app operations are unavailable in this workspace")
        })
    }

    pub async fn query(&self, name: &str, params: Value) -> Result<Value> {
        dto::bounded(&params, dto::MAX_INPUT_BYTES)?;
        ensure!(params.is_object(), "Query parameters must be an object");
        match name {
            "dashboard" => self.dashboard().await,
            "provider_types" => {
                let types = self.store.provider_types();
                dto::bounded(&types, dto::MAX_OUTPUT_BYTES)?;
                Ok(types)
            }
            "software" => Ok(json!({"software": self.software().await?})),
            "app_tracking" => self.app_tracking_status(),
            "batch_status" => self.batch_runtime()?.batch_status(&params).await,
            "software_files" => {
                let id = dto::id(&params, "softwareId")?.to_owned();
                let limit = dto::limit(&params)?;
                let snapshot = self.snapshot()?;
                let record = dto::software_record(&snapshot, &id)?;
                ensure!(
                    record["tracked"] == true,
                    "Discovered software has no approved filesystem authority"
                );
                let _active = Active::acquire(&self.lifetime, false)?;
                let scope = dto::fingerprint(
                    &json!({"softwareId":id,"roots":native::authority_roots(record)?,"trackingGrant":record.get("trackingGrant")}),
                )?;
                let cursor = scoped_cursor(params.get("cursor"), &scope)?;
                let mut listing = dto::files(
                    &self
                        .tracking_call(
                            "file_listing",
                            json!({"softwareId":id,"cursor":cursor,"limit":limit}),
                        )
                        .await?,
                    limit,
                )?;
                wrap_cursor(&mut listing, &scope)?;
                Ok(listing)
            }
            "bundles" => self.bundles(params).await,
            "catalog_apps" => self.catalog_page(params, catalog::CatalogView::Apps).await,
            "history" => {
                self.catalog_page(params, catalog::CatalogView::History)
                    .await
            }
            "pending_deletions" => {
                self.catalog_page(params, catalog::CatalogView::PendingDeletions)
                    .await
            }
            "deletion_targets" => {
                self.catalog_page(params, catalog::CatalogView::DeletionTargets)
                    .await
            }
            "bundle_files" => {
                let provider = dto::id(&params, "providerId")?.to_owned();
                let bundle = dto::id(&params, "bundleId")?.to_owned();
                let app = dto::id(&params, "appId")?.to_owned();
                let limit = dto::limit(&params)?;
                dto::provider_record(&self.snapshot()?, &provider)?;
                let scope = dto::fingerprint(
                    &json!({"providerId":provider,"bundleId":bundle,"appId":app}),
                )?;
                let cursor = scoped_cursor(params.get("cursor"), &scope)?;
                let _active = Active::acquire(&self.lifetime, false)?;
                self.ensure_provider_health(&provider).await?;
                let access = self
                    .access(&provider, &Uuid::new_v4().to_string(), false)
                    .await?;
                let raw = self
                    .engine_call(
                        "files",
                        Some(access),
                        json!({"bundleId":bundle,"appId":app,"cursor":cursor,"limit":limit}),
                    )
                    .await?;
                let mut files = dto::files(&raw, limit)?;
                wrap_cursor(&mut files, &scope)?;
                Ok(files)
            }
            "activity" => Ok(json!({"activity":self.activities().await?})),
            "operation" => self.operation(dto::id(&params, "operationId")?).await,
            "noland_import_preview" => Ok(json!({
                "requiresNativeDiscovery":true, "requiresNativeConsent":true, "manualFallback":"advanced_only",
                "profiles":[], "message":"Find No Land automatically in its standard application-data locations after native consent. A chooser is needed only for multiple sources; manual file selection is an advanced fallback."
            })),
            _ => bail!("This workspace query is not supported"),
        }
    }

    async fn software(&self) -> Result<Vec<Value>> {
        let tracked = self.tracking_call("software", json!({})).await?;
        let records = tracked
            .as_array()
            .or_else(|| tracked.get("software").and_then(Value::as_array))
            .ok_or_else(|| anyhow!("Tracked software is unavailable"))?;
        ensure!(
            records.len() <= 4096,
            "Tracked software exceeds the bounded limit"
        );
        let pending = records.iter().filter(|record|record["authorizationPending"] == true)
            .take(128).map(|record|json!({
                "appId":record["appId"],"name":record["name"],
                "code":"tracking_authorization_unavailable",
                "message":"This stored application's authorization is temporarily unavailable. Its approvals and history are retained; it is not counted as a verified bundle or Saved.",
            })).collect::<Vec<_>>();
        *self
            .tracking_authorization_issues
            .lock()
            .map_err(|_| anyhow!("Tracking diagnostic lock failed"))? = pending;
        let output = records
            .iter()
            .filter(|record| record["tracked"] == true)
            .map(dto::software)
            .collect::<Result<Vec<_>>>()?;
        // Discovery is an input to native identity/root reconciliation, not a
        // producer of placeholder software or bundles. Only actual tracker
        // records belong here; discovery diagnostics have a separate endpoint.
        Ok(output)
    }

    async fn dashboard(&self) -> Result<Value> {
        let snapshot = self.snapshot()?;
        let healthy = self
            .healthy
            .lock()
            .map_err(|_| anyhow!("Provider health lock failed"))?
            .clone();
        let providers = snapshot["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|provider| {
                let verified = provider["id"]
                    .as_str()
                    .and_then(|id| healthy.get(id))
                    .is_some_and(|expected| {
                        provider_health_scope(provider).is_ok_and(|scope| &scope == expected)
                    });
                dto::provider(provider, verified)
            })
            .collect::<Result<Vec<_>>>()?;
        let software = self.software().await?;
        let (activity, activity_unavailable) = match self.activities().await {
            Ok(activity) => (activity, false),
            Err(_) => (Vec::new(), true),
        };
        Ok(json!({
            "summary":{
                "needsBackup":software.iter().filter(|s| s["tracked"] == true && (s["dirty"] == true || s["status"] == "needs_backup")).count(),
                "autosaveEnabled":software.iter().filter(|s| s["autosave"] == true).count(),
                "connectedProviders":providers.iter().filter(|p| p["status"] == "connected").count(),
            },
            "providers":providers,"software":software,"activity":activity,
            "activityUnavailable":activity_unavailable,
            "activityIssue":if activity_unavailable {
                Some("History could not be authenticated or loaded. Existing work is retained; local tracking is independent. No completion or cancellation is inferred.")
            } else {None::<&str>},
        }))
    }

    async fn bundles(&self, params: Value) -> Result<Value> {
        if self.engine.rich_catalog_supported() {
            return self
                .catalog_page(params, catalog::CatalogView::Bundles)
                .await;
        }
        let provider = dto::id(&params, "providerId")?.to_owned();
        dto::provider_record(&self.snapshot()?, &provider)?;
        let limit = dto::limit(&params)?;
        let scope = dto::fingerprint(&json!({"providerId":provider,"kind":"catalog"}))?;
        let cursor = scoped_cursor(params.get("cursor"), &scope)?;
        let offset = cursor
            .as_deref()
            .unwrap_or("0")
            .parse::<usize>()
            .map_err(|_| anyhow!("Catalog cursor is invalid"))?;
        let _active = Active::acquire(&self.lifetime, false)?;
        self.ensure_provider_health(&provider).await?;
        let access = self
            .access(&provider, &Uuid::new_v4().to_string(), false)
            .await?;
        let catalog = self.engine_call("catalog", Some(access), json!({})).await?;
        let bundles = catalog["bundles"]
            .as_array()
            .ok_or_else(|| anyhow!("Native catalog is unavailable"))?;
        ensure!(
            bundles.len() <= 4096 && offset <= bundles.len(),
            "Catalog exceeds its bounded scope or cursor is stale"
        );
        let end = offset.saturating_add(limit).min(bundles.len());
        let entries = bundles[offset..end]
            .iter()
            .map(|bundle| dto::bundle(bundle, &provider))
            .collect::<Result<Vec<_>>>()?;
        let mut output = json!({"bundles":entries});
        if end < bundles.len() {
            output["nextCursor"] = json!(format!("{scope}:{end}"));
        }
        Ok(output)
    }

    async fn catalog_page(&self, params: Value, view: catalog::CatalogView) -> Result<Value> {
        ensure!(
            self.engine.rich_catalog_supported(),
            "Revision-bound native catalog history is unavailable"
        );
        let provider = dto::id(&params, "providerId")?.to_owned();
        let snapshot = self.snapshot()?;
        let profile = dto::provider_record(&snapshot, &provider)?;
        let app = params
            .get("appId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        ensure!(
            view != catalog::CatalogView::History || app.is_some(),
            "Application history needs an exact original application identity"
        );
        let mode = params
            .get("mode")
            .and_then(Value::as_str)
            .map(|value| match value {
                "complete_application" => Ok(catalog::CatalogMode::CompleteApplication),
                "personal_state" => Ok(catalog::CatalogMode::PersonalState),
                "custom" => Ok(catalog::CatalogMode::Custom),
                _ => bail!("Unknown native catalog backup mode"),
            })
            .transpose()?;
        let plan_id = params
            .get("planId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let scope = dto::fingerprint(&json!({"provider":provider_health_scope(profile)?,
            "view":view,"appId":app,"mode":mode,"planId":plan_id}))?;
        let cursor = scoped_cursor(params.get("cursor"), &scope)?;
        if cursor.is_none() {
            let _active = Active::acquire(&self.lifetime, false)?;
            self.ensure_provider_health(&provider).await?;
            let access = self
                .access(&provider, &Uuid::new_v4().to_string(), false)
                .await?;
            let raw = self.engine_call("catalog", Some(access), json!({})).await?;
            self.catalog.replace(&provider, raw)?;
        }
        let mut page = self.catalog.page(
            &provider,
            catalog::CatalogQuery {
                view,
                app_id: app,
                mode,
                plan_id,
                cursor,
                limit: dto::limit(&params)?.min(100),
            },
        )?;
        wrap_cursor(&mut page, &scope)?;
        Ok(page)
    }

    /// Deterministic native-dialog context. Never opens newly selected paths,
    /// reads an import source, or obtains provider/vault credentials.
    pub async fn approval_scope(&self, action: &str, params: &Value) -> Result<Value> {
        dto::validate_action(action, params)?;
        let snapshot = self.snapshot()?;
        let mut summary = json!({"action":action});
        // Authority generations are root/profile/grant revisions, not scan
        // progress or dirty-content generations. Otherwise an autosave change
        // stream could continually invalidate its own disable/cancel dialog.
        let mut authority =
            json!({"action":action,"params":dto::without_native_fingerprint(params)});
        if let Some(provider_id) = params
            .get("providerId")
            .or_else(|| params.get("defaultProviderId"))
            .and_then(Value::as_str)
        {
            let provider = dto::provider_record(&snapshot, provider_id)?;
            summary["provider"] = dto::copy_fields(
                provider,
                &[
                    "id",
                    "name",
                    "kind",
                    "origin",
                    "readOnly",
                    "status",
                    "bucket",
                    "prefix",
                    "publicScope",
                ],
            );
            // Full non-secret native profile binds configuration/reference
            // changes without revealing account references to the webview.
            authority["provider"] = provider.clone();
        }
        if let Some(software_id) = params.get("softwareId").and_then(Value::as_str) {
            let software = dto::software_record(&snapshot, software_id)?;
            summary["software"] =
                dto::copy_fields(software, &["id", "name", "appId", "providerId"]);
            summary["software"]["roots"] = native::authority_roots(software)?;
            authority["software"] = dto::copy_fields(
                software,
                &[
                    "id",
                    "appId",
                    "name",
                    "tracked",
                    "providerId",
                    "roots",
                    "trackingGrant",
                    "autosave",
                    "autosaveGrant",
                    "authorityGeneration",
                ],
            );
            summary["software"]["authorityGeneration"] =
                json!(dto::fingerprint(&authority["software"])?);
        }
        if action == "delete_cloud" {
            let preview = self.preview(
                dto::id(params, "providerId")?,
                dto::id(params, "previewId")?,
            )?;
            summary["deletion"] = preview.summary.clone();
            authority["deletion"] = preview.summary;
        }
        if action == "download" {
            let preview = self.restore_preview(dto::id(params, "restorePreviewId")?)?;
            let current = self
                .engine_call(
                    "restore_preview_scope",
                    None,
                    json!({"restorePreviewId":params["restorePreviewId"]}),
                )
                .await?;
            ensure!(
                current["previewId"] == params["restorePreviewId"]
                    && current["frozenPlanFingerprint"] == preview.summary["frozenPlanFingerprint"],
                "The native restore preview changed or expired; preview again"
            );
            let provider =
                dto::provider_record(&snapshot, dto::id(&preview.params, "providerId")?)?;
            summary["provider"] = dto::copy_fields(
                provider,
                &[
                    "id",
                    "name",
                    "kind",
                    "origin",
                    "readOnly",
                    "bucket",
                    "prefix",
                    "publicScope",
                ],
            );
            summary["restore"] = preview.summary.clone();
            authority["restore"] = preview.summary;
            authority["provider"] = provider.clone();
        }
        if action == "recover_restore" {
            let recovery = self.recovery_scope(dto::id(params, "operationId")?).await?;
            summary["restore"] = recovery.clone();
            authority["restore"] = recovery;
        }
        if action == "upload_all" {
            let batch = self
                .batch_runtime()?
                .approval_scope(dto::id(params, "planSetId")?)?;
            let provider = dto::provider_record(&snapshot, dto::id(&batch, "providerId")?)?;
            summary["batch"] = batch.clone();
            summary["provider"] = dto::copy_fields(
                provider,
                &["id", "name", "kind", "origin", "readOnly", "publicScope"],
            );
            authority["batch"] = batch;
            authority["provider"] = provider.clone();
        }
        if action == "import_noland" {
            if let Some(source) = params.get("sourceId").and_then(Value::as_str) {
                let store = self.store.clone();
                let id = source.to_owned();
                let pinned = tokio::task::spawn_blocking(move || store.noland_source_scope(&id))
                    .await
                    .map_err(|_| anyhow!("Native No Land source verification failed"))??;
                dto::bounded(&pinned, 16 * 1024)?;
                ensure!(
                    pinned["sourceId"] == source,
                    "Native No Land source scope mismatch"
                );
                summary["source"] = pinned.clone();
                authority["source"] = pinned;
            }
        }
        if action == "discover_noland_import" {
            summary["discovery"] = json!({"summary":
                "Locate state.json only in No Land's authoritative com.noland.connect application-data directories. Discovery inspects file metadata only; it does not read state contents or credential vaults."});
        }
        if action == "enable_app_tracking" && params["enabled"] == true {
            let native = self.discovery.tracking_scope()?;
            dto::bounded(&native, 64 * 1024)?;
            summary["enrollment"] = native.clone();
            authority["enrollment"] = native;
        }
        if action == "refresh_app_tracking" {
            let policy = snapshot
                .pointer("/settings/appTracking")
                .filter(|policy| !policy.is_null())
                .ok_or_else(|| anyhow!("Enable native automatic app tracking before refreshing"))?;
            summary["enrollment"] = json!({"summary":"Reconcile verified application identities and real file indices only within the previously approved, pinned native enrollment policy. This does not enable uploads or autosave."});
            authority["enrollment"] = policy.clone();
        }
        if matches!(action, "cancel" | "retry") {
            let operations = self
                .operations
                .lock()
                .map_err(|_| anyhow!("Operation state lock failed"))?;
            if let Some(operation) = operations.get(dto::id(params, "operationId")?) {
                summary["operation"] = dto::copy_fields(
                    &operation.activity,
                    &["id", "kind", "name", "providerId", "softwareId"],
                );
                if let Some(plan) = &operation.retry {
                    authority["operationScope"] = json!(plan.scope);
                }
            }
        }
        summary["scopeFingerprint"] = json!(dto::fingerprint(&authority)?);
        Ok(summary)
    }

    pub async fn confirmation_details(&self, action: &str, params: &Value) -> Result<Value> {
        self.approval_scope(action, params).await
    }

    pub async fn execute_authorized(&self, action: &str, params: Value) -> Result<Value> {
        dto::validate_action(action, &params)?;
        if let Some(expected) = params.get("_scopeFingerprint").and_then(Value::as_str) {
            let scope = self.approval_scope(action, &params).await?;
            ensure!(
                scope["scopeFingerprint"] == expected,
                "The approved workspace scope changed; obtain new native approval"
            );
        }
        let approved_paths = params.get("_approvedPaths").cloned();
        let mut params = dto::without_native_fingerprint(&params);
        if let Some(proofs) = approved_paths {
            params["_approvedPaths"] = proofs;
        }
        match action {
            "connect_oauth" => {
                ensure!(self.oauth.supports(dto::id(&params,"kind")?), "Native OAuth PKCE for this provider is not available. No account was connected.");
                self.start_operation("connect", "connect_oauth", params, None, None, None)
            }
            "connect_provider" => {
                self.start_operation("connect", "connect_provider", params, None, None, None)
            }
            "reauthorize_provider" => {
                self.start_operation("connect", "reauthorize_provider", params, None, None, None)
            }
            "export_recovery_key" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let store = self.store.clone();
                tokio::task::spawn_blocking(move || store.export_recovery_key(&params)).await
                    .map_err(|_| anyhow!("Native recovery-key export worker failed"))?
                    .map_err(|_| anyhow!("Recovery key could not be exported safely to the new external private file"))
            }
            "upload" => self.start_operation("upload", "upload", params, None, None, None),
            "preview_upload_all" => self.batch_runtime()?.preview_upload_all(params).await,
            "upload_all" => self
                .batch_runtime()?
                .execute(dto::id(&params, "planSetId")?),
            "download" => {
                let preview_id = dto::id(&params, "restorePreviewId")?.to_owned();
                let preview = self.restore_preview(&preview_id)?;
                ensure!(
                    preview.summary["requiresOverwriteAcknowledgement"] != true
                        || params["overwriteAcknowledgement"] == true,
                    "The frozen restore requires explicit overwrite acknowledgement"
                );
                let mut frozen = preview.params;
                frozen["restorePreviewId"] = json!(preview_id);
                frozen["overwriteAcknowledgement"] = params["overwriteAcknowledgement"].clone();
                if let Some(proofs) = params.get("_approvedPaths") {
                    frozen["_approvedPaths"] = proofs.clone();
                }
                let result =
                    self.start_operation("download", "download", frozen, None, None, None)?;
                self.restore_previews
                    .lock()
                    .map_err(|_| anyhow!("Restore preview lock failed"))?
                    .remove(&preview_id);
                Ok(result)
            }
            "delete_cloud" => {
                let preview = self.preview(
                    dto::id(&params, "providerId")?,
                    dto::id(&params, "previewId")?,
                )?;
                ensure!(
                    dto::boolean(&params, "acknowledgeDependencies")?
                        || preview.summary["dependentBundleCount"].as_u64() == Some(0),
                    "Dependent backups require a separate explicit acknowledgement"
                );
                self.start_operation("delete", "delete", params, None, None, None)
            }
            "preview_delete" => self.prepare_delete(params).await,
            "preview_restore" => self.prepare_restore(params).await,
            "recover_restore" => self.recover_restore(params).await,
            "enable_app_tracking" if params["enabled"] == false => {
                ensure!(
                    !self.app_tracking_status()?["scanning"]
                        .as_bool()
                        .unwrap_or(false),
                    "Application indexing is still finalizing; disable tracking after it finishes"
                );
                let _active = Active::acquire(&self.lifetime, false)?;
                self.tracking_call("disable_app_tracking", json!({}))
                    .await?;
                *self
                    .app_tracking
                    .lock()
                    .map_err(|_| anyhow!("Application tracking status lock failed"))? = json!({"enabled":false,"state":"disabled","scanning":false,"canRefresh":false,"diagnostics":[]});
                self.dashboard().await
            }
            "enable_app_tracking" | "refresh_app_tracking" => {
                self.start_app_tracking(params, action == "enable_app_tracking")
            }
            "cancel" => self.cancel(dto::id(&params, "operationId")?).await,
            "retry" => self.retry(dto::id(&params, "operationId")?).await,
            "track_software" | "add_files" | "set_provider" | "set_autosave" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                if action == "track_software" && params.get("appId").is_none_or(Value::is_null) {
                    let existing =
                        if let Some(id) = params.get("softwareId").and_then(Value::as_str) {
                            let snapshot = self.snapshot()?;
                            dto::software_record(&snapshot, id)?["appId"]
                                .as_str()
                                .map(str::to_owned)
                        } else {
                            None
                        };
                    params["appId"] =
                        json!(existing
                            .unwrap_or_else(|| format!("quicksave.manual.{}", Uuid::new_v4())));
                }
                if action == "set_autosave" && dto::boolean(&params, "enabled")? {
                    let provider = dto::id(&params, "providerId")?;
                    // Vault-backed write access must independently agree; an
                    // editable readOnly=false is not write authorization.
                    let _access = self
                        .access(provider, &Uuid::new_v4().to_string(), true)
                        .await?;
                    self.ensure_provider_health(provider).await?;
                }
                let method = match action {
                    "track_software" => "approve_software",
                    "set_autosave" => "configure_autosave",
                    other => other,
                };
                let updated = self.tracking_call(method, params).await?;
                if matches!(action, "track_software" | "add_files") {
                    // A signed root approval is not a displayed bundle until
                    // its actual metadata index has been durably materialized.
                    let id = dto::id(&updated, "id")?;
                    self.tracking_call("scan_metadata", json!({"softwareId":id}))
                        .await?;
                }
                self.dashboard().await
            }
            "disconnect_provider" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let provider = dto::id(&params, "providerId")?.to_owned();
                let store = self.store.clone();
                let id = provider.clone();
                tokio::task::spawn_blocking(move || store.disconnect_provider(&id))
                    .await
                    .map_err(|_| anyhow!("The provider state worker failed"))?
                    .map_err(|_| anyhow!("Provider disconnection could not be committed"))?;
                self.healthy
                    .lock()
                    .map_err(|_| anyhow!("Provider health lock failed"))?
                    .remove(&provider);
                // Tracker is the grant owner. Disconnecting must disable every
                // bound persistent autosave scope without deleting local data.
                self.tracking_call("disconnect_provider", json!({"providerId":provider}))
                    .await?;
                self.dashboard().await
            }
            "verify_provider" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let provider = dto::id(&params, "providerId")?.to_owned();
                let snapshot = self.snapshot()?;
                ensure!(dto::provider_record(&snapshot,&provider)?["status"] != "disconnected",
                    "This provider was disconnected and its credentials were removed; connect it again or reimport its profile.");
                // An explicit retry always performs a real read-only probe,
                // never merely reuses a previously cached successful report.
                self.healthy
                    .lock()
                    .map_err(|_| anyhow!("Provider health lock failed"))?
                    .remove(&provider);
                if let Err(error) = self.ensure_provider_health(&provider).await {
                    let store = self.store.clone();
                    let id = provider.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        store.record_provider_health(&id,&json!({
                        "providerId":id,"canList":false,"canRead":false,
                        "repositoryAccessible":false,"repositoryEmpty":false,"keyVerified":false,
                        "error":"Native provider access could not be verified",
                    }))
                    })
                    .await;
                    return Err(error);
                }
                self.dashboard().await
            }
            "authorize_provider_writes" | "approve_provider_writes" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let store = self.store.clone();
                let provider = dto::id(&params, "providerId")?.to_owned();
                tokio::task::spawn_blocking(move || store.grant_provider_write(&provider))
                    .await
                    .map_err(|_| anyhow!("The native write-authority worker failed"))?
                    .map_err(|_| anyhow!("Native provider write authority could not be sealed"))?;
                self.dashboard().await
            }
            "import_noland" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let store = self.store.clone();
                tokio::task::spawn_blocking(move || store.import_noland(&params))
                    .await
                    .map_err(|_| anyhow!("The native read-only import worker failed"))?
                    .map_err(|_| {
                        anyhow!("The read-only No Land import could not be committed safely")
                    })?;
                // Import alone never proves cloud authentication and never
                // automatically grants uploads or starts provider health I/O.
                self.dashboard().await
            }
            "discover_noland_import" => {
                let _active = Active::acquire(&self.lifetime, false)?;
                let store = self.store.clone();
                let result = tokio::task::spawn_blocking(move || store.discover_noland_sources())
                    .await.map_err(|_| anyhow!("The native No Land discovery worker failed"))?
                    .map_err(|_| anyhow!("No Land discovery could not inspect the known application-data locations safely"))?;
                dto::bounded(&result, 64 * 1024)?;
                dto::noland_discovery(&result)
            }
            _ => bail!("This workspace action is not supported"),
        }
    }

    fn source_scope(&self, params: &Value) -> Result<String> {
        let snapshot = self.snapshot()?;
        let mut scope = json!({});
        if params.get("restorePreviewId").is_some() {
            scope["restore"] = dto::copy_fields(
                params,
                &[
                    "restorePreviewId",
                    "bundleId",
                    "appId",
                    "destination",
                    "fileIds",
                    "mode",
                    "overwriteAcknowledgement",
                ],
            );
        }
        if let Some(id) = params.get("providerId").and_then(Value::as_str) {
            scope["provider"] = dto::copy_fields(
                dto::provider_record(&snapshot, id)?,
                &[
                    "id",
                    "kind",
                    "origin",
                    "readOnly",
                    "bucket",
                    "prefix",
                    "credentialRef",
                    "repositoryKeyRef",
                    "sourceProfileId",
                    "authorityGeneration",
                    "profileFingerprint",
                    "publicScope",
                ],
            );
        }
        if let Some(id) = params.get("softwareId").and_then(Value::as_str) {
            scope["software"] = dto::copy_fields(
                dto::software_record(&snapshot, id)?,
                &[
                    "id",
                    "appId",
                    "providerId",
                    "roots",
                    "trackingGrant",
                    "authorityGeneration",
                ],
            );
        }
        dto::fingerprint(&scope)
    }

    fn start_operation(
        &self,
        kind: &str,
        action: &str,
        params: Value,
        work: Option<Value>,
        retry_native: Option<String>,
        expected_capture: Option<Value>,
    ) -> Result<Value> {
        ensure!(
            kind == "connect" || !self.history_initialization_failed.load(Ordering::Acquire),
            "Existing native history is unavailable; new data operations remain blocked"
        );
        let active = Active::acquire(&self.lifetime, true)?;
        let id = Uuid::new_v4().to_string();
        let name = match kind {
            "connect" => params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Connect provider"),
            "upload" | "autosave" => "Save approved software",
            "download" => "Restore approved files",
            _ => "Delete confirmed cloud backups",
        };
        let scope = self.source_scope(&params)?;
        let plan = RetryPlan {
            action: action.to_owned(),
            params: params.clone(),
            captured: expected_capture,
            scope,
        };
        let mut activity = json!({
            "id":id,"kind":kind,"name":name,"state":"queued","phase":"preparing",
            "canCancel":true,"canRetry":false,"startedAt":chrono::Utc::now().to_rfc3339(),
            "error":Value::Null,
        });
        for field in ["providerId", "softwareId"] {
            if let Some(value) = params.get(field) {
                activity[field] = value.clone();
            }
        }
        self.insert_operation(
            &id,
            Operation {
                activity,
                native_id: None,
                cancelled: false,
                retry: if kind == "connect" {
                    None
                } else {
                    retain_retry(&plan)
                },
            },
        )?;
        let service = self.strong()?;
        let operation_id = id.clone();
        let handle = tokio::spawn(async move {
            let guard = OperationGuard {
                active,
                finalized: false,
            };
            if plan.action == "reauthorize_provider" {
                service
                    .run_reauthorization(&operation_id, plan, guard)
                    .await;
            } else if matches!(plan.action.as_str(), "connect_provider" | "connect_oauth") {
                let oauth = plan.action == "connect_oauth";
                service
                    .run_connect(&operation_id, plan.params, oauth, guard)
                    .await;
            } else {
                service
                    .run_transfer(&operation_id, plan, work, retry_native, guard)
                    .await;
            }
        });
        self.remember_task(handle)?;
        Ok(json!({"operationId":id}))
    }

    fn insert_operation(&self, id: &str, operation: Operation) -> Result<()> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| anyhow!("Operation state lock failed"))?;
        if operations.len() >= dto::MAX_ACTIVITY {
            let removable = operations
                .iter()
                .find(|(_, op)| dto::terminal(&op.activity))
                .map(|(id, _)| id.clone());
            if let Some(id) = removable {
                operations.remove(&id);
            }
        }
        ensure!(
            operations.len() < dto::MAX_ACTIVITY,
            "The bounded operation history is full"
        );
        operations.insert(id.to_owned(), operation);
        Ok(())
    }

    fn remember_task(&self, task: JoinHandle<()>) -> Result<()> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| anyhow!("Workspace task lock failed"))?;
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(())
    }

    fn patch_operation(&self, id: &str, patch: Value) {
        if let Ok(mut operations) = self.operations.lock() {
            if let Some(operation) = operations.get_mut(id) {
                if let (Some(target), Some(patch)) =
                    (operation.activity.as_object_mut(), patch.as_object())
                {
                    target.extend(
                        patch
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone())),
                    );
                }
            }
        } else {
            self.lifetime
                .finalization_blocked
                .store(true, Ordering::Release);
        }
    }

    fn cancelled(&self, id: &str) -> bool {
        self.operations
            .lock()
            .map(|operations| {
                operations
                    .get(id)
                    .is_none_or(|operation| operation.cancelled)
            })
            .unwrap_or(true)
    }

    fn finish(&self, id: &str, state: &str, failed: bool) {
        let retryable = self
            .operations
            .lock()
            .map(|operations| {
                operations.get(id).is_some_and(|operation| {
                    operation
                        .retry
                        .as_ref()
                        .is_some_and(|plan| plan.action != "download")
                })
            })
            .unwrap_or(false)
            && matches!(state, "failed" | "cancelled" | "interrupted")
            && !self.lifetime.finalization_blocked.load(Ordering::Acquire);
        self.patch_operation(id, json!({
            "state":state,"phase":if failed {"failed"} else {"finalized"},
            "canCancel":false,"canRetry":retryable,
            "finishedAt":chrono::Utc::now().to_rfc3339(),
            "error":if failed {json!("The native operation did not complete safely. No saved baseline was acknowledged.")} else {Value::Null},
        }));
    }

    async fn run_connect(
        self: Arc<Self>,
        id: &str,
        input: Value,
        oauth: bool,
        mut guard: OperationGuard,
    ) {
        if self.cancelled(id) {
            self.finish(id, "cancelled", false);
            guard.finalized = true;
            return;
        }
        let input = if oauth {
            self.patch_operation(id,json!({"state":"running","phase":"checking_native_prerequisites","canCancel":false}));
            match self.engine_call("preflight", None, json!({})).await {
                Err(error) => {
                    self.finish(id, "failed", true);
                    self.patch_operation(id, json!({"error":dto::engine_error(&error)}));
                    guard.finalized = true;
                    return;
                }
                Ok(report)
                    if report["available"] != true || report["oauthRefreshPersistence"] != true =>
                {
                    self.finish(id, "failed", true);
                    self.patch_operation(id, json!({"error":dto::OAUTH_STORAGE_UNAVAILABLE}));
                    guard.finalized = true;
                    return;
                }
                Ok(_) => {}
            }
            self.patch_operation(
                id,
                json!({"state":"running","phase":"authorizing_oauth","canCancel":false}),
            );
            match self.oauth.authorize(input).await {
                Ok(input) => input,
                Err(_) => {
                    self.finish(id, "failed", true);
                    guard.finalized = true;
                    return;
                }
            }
        } else {
            input
        };
        self.patch_operation(
            id,
            json!({"state":"running","phase":"storing_native_credentials","canCancel":false}),
        );
        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || store.connect_provider(&input)).await;
        let provider_id = match result {
            Ok(Ok(value)) => value
                .get("id")
                .or_else(|| value.get("provider").and_then(|p| p.get("id")))
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        let Some(provider_id) = provider_id else {
            self.finish(id, "failed", true);
            guard.finalized = true;
            return;
        };
        self.patch_operation(
            id,
            json!({"providerId":provider_id,"phase":"verifying_provider_access"}),
        );
        let result = async {
            let access = self.access(&provider_id, id, false).await?;
            let report = self
                .engine_call("health_check", Some(access), json!({}))
                .await?;
            ensure!(
                verified_health(&report),
                "The engine did not verify provider access or an authenticated existing repository"
            );
            let store = self.store.clone();
            let provider = provider_id.clone();
            tokio::task::spawn_blocking(move || store.record_provider_health(&provider, &report))
                .await
                .map_err(|_| anyhow!("Provider health worker failed"))?
                .map_err(|_| anyhow!("Verified provider health could not be committed"))?;
            let snapshot = self.snapshot()?;
            let scope = provider_health_scope(dto::provider_record(&snapshot, &provider_id)?)?;
            self.healthy
                .lock()
                .map_err(|_| anyhow!("Provider health lock failed"))?
                .insert(provider_id.clone(), scope);
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let store = self.store.clone();
            let provider = provider_id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                store.record_provider_health(&provider,&json!({
                "authenticated":false,"canList":false,"canRead":false,"repositoryAccessible":false,
                "error":"Native provider access could not be verified",
            }))
            })
            .await;
            self.finish(id, "failed", true);
            self.patch_operation(id, json!({"error":dto::engine_error(&error)}));
        } else {
            self.finish(id, "completed", false);
        }
        guard.finalized = true;
    }

    async fn ensure_provider_health(&self, provider_id: &str) -> Result<()> {
        let snapshot = self.snapshot()?;
        let provider = dto::provider_record(&snapshot, provider_id)?;
        let scope = provider_health_scope(provider)?;
        let already_verified = self
            .healthy
            .lock()
            .map_err(|_| anyhow!("Provider health lock failed"))?
            .get(provider_id)
            .is_some_and(|verified| verified == &scope);
        if already_verified && provider["status"] == "connected" {
            return Ok(());
        }
        let access = self
            .access(provider_id, &Uuid::new_v4().to_string(), false)
            .await?;
        let report = self
            .engine_call("health_check", Some(access), json!({}))
            .await?;
        ensure!(
            verified_health(&report),
            "Actual provider access or existing repository authentication failed"
        );
        let store = self.store.clone();
        let id = provider_id.to_owned();
        tokio::task::spawn_blocking(move || store.record_provider_health(&id, &report))
            .await
            .map_err(|_| anyhow!("Provider health worker failed"))?
            .map_err(|_| anyhow!("Verified provider health could not be committed"))?;
        let current = self.snapshot()?;
        let provider = dto::provider_record(&current, provider_id)?;
        ensure!(
            scope == provider_health_scope(provider)? && provider["status"] == "connected",
            "Provider configuration changed during health verification"
        );
        self.healthy
            .lock()
            .map_err(|_| anyhow!("Provider health lock failed"))?
            .insert(provider_id.to_owned(), scope);
        Ok(())
    }

    async fn pin(&self, record: Value) -> Result<Arc<dyn SourceGuard>> {
        let tracking = self.tracking.clone();
        tokio::task::spawn_blocking(move || tracking.pin_scope(&record))
            .await
            .map_err(|_| anyhow!("Native source pinning worker failed"))?
            .map_err(|_| anyhow!("Signed source scope or pinned native root identity changed"))
    }

    async fn verify_pin(&self, pin: &Arc<dyn SourceGuard>) -> Result<()> {
        let pin = pin.clone();
        tokio::task::spawn_blocking(move || pin.verify())
            .await
            .map_err(|_| anyhow!("Native source verification worker failed"))?
            .map_err(|_| anyhow!("The approved native source identity changed"))
    }

    fn publication_guard(
        &self,
        id: &str,
        plan: &RetryPlan,
        work: &Value,
        pin: Arc<dyn SourceGuard>,
    ) -> (PublishGuard, PublicationLease) {
        let weak = self.weak.clone();
        let id = id.to_owned();
        let work = if work["automatic"] == true {
            json!({"automatic":true,"authorization":work["authorization"]})
        } else {
            json!({"automatic":false})
        };
        let payload = Arc::new(Mutex::new(Some(PublicationPayload {
            params: plan.params.clone(),
            scope: plan.scope.clone(),
            work,
            pin,
        })));
        let lease = PublicationLease(payload.clone());
        let guard: PublishGuard = Arc::new(move || {
            let payload = payload
                .lock()
                .map_err(|_| anyhow!("Native publication authority lock failed"))?;
            let payload = payload.as_ref().ok_or_else(|| {
                anyhow!("This publication attempt ended; a fresh retry guard is required")
            })?;
            let params = &payload.params;
            let work = &payload.work;
            let service = weak
                .upgrade()
                .ok_or_else(|| anyhow!("The native workspace is no longer available"))?;
            if let Some(plan) = params.get("_nativeBatchPlanId").and_then(Value::as_str) {
                service
                    .batch_runtime()?
                    .check_child_publication(&id, plan)?;
            }
            ensure!(
                !service.cancelled(&id),
                "The native operation was cancelled"
            );
            ensure!(
                payload.scope == service.source_scope(params)?,
                "The approved provider/root scope was revoked or changed"
            );
            let provider = dto::id(params, "providerId")?;
            let snapshot = service.snapshot()?;
            ensure!(
                dto::provider_record(&snapshot, provider)?["status"] == "connected",
                "The provider is no longer connected"
            );
            ensure!(
                service.store.provider_writable(provider).unwrap_or(false),
                "Native provider write authority was revoked"
            );
            payload
                .pin
                .verify()
                .map_err(|_| anyhow!("The approved native root identity changed"))?;
            if work["automatic"] == true {
                let record = dto::software_record(&snapshot, dto::id(params, "softwareId")?)?;
                ensure!(
                    record["autosave"] == true && record["providerId"] == provider,
                    "Persistent autosave was disabled or its provider changed"
                );
                ensure!(
                    record["autosaveGrant"] == work["authorization"]["autosaveGrant"],
                    "The frozen autosave grant was replaced or revoked"
                );
            }
            service
                .tracking
                .verify_upload_authority(
                    dto::id(params, "softwareId")?,
                    provider,
                    work["automatic"].as_bool().unwrap_or(false),
                    work,
                )
                .map_err(|_| {
                    anyhow!("The signed tracking/autosave authority or captured work was revoked")
                })?;
            Ok(())
        });
        (guard, lease)
    }

    fn restore_publication_guard(&self, id: &str, plan: &RetryPlan) -> PublishGuard {
        let weak = self.weak.clone();
        let id = id.to_owned();
        let params = plan.params.clone();
        let scope = plan.scope.clone();
        let write = plan.action == "delete";
        Arc::new(move || {
            let service = weak
                .upgrade()
                .ok_or_else(|| anyhow!("The native workspace is no longer available"))?;
            ensure!(
                !service.cancelled(&id),
                "The frozen native restore was cancelled"
            );
            ensure!(
                scope == service.source_scope(&params)?,
                "The approved native restore/provider scope changed"
            );
            let snapshot = service.snapshot()?;
            let provider = dto::provider_record(&snapshot, dto::id(&params, "providerId")?)?;
            ensure!(
                provider["status"] != "disconnected",
                "The restore provider was disconnected"
            );
            if write {
                ensure!(
                    provider["status"] == "connected"
                        && service
                            .store
                            .provider_writable(dto::id(&params, "providerId")?)?,
                    "Native provider deletion authority was revoked"
                );
            }
            Ok(())
        })
    }

    async fn check_publication_guard(guard: &PublishGuard) -> Result<()> {
        let guard = guard.clone();
        tokio::task::spawn_blocking(move || guard())
            .await
            .map_err(|_| anyhow!("Native publication authority verification failed"))?
    }

    async fn finalize_work(&self, work: &Value, success: bool) -> Result<()> {
        let id = dto::id(work, "workId")?;
        let generation = work["generation"]
            .as_u64()
            .ok_or_else(|| anyhow!("The captured dirty generation is missing"))?;
        self.tracking_call(
            "complete_upload",
            json!({"workId":id,"generation":generation,"success":success}),
        )
        .await?;
        Ok(())
    }

    async fn run_transfer(
        self: Arc<Self>,
        id: &str,
        mut plan: RetryPlan,
        mut work: Option<Value>,
        retry_native: Option<String>,
        mut guard: OperationGuard,
    ) {
        let mut source_pin = None;
        let result = self
            .submit_and_monitor(id, &mut plan, &mut work, retry_native, &mut source_pin)
            .await;
        match result {
            Ok(state) => {
                if let Some(work) = &work {
                    if plan.params.get("_nativeBatchPlanId").is_some() {
                        let verified = match self.batch_runtime() {
                            Ok(runtime) => {
                                runtime
                                    .before_child_finalization(id, work, state == "completed")
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        if verified.is_err() {
                            // Preserve the original work and never acknowledge
                            // Saved from an unauthenticated terminal projection.
                            self.lifetime
                                .finalization_blocked
                                .store(true, Ordering::Release);
                            self.patch_operation(id,json!({"state":"failed","phase":"durable_finalization_required","canCancel":false,"canRetry":false}));
                            return;
                        }
                    }
                    if self
                        .finalize_work(work, state == "completed")
                        .await
                        .is_err()
                    {
                        self.lifetime
                            .finalization_blocked
                            .store(true, Ordering::Release);
                        self.patch_operation(id,json!({
                            "state":"failed","phase":"durable_finalization_required","canCancel":false,"canRetry":false,
                            "error":"The native operation is terminal but its tracking baseline could not be durably finalized. Keep QuickSave open.",
                        }));
                        return;
                    }
                }
                self.finish(
                    id,
                    &state,
                    matches!(state.as_str(), "failed" | "interrupted"),
                );
            }
            Err(error) => {
                if let Some(work) = &work {
                    if self.finalize_work(work, false).await.is_err() {
                        self.lifetime
                            .finalization_blocked
                            .store(true, Ordering::Release);
                        self.patch_operation(id, json!({"phase":"durable_finalization_required"}));
                    }
                }
                self.finish(
                    id,
                    if self.cancelled(id) {
                        "cancelled"
                    } else {
                        "failed"
                    },
                    !self.cancelled(id),
                );
                if !self.cancelled(id) {
                    self.patch_operation(id, json!({"error":dto::engine_error(&error)}));
                }
            }
        }
        guard.finalized = !self.lifetime.finalization_blocked.load(Ordering::Acquire);
    }

    async fn submit_and_monitor(
        &self,
        id: &str,
        plan: &mut RetryPlan,
        work: &mut Option<Value>,
        retry_native: Option<String>,
        pin: &mut Option<Arc<dyn SourceGuard>>,
    ) -> Result<String> {
        if self.cancelled(id) {
            return Ok("cancelled".into());
        }
        ensure!(
            plan.scope == self.source_scope(&plan.params)?,
            "Approved source/provider scope changed before submission"
        );
        let provider = dto::id(&plan.params, "providerId")?.to_owned();
        let mut selection = plan.params.clone();
        if plan.action == "upload" {
            let software_id = dto::id(&plan.params, "softwareId")?.to_owned();
            let snapshot = self.snapshot()?;
            let initial = dto::software_record(&snapshot, &software_id)?.clone();
            *pin = Some(self.pin(initial).await?);
            let _write_access = self.access(&provider, id, true).await?;
            self.ensure_provider_health(&provider).await?;
            if work.is_none() {
                let begin = self
                    .tracking_call(
                        if self.engine.native_capture_supported() {
                            "prepare_upload_scope"
                        } else {
                            "begin_upload"
                        },
                        plan.params.clone(),
                    )
                    .await?;
                *work = Some(begin);
            }
            let captured = work.as_ref().unwrap();
            dto::bounded(captured, dto::MAX_WORK_BYTES)?;
            ensure!(
                captured["softwareId"] == software_id && captured["providerId"] == provider,
                "Captured upload scope mismatch"
            );
            dto::id(captured, "workId")?;
            ensure!(
                captured["generation"].as_u64().is_some() && captured["captureSource"].is_object(),
                "Captured upload proof is incomplete"
            );
            let empty_native_batch = if captured["fileIds"].as_array().is_some_and(Vec::is_empty)
                && plan.params.get("_nativeBatchPlanId").is_some()
            {
                self.batch_runtime()?.check_empty_child_work(id, captured)?;
                true
            } else {
                false
            };
            ensure!(
                captured["fileIds"].as_array().is_some_and(|ids|
                    ids.len() <= 250_000 && (!ids.is_empty() || empty_native_batch
                        || self.engine.native_capture_supported()
                            && captured["captureSource"]["selectionKind"] == "full_scope"
                            && captured["captureSource"]["metadataSelection"]["nodeCount"] == 0
                            && captured["captureSource"]["expectedFullScope"].is_object())),
                "Exact captured nodes or the original native whole-snapshot authority are required; an empty list is not permission"
            );
            if let Some(original) = &plan.captured {
                ensure!(
                    original["selectionDigest"] == dto::fingerprint(&captured["fileIds"])?
                        && original["captureSource"]["snapshotIdentity"]
                            == captured["captureSource"]["snapshotIdentity"],
                    "Retry source contents changed; obtain approval for a new upload instead"
                );
            }
            let snapshot = self.snapshot()?;
            let record = dto::software_record(&snapshot, &software_id)?.clone();
            ensure!(
                record["tracked"] == true && captured["roots"] == native::authority_roots(&record)?,
                "Captured native root/allowlist scope changed"
            );
            self.engine_call("register", None, record).await?;
            self.verify_pin(pin.as_ref().unwrap()).await?;
            plan.captured = Some(capture_summary(captured, &plan.params)?);
            let retained = retain_retry(plan);
            if retained.is_none() {
                plan.captured = None;
            }
            if let Ok(mut operations) = self.operations.lock() {
                if let Some(operation) = operations.get_mut(id) {
                    operation.retry = retained;
                }
            }
            selection = captured.clone();
        }
        if self.cancelled(id) {
            return Ok("cancelled".into());
        }
        let access = self
            .access(&provider, id, plan.action != "download")
            .await?;
        if let Some(pin) = pin.as_ref() {
            self.verify_pin(pin).await?;
        }
        if let Some(proofs) = plan.params.get("_approvedPaths") {
            selection["_approvedPaths"] = proofs.clone();
        }
        ensure!(
            plan.scope == self.source_scope(&plan.params)?,
            "The approved provider/root scope changed before native submission"
        );
        if let Some(work) = work.as_ref().filter(|work| work["automatic"] == true) {
            self.tracking_call("verify_autosave_work", work.clone())
                .await?;
        }
        let mut publication_lease = None;
        let publication_guard = if plan.action == "upload" {
            let (guard, lease) = self.publication_guard(
                id,
                plan,
                work.as_ref().unwrap(),
                pin.as_ref().unwrap().clone(),
            );
            publication_lease = Some(lease);
            Self::check_publication_guard(&guard).await?;
            Some(guard)
        } else if matches!(plan.action.as_str(), "download" | "delete") {
            let guard = self.restore_publication_guard(id, plan);
            Self::check_publication_guard(&guard).await?;
            Some(guard)
        } else {
            None
        };
        selection["operationId"] = json!(id);
        let submitted = if let Some(original) = retry_native {
            self.engine_call("reattach", Some(access), json!({"operationId":original}))
                .await?;
            if let Some(guard) = &publication_guard {
                self.engine
                    .retry_guarded(&original, guard.clone())
                    .await
                    .map_err(|error| anyhow!(dto::engine_error(&error)))?
            } else {
                self.engine_call("retry", None, json!({"operationId":original}))
                    .await?
            }
        } else if plan.action == "download" {
            self.engine
                .download_guarded(
                    access,
                    selection,
                    publication_guard.as_ref().unwrap().clone(),
                )
                .await
                .map_err(|error| anyhow!(dto::engine_error(&error)))?
        } else if plan.action == "delete" {
            self.engine
                .delete_guarded(
                    access,
                    selection,
                    publication_guard.as_ref().unwrap().clone(),
                )
                .await
                .map_err(|error| anyhow!(dto::engine_error(&error)))?
        } else if let Some(guard) = &publication_guard {
            #[cfg(any(unix, windows))]
            let result = if selection["captureSource"]["stage"] == "awaiting_native_capture_receipt"
            {
                let controller = Arc::new(capture::CaptureController::new(
                    self.tracking.clone(),
                    &selection,
                )?);
                self.engine
                    .upload_captured_guarded(access, selection, guard.clone(), controller)
                    .await
            } else {
                self.engine
                    .upload_guarded(access, selection, guard.clone())
                    .await
            };
            #[cfg(not(any(unix, windows)))]
            let result = self
                .engine
                .upload_guarded(access, selection, guard.clone())
                .await;
            result.map_err(|error| anyhow!(dto::engine_error(&error)))?
        } else {
            self.engine_call(&plan.action, Some(access), selection)
                .await?
        };
        let _publication_lease = publication_lease;
        dto::bounded(&submitted, 16 * 1024)?;
        let native_id = dto::id(&submitted, "operationId")?.to_owned();
        {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| anyhow!("Operation state lock failed"))?;
            let operation = operations
                .get_mut(id)
                .ok_or_else(|| anyhow!("Operation admission disappeared"))?;
            operation.native_id = Some(native_id.clone());
        }
        self.patch_operation(
            id,
            json!({"state":"running","phase":"native_operation","canCancel":true}),
        );
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let revoked = if let Some(guard) = &publication_guard {
                Self::check_publication_guard(guard).await.is_err()
            } else {
                self.snapshot()
                    .ok()
                    .and_then(|snapshot| {
                        dto::provider_record(&snapshot, &provider)
                            .ok()
                            .map(|provider| provider["status"] == "disconnected")
                    })
                    .unwrap_or(true)
            };
            if self.cancelled(id)
                || revoked
                || if let Some(pin) = pin.as_ref() {
                    self.verify_pin(pin).await.is_err()
                } else {
                    false
                }
            {
                let _ = self
                    .engine_call("cancel", None, json!({"operationId":native_id}))
                    .await;
            }
            match self
                .engine_call("status", None, json!({"operationId":native_id}))
                .await
            {
                Ok(value) => {
                    let Ok(mut status) = dto::activity(&value) else {
                        self.patch_operation(id,json!({"phase":"native_status_unavailable","error":"The native journal returned an invalid projection; keep QuickSave open."}));
                        continue;
                    };
                    status["id"] = json!(id);
                    if let Ok(operations) = self.operations.lock() {
                        if operations
                            .get(id)
                            .is_some_and(|operation| operation.activity["kind"] == "autosave")
                        {
                            status["kind"] = json!("autosave");
                        }
                    }
                    // The real journal is the sole progress source.
                    self.patch_operation(id, status.clone());
                    if dto::terminal(&status) {
                        if status["state"] == "completed" {
                            if let Some(guard) = &publication_guard {
                                Self::check_publication_guard(guard).await?;
                            }
                            // A changed record must never acknowledge a newer
                            // or differently authorized tracking generation.
                            ensure!(
                                plan.scope == self.source_scope(&plan.params)?,
                                "Source/provider authority changed during upload"
                            );
                            if plan.action == "upload"
                                && self.engine.native_capture_supported()
                                && plan.params.get("_nativeBatchPlanId").is_none()
                            {
                                let captured = work.as_ref().ok_or_else(|| {
                                    anyhow!("The original native capture owner is unavailable")
                                })?;
                                let binding = self
                                    .tracking_call(
                                        "capture_completion_binding",
                                        json!({"workId":dto::id(captured,"workId")?}),
                                    )
                                    .await?;
                                dto::bounded(&binding, 128 * 1024)?;
                                let verified = self
                                    .engine
                                    .verify_capture_completion(&native_id, binding)
                                    .await
                                    .map_err(|error| anyhow!(dto::engine_error(&error)))?;
                                dto::bounded(&verified, 16 * 1024)?;
                                ensure!(verified["verified"] == true
                                    && verified["operationId"] == native_id
                                    && verified["workId"] == captured["workId"]
                                    && verified["generation"] == captured["generation"],
                                    "The native committed result does not match the original capture");
                            }
                        }
                        return Ok(status["state"].as_str().unwrap().to_owned());
                    }
                }
                Err(_) => {
                    // Unknown status is NOT terminal failure/success. Keep
                    // admission/close protection until the journal recovers.
                    self.patch_operation(id,json!({"phase":"native_status_unavailable","error":"The native journal is temporarily unavailable; keep QuickSave open."}));
                }
            }
        }
    }

    async fn prepare_delete(&self, params: Value) -> Result<Value> {
        let _active = Active::acquire(&self.lifetime, false)?;
        let provider = dto::id(&params, "providerId")?.to_owned();
        dto::provider_record(&self.snapshot()?, &provider)?;
        let access = self
            .access(&provider, &Uuid::new_v4().to_string(), false)
            .await?;
        let raw = self
            .engine_call("preview_delete", Some(access), params.clone())
            .await?;
        let preview_id = dto::id(&raw, "previewId")?.to_owned();
        let dependencies = raw
            .get("dependentBundles")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let dependency_count = raw["dependentBundles"]
            .as_u64()
            .or_else(|| raw["dependentBundleCount"].as_u64())
            .unwrap_or(dependencies.len() as u64);
        ensure!(
            dependencies.len() <= 256 && dependencies.len() as u64 == dependency_count,
            "The native deletion preview must identify every exact dependent backup"
        );
        let mut summaries = Vec::with_capacity(dependencies.len());
        for dependency in dependencies {
            let item = if dependency.is_string() {
                let id = dependency.as_str().unwrap();
                ensure!(
                    id.len() <= 512 && !id.chars().any(char::is_control),
                    "Invalid dependent bundle identity"
                );
                json!({"id":id})
            } else {
                dto::copy_fields(
                    &dependency,
                    &[
                        "id",
                        "appId",
                        "commitId",
                        "name",
                        "fileCount",
                        "logicalBytes",
                    ],
                )
            };
            dto::bounded(&item, 16 * 1024)?;
            summaries.push(item);
        }
        let mut summary = dto::copy_fields(
            &raw,
            &[
                "previewId",
                "fileCount",
                "items",
                "logicalBytes",
                "physicalBytes",
                "packCount",
                "objectCount",
            ],
        );
        summary["providerId"] = json!(provider);
        summary["bundleId"] = params["bundleId"].clone();
        summary["appId"] = params["appId"].clone();
        summary["dependentBundles"] = json!(summaries);
        summary["dependentBundleCount"] = json!(dependency_count);
        summary["affectedBundles"] = raw.get("affectedBundles").cloned().unwrap_or(Value::Null);
        summary["planDigest"] = raw.get("planDigest").cloned().unwrap_or(Value::Null);
        summary["frozenPlanFingerprint"] = json!(dto::fingerprint(&raw)?);
        let number = |field: &str| {
            raw[field]
                .as_u64()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into())
        };
        summary["summary"] = json!(format!(
            "Delete cloud backup {} for application {}; {} item(s), {} logical bytes, {} physical bytes, {} dependent backup(s). Local originals are kept.",
            dto::id(&params,"bundleId")?,dto::id(&params,"appId")?,
            raw["items"].as_u64().or_else(||raw["fileCount"].as_u64()).map(|v|v.to_string()).unwrap_or_else(||"unknown".into()),
            number("logicalBytes"),number("physicalBytes"),dependency_count,
        ));
        let mut previews = self
            .previews
            .lock()
            .map_err(|_| anyhow!("Deletion preview lock failed"))?;
        previews.retain(|_, preview| preview.created.elapsed() < PREVIEW_LIFETIME);
        ensure!(
            previews.len() < PREVIEW_LIMIT,
            "The bounded deletion preview cache is full; wait for older previews to expire"
        );
        previews.insert(
            preview_id,
            Preview {
                provider_id: provider,
                summary: summary.clone(),
                created: Instant::now(),
            },
        );
        Ok(summary)
    }

    fn preview(&self, provider: &str, id: &str) -> Result<Preview> {
        let previews = self
            .previews
            .lock()
            .map_err(|_| anyhow!("Deletion preview lock failed"))?;
        let preview = previews.get(id).ok_or_else(|| {
            anyhow!("Create a fresh deletion preview before requesting native confirmation")
        })?;
        ensure!(
            preview.provider_id == provider && preview.created.elapsed() < PREVIEW_LIFETIME,
            "Deletion preview scope changed or expired; create a new preview"
        );
        Ok(preview.clone())
    }

    async fn operation(&self, id: &str) -> Result<Value> {
        if let Some(batch) = self.batch.get().filter(|batch| batch.has_batch(id)) {
            return batch.operation(id).await;
        }
        if let Some(value) = self
            .operations
            .lock()
            .map_err(|_| anyhow!("Operation state lock failed"))?
            .get(id)
            .map(|operation| operation.activity.clone())
        {
            return dto::activity(&value);
        }
        dto::activity(
            &self
                .engine_call("status", None, json!({"operationId":id}))
                .await?,
        )
    }

    async fn activities(&self) -> Result<Vec<Value>> {
        ensure!(
            !self.history_initialization_failed.load(Ordering::Acquire),
            "Native history is unavailable; no existing work was discarded"
        );
        let mut values = self
            .operations
            .lock()
            .map_err(|_| anyhow!("Operation state lock failed"))?
            .values()
            .map(|operation| operation.activity.clone())
            .collect::<Vec<_>>();
        if let Some(batch) = self.batch.get() {
            // Durable groups must be discoverable after restart, not hidden
            // behind renderer-local remembered IDs. Corrupt/unbound journals
            // are errors, never silently omitted unfinished work.
            let groups = batch.recent_activity(dto::MAX_ACTIVITY).await?;
            for group in groups {
                let group = dto::activity(&group)?;
                if !values.iter().any(|value| value["id"] == group["id"]) {
                    values.push(group);
                }
            }
        }
        let known = self
            .operations
            .lock()
            .map_err(|_| anyhow!("Operation state lock failed"))?
            .values()
            .filter_map(|operation| operation.native_id.clone())
            .collect::<BTreeSet<_>>();
        if let Ok(recent) = self.engine_call("recent", None, json!({})).await {
            if let Some(recent) = recent
                .as_array()
                .or_else(|| recent.get("activity").and_then(Value::as_array))
            {
                for value in recent.iter().take(dto::MAX_ACTIVITY) {
                    if value["id"].as_str().is_some_and(|id| known.contains(id)) {
                        continue;
                    }
                    if let Ok(value) = dto::activity(value) {
                        values.push(value);
                    }
                }
            }
        }
        values.sort_by(|a, b| b["startedAt"].as_str().cmp(&a["startedAt"].as_str()));
        values.truncate(dto::MAX_ACTIVITY);
        values.iter().map(dto::activity).collect()
    }

    async fn cancel(&self, id: &str) -> Result<Value> {
        if let Some(batch) = self.batch.get().filter(|batch| batch.has_batch(id)) {
            return batch.cancel(id).await;
        }
        let native_id = {
            let mut operations = self
                .operations
                .lock()
                .map_err(|_| anyhow!("Operation state lock failed"))?;
            if let Some(operation) = operations.get_mut(id) {
                ensure!(
                    !dto::terminal(&operation.activity),
                    "The operation is already terminal"
                );
                ensure!(
                    operation.activity["canCancel"] == true,
                    "The native operation cannot be cancelled in its current phase"
                );
                operation.cancelled = true;
                operation.native_id.clone()
            } else {
                Some(id.to_owned())
            }
        };
        if let Some(native_id) = native_id {
            self.engine_call("cancel", None, json!({"operationId":native_id}))
                .await?;
        }
        self.operation(id).await
    }

    async fn retry(&self, id: &str) -> Result<Value> {
        if let Some(batch) = self.batch.get().filter(|batch| batch.has_batch(id)) {
            return batch.retry(id);
        }
        let (plan, native_id, state) = {
            let operations = self
                .operations
                .lock()
                .map_err(|_| anyhow!("Operation state lock failed"))?;
            let original = operations.get(id).ok_or_else(|| anyhow!("This retry has no authenticated in-session capture plan. Start a newly approved operation; the saved cloud history is unchanged."))?;
            (
                original.retry.clone(),
                original.native_id.clone(),
                original.activity["state"].clone(),
            )
        };
        ensure!(
            matches!(state.as_str(), Some("failed" | "cancelled" | "interrupted")),
            "Only failed, cancelled or interrupted operations can be retried"
        );
        let mut plan =
            plan.ok_or_else(|| anyhow!("This operation has no retryable storage plan"))?;
        ensure!(plan.action != "download","Restore retry is unsupported while retained outputs cannot be safely reused; choose a new native-confirmed empty destination.");
        ensure!(
            plan.scope == self.source_scope(&plan.params)?,
            "The original approved provider/root scope changed; obtain a new native approval"
        );
        if let Some(captured) = &plan.captured {
            // Freeze the actual original logical file selection, including the
            // original full-software enumeration. A retry cannot add new files.
            if captured["fileIds"].is_array() {
                plan.params["fileIds"] = captured["fileIds"].clone();
            }
        }
        let kind = match plan.action.as_str() {
            "upload" => "upload",
            "download" => "download",
            "delete" => "delete",
            _ => bail!("This operation cannot be retried"),
        };
        // begin_upload obtains a new tracker work token; compare against the
        // original capture before asking the engine for its exact retry.
        self.start_operation(
            kind,
            &plan.action,
            plan.params,
            None,
            native_id,
            plan.captured,
        )
    }

    async fn autosave_worker(
        weak: Weak<Self>,
        mut receiver: mpsc::Receiver<QueueItem>,
        mut stop: oneshot::Receiver<()>,
    ) {
        loop {
            let item = tokio::select! {
                biased;
                _ = &mut stop => break,
                request = receiver.recv() => match request {Some(request)=>request,None=>break},
            };
            let (request, bytes) = match item {
                QueueItem::Work(request, bytes) => (request, bytes),
                QueueItem::Barrier(ack) => {
                    let _ = ack.send(());
                    continue;
                }
            };
            let Some(service) = weak.upgrade() else { break };
            // Protect the handoff before reducing the queue close counter.
            service.lifetime.active.fetch_add(1, Ordering::SeqCst);
            service.lifetime.queued.fetch_sub(1, Ordering::SeqCst);
            service
                .lifetime
                .queued_bytes
                .fetch_sub(bytes, Ordering::SeqCst);
            let handoff = Active {
                lifetime: service.lifetime.clone(),
                admitted: false,
            };
            let params = dto::copy_fields(&request, &["softwareId", "providerId"]);
            let result = async {
                dto::id(&request, "workId")?;
                dto::id(&request, "softwareId")?;
                dto::id(&request, "providerId")?;
                // Tracker validates persistent device-vault grants at startup
                // and before enqueue. Recheck again off the notify callback.
                service
                    .tracking_call("verify_autosave_work", request.clone())
                    .await?;
                service.start_operation(
                    "autosave",
                    "upload",
                    params,
                    Some(request.clone()),
                    None,
                    None,
                )?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if result.is_err() && service.finalize_work(&request, false).await.is_err() {
                service
                    .lifetime
                    .finalization_blocked
                    .store(true, Ordering::Release);
            }
            drop(handoff);
        }
    }
}

fn capture_summary(work: &Value, params: &Value) -> Result<Value> {
    let mut summary = json!({
        "selectionDigest":dto::fingerprint(&work["fileIds"])?,
        "captureSource":{"snapshotIdentity":work["captureSource"]["snapshotIdentity"],"stage":work["captureSource"]["stage"]},
    });
    if params.get("fileIds").is_some() || work["automatic"] == true {
        summary["fileIds"] = work["fileIds"].clone();
    }
    Ok(summary)
}

fn retain_retry(plan: &RetryPlan) -> Option<RetryPlan> {
    // A new tracker work token cannot silently replace the original source
    // receipt's work identity. Durable receipt-backed retry must reattach that
    // exact work first; do not advertise the legacy recapture retry as equivalent.
    if plan.captured.as_ref().is_some_and(|capture| {
        capture["captureSource"]["stage"] == "awaiting_native_capture_receipt"
    }) {
        return None;
    }
    // UI history has an independent bound. Whole-software retry binds original
    // snapshot+selection digests, not another 186k-file metadata tree.
    dto::bounded(&plan.params, 512 * 1024).ok()?;
    if let Some(captured) = &plan.captured {
        dto::bounded(captured, 512 * 1024).ok()?;
    }
    Some(plan.clone())
}

fn provider_health_scope(provider: &Value) -> Result<String> {
    dto::fingerprint(&dto::copy_fields(
        provider,
        &[
            "id",
            "kind",
            "bucket",
            "prefix",
            "credentialRef",
            "repositoryKeyRef",
            "sourceProfileId",
            "profileFingerprint",
            "authorityGeneration",
            "publicScope",
        ],
    ))
}

fn verified_health(report: &Value) -> bool {
    report["canList"] == true
        && report["repositoryAccessible"] == true
        && match report["repositoryEmpty"].as_bool() {
            Some(true) => report["canRead"] == false && report["keyVerified"] == false,
            Some(false) => report["canRead"] == true && report["keyVerified"] == true,
            None => false,
        }
}

fn scoped_cursor(cursor: Option<&Value>, scope: &str) -> Result<Option<String>> {
    let Some(cursor) = cursor.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let cursor = cursor
        .as_str()
        .ok_or_else(|| anyhow!("Invalid page cursor"))?;
    ensure!(
        cursor.len() <= 8192,
        "Page cursor exceeds the bounded limit"
    );
    let (bound, value) = cursor
        .split_once(':')
        .ok_or_else(|| anyhow!("Page cursor is not scope bound"))?;
    ensure!(
        bound == scope,
        "Page cursor belongs to a different source scope"
    );
    Ok(Some(value.to_owned()))
}

fn wrap_cursor(listing: &mut Value, scope: &str) -> Result<()> {
    if let Some(cursor) = listing.get("nextCursor").and_then(Value::as_str) {
        ensure!(
            cursor.len() <= 4096,
            "Native page cursor exceeds the bounded limit"
        );
        listing["nextCursor"] = json!(format!("{scope}:{cursor}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
