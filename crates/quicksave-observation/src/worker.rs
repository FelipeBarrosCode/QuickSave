// SPDX-License-Identifier: GPL-3.0-only
//! One owned worker, bounded nonblocking callbacks, no detached subprocesses.
use crate::*;
use anyhow::{ensure, Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{sync_channel, RecvTimeoutError, SyncSender, TryRecvError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub type ObservationCallback = Arc<dyn Fn(Arc<ObservationSnapshot>) -> Result<()> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    pub poll_interval: Duration,
    /// Exponential idle backoff cap; missing events remain explicitly unknown.
    pub idle_poll_interval: Duration,
    pub queue_capacity: usize,
    /// False is intended for deterministic fixtures. Missing watcher evidence
    /// remains an explicit gap, not an implicit "watching successfully" claim.
    pub watch_roots: bool,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            idle_poll_interval: Duration::from_secs(30),
            queue_capacity: 256,
            watch_roots: true,
        }
    }
}

enum Command {
    Wake,
    Hint(RootHint),
    Gap(GapReason),
}

struct Shared {
    stop: AtomicBool,
    overflow: AtomicBool,
    watcher_loss: AtomicBool,
    event_epoch: AtomicU64,
    latest: Mutex<Arc<ObservationSnapshot>>,
    sender: SyncSender<Command>,
}

pub struct ObservationWorker {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ObservationWorker {
    pub fn start(
        mut engine: ObservationEngine,
        config: WorkerConfig,
        callback: ObservationCallback,
    ) -> Result<Self> {
        ensure!(
            config.queue_capacity > 0
                && config.queue_capacity <= 4096
                && config.poll_interval >= Duration::from_millis(10)
                && config.poll_interval <= config.idle_poll_interval
                && config.idle_poll_interval
                    <= Duration::from_millis(engine.maximum_poll_interval_ms()),
            "observation worker configuration exceeds hard bounds"
        );
        let (sender, receiver) = sync_channel(config.queue_capacity);
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            watcher_loss: AtomicBool::new(false),
            event_epoch: AtomicU64::new(0),
            latest: Mutex::new(engine.snapshot()),
            sender,
        });
        let owned = shared.clone();
        let worker = thread::Builder::new()
            .name("quicksave-observation".into())
            .spawn(move || {
                let _exit_fence = ExitFence(owned.clone());
                let watcher = if config.watch_roots {
                    install_watcher(&engine, owned.clone()).ok()
                } else {
                    None
                };
                if watcher.is_none() {
                    engine.persistent_gap(GapReason::WatcherUnavailable, true);
                }
                let origin = Instant::now();
                let mut backoff = PollBackoff::new(config.poll_interval, config.idle_poll_interval);
                let mut due = Instant::now();
                let mut earliest_poll = due;
                let mut requested = false;
                while !owned.stop.load(Ordering::Acquire) {
                    let wait = due.saturating_duration_since(Instant::now());
                    let mut reconcile = wait.is_zero();
                    if !reconcile {
                        match receiver.recv_timeout(wait) {
                            Ok(command) => {
                                consume(&mut engine, command);
                                requested = true;
                            }
                            Err(RecvTimeoutError::Timeout) => reconcile = true,
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    // A producer storm cannot keep the worker in the drain loop.
                    for _ in 0..config.queue_capacity {
                        match receiver.try_recv() {
                            Ok(command) => {
                                consume(&mut engine, command);
                                requested = true;
                            }
                            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                        }
                    }
                    if owned.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if owned.overflow.swap(false, Ordering::AcqRel) {
                        engine.signal_gap(GapReason::QueueOverflow);
                    }
                    if owned.watcher_loss.swap(false, Ordering::AcqRel) {
                        engine.signal_gap(GapReason::WatcherOverflow);
                    }
                    if requested {
                        due = due.min(earliest_poll);
                        reconcile = Instant::now() >= due;
                    }
                    if !reconcile {
                        continue;
                    }
                    requested = false;
                    let before = owned.event_epoch.load(Ordering::Acquire);
                    let now = origin.elapsed().as_millis().min(u64::MAX as u128) as u64;
                    if engine.reconcile(now).is_err() {
                        engine.fence_current(GapReason::SourceUnavailable);
                    }
                    if owned.event_epoch.load(Ordering::Acquire) != before {
                        engine.fence_current(GapReason::EventsDuringReconciliation);
                    }
                    // Include newly sampled native evidence/loss in capture
                    // watermarks too, not just notify/queued commands. Idle
                    // incomplete polls do not advance this event fence.
                    if engine.snapshot().activity_observed {
                        owned.event_epoch.fetch_add(1, Ordering::AcqRel);
                    }
                    store_snapshot(&owned, engine.snapshot());
                    // Callback is synchronous and outside every worker/state lock.
                    // It must be bounded and non-reentrant; shutdown waits for it.
                    let activity = engine.snapshot().activity_observed;
                    if activity
                        && !owned.stop.load(Ordering::Acquire)
                        && callback(engine.snapshot()).is_err()
                    {
                        engine.fence_current(GapReason::CallbackFailed);
                        owned.event_epoch.fetch_add(1, Ordering::AcqRel);
                        store_snapshot(&owned, engine.snapshot());
                    }
                    let finished = Instant::now();
                    earliest_poll = finished + config.poll_interval;
                    due = finished + backoff.next_interval(activity);
                }
                // Drop notify's owned backend before join can return.
                drop(watcher);
                engine.fence_current(GapReason::WorkerStopped);
                store_snapshot(&owned, engine.snapshot());
            })
            .context("spawn owned native observation worker")?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn snapshot(&self) -> Result<Arc<ObservationSnapshot>> {
        self.shared
            .latest
            .lock()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| anyhow::anyhow!("observation snapshot lock poisoned"))
    }

    /// Captures pending-event/loss state without waiting for an OS poll. A parent
    /// capture receipt can compare these around its own stable-file work; a
    /// matching watermark still does not imply complete polling coverage.
    pub fn watermark(&self) -> ObservationWatermark {
        ObservationWatermark {
            event_epoch: self.shared.event_epoch.load(Ordering::Acquire),
            pending_loss: self.shared.overflow.load(Ordering::Acquire)
                || self.shared.watcher_loss.load(Ordering::Acquire),
            stopped: self.shared.stop.load(Ordering::Acquire),
        }
    }

    pub fn request_reconcile(&self) -> Result<()> {
        self.send(Command::Wake)
    }
    pub fn root_hint(&self, root_id: impl Into<String>) -> Result<()> {
        let root_id = root_id.into();
        crate::scope::valid_id(&root_id)?;
        self.send(Command::Hint(RootHint { root_id }))
    }
    pub fn signal_gap(&self, reason: GapReason) -> Result<()> {
        self.send(Command::Gap(reason))
    }

    fn send(&self, command: Command) -> Result<()> {
        ensure!(
            !self.shared.stop.load(Ordering::Acquire),
            "observation worker is stopped"
        );
        self.shared.event_epoch.fetch_add(1, Ordering::AcqRel);
        if self.shared.sender.try_send(command).is_err() {
            self.shared.overflow.store(true, Ordering::Release);
            anyhow::bail!("observation work queue is full or unavailable; unknown epoch recorded");
        }
        Ok(())
    }

    /// Does not return until native watchers and the owned worker are released.
    /// Calling from inside the callback is unsupported and detected, not hung.
    pub fn shutdown(&self) -> Result<()> {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.shared.sender.try_send(Command::Wake);
        let mut slot = self
            .worker
            .lock()
            .map_err(|_| anyhow::anyhow!("observation worker lock poisoned"))?;
        if slot
            .as_ref()
            .is_some_and(|handle| handle.thread().id() == thread::current().id())
        {
            anyhow::bail!("observation callback cannot join its own worker");
        }
        if let Some(handle) = slot.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("native observation worker panicked"))?;
        }
        Ok(())
    }
}

struct PollBackoff {
    active: Duration,
    idle: Duration,
    current: Duration,
}
impl PollBackoff {
    fn new(active: Duration, idle: Duration) -> Self {
        Self {
            active,
            idle,
            current: active,
        }
    }
    fn next_interval(&mut self, activity: bool) -> Duration {
        self.current = if activity {
            self.active
        } else {
            self.current.saturating_mul(2).min(self.idle)
        };
        self.current
    }
}

impl Drop for ObservationWorker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.shared.sender.try_send(Command::Wake);
        let slot = self
            .worker
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(handle) = slot.take() {
            // The callback cannot normally own this worker (it is constructed
            // before the worker is returned). Do not self-join on misuse.
            if handle.thread().id() != thread::current().id() {
                let _ = handle.join();
            }
        }
    }
}

/// Also runs on an adapter/callback panic, after notify has unwound and released
/// its handles. A stale running snapshot cannot survive a dead worker.
struct ExitFence(Arc<Shared>);
impl Drop for ExitFence {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::Release);
        if let Ok(mut latest) = self.0.latest.lock() {
            let snapshot = Arc::make_mut(&mut *latest);
            if !snapshot
                .gaps
                .iter()
                .any(|gap| gap.reason == GapReason::WorkerStopped)
            {
                snapshot
                    .gaps
                    .push(ObservationGap::global(GapReason::WorkerStopped));
                snapshot.uncertainty_epoch = snapshot.uncertainty_epoch.saturating_add(1);
            }
            let uncertainty = snapshot.uncertainty_epoch;
            for app in &mut snapshot.applications {
                app.execution_state = ExecutionState::Unknown;
                app.open_file_state = OpenFileState::Unknown;
                app.completeness = "unknown";
                app.uncertainty_epoch = uncertainty;
                for session in &mut app.active_sessions {
                    session.currently_observed = false;
                }
                for candidate in &mut app.root_candidates {
                    candidate.currently_open = false;
                }
            }
        }
    }
}

fn consume(engine: &mut ObservationEngine, command: Command) {
    match command {
        Command::Wake => {}
        Command::Hint(hint) => {
            if engine.root_hint(hint).is_err() {
                engine.signal_gap(GapReason::BoundExceeded);
            }
        }
        Command::Gap(reason) => engine.signal_gap(reason),
    }
}

fn store_snapshot(shared: &Shared, snapshot: Arc<ObservationSnapshot>) {
    if let Ok(mut latest) = shared.latest.lock() {
        *latest = snapshot;
    } else {
        shared.stop.store(true, Ordering::Release);
    }
}

fn install_watcher(engine: &ObservationEngine, shared: Arc<Shared>) -> Result<RecommendedWatcher> {
    let roots: Vec<_> = engine
        .scope
        .roots()
        .filter(|root| root.kind.allows(ObservationRootKind::Data))
        .cloned()
        .collect();
    let excluded = engine.scope.request.excluded_paths.clone();
    engine.scope.check()?;
    let callback_shared = shared.clone();
    let routes = roots.clone();
    let mut watcher = RecommendedWatcher::new(
        move |event: notify::Result<Event>| {
            let event = match event {
                Ok(event) => event,
                Err(_) => {
                    watcher_gap(&callback_shared);
                    return;
                }
            };
            // Metadata-handle opens must not recursively generate our own hints.
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            if event.need_rescan() || event.paths.is_empty() || event.paths.len() > 1024 {
                watcher_gap(&callback_shared);
                return;
            }
            for root in &routes {
                let matches = event.paths.iter().any(|path| {
                    if crate::scope::validate_absolute(path).is_err()
                        || crate::scope::private_path(path)
                        || excluded.iter().any(|excluded| path.starts_with(excluded))
                    {
                        return false;
                    }
                    if path == &root.path {
                        return true;
                    }
                    path.strip_prefix(&root.path)
                        .ok()
                        .and_then(crate::scope::portable_relative)
                        .is_some_and(|relative| {
                            crate::scope::validate_relative(&relative).is_ok()
                                && root
                                    .allowed_files
                                    .as_ref()
                                    .is_none_or(|files| files.contains(&relative))
                        })
                });
                if matches {
                    callback_shared.event_epoch.fetch_add(1, Ordering::AcqRel);
                    if callback_shared
                        .sender
                        .try_send(Command::Hint(RootHint {
                            root_id: root.id.clone(),
                        }))
                        .is_err()
                    {
                        callback_shared.overflow.store(true, Ordering::Release);
                    }
                }
            }
        },
        Config::default().with_follow_symlinks(false),
    )?;
    // Non-recursive registrations avoid an implicit walk/stat of excluded
    // children and secret directories by the inotify backend. The native
    // process/open-file source still observes nested approved leaves. Missing
    // subdirectory hints are part of the explicit incomplete-polling contract.
    let paths: std::collections::BTreeSet<_> = roots.into_iter().map(|root| root.path).collect();
    for path in paths {
        watcher.watch(&path, RecursiveMode::NonRecursive)?;
    }
    engine.scope.check()?;
    Ok(watcher)
}

fn watcher_gap(shared: &Shared) {
    shared.event_epoch.fetch_add(1, Ordering::AcqRel);
    shared.watcher_loss.store(true, Ordering::Release);
    if shared.sender.try_send(Command::Wake).is_err() {
        shared.overflow.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    #[test]
    fn idle_backoff_is_bounded_and_activity_resets_without_real_processes() {
        let mut backoff = PollBackoff::new(Duration::from_secs(2), Duration::from_secs(30));
        assert_eq!(backoff.next_interval(false), Duration::from_secs(4));
        assert_eq!(backoff.next_interval(false), Duration::from_secs(8));
        assert_eq!(backoff.next_interval(false), Duration::from_secs(16));
        assert_eq!(backoff.next_interval(false), Duration::from_secs(30));
        assert_eq!(backoff.next_interval(false), Duration::from_secs(30));
        assert_eq!(backoff.next_interval(true), Duration::from_secs(2));
    }
}
