// SPDX-License-Identifier: GPL-3.0-only
//! notify callbacks do no filesystem/cloud I/O. A bounded channel carries hints.

use crate::{model::ApprovedRoot, scan, sync_record, Shared};
use anyhow::{anyhow, Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{sync_channel, Receiver, RecvTimeoutError, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(crate) const QUEUE_CAPACITY: usize = 256;
const TICK: Duration = Duration::from_millis(250);

pub(crate) enum Hint {
    Software(String),
    Wake,
}

pub(crate) struct WatchRoute {
    software_id: String,
    root: ApprovedRoot,
    epoch: Arc<AtomicU64>,
}

impl WatchRoute {
    fn matches(&self, path: &Path) -> bool {
        if let Some(leaves) = &self.root.allowed_files {
            // Some native backends report a parent-directory modification only.
            if path == self.root.path {
                return true;
            }
            path.strip_prefix(&self.root.path)
                .ok()
                .and_then(|relative| relative.to_str())
                .is_some_and(|leaf| leaves.contains(leaf))
        } else {
            path.starts_with(&self.root.path)
        }
    }
}

pub(crate) fn start(shared: Arc<Shared>, receiver: Receiver<Hint>) -> Result<JoinHandle<()>> {
    let (started_tx, started_rx) = sync_channel(1);
    let worker = thread::Builder::new()
        .name("quicksave-tracking".into())
        .spawn(move || {
            let callback_shared = shared.clone();
            let watcher = notify::recommended_watcher(move |event: notify::Result<Event>| {
                deliver(&callback_shared, event);
            });
            let mut watcher = match watcher {
                Ok(watcher) => {
                    let _ = started_tx.send(Ok::<(), String>(()));
                    watcher
                }
                Err(_) => {
                    let _ =
                        started_tx.send(Err("native notify watcher initialization failed".into()));
                    return;
                }
            };
            let mut registered: BTreeMap<PathBuf, RecursiveMode> = BTreeMap::new();
            let mut last_audit = shared.now();
            let mut seen_uncertainty = shared.uncertainty_epoch.load(Ordering::Acquire);
            while !shared.stop.load(Ordering::Acquire) {
                let mut hints = BTreeSet::new();
                match receiver.recv_timeout(TICK) {
                    Ok(Hint::Software(id)) => {
                        hints.insert(id);
                    }
                    Ok(Hint::Wake) | Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                // A producer storm can never monopolize the worker indefinitely.
                for _ in 1..QUEUE_CAPACITY {
                    match receiver.try_recv() {
                        Ok(Hint::Software(id)) => {
                            hints.insert(id);
                        }
                        Ok(Hint::Wake) => {}
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                    }
                }
                if shared.stop.load(Ordering::Acquire) {
                    break;
                }
                let now = shared.now();
                let uncertainty = shared.uncertainty_epoch.load(Ordering::Acquire);
                let overflowed = uncertainty != seen_uncertainty;
                seen_uncertainty = uncertainty;
                let audit_ms = shared
                    .policy
                    .audit_interval
                    .as_millis()
                    .min(u64::MAX as u128) as u64;
                let audit_due = now.saturating_sub(last_audit) >= audit_ms;
                if audit_due {
                    last_audit = now;
                    // Also reestablish native watches after transient permission/
                    // mount failures. No OS service/relogin behavior is invented.
                    shared.reconfigure.store(true, Ordering::Release);
                }
                if shared.reconfigure.swap(false, Ordering::AcqRel)
                    && rebuild(&shared, &mut watcher, &mut registered).is_err()
                {
                    shared.uncertain(true);
                }
                let requests = tick(&shared, hints, overflowed, audit_due);
                for request in requests {
                    if shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    // Never call an external callback while holding tracker locks.
                    let work = request
                        .get("workId")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let generation = request
                        .get("generation")
                        .and_then(serde_json::Value::as_u64);
                    if (shared.enqueue)(request).is_err() {
                        if let (Some(work), Some(generation)) = (work, generation) {
                            let _ = shared.complete_upload(&work, generation, false);
                        }
                    }
                }
            }
            // Drop native notify resources before clearing route references/joining.
            drop(watcher);
            if let Ok(mut routes) = shared.routes.write() {
                routes.clear();
            }
        })
        .context("spawn owned native tracking worker")?;
    match started_rx.recv() {
        Ok(Ok(())) => Ok(worker),
        Ok(Err(message)) => {
            let _ = worker.join();
            Err(anyhow!(message))
        }
        Err(_) => {
            let _ = worker.join();
            Err(anyhow!(
                "native tracking worker stopped during initialization"
            ))
        }
    }
}

fn deliver(shared: &Shared, event: notify::Result<Event>) {
    let event = match event {
        Ok(event) => event,
        Err(_) => {
            shared.uncertain(true);
            shared.reconfigure.store(true, Ordering::Release);
            return;
        }
    };
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }
    if event.need_rescan() || event.paths.is_empty() {
        shared.uncertain(false);
        return;
    }
    let routes = match shared.routes.read() {
        Ok(routes) => routes,
        Err(_) => {
            shared.uncertain(true);
            return;
        }
    };
    // The OS event payload itself may contain many paths; we never retain it.
    // Bounded routes × bounded inspected paths, then global reconciliation.
    if event.paths.len() > 1024 {
        shared.uncertain(false);
        return;
    }
    let mut seen = BTreeSet::new();
    for route in routes.iter() {
        if event.paths.iter().any(|path| route.matches(path)) && seen.insert(&route.software_id) {
            // Increment before queueing. Completion sees mutations even if the
            // bounded hint has not yet been consumed (or the queue overflows).
            route.epoch.fetch_add(1, Ordering::AcqRel);
            if shared
                .wake
                .try_send(Hint::Software(route.software_id.clone()))
                .is_err()
            {
                shared.uncertain(false);
            }
        }
    }
}

fn rebuild(
    shared: &Shared,
    watcher: &mut RecommendedWatcher,
    registered: &mut BTreeMap<PathBuf, RecursiveMode>,
) -> Result<()> {
    let requested_reset = shared.watch_reset_requested.load(Ordering::Acquire);
    if requested_reset > shared.watch_reset_confirmed.load(Ordering::Acquire) {
        // A native watcher error is not evidence that old registrations remain
        // healthy. Keep the proof fence raised through all re-registrations.
        for path in registered.keys() {
            let _ = watcher.unwatch(path);
        }
        registered.clear();
    }
    let mut apps = shared.apps()?;
    let mut routes = Vec::new();
    let mut desired = BTreeMap::new();
    for app in apps.values_mut() {
        if shared.validate_tracking(app).is_err() {
            continue;
        }
        if app.scheduler.paused {
            continue;
        }
        app.watch_ok = true;
        for root in &app.record.roots {
            if scan::PinnedRoot::open(root)
                .and_then(|pinned| pinned.check())
                .is_err()
            {
                app.watch_ok = false;
                app.scheduler.failed(shared.now());
                app.force_hash = true;
                app.record.error =
                    Some("Root watcher requires native source reconciliation.".into());
                continue;
            }
            let mode = if root.allowed_files.is_some() {
                RecursiveMode::NonRecursive
            } else {
                RecursiveMode::Recursive
            };
            desired
                .entry(root.path.clone())
                .and_modify(|previous| {
                    if mode == RecursiveMode::Recursive {
                        *previous = mode;
                    }
                })
                .or_insert(mode);
            routes.push(WatchRoute {
                software_id: app.record.id.clone(),
                root: root.clone(),
                epoch: app.event_epoch.clone(),
            });
        }
    }
    // Update only changed paths. Periodic audits must not drop healthy watches.
    let removed: Vec<_> = registered
        .iter()
        .filter(|(path, mode)| desired.get(*path) != Some(*mode))
        .map(|(path, _)| path.clone())
        .collect();
    if !removed.is_empty() {
        // Changing an existing native registration creates a real coverage gap,
        // unlike merely adding a disjoint application's first watch.
        shared.uncertain(false);
    }
    for path in removed {
        let _ = watcher.unwatch(&path);
        registered.remove(&path);
    }
    for (path, mode) in &desired {
        if registered.get(path) == Some(mode) {
            continue;
        }
        match watcher.watch(path, *mode) {
            Ok(()) => {
                registered.insert(path.clone(), *mode);
            }
            Err(_) => {
                for route in routes.iter().filter(|route| &route.root.path == path) {
                    if let Some(app) = apps.get_mut(&route.software_id) {
                        app.watch_ok = false;
                        app.scheduler.failed(shared.now());
                        app.force_hash = true;
                        app.record.error = Some(
                            "Native watcher unavailable; autosave is paused until reconciliation."
                                .into(),
                        );
                    }
                }
            }
        }
    }
    // Registering an initial/restarted watch always demands a baseline audit;
    // it never implies that missed events did not occur.
    for app in apps.values_mut() {
        if !app.scheduler.paused {
            app.scheduler.require_reconcile();
            shared.persist(app)?;
        }
    }
    *shared
        .routes
        .write()
        .map_err(|_| anyhow!("native watch routing lock poisoned"))? = routes;
    // A concurrent later error has a larger requested epoch and cannot be
    // erased by this rebuild's completion.
    shared
        .watch_reset_confirmed
        .fetch_max(requested_reset, Ordering::AcqRel);
    Ok(())
}

pub(crate) fn tick(
    shared: &Shared,
    hints: BTreeSet<String>,
    overflowed: bool,
    audit_due: bool,
) -> Vec<serde_json::Value> {
    let mut requests = Vec::new();
    let Ok(mut apps) = shared.apps() else {
        return requests;
    };
    for app in apps.values_mut() {
        if shared.stop.load(Ordering::Acquire) {
            break;
        }
        let now = shared.now();
        // A denial latch/revocation requires explicit recovery, not another
        // expensive vault/state verification on every idle timer wake.
        if app.authorization_paused || app.scheduler.paused {
            continue;
        }
        let uncertainty =
            shared.uncertainty_epoch.load(Ordering::Acquire) != app.observation_uncertainty_epoch;
        if audit_due
            || uncertainty
            || app.event_epoch.load(Ordering::Acquire) != app.observation_event_epoch
        {
            // Scheduling hints grant no source access or cleanliness.
            app.scheduler.require_reconcile();
            if uncertainty {
                app.force_hash = true;
            }
        }
        let hinted = overflowed || hints.contains(&app.record.id);
        let upload_due = app
            .scheduler
            .ready(now, app.record.autosave && app.watch_ok);
        if !hinted && !app.scheduler.can_reconcile(now) && !upload_due {
            continue;
        }
        // Always verify fresh native authority before actual source work,
        // persistence of a hint, or upload admission. Never cache a valid grant.
        if shared.validate_tracking(app).is_err() {
            continue;
        }
        if overflowed || hints.contains(&app.record.id) {
            if app.scheduler.hint(now).is_err() {
                app.scheduler.revoke();
            }
            if overflowed {
                app.force_hash = true;
            }
            let _ = shared.persist(app);
        } else if audit_due {
            app.scheduler.require_reconcile();
        }
        if app.scheduler.can_reconcile(now) && shared.reconcile_mode(app, false, false).is_err() {
            continue;
        }
        let authorized = shared.validate_autosave(app).unwrap_or(false) && app.watch_ok;
        if !app.scheduler.ready(shared.now(), authorized) {
            continue;
        }
        let Some(provider) = app.record.provider_id.clone() else {
            continue;
        };
        let Some(current) = &app.current else {
            continue;
        };
        // Every automatic generation is a whole approved-scope manifest.
        // Narrowing it to changed IDs creates custom patches and leaves the
        // application's latest complete head stale. The actual source engine
        // reuses authenticated unchanged file/chunk proofs instead.
        if app.record.baseline_full_scope
            && current.content_verified()
            && app.baseline.as_deref() == Some(current.as_ref())
        {
            continue;
        }
        match shared.prepare_upload_mode(app, &provider, None, true, true) {
            Ok(request) => requests.push(request),
            Err(error) => {
                app.scheduler.failed(shared.now());
                app.record.error = Some(format!(
                    "Autosave scope is pending: {}",
                    error.to_string().chars().take(1024).collect::<String>()
                ));
                sync_record(app);
                let _ = shared.persist(app);
            }
        }
    }
    requests
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) fn inject_event(shared: &Shared, event: notify::Result<Event>) {
    deliver(shared, event);
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) fn install_test_routes(shared: &Shared) {
    let apps = shared.apps().unwrap();
    *shared.routes.write().unwrap() = apps
        .values()
        .flat_map(|app| {
            app.record.roots.iter().map(|root| WatchRoute {
                software_id: app.record.id.clone(),
                root: root.clone(),
                epoch: app.event_epoch.clone(),
            })
        })
        .collect();
}
