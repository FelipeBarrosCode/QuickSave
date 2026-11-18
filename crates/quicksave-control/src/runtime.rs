// SPDX-License-Identifier: GPL-3.0-only
//! Bounded native work. No GUI-visible lock is held across filesystem IO.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use quicksave_client::OperationManager;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::{
    approval::{Approval, ApprovalStore, PathProofs, Scope},
    message,
};

pub enum Lane {
    Read,
    Mutation,
    Dialog,
}

pub struct AppState {
    // This mutex protects only an Arc publication/clone, never loading or IO.
    manager: Mutex<Option<Arc<OperationManager>>>,
    // Background-only coalescing gate. The GUI never waits on this lock.
    manager_load: Mutex<()>,
    approvals: Mutex<ApprovalStore<PathProofs>>,
    reads: Arc<Semaphore>,
    mutations: Arc<Semaphore>,
    dialogs: Arc<Semaphore>,
    active_workers: AtomicUsize,
    // Admission and shutdown coordinate through a short, IO-free critical
    // section. Shutdown uses try_lock and conservatively refuses on contention.
    lifecycle: Mutex<()>,
    stopping: AtomicBool,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            manager: Mutex::new(None),
            manager_load: Mutex::new(()),
            approvals: Mutex::new(ApprovalStore::default()),
            reads: Arc::new(Semaphore::new(2)),
            mutations: Arc::new(Semaphore::new(1)),
            dialogs: Arc::new(Semaphore::new(1)),
            active_workers: AtomicUsize::new(0),
            lifecycle: Mutex::new(()),
            stopping: AtomicBool::new(false),
        }
    }

    fn cached_manager(&self) -> Result<Option<Arc<OperationManager>>, String> {
        self.manager
            .lock()
            .map(|manager| manager.clone())
            .map_err(|_| "Operation manager is unavailable".into())
    }

    /// Background-only. Concurrent callers share one initialization. A history
    /// read with no existing history does not create any application state.
    pub fn load_manager(&self, create: bool) -> Result<Option<Arc<OperationManager>>, String> {
        if let Some(manager) = self.cached_manager()? {
            return Ok(Some(manager));
        }
        let _loading = self
            .manager_load
            .lock()
            .map_err(|_| "Operation history initialization is unavailable".to_owned())?;
        if let Some(manager) = self.cached_manager()? {
            return Ok(Some(manager));
        }
        let directory = manager_path()?;
        if !create {
            match std::fs::symlink_metadata(&directory) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(format!(
                        "Cannot inspect QuickSave operation history: {error}"
                    ))
                }
            }
        }
        let manager = Arc::new(OperationManager::open(&directory).map_err(message)?);
        *self
            .manager
            .lock()
            .map_err(|_| "Operation manager is unavailable".to_owned())? =
            Some(Arc::clone(&manager));
        Ok(Some(manager))
    }

    pub fn check_approval_capacity(&self) -> Result<(), String> {
        self.approvals
            .lock()
            .map_err(|_| "Native approval storage is unavailable".to_owned())?
            .check_capacity(Instant::now())
    }

    pub fn record_approval(
        &self,
        scope: Scope,
        proofs: PathProofs,
        issued_at: Instant,
    ) -> Result<String, String> {
        self.approvals
            .lock()
            .map_err(|_| "Native approval storage is unavailable".to_owned())?
            .insert(scope, proofs, issued_at)
    }

    pub fn consume_approval(
        &self,
        id: Uuid,
        scope: &Scope,
    ) -> Result<Approval<PathProofs>, String> {
        self.approvals
            .lock()
            .map_err(|_| "Native approval storage is unavailable".to_owned())?
            .consume(id, scope, Instant::now())
    }

    /// Called by GUI lifecycle callbacks. Never waits for a mutex or performs
    /// filesystem IO. OperationManager::active is the client's atomic flag.
    pub fn prevent_shutdown(&self) -> bool {
        let Ok(_lifecycle) = self.lifecycle.try_lock() else {
            return true;
        };
        if self.active_workers.load(Ordering::Acquire) != 0 {
            return true;
        }
        let Ok(manager) = self.manager.try_lock() else {
            return true;
        };
        if manager.as_ref().is_some_and(|manager| manager.active()) {
            return true;
        }
        self.stopping.store(true, Ordering::Release);
        false
    }

    /// A native workspace may discover a just-enqueued autosave while joining
    /// its own workers. If its shutdown is refused, reopen IPC admission rather
    /// than leaving a running application permanently stuck in "closing".
    pub fn resume_after_failed_shutdown(&self) {
        self.stopping.store(false, Ordering::Release);
    }
}

fn manager_path() -> Result<PathBuf, String> {
    let directories = quicksave_platform::app_directories().map_err(message)?;
    let data = directories
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| "Platform did not provide a private QuickSave data directory".to_owned())?;
    Ok(Path::new(data).join("operations"))
}

struct WorkTicket {
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
}

impl WorkTicket {
    fn acquire(state: Arc<AppState>, lane: Lane) -> Result<Self, String> {
        let (semaphore, busy) = match lane {
            Lane::Read => (
                &state.reads,
                "QuickSave read workers are busy; try again shortly",
            ),
            Lane::Mutation => (
                &state.mutations,
                "QuickSave operation admission is busy; try again shortly",
            ),
            Lane::Dialog => (
                &state.dialogs,
                "Another native authorization is in progress; finish or cancel it first",
            ),
        };
        // No wait queue: reject before spawning or retaining another request.
        let permit = Arc::clone(semaphore)
            .try_acquire_owned()
            .map_err(|_| busy.to_owned())?;
        {
            let _lifecycle = state
                .lifecycle
                .lock()
                .map_err(|_| "QuickSave worker admission is unavailable".to_owned())?;
            if state.stopping.load(Ordering::Acquire) {
                return Err("QuickSave is closing; no new native work was started".into());
            }
            state.active_workers.fetch_add(1, Ordering::AcqRel);
        }
        Ok(Self {
            state,
            _permit: permit,
        })
    }
}

impl Drop for WorkTicket {
    fn drop(&mut self) {
        self.state.active_workers.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Every normal invocation awaits its worker. If an invoking future disappears,
/// the ticket still lives IN the native worker: its lane remains occupied, the
/// application state stays alive, and normal close/quit remains blocked until
/// the native call has actually returned, including unwinding.
pub async fn blocking<T>(
    state: Arc<AppState>,
    lane: Lane,
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    let ticket = WorkTicket::acquire(state, lane)?;
    tokio::task::spawn_blocking(move || {
        let _ticket = ticket;
        work()
    })
    .await
    .map_err(|_| "Native worker did not finish; no automatic retry was started".to_owned())?
}

/// Async counterpart for native storage/provider work. The admitted task owns
/// its lane even when the original IPC future is canceled or the webview reloads.
pub async fn asynchronous<T>(
    state: Arc<AppState>,
    lane: Lane,
    work: impl std::future::Future<Output = Result<T, String>> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    let ticket = WorkTicket::acquire(state, lane)?;
    tokio::spawn(async move {
        let _ticket = ticket;
        work.await
    })
    .await
    .map_err(|_| "Native task did not finish; no automatic retry was started".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lanes_reject_without_queuing_and_all_native_work_blocks_shutdown() {
        let state = Arc::new(AppState::new());
        let read_a = WorkTicket::acquire(Arc::clone(&state), Lane::Read).unwrap();
        let read_b = WorkTicket::acquire(Arc::clone(&state), Lane::Read).unwrap();
        assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Read).is_err());
        let dialog = WorkTicket::acquire(Arc::clone(&state), Lane::Dialog).unwrap();
        assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Dialog).is_err());
        let mutation = WorkTicket::acquire(Arc::clone(&state), Lane::Mutation).unwrap();
        assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Mutation).is_err());
        assert_eq!(state.active_workers.load(Ordering::Acquire), 4);
        assert!(state.prevent_shutdown());
        drop((read_a, read_b, dialog, mutation));
        assert_eq!(state.active_workers.load(Ordering::Acquire), 0);
        assert!(!state.prevent_shutdown());
        assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Read).is_err());
    }

    #[test]
    fn shutdown_never_waits_on_contended_gui_visible_locks() {
        let state = AppState::new();
        {
            let _held = state.manager.lock().unwrap();
            assert!(state.prevent_shutdown());
        }
        {
            let _held = state.lifecycle.lock().unwrap();
            assert!(state.prevent_shutdown());
        }
        assert!(!state.prevent_shutdown());
    }

    #[test]
    fn canceled_callers_cannot_drop_the_state_or_release_an_active_lane() {
        let state = Arc::new(AppState::new());
        let weak = Arc::downgrade(&state);
        let ticket = WorkTicket::acquire(Arc::clone(&state), Lane::Dialog).unwrap();
        drop(state);
        let live = weak.upgrade().unwrap();
        assert!(live.prevent_shutdown());
        assert!(WorkTicket::acquire(Arc::clone(&live), Lane::Dialog).is_err());
        drop(ticket);
        assert_eq!(live.active_workers.load(Ordering::Acquire), 0);
    }

    #[test]
    fn unwind_releases_the_lane_and_shutdown_counter() {
        let state = Arc::new(AppState::new());
        let ticket = WorkTicket::acquire(Arc::clone(&state), Lane::Read).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ticket = ticket;
            panic!("test-only native worker unwind");
        }));
        assert!(result.is_err());
        assert_eq!(state.active_workers.load(Ordering::Acquire), 0);
        assert!(WorkTicket::acquire(state, Lane::Read).is_ok());
    }

    #[test]
    fn canceled_async_ipc_keeps_its_lane_until_the_owned_task_finishes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let state = Arc::new(AppState::new());
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let call = tokio::spawn(asynchronous(
                Arc::clone(&state),
                Lane::Mutation,
                async move {
                    started_tx.send(()).unwrap();
                    finish_rx.await.unwrap();
                    done_tx.send(()).unwrap();
                    Ok(())
                },
            ));
            started_rx.await.unwrap();
            call.abort();
            assert!(state.prevent_shutdown());
            assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Mutation).is_err());
            finish_tx.send(()).unwrap();
            done_rx.await.unwrap();
            // This current-thread runtime completes the admitted task and drops
            // its ticket before waking this receiver.
            assert_eq!(state.active_workers.load(Ordering::Acquire), 0);
            assert!(WorkTicket::acquire(state, Lane::Mutation).is_ok());
        });
    }

    #[test]
    fn refused_workspace_shutdown_can_reopen_native_admission() {
        let state = Arc::new(AppState::new());
        assert!(!state.prevent_shutdown());
        assert!(WorkTicket::acquire(Arc::clone(&state), Lane::Read).is_err());
        state.resume_after_failed_shutdown();
        assert!(WorkTicket::acquire(state, Lane::Read).is_ok());
    }
}
