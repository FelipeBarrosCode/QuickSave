// SPDX-License-Identifier: GPL-3.0-only
//! Synchronous, thread-confined metadata verification. No cross-request cache,
//! native authority capability, vault nonce cache, or publication shortcut.

use crate::{normalize_scope, Inner, WorkspaceReadSnapshot, WorkspaceStore};
use anyhow::{ensure, Result};
use serde_json::Value;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
};

const MAX_DEPTH: usize = 8;

#[derive(Debug)]
pub struct MetadataProjectionChanged;
impl std::fmt::Display for MetadataProjectionChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("workspace changed during metadata projection; discard the result and retry a fresh metadata request")
    }
}
impl std::error::Error for MetadataProjectionChanged {}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Frame>>> = const { RefCell::new(None) };
}

struct Frame {
    snapshot: WorkspaceReadSnapshot,
    previous: Option<Rc<Frame>>,
    depth: usize,
    invalidated: Cell<bool>,
}

// Rc deliberately prevents moving this guard/frame to another thread. The
// caller never receives either one, and returned futures inherit no frame.
struct Installed {
    frame: Rc<Frame>,
}

impl Drop for Installed {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            *current.borrow_mut() = self.frame.previous.clone();
        });
    }
}

fn matches(frame: &Frame, inner: &Arc<Inner>) -> bool {
    Arc::ptr_eq(&frame.snapshot.store.inner, inner)
}

pub(crate) fn invalidate(store: &WorkspaceStore) {
    CURRENT.with(|current| {
        let current = current.borrow();
        let mut frame = current.as_ref();
        while let Some(found) = frame {
            if matches(found, &store.inner) {
                found.invalidated.set(true);
            }
            frame = found.previous.as_ref();
        }
    });
}

pub(crate) fn verify(
    store: &WorkspaceStore,
    scope: &Value,
    signature: &Value,
) -> Option<Result<bool>> {
    let (kind, _) = match normalize_scope(scope) {
        Ok(scope) => scope,
        Err(error) => return Some(Err(error)),
    };
    // Only the grant kinds consumed by software/file-listing DTO validation.
    // Upload/restore/delete/receipt/baseline/sidecar/publication kinds stay fresh,
    // even if accidentally requested inside a metadata projection.
    if !matches!(
        kind.as_str(),
        "tracking" | "autosave" | "app_tracking_policy" | "bundle_discovery"
    ) {
        return None;
    }
    let frame = CURRENT.with(|current| {
        let current = current.borrow();
        let mut frame = current.as_ref();
        while let Some(found) = frame {
            if matches(found, &store.inner) {
                return (!found.invalidated.get()).then(|| Rc::clone(found));
            }
            frame = found.previous.as_ref();
        }
        None
    })?;
    // The original verifier still authenticates the actual HMAC and reads the
    // current persistent vault nonce on EVERY call. A snapshot creates no key.
    Some(frame.snapshot.with_secret_access(|vault| {
        store.verify_bound(vault, &frame.snapshot.document, scope, signature)
    }))
}

impl WorkspaceStore {
    /// Wrap ONLY a synchronous software/file-listing metadata projection. Never
    /// wrap prepares, capture receipts, publication/write guards or any worker.
    ///
    /// Existing TrackingStore::verify_grant calls on this thread and this exact
    /// store Inner share one state read; other threads/stores do not inherit it.
    /// All writes, provider operations and non-metadata grant kinds stay fresh.
    /// After the closure, a fresh decoded-document equality check is mandatory.
    /// A change discards the result with an error; the closure is NOT replayed.
    /// A caller may retry the whole metadata request a bounded number of times.
    pub fn with_metadata_verification_snapshot<T>(
        &self,
        projection: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let previous = CURRENT.with(|current| current.borrow().clone());
        let depth = previous.as_ref().map_or(1, |frame| frame.depth + 1);
        ensure!(
            depth <= MAX_DEPTH,
            "metadata verification nesting exceeds its bound"
        );
        let frame = Rc::new(Frame {
            snapshot: self.read_snapshot()?,
            previous,
            depth,
            invalidated: Cell::new(false),
        });
        CURRENT.with(|current| *current.borrow_mut() = Some(Rc::clone(&frame)));
        let installed = Installed {
            frame: Rc::clone(&frame),
        };
        let result = projection();
        drop(installed); // Restore before the mandatory, always-fresh end read.
        let current = frame.snapshot.is_current()?;
        if !current || frame.invalidated.get() {
            return Err(MetadataProjectionChanged.into());
        }
        result
    }
}
