// SPDX-License-Identifier: GPL-3.0-only
// Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.
//! Trusted in-process bridge to actual source capture. This module intentionally
//! has no Deserialize implementation for controllers, callbacks or receipts.
//! Service code wraps PreparedCaptureReceipt in the tracker's receipt trait;
//! there is no dependency from this engine adapter back into the tracking engine.

use std::sync::Arc;

use anyhow::{Context, Result};
use noland_state_agent::{
    native_capture::{
        self, NativeCaptureNode, NativeCaptureReceipt, NativeCaptureScope, NativeCaptureSink,
    },
    native_host::NativeFileKey,
    StateAgent,
};
use noland_state_core::{AppId, StateError};
use serde_json::Value;
use uuid::Uuid;

pub use noland_state_agent::native_capture::{
    NativeCaptureNode as FrozenCaptureNode, NativeCaptureScope as CaptureScope,
    NativeCaptureStamp as CaptureStamp, NativeFullScopeBinding,
    NativeFullScopeBinding as FullScopeBinding,
};

/// Platform-neutral native Rust authority. There are no StateAgent, filesystem,
/// controller-implementation or Deserialize types in this contract, so the
/// Windows facade can provide the same boundary without depending on the agent.
///
/// Obtain evidence from the SAME Tracker owner/work ID that issued its original
/// full-scope and baseline grants. Revalidate their MACs, authorization, roots,
/// provider scope and unchanged frozen evidence; never wrap incoming UI JSON.
/// Later live changes after completed stable capture must remain dirty, not be
/// treated as if this older generation saved them.
pub trait NativeFullScopeAuthority: Send + Sync + 'static {
    fn evidence(&self) -> Result<Value>;
    fn revalidate(&self) -> Result<()>;
}

/// Free-function counterpart of CaptureScope::full_scope_from_evidence.
/// Both use the exact source bounded serde-JSON/BLAKE3 binding algorithm.
pub fn full_scope_from_evidence(evidence: &Value) -> Result<FullScopeBinding> {
    CaptureScope::full_scope_from_evidence(evidence)
        .context("bind original native full-scope evidence")
}

/// The service retains its exact tracker work/provider/root authority here.
/// Pages come from Tracker::prepared_node_listing, not webview file metadata.
pub trait NativeCaptureController: Send + Sync + 'static {
    fn node_page(
        &self,
        scope: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FrozenCaptureNode>>;
    /// An opaque native tracker-instance + uncertainty-generation proof. Never
    /// forward a webview field here. Default None keeps full content validation.
    fn reuse_epoch(&self, _scope: &CaptureScope) -> Result<Option<String>> {
        Ok(None)
    }
    /// Selected-node controllers may return None. A full scope MUST return its
    /// original native grant owner; the source refuses a missing owner, even for
    /// zero nodes. The default is absence, never successful full-scope authority.
    fn full_scope_authority(
        &self,
        _scope: &CaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        Ok(None)
    }
    fn accept(&self, receipt: Arc<PreparedCaptureReceipt>) -> Result<()>;
    /// Mandatory post-acceptance publication authority. The service implements
    /// this with Tracker::verify_capture_receipt. Call only at actual source
    /// COMMITTED/LATEST barriers, never at admission or a 4 Hz revocation poll.
    /// There is deliberately no default successful implementation.
    fn verify_publication(&self) -> Result<()>;
}

pub struct PreparedCaptureReceipt {
    source: Arc<NativeCaptureReceipt>,
}

impl PreparedCaptureReceipt {
    /// Only an actual source-owned Rust receipt can enter this wrapper. The
    /// normal acceptance/publication paths still call its real revalidation.
    pub(crate) fn from_source_receipt(source: Arc<NativeCaptureReceipt>) -> Self {
        Self { source }
    }

    pub fn evidence(&self) -> Result<Value> {
        self.source
            .evidence()
            .context("read actual source capture evidence")
    }

    /// Never calls the service publication guard. That guard may itself call
    /// Tracker::verify_capture_receipt, so doing so would recurse/deadlock.
    pub fn revalidate(&self) -> Result<()> {
        self.source
            .revalidate()
            .context("revalidate authenticated capture proof and native root identities")
    }
}

struct Sink {
    controller: Arc<dyn NativeCaptureController>,
}

struct SourceFullScopeAuthority {
    owner: Arc<dyn NativeFullScopeAuthority>,
}

impl native_capture::NativeFullScopeAuthority for SourceFullScopeAuthority {
    fn evidence(&self) -> noland_state_core::Result<Value> {
        self.owner.evidence().map_err(|_| {
            StateError::Conflict("original native full-scope evidence is unavailable".into())
        })
    }
    fn revalidate(&self) -> noland_state_core::Result<()> {
        self.owner.revalidate().map_err(|_| {
            StateError::Conflict(
                "original native full-scope/baseline authority was revoked or changed".into(),
            )
        })
    }
}

impl NativeCaptureSink for Sink {
    fn node_page(
        &self,
        scope: &NativeCaptureScope,
        offset: usize,
        limit: usize,
    ) -> noland_state_core::Result<Vec<NativeCaptureNode>> {
        self.controller
            .node_page(scope, offset, limit)
            .map_err(|_| {
                StateError::Conflict(
                    "trusted native frozen-node authority is unavailable or changed".into(),
                )
            })
    }

    fn reuse_epoch(&self, scope: &NativeCaptureScope) -> noland_state_core::Result<Option<String>> {
        self.controller.reuse_epoch(scope).map_err(|_| {
            StateError::Conflict("native capture reuse-generation proof is unavailable".into())
        })
    }

    fn full_scope_authority(
        &self,
        scope: &NativeCaptureScope,
    ) -> noland_state_core::Result<Option<Arc<dyn native_capture::NativeFullScopeAuthority>>> {
        let authority = self.controller.full_scope_authority(scope).map_err(|_| {
            StateError::Conflict("trusted full-scope tracker authority is unavailable".into())
        })?;
        Ok(authority.map(|owner| {
            Arc::new(SourceFullScopeAuthority { owner })
                as Arc<dyn native_capture::NativeFullScopeAuthority>
        }))
    }

    fn accept(&self, receipt: Arc<NativeCaptureReceipt>) -> noland_state_core::Result<()> {
        self.controller
            .accept(Arc::new(PreparedCaptureReceipt { source: receipt }))
            .map_err(|_| {
                StateError::Conflict(
                    "tracker refused the actual source capture receipt before publication".into(),
                )
            })
    }
}

/// Parent NativeEngine calls this before StartBackup, then persists these exact
/// returned keys and `scope` in NativeSelection. No local_files reconciliation,
/// tracker prehash, provider lookup or vault lookup occurs per node/chunk.
pub fn install(
    agent: &StateAgent,
    operation: Uuid,
    app: &AppId,
    scope: CaptureScope,
    controller: Arc<dyn NativeCaptureController>,
) -> Result<Vec<NativeFileKey>> {
    native_capture::install(agent, operation, app, scope, Arc::new(Sink { controller }))
        .context("install exact native source capture coordinator")
}
