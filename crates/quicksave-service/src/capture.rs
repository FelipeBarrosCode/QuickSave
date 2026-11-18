// SPDX-License-Identifier: GPL-3.0-only
//! Trusted Rust-only source receipt handoff. No webview implements these traits.

use crate::{boundary as dto, interfaces::ServiceTracking};
use anyhow::{ensure, Context, Result};
use quicksave_noland::capture_control::{
    CaptureScope, FrozenCaptureNode, NativeCaptureController, NativeFullScopeAuthority,
    PreparedCaptureReceipt,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub(super) struct CaptureController {
    tracking: Arc<dyn ServiceTracking>,
    work_id: String,
    app_id: String,
    metadata_identity: String,
    full_scope: Option<Arc<FullScopeOwner>>,
}

impl CaptureController {
    pub fn new(tracking: Arc<dyn ServiceTracking>, work: &Value) -> Result<Self> {
        ensure!(
            work["captureSource"]["stage"] == "awaiting_native_capture_receipt",
            "Source capture requires metadata-only frozen work"
        );
        let work_id = dto::id(work, "workId")?.to_owned();
        let full_scope = if work["captureSource"]["selectionKind"] == "full_scope" {
            let evidence = tracking.call("full_scope_evidence", &json!({"workId":work_id}))?;
            dto::bounded(&evidence, dto::MAX_WORK_BYTES)?;
            Some(Arc::new(FullScopeOwner {
                tracking: tracking.clone(),
                work_id: work_id.clone(),
                evidence,
            }))
        } else {
            None
        };
        Ok(Self {
            tracking,
            full_scope,
            work_id: dto::id(work, "workId")?.into(),
            app_id: work
                .pointer("/sourceIdentity/app_id")
                .and_then(Value::as_str)
                .unwrap_or(dto::id(work, "appId")?)
                .into(),
            metadata_identity: dto::text(
                &work["captureSource"]["metadataSelection"],
                "metadataIdentity",
                512,
            )?
            .into(),
        })
    }
}

struct FullScopeOwner {
    tracking: Arc<dyn ServiceTracking>,
    work_id: String,
    evidence: Value,
}
impl NativeFullScopeAuthority for FullScopeOwner {
    fn evidence(&self) -> Result<Value> {
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        let current = self
            .tracking
            .call("full_scope_evidence", &json!({"workId":self.work_id}))?;
        ensure!(
            current == self.evidence,
            "The original native full-snapshot work/omission authority changed"
        );
        Ok(())
    }
}

struct Receipt(Arc<PreparedCaptureReceipt>);
impl quicksave_tracking::NativeCaptureReceipt for Receipt {
    fn evidence(&self) -> Result<Value> {
        self.0.evidence()
    }
    fn revalidate(&self) -> Result<()> {
        self.0.revalidate()
    }
    fn immutable_prepared_capture(&self) -> bool {
        // Only constructed below after the actual source authenticates its
        // immutable prepared revision. Every use still calls revalidate().
        true
    }
}

impl NativeCaptureController for CaptureController {
    fn full_scope_authority(
        &self,
        scope: &CaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        ensure!(
            scope.work_id == self.work_id && scope.metadata_identity == self.metadata_identity,
            "Native full-scope work identity changed"
        );
        Ok(self
            .full_scope
            .clone()
            .map(|authority| authority as Arc<dyn NativeFullScopeAuthority>))
    }
    fn node_page(
        &self,
        scope: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FrozenCaptureNode>> {
        ensure!(
            scope.work_id == self.work_id && scope.metadata_identity == self.metadata_identity,
            "The source requested a different frozen tracker scope"
        );
        let page = self.tracking.call("prepared_node_listing", &json!({
            "workId":self.work_id,
            "cursor":format!("{}:{}:{offset}",self.work_id,self.metadata_identity),"limit":limit,
        }))?;
        let nodes = page["nodes"]
            .as_array()
            .context("Frozen native node page is unavailable")?;
        ensure!(
            nodes.len() <= limit && page["metadataIdentity"] == self.metadata_identity,
            "Native frozen node page changed scope or exceeded its bound"
        );
        nodes
            .iter()
            .map(|node| {
                let root = dto::id(node, "rootId")?;
                Ok(FrozenCaptureNode {
                    id: dto::id(node, "id")?.into(),
                    root_id: root.into(),
                    logical_root: quicksave_noland::native_capture_root_token(&self.app_id, root)?,
                    path: dto::text(node, "path", 32_768)?.into(),
                    kind: dto::text(node, "kind", 32)?.into(),
                    size: node["size"]
                        .as_u64()
                        .context("Native node size is missing")?,
                    link_target_hash: node
                        .get("linkTargetHash")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    stamp: serde_json::from_value(node["stamp"].clone())
                        .context("Complete native source stamp is missing")?,
                })
            })
            .collect()
    }
    fn reuse_epoch(&self, scope: &CaptureScope) -> Result<Option<String>> {
        ensure!(scope.work_id == self.work_id, "Native reuse scope changed");
        let result = self
            .tracking
            .call("capture_reuse_epoch", &json!({"workId":self.work_id}))?;
        Ok(result["epoch"].as_str().map(str::to_owned))
    }
    fn accept(&self, receipt: Arc<PreparedCaptureReceipt>) -> Result<()> {
        receipt.revalidate()?;
        self.tracking
            .accept_capture_receipt(&self.work_id, Arc::new(Receipt(receipt)))?;
        Ok(())
    }
    fn verify_publication(&self) -> Result<()> {
        self.tracking
            .call("verify_capture_receipt", &json!({"workId":self.work_id}))?;
        Ok(())
    }
}
