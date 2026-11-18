// SPDX-License-Identifier: GPL-3.0-only
//! A trusted Rust boundary to actual source-engine capture/publication evidence.
//! JSON received from IPC must NEVER implement or instantiate this authority.

use crate::{bundle, expected_files, model, scan, Pending, Tracker};
use anyhow::{ensure, Context, Result};
use quicksave_platform::{FileStamp, SafeRoot};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{atomic::Ordering, Arc},
};

const MAX_COMPLETION_BINDING_BYTES: u64 = 128 * 1024;

pub(crate) fn compact_source_auth(evidence: &Value) -> Result<Value> {
    let source = &evidence["sourceExpectedManifestAuth"];
    ensure!(
        source.as_object().is_some_and(|object| !object.is_empty()),
        "actual compact source expected-manifest authentication is missing"
    );
    model::bounded_serialized(source, MAX_COMPLETION_BINDING_BYTES)?;
    Ok(source.clone())
}

fn verify_receipt_sidecar_reference(
    shared: &crate::Shared,
    record: &model::TrackedSoftware,
    sealed: &Value,
) -> Result<()> {
    let reference = &sealed["reference"];
    let name = reference["name"]
        .as_str()
        .context("accepted receipt sidecar name is missing")?;
    model::validate_relative(name)?;
    let hash = reference["hash"]
        .as_str()
        .context("accepted receipt sidecar hash is missing")?;
    let scope = json!({
        "version":1,"tracking":record.tracking_scope(),"captureScope":sealed["scope"],
        "name":name,"hash":hash,
    });
    ensure!(
        !name.contains('/')
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            && reference["scope"] == scope
            && shared.store.verify_grant(
                "tracking_capture_receipt_sidecar",
                &scope,
                &reference["grant"]
            )?,
        "accepted receipt sidecar reference/hash/MAC is invalid or revoked"
    );
    Ok(())
}

/// Owned adapter to a *real prepared native source capture*. The parent keeps
/// its source handles, authenticated expected manifest and original publication
/// guard alive here. Methods must not reenter Tracker or write cloud data.
///
/// `evidence()` is called once. Return:
/// `{workId,metadataIdentity,sourceSnapshotId,sourceExpectedManifestAuth,nodes}`
/// where each node is `{id,rootId,path,kind,size,stamp,fileHash? /
/// linkTargetHash?}`. Hashes describe the actual prepared manifest, not a tracker
/// prediction. `stamp` is the source's verified complete FileStamp, including
/// ctime/change time. `revalidate()` must call the real source publication guard.
pub trait NativeCaptureReceipt: Send + Sync + 'static {
    fn evidence(&self) -> Result<Value>;
    fn revalidate(&self) -> Result<()>;
    /// Override ONLY for a real source receipt whose completed stable capture,
    /// prepared manifest and immutable captured bytes/ciphertext remain
    /// authenticated independently of later live-file changes. `revalidate`
    /// must still verify that immutable preparation and native root authority.
    /// This native-only capability is never read from JSON/plaintext settings.
    fn immutable_prepared_capture(&self) -> bool {
        false
    }
    /// Recovery completion ONLY. Override solely when the actual source owner
    /// verifies a durable authenticated COMMITTED manifest bound to evidence().
    /// A database status/completed JSON or captured/prepared flag is not proof.
    fn verify_committed(&self) -> Result<()> {
        anyhow::bail!("actual authenticated source COMMITTED receipt is required")
    }
}

pub(crate) fn expected_metadata(
    selected: &BTreeSet<String>,
    captured: &model::Snapshot,
) -> Result<Value> {
    let mut nodes = Vec::with_capacity(selected.len());
    for id in selected {
        let Some(node) = captured.nodes.get(id) else {
            continue;
        };
        nodes.push(indexed_metadata_node(id, node)?);
    }
    Ok(json!(nodes))
}

/// Shared wire shape for prepared capture and immutable metadata-index pages.
/// Existing file-content hashes are deliberately NOT projected into this DTO.
pub(crate) fn indexed_metadata_node(id: &str, node: &model::Node) -> Result<Value> {
    ensure!(
        node.stamp.is_some() && node.metadata.is_some(),
        "selected node lacks native metadata"
    );
    Ok(json!({
        "id": id, "rootId": node.root_id, "path": node.path,
        "kind": node.kind(), "size": node.size, "stamp": node.stamp,
        "metadata": node.metadata,
        "linkTargetHash": node.link.as_ref().map(|link| blake3::hash(link.target.as_bytes()).to_hex().to_string()),
    }))
}

pub(crate) fn validate_metadata_work(request: &Value, pending: &Pending) -> Result<()> {
    ensure!(
        request["captureSource"]["stage"] == "awaiting_native_capture_receipt"
            && request["captureSource"].get("expectedFiles").is_none(),
        "unprepared metadata scope cannot carry fabricated content proof"
    );
    let ids = request["fileIds"]
        .as_array()
        .context("queued exact node IDs are missing")?;
    let count = if pending.full_scope {
        pending.captured.nodes.len()
    } else {
        pending.selected.len()
    };
    ensure!(
        ids.len() == count
            && request["captureSource"]["metadataSelection"]
                == json!({
                    "workId": pending.work_id, "metadataIdentity": pending.frozen_metadata_identity,
                    "nodeCount": count, "source": "tracker_native_index",
                }),
        "queued metadata selection changed"
    );
    let selected: Box<dyn Iterator<Item = &String> + '_> = if pending.full_scope {
        Box::new(pending.captured.nodes.keys())
    } else {
        Box::new(pending.selected.iter())
    };
    for (id, given) in selected.zip(ids) {
        ensure!(
            given.as_str() == Some(id.as_str()),
            "queued metadata ID changed"
        );
    }
    Ok(())
}

pub(crate) fn verify_pending_receipt(
    shared: &crate::Shared,
    app: &crate::Runtime,
    pending: &Pending,
) -> Result<()> {
    ensure!(
        !pending.awaiting_receipt,
        "actual source capture receipt has not been accepted"
    );
    let receipt = pending
        .receipt
        .as_ref()
        .context("source capture receipt owner is unavailable")?;
    let sealed = pending
        .receipt_evidence
        .as_ref()
        .context("source capture receipt seal is missing")?;
    ensure!(
        pending.scope == app.record.autosave_scope()
            && shared.store.verify_grant(
                "tracking_capture_receipt",
                &sealed["scope"],
                &sealed["grant"]
            )?,
        "capture receipt scope/provider/authentication changed"
    );
    ensure!(
        sealed["scope"]["workId"] == pending.work_id
            && sealed["scope"]["generation"] == pending.generation
            && sealed["scope"]["metadataIdentity"] == pending.frozen_metadata_identity
            && sealed["scope"]["trackingScopeHash"]
                == bundle::digest(&app.record.tracking_scope())?
            && sealed["scope"]["immutablePreparedCapture"] == pending.immutable_prepared_capture
            && sealed["scope"]["unknownGeneration"] == pending.unknown_generation,
        "capture receipt no longer binds the original native scope"
    );
    if let Some(proof) = &pending.full_scope_proof {
        ensure!(
            shared
                .store
                .verify_grant("tracking_full_capture", &proof["scope"], &proof["grant"])?,
            "full-root omission snapshot authority is invalid or revoked"
        );
    }
    ensure!(
        pending.immutable_prepared_capture
            || (app.event_epoch.load(Ordering::Acquire) == pending.event_epoch
                && app.record.unknown_generation == pending.unknown_generation
                && shared.uncertainty_epoch.load(Ordering::Acquire) == pending.uncertainty_epoch),
        "source changed or observation became uncertain after native capture"
    );
    if let Some(enrollment) = &app.record.auto_enrollment {
        enrollment.revalidate_native(shared.store.as_ref(), &shared.policy)?;
    }
    for root in &app.record.roots {
        scan::PinnedRoot::open(root)?.check()?;
    }
    for pin in &pending.source_pins {
        pin.check()?;
    }
    receipt
        .revalidate()
        .context("revalidate actual native source publication receipt")
}

impl Tracker {
    /// Native-only expansion of a previously frozen whole-scope work item.
    /// Never accepts a caller-supplied proof, infers permission from an empty
    /// list, reads payload bytes, changes grants, or mutates the baseline.
    pub fn full_scope_evidence(&self, work_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown frozen full-scope work")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "full-scope tracking authority was revoked"
        );
        let automatic = app.pending.as_ref().unwrap().automatic;
        ensure!(
            !automatic || self.shared.validate_autosave(app)?,
            "automatic full-scope authority was revoked"
        );
        let pending = app.pending.as_ref().unwrap();
        ensure!(
            pending.full_scope && pending.scope == app.record.autosave_scope(),
            "selected-node or changed-provider work is not full-scope authority"
        );
        let proof = pending
            .full_scope_proof
            .as_ref()
            .context("frozen full-scope proof is missing")?;
        ensure!(
            self.shared.store.verify_grant(
                "tracking_full_capture",
                &proof["scope"],
                &proof["grant"]
            )? && proof["scope"]["workId"] == pending.work_id
                && proof["scope"]["generation"] == pending.generation
                && proof["scope"]["metadataIdentity"] == pending.frozen_metadata_identity
                && proof["scope"]["trackingScopeHash"]
                    == bundle::digest(&app.record.tracking_scope())?
                && proof["scope"]["expectedNodeIdsHash"]
                    == bundle::digest(&json!(pending.captured.nodes.keys().collect::<Vec<_>>()))?
                && proof["scope"]["deletedNodeIdsHash"] == bundle::digest(&json!(pending.deleted))?,
            "frozen full-scope proof no longer matches work/root/omission authority"
        );
        let authorization = &pending.frozen_authorization;
        ensure!(
            authorization["trackingScope"] == app.record.tracking_scope()
                && self.shared.store.verify_grant(
                    "tracking",
                    &authorization["trackingScope"],
                    &authorization["trackingGrant"]
                )?,
            "original native tracking grant is invalid or revoked"
        );
        if automatic {
            ensure!(
                authorization["autosaveScope"] == pending.scope
                    && self.shared.store.verify_grant(
                        "autosave",
                        &authorization["autosaveScope"],
                        &authorization["autosaveGrant"]
                    )?,
                "original automatic-capture grant is invalid or revoked"
            );
        }
        for pin in &pending.source_pins {
            pin.check()?;
        }
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.revalidate_native(self.shared.store.as_ref(), &self.shared.policy)?;
        }
        let baseline_identity = pending
            .frozen_baseline
            .as_ref()
            .map(|snapshot| snapshot.identity())
            .transpose()?;
        let baseline_kind = if pending.frozen_baseline.is_none() {
            "none"
        } else if pending.frozen_baseline_full_scope {
            "full"
        } else {
            "partial"
        };
        ensure!(
            proof["scope"]["baselineIdentity"] == json!(baseline_identity)
                && proof["scope"]["baselineKind"] == baseline_kind,
            "frozen baseline identity/completeness changed"
        );
        match (
            &pending.frozen_baseline_reference,
            &pending.frozen_baseline_scope,
        ) {
            (Some(reference), Some(scope)) => ensure!(
                self.shared
                    .store
                    .verify_grant("tracking_baseline", scope, &reference.grant)?,
                "original confirmed baseline reference is invalid or revoked"
            ),
            (None, None) => ensure!(
                pending.frozen_baseline.is_none(),
                "a baseline without an authenticated reference cannot authorize omissions"
            ),
            _ => anyhow::bail!("incomplete frozen baseline reference"),
        }
        ensure!(
            app.record
                .roots
                .iter()
                .filter(|root| root.allowed_files.is_none())
                .all(|root| pending.captured.root_metadata.contains_key(&root.id)
                    && pending.captured.root_stamps.contains_key(&root.id)),
            "full-scope evidence lacks actual native root metadata/stamps"
        );
        let mut deleted = Vec::with_capacity(pending.deleted.len());
        for id in &pending.deleted {
            ensure!(
                !pending.captured.nodes.contains_key(id),
                "an omitted node exists in frozen current scope"
            );
            let previous = pending
                .frozen_baseline
                .as_ref()
                .and_then(|baseline| baseline.nodes.get(id))
                .context("omitted node was not in the authenticated frozen baseline")?;
            let root = app
                .record
                .roots
                .iter()
                .find(|root| root.id == previous.root_id)
                .context("omitted node's root is outside the original approved scope")?;
            ensure!(
                root.allowed_files
                    .as_ref()
                    .is_none_or(|leaves| leaves.contains(&previous.path))
                    && previous.id() == *id,
                "omitted node exceeds original root/file authority"
            );
            deleted.push(json!({
                "id": id, "rootId": previous.root_id, "path": previous.path,
                "kind": previous.kind(), "size": previous.size, "stamp": previous.stamp,
                "metadata": previous.metadata, "fileHash": previous.hash,
                "linkTargetHash": previous.link.as_ref().map(|link| blake3::hash(link.target.as_bytes()).to_hex().to_string()),
            }));
        }
        let value = json!({
            "version": 1, "workId": pending.work_id, "softwareId": app.record.id,
            "sourceIdentity": app.record.source_identity, "providerId": app.record.provider_id,
            "generation": pending.generation, "metadataIdentity": pending.frozen_metadata_identity,
            "fullScope": true, "completeFileList": true, "keepsVersionHistory": true,
            "coverageScope": "approved_evidenced_roots_only",
            "coverage": app.record.bundle_index_source.as_ref().map(|source| &source.coverage),
            "expectedFullScope": proof, "authorization": authorization,
            "roots": app.record.roots.iter().map(scan::root_request).collect::<Vec<_>>(),
            "rootMetadata": pending.captured.root_metadata, "rootStamps": pending.captured.root_stamps,
            "deletedFileIds": pending.deleted, "deletedNodes": deleted,
            "baseline": {
                "kind": baseline_kind, "snapshotIdentity": baseline_identity,
                "reference": pending.frozen_baseline_reference, "scope": pending.frozen_baseline_scope,
            },
            "autoEnrollment": app.record.auto_enrollment.as_ref().map(|enrollment| json!({
                "policyScope": enrollment.policy_scope, "policyGrant": enrollment.policy_grant,
                "discoveryScope": enrollment.discovery_scope, "discoveryGrant": enrollment.discovery_grant,
            })),
        });
        model::bounded_serialized(&value, 512 * 1024 * 1024)?;
        Ok(value)
    }

    /// One call per native capture, never per chunk or UI poll. This opaque
    /// partition tag is NOT a hash/clean/durability proof. The source must still
    /// authenticate its own exact parent chunks, full native file stamps and
    /// prepared manifest before reusing any content.
    pub fn capture_reuse_epoch(&self, work_id: &str) -> Result<Option<String>> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown native capture scope")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "native capture authority was revoked"
        );
        let automatic = app.pending.as_ref().unwrap().automatic;
        ensure!(
            !automatic || self.shared.validate_autosave(app)?,
            "native automatic capture permission was revoked"
        );
        let pending = app.pending.as_ref().unwrap();
        if !app.watch_ok
            || app.record.unknown_generation != pending.unknown_generation
            || self.shared.watch_reset_requested.load(Ordering::Acquire)
                > self.shared.watch_reset_confirmed.load(Ordering::Acquire)
            || pending.scope != app.record.autosave_scope()
            || app.event_epoch.load(Ordering::Acquire) != pending.event_epoch
            || self.shared.uncertainty_epoch.load(Ordering::Acquire) != pending.uncertainty_epoch
            || app
                .current
                .as_ref()
                .is_none_or(|current| !current.same_metadata(&pending.captured))
        {
            return Ok(None);
        }
        for pin in &pending.source_pins {
            pin.check()?;
        }
        // First captures can obtain a fresh epoch even though content hashes
        // are absent/force_hash is set. A fresh tracker-instance nonce ensures
        // no proof from a previous restart can match that epoch.
        if !scan::qualified_change_stamps(&app.record.roots, &pending.captured).unwrap_or(false) {
            return Ok(None);
        }
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.revalidate_native(self.shared.store.as_ref(), &self.shared.policy)?;
        }
        if app.event_epoch.load(Ordering::Acquire) != pending.event_epoch
            || self.shared.uncertainty_epoch.load(Ordering::Acquire) != pending.uncertainty_epoch
            || self.shared.watch_reset_requested.load(Ordering::Acquire)
                > self.shared.watch_reset_confirmed.load(Ordering::Acquire)
        {
            return Ok(None);
        }
        self.shared.check_running()?;
        Ok(Some(format!(
            "native-reuse-{}",
            bundle::digest(&json!({
                "version": 1, "instance": self.shared.instance_nonce,
                "uncertaintyEpoch": pending.uncertainty_epoch,
                "unknownGeneration": pending.unknown_generation,
                "scope": pending.scope,
                "trackingGrantHash": bundle::digest(&app.record.tracking_grant)?,
                "autosaveGrantHash": if automatic {
                    app.record.autosave_grant.as_ref().map(bundle::digest).transpose()?
                } else { None },
            }))?
        )))
    }

    /// Native-only bounded access to the frozen scope. The work queue carries a
    /// compact token, not 250k duplicated JSON stamps on every event/poll.
    pub fn prepared_node_listing(
        &self,
        work_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Value> {
        self.shared.check_running()?;
        ensure!(
            limit > 0 && limit <= model::MAX_PAGE,
            "prepared node page limit must be 1..=500"
        );
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown prepared native scope")?;
        self.shared.validate_tracking(app)?;
        ensure!(!app.scheduler.paused, "prepared native scope was revoked");
        let pending = app.pending.as_ref().unwrap();
        let prefix = format!("{}:{}", pending.work_id, pending.frozen_metadata_identity);
        let offset = if let Some(cursor) = cursor {
            ensure!(cursor.len() <= 1024, "oversized prepared scope cursor");
            let (given, offset) = cursor
                .rsplit_once(':')
                .context("invalid prepared scope cursor")?;
            ensure!(given == prefix, "prepared native scope cursor changed");
            offset
                .parse::<usize>()
                .context("invalid prepared node page offset")?
        } else {
            0
        };
        let mut selection = BTreeSet::new();
        let mut count = 0_usize;
        let mut more = false;
        for id in pending
            .selected
            .iter()
            .filter(|id| pending.captured.nodes.contains_key(*id))
        {
            if count >= offset {
                if selection.len() == limit {
                    more = true;
                    break;
                }
                selection.insert(id.clone());
            }
            count += 1;
        }
        ensure!(
            offset <= count,
            "prepared node cursor exceeds frozen selection"
        );
        Ok(json!({
            "nodes": expected_metadata(&selection, &pending.captured)?,
            "nextCursor": if more { Some(format!("{prefix}:{}", offset + limit)) } else { None },
            "metadataIdentity": pending.frozen_metadata_identity,
        }))
    }

    pub fn accept_capture_receipt(
        &self,
        work_id: &str,
        receipt: Arc<dyn NativeCaptureReceipt>,
    ) -> Result<Value> {
        self.shared.check_running()?;
        // No source bytes are read by Tracker here. The callback must own the
        // original source engine's stable capture and exact manifest proof.
        receipt.revalidate()?;
        let evidence = receipt.evidence()?;
        let source_auth = compact_source_auth(&evidence)?;
        let immutable_prepared_capture = receipt.immutable_prepared_capture();
        model::bounded_serialized(&evidence, 512 * 1024 * 1024)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown native capture work")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "native capture tracking grant was revoked"
        );
        let pending = app.pending.as_ref().unwrap();
        ensure!(
            pending.awaiting_receipt && pending.receipt.is_none(),
            "capture receipt is already frozen for this work"
        );
        ensure!(
            pending.scope == app.record.autosave_scope(),
            "source capture selection/provider changed"
        );
        ensure!(
            app.current
                .as_ref()
                .is_some_and(|current| current.same_metadata(&pending.captured)),
            "indexed native metadata changed while the source prepared its initial frozen capture"
        );
        ensure!(
            evidence["workId"] == pending.work_id
                && evidence["metadataIdentity"] == pending.frozen_metadata_identity,
            "source receipt is for another frozen native scope"
        );
        let source_id = evidence["sourceSnapshotId"]
            .as_str()
            .context("source capture identity is missing")?;
        model::validate_id(source_id)?;
        ensure!(
            evidence["sourceExpectedManifestAuth"]
                .as_object()
                .is_some_and(|object| !object.is_empty()),
            "actual source expected-manifest authentication is missing"
        );
        let nodes = evidence["nodes"]
            .as_array()
            .context("actual prepared source nodes are missing")?;
        let count = pending
            .selected
            .iter()
            .filter(|id| pending.captured.nodes.contains_key(*id))
            .count();
        ensure!(
            nodes.len() == count,
            "actual prepared source added/omitted selected nodes"
        );
        let mut captured = (*pending.captured).clone();
        captured.content_captured = true;
        let mut seen = BTreeSet::new();
        for actual in nodes {
            let id = actual["id"]
                .as_str()
                .context("source capture node has no logical ID")?;
            ensure!(
                pending.selected.contains(id) && seen.insert(id.to_owned()),
                "source receipt node is duplicate or outside exact selected scope"
            );
            let node = captured
                .nodes
                .get_mut(id)
                .context("source prepared a deleted/unselected node")?;
            let stamp: FileStamp = serde_json::from_value(actual["stamp"].clone())
                .context("source node lacks its verified complete native file stamp")?;
            ensure!(
                actual["rootId"] == node.root_id
                    && actual["path"] == node.path
                    && actual["kind"] == node.kind()
                    && actual["size"] == node.size
                    && node.stamp.as_ref() == Some(&stamp),
                "source receipt identity/path/kind/size/stamp differs from frozen native metadata"
            );
            if let Some(link) = &node.link {
                ensure!(
                    actual["linkTargetHash"]
                        == blake3::hash(link.target.as_bytes()).to_hex().to_string(),
                    "source prepared a different confined link target"
                );
            } else if !node.directory {
                let hash = actual["fileHash"]
                    .as_str()
                    .context("actual prepared regular-file hash is missing")?;
                let hash = hash.strip_prefix("blake3:").unwrap_or(hash);
                ensure!(
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "actual source content hash is invalid/noncanonical"
                );
                node.hash = Some(hash.into());
            }
        }
        if pending.full_scope {
            captured.validate_content(&app.record.roots)?;
        } else {
            captured.validate(&app.record.roots)?;
        }
        ensure!(
            app.event_epoch.load(Ordering::Acquire) == pending.event_epoch
                && app.record.unknown_generation == pending.unknown_generation
                && self.shared.uncertainty_epoch.load(Ordering::Acquire)
                    == pending.uncertainty_epoch,
            "source events/uncertainty changed while the engine prepared capture"
        );
        for pin in &pending.source_pins {
            pin.check()?;
        }
        receipt.revalidate()?;
        let files = expected_files(&pending.selected, &captured)?;
        let scope = json!({
            "version": 1, "workId": pending.work_id, "generation": pending.generation,
            "softwareId": app.record.id, "providerId": app.record.provider_id,
            "trackingScopeHash": bundle::digest(&app.record.tracking_scope())?,
            "metadataIdentity": pending.frozen_metadata_identity,
            "unknownGeneration": pending.unknown_generation,
            "capturedSnapshotIdentity": captured.identity()?,
            "expectedFilesHash": bundle::digest(&files)?,
            "sourceSnapshotId": source_id,
            "sourceExpectedManifestAuthHash": bundle::digest(&evidence["sourceExpectedManifestAuth"])?,
            "fullScopeProofHash": bundle::digest(&json!(pending.full_scope_proof))?,
            "immutablePreparedCapture": immutable_prepared_capture,
        });
        let grant = self
            .shared
            .store
            .issue_grant("tracking_capture_receipt", &scope)?;
        ensure!(
            self.shared
                .store
                .verify_grant("tracking_capture_receipt", &scope, &grant)?,
            "native source capture receipt could not be authenticated"
        );
        let reference = persist_receipt(
            &evidence,
            &scope,
            &app.record,
            self.shared.store.as_ref(),
            &self.shared.policy,
        )?;
        let sealed = json!({"scope": scope, "grant": grant, "reference": reference});
        let mut record = app.record.clone();
        record.capture_receipt = Some(sealed.clone());
        let accepted_frame = crate::trackingresume::persist_accepted(
            &self.shared,
            app,
            &mut record,
            &sealed,
            &source_auth,
        )?;
        record.bundle_index_source = Some(bundle::write_index(
            &captured,
            &record,
            self.shared.store.as_ref(),
            &self.shared.policy,
        )?);
        record.tracked = true;
        self.shared
            .store
            .save_record(&serde_json::to_value(&record)?)?;
        crate::trackingresume::readback_reference(self.shared.store.as_ref(), &record)?;
        let pending = app.pending.as_mut().unwrap();
        pending.captured = Arc::new(captured);
        pending.receipt = Some(receipt);
        pending.receipt_evidence = Some(sealed.clone());
        pending.source_expected_manifest_auth = Some(source_auth);
        pending.awaiting_receipt = false;
        pending.immutable_prepared_capture = immutable_prepared_capture;
        pending.original_frame = accepted_frame;
        app.record = record;
        if let Some(reference) = &app.record.pending_work {
            self.shared
                .frozen_frames
                .lock()
                .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
                .install(&app.record.id, reference)?;
        }
        // Retain the actual source index, not a separately recomputed hash pass.
        let current = app.pending.as_ref().unwrap().captured.clone();
        self.shared.replace_current(app, current)?;
        Ok(json!({
            "workId": work_id, "generation": app.pending.as_ref().unwrap().generation,
            "captureSource": {
                "stage": "native_capture_receipt_accepted",
                "snapshotIdentity": app.pending.as_ref().unwrap().frozen_metadata_identity,
                "expectedFiles": files, "captureReceipt": sealed,
                "sourceExpectedManifestAuth": evidence["sourceExpectedManifestAuth"],
                "expectedFullScope": app.pending.as_ref().unwrap().full_scope_proof,
                "consistency": "validated_stable_files_not_application_atomic",
                "keepsLocalCopy": true,
            }
        }))
    }

    /// Call in the actual native engine publication guard, not after commit.
    pub fn verify_capture_receipt(&self, work_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown capture receipt work")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "tracking authority was revoked before publication"
        );
        let automatic = app.pending.as_ref().unwrap().automatic;
        ensure!(
            !automatic || self.shared.validate_autosave(app)?,
            "automatic capture authority was revoked before publication"
        );
        let pending = app.pending.as_ref().unwrap();
        verify_pending_receipt(&self.shared, app, pending)?;
        let provider = app
            .record
            .provider_id
            .as_deref()
            .context("capture provider is missing")?;
        ensure!(
            self.shared.store.provider_writable(provider)?,
            "capture provider is no longer writable"
        );
        Ok(
            json!({"verified": true, "workId": work_id, "generation": pending.generation,
            "sourceExpectedManifestAuthPreserved": true}),
        )
    }

    /// Native-only finalization binding, BEFORE complete_upload consumes
    /// Pending. Not a COMMITTED verdict: the source engine must verify its real
    /// post-COMMITTED manifest. Never calls evidence() or reads a large sidecar.
    pub fn capture_completion_binding(&self, work_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        model::validate_id(work_id)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .values_mut()
            .find(|app| {
                app.pending
                    .as_ref()
                    .is_some_and(|pending| pending.work_id == work_id)
            })
            .context("unknown actual capture completion work")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused,
            "capture completion tracking authority was revoked"
        );
        let automatic = app.pending.as_ref().unwrap().automatic;
        ensure!(
            !automatic || self.shared.validate_autosave(app)?,
            "capture completion automatic authority was revoked"
        );
        let pending = app.pending.as_ref().unwrap();
        verify_pending_receipt(&self.shared, app, pending)?;
        let provider = app
            .record
            .provider_id
            .as_deref()
            .context("capture completion provider is missing")?;
        ensure!(
            self.shared.store.provider_writable(provider)?,
            "capture completion provider is no longer writable"
        );
        let sealed = pending
            .receipt_evidence
            .as_ref()
            .context("accepted capture receipt is missing")?;
        let source = pending.source_expected_manifest_auth.as_ref().context(
            "accepted compact source envelope is unavailable; no JSON/status fallback is permitted",
        )?;
        model::bounded_serialized(source, MAX_COMPLETION_BINDING_BYTES)?;
        ensure!(
            source.as_object().is_some_and(|object| !object.is_empty())
                && sealed["scope"]["sourceExpectedManifestAuthHash"] == bundle::digest(source)?
                && sealed["scope"]["softwareId"] == app.record.id
                && sealed["scope"]["providerId"] == provider,
            "accepted source envelope/completion binding differs from its authenticated receipt"
        );
        verify_receipt_sidecar_reference(&self.shared, &app.record, sealed)?;
        let canonical = app
            .record
            .source_identity
            .as_ref()
            .and_then(|identity| identity["app_id"].as_str())
            .context("canonical source app identity is required for capture completion")?;
        let instance = app
            .record
            .app_id
            .as_deref()
            .context("source software instance ID is missing")?;
        model::validate_id(canonical)?;
        model::validate_id(instance)?;
        let binding = json!({
            "softwareId":app.record.id,"appId":canonical,"softwareInstanceId":instance,
            "providerId":provider,"workId":pending.work_id,"generation":pending.generation,
            "metadataIdentity":pending.frozen_metadata_identity,
            "captureReceipt":{"scope":sealed["scope"],"grant":sealed["grant"]},
            "sourceExpectedManifestAuth":source,
        });
        model::bounded_serialized(&binding, MAX_COMPLETION_BINDING_BYTES)?;
        self.shared.check_running()?;
        Ok(binding)
    }
}

pub(crate) fn persist_receipt(
    evidence: &Value,
    scope: &Value,
    record: &model::TrackedSoftware,
    store: &dyn crate::TrackingStore,
    policy: &model::TrackingPolicy,
) -> Result<Value> {
    quicksave_platform::ensure_private_directory(&policy.bundle_dir())?;
    let safe = SafeRoot::open(&policy.bundle_dir())?;
    let name = format!("receipt-{}.json", uuid::Uuid::new_v4());
    let hash = bundle::write_local_json_bounded(&safe, &name, evidence, 512 * 1024 * 1024)?;
    let sidecar_scope = json!({
        "version": 1, "tracking": record.tracking_scope(),
        "captureScope": scope, "name": name, "hash": hash,
    });
    let grant = store.issue_grant("tracking_capture_receipt_sidecar", &sidecar_scope)?;
    ensure!(
        store.verify_grant("tracking_capture_receipt_sidecar", &sidecar_scope, &grant)?,
        "capture receipt sidecar could not be authenticated"
    );
    Ok(json!({"name": name, "hash": hash, "scope": sidecar_scope, "grant": grant}))
}
