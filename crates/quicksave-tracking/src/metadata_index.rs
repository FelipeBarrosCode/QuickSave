// SPDX-License-Identifier: GPL-3.0-only
//! Native capability over a real authenticated immutable metadata index.
//! No incoming JSON constructor, source traversal, content read or saved proof.

use crate::{
    bundle::BundleIndexSource,
    model::{
        self, Snapshot, MAX_BASELINE_BYTES, MAX_FILES, MAX_PAGE, MAX_PATH_BYTES, MAX_SOFTWARE,
    },
    receipt, Runtime, Shared, Tracker,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{Arc, Weak},
};

const MAX_NATIVE_INDEX_PAGE_BYTES: u64 = 32 * 1024 * 1024;

/// An owned *metadata-only* view of an actual materialized Tracker index.
/// It cannot be deserialized or constructed from IPC. Private Arcs and grants
/// retain the original index, while current authority is rechecked on every
/// header/page call. Never treats metadata or a prior content hash as "saved".
///
/// Methods must not be called while the caller holds Tracker's state lock.
pub struct NativeMetadataIndex {
    shared: Weak<Shared>,
    snapshot: Arc<Snapshot>,
    source: BundleIndexSource,
    tracking_scope: Value,
    tracking_grant: Value,
    enrollment_grants: Option<(Value, Value)>,
    index_identity: String,
    header: Value,
    // One key per 500 nodes, NOT a duplicated 250k-node/ID list. This bounds
    // arbitrary-offset paging to a BTree lookup and at most 999 visited nodes.
    checkpoints: Vec<String>,
    snapshot_bytes: u64,
    binding_bytes: u64,
    path_bytes: usize,
}

#[derive(Default)]
pub(crate) struct FrozenIndices {
    owners: Vec<Weak<NativeMetadataIndex>>,
}

#[derive(Default)]
struct RetentionBudget {
    nodes: usize,
    bytes: u64,
    paths: usize,
}

impl RetentionBudget {
    fn charge(&mut self, nodes: usize, bytes: u64, paths: usize) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .context("native frozen-index node budget overflow")?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("native frozen-index byte budget overflow")?;
        self.paths = self
            .paths
            .checked_add(paths)
            .context("native frozen-index path budget overflow")?;
        ensure!(
            self.nodes <= MAX_FILES && self.bytes <= MAX_BASELINE_BYTES && self.paths <= MAX_PATH_BYTES,
            "retained native metadata indexes exceed the bounded node/metadata/path budget; release obsolete native owners"
        );
        Ok(())
    }
}

impl NativeMetadataIndex {
    /// Canonical source app ID and installation instance ID are distinct.
    /// Always declares VERIFY_REQUIRED, including after restart or uncertainty.
    pub fn header(&self) -> Result<Value> {
        self.revalidate()?;
        Ok(self.header.clone())
    }

    /// Actual ID-sorted cached nodes, in the same shape as
    /// Tracker::prepared_node_listing. Offset == nodeCount returns an empty
    /// terminal page; larger offsets and limits outside 1..=500 fail explicitly.
    pub fn node_page(&self, offset: usize, limit: usize) -> Result<Value> {
        ensure!(
            limit > 0 && limit <= MAX_PAGE,
            "native metadata index page limit must be 1..=500"
        );
        let count = self.snapshot.nodes.len();
        ensure!(
            offset <= count,
            "native metadata index offset exceeds node count"
        );
        self.revalidate()?;
        let mut nodes = Vec::with_capacity(limit.min(count - offset));
        if offset < count {
            let checkpoint = self
                .checkpoints
                .get(offset / MAX_PAGE)
                .context("native metadata index checkpoint is unavailable")?;
            for (id, node) in self
                .snapshot
                .nodes
                .range(checkpoint.clone()..)
                .skip(offset % MAX_PAGE)
                .take(limit)
            {
                nodes.push(receipt::indexed_metadata_node(id, node)?);
            }
        }
        let next = offset
            .checked_add(nodes.len())
            .context("native index page overflow")?;
        ensure!(
            nodes.len() == limit.min(count - offset),
            "native immutable index page count changed"
        );
        let page = json!({
            "nodes": nodes, "offset": offset,
            "nextOffset": if next < count { Some(next) } else { None },
            "nodeCount": count, "revisionId": self.source.revision_id,
            "metadataIdentity": self.source.snapshot_identity,
            "metadataOnly": true, "fileStateTrust": "VERIFY_REQUIRED",
            "payloadReadability": "not_established",
            "reconciliationRequired": true, "saved": false,
        });
        model::bounded_serialized(&page, MAX_NATIVE_INDEX_PAGE_BYTES)?;
        // A revocation/revision change while serializing a page is failure,
        // never publication of a successful empty/partial native index.
        self.revalidate()?;
        Ok(page)
    }

    /// Cached-record and authenticated reference checks only. No native root
    /// open, filesystem walk, payload read, grant issuance or clean transition.
    /// The service/source root-authority guard separately pins live no-follow
    /// roots before importing graph rows. A cached index can remain valid while
    /// reconciliation is pending: it is ALWAYS source VERIFY_REQUIRED.
    pub fn revalidate(&self) -> Result<()> {
        let shared = self
            .shared
            .upgrade()
            .context("native metadata index tracker is unavailable")?;
        shared.check_running()?;
        let mut apps = shared.apps()?;
        let software = self.header["softwareId"]
            .as_str()
            .context("native index has no software ID")?;
        let app = apps
            .get_mut(software)
            .context("native metadata index software no longer exists")?;
        shared.validate_tracking(app)?;
        self.verify_current(&shared, app)?;
        shared.check_running()
    }

    fn verify_current(&self, shared: &Shared, app: &Runtime) -> Result<()> {
        ensure!(
            !app.scheduler.paused && app.record.tracked && app.current.is_some(),
            "native metadata index is unmaterialized, paused or revoked"
        );
        ensure!(
            app.record.tracking_scope() == self.tracking_scope
                && app.record.tracking_grant == self.tracking_grant
                && match (&app.record.auto_enrollment, &self.enrollment_grants) {
                    (Some(current), Some((policy, discovery))) =>
                        &current.policy_grant == policy && &current.discovery_grant == discovery,
                    (None, None) => true,
                    _ => false,
                },
            "native metadata index revision, identity or original authority changed"
        );
        ensure!(
            shared
                .store
                .verify_grant("tracking", &self.tracking_scope, &self.tracking_grant)?,
            "native metadata index original tracking grant is invalid or revoked"
        );
        if let Some(enrollment) = &app.record.auto_enrollment {
            enrollment.verify_record(&app.record, shared.store.as_ref(), &shared.policy)?;
        }
        if app.record.bundle_index_source.as_ref() != Some(&self.source)
            || app.index_identity.as_deref() != Some(self.index_identity.as_str())
        {
            return Err(MetadataIndexRevisionChanged.into());
        }
        self.source
            .verify_reference_grants(&self.tracking_scope, shared.store.as_ref())
    }
}

/// A new cached metadata revision under the SAME freshly verified authority.
/// Never denotes revoked/replaced tracking, roots or policy. Readers may retry
/// one fresh index acquisition, not accept the obsolete index as current.
#[derive(Debug)]
pub struct MetadataIndexRevisionChanged;
impl std::fmt::Display for MetadataIndexRevisionChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native metadata index revision changed under unchanged authority")
    }
}
impl std::error::Error for MetadataIndexRevisionChanged {}

impl Tracker {
    /// Freeze the real current materialized index for a native source graph
    /// owner. Never scans files, invents a source identity, prepares capture,
    /// issues grants, changes the baseline, or clears pending reconciliation.
    pub fn freeze_metadata_index(&self, software_id: &str) -> Result<Arc<NativeMetadataIndex>> {
        self.shared.check_running()?;
        model::validate_id(software_id)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("unknown native metadata index software")?;
        self.shared.validate_tracking(app)?;
        app.record.validate()?;
        ensure!(
            !app.scheduler.paused && app.record.tracked,
            "native metadata index requires an authenticated materialized record"
        );
        let snapshot = app
            .current
            .as_ref()
            .context("native materialized index is unavailable")?;
        let source = app
            .record
            .bundle_index_source
            .as_ref()
            .context("native materialized index reference is unavailable")?;
        let tracking_scope = app.record.tracking_scope();
        source.verify_reference_grants(&tracking_scope, self.shared.store.as_ref())?;
        let instance = app
            .record
            .app_id
            .as_deref()
            .context("native source installation instance identity is missing")?;
        let canonical = app.record.source_identity.as_ref().and_then(|identity| identity["app_id"].as_str())
            .context("canonical native source app identity is missing; no instance/display-name fallback is permitted")?;
        model::validate_id(instance)?;
        model::validate_id(canonical)?;
        ensure!(
            !canonical.starts_with("quicksave.observed:"),
            "unconfirmed observed identities cannot become native source index ownership"
        );
        let enrollment_grants = app.record.auto_enrollment.as_ref().map(|enrollment| {
            (
                enrollment.policy_grant.clone(),
                enrollment.discovery_grant.clone(),
            )
        });
        let mut registry = self
            .shared
            .frozen_indices
            .lock()
            .map_err(|_| anyhow::anyhow!("native frozen-index registry lock poisoned"))?;
        let live = registry
            .owners
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        registry.owners = live.iter().map(Arc::downgrade).collect();
        for existing in &live {
            if app.index_identity.as_deref() == Some(existing.index_identity.as_str())
                && existing.source == *source
                && existing.tracking_scope == tracking_scope
                && existing.tracking_grant == app.record.tracking_grant
                && existing.enrollment_grants == enrollment_grants
            {
                existing.verify_current(&self.shared, app)?;
                self.shared.check_running()?;
                return Ok(existing.clone());
            }
        }
        ensure!(
            live.len() < MAX_SOFTWARE,
            "native frozen-index owner limit reached"
        );
        snapshot.validate(&app.record.roots)?;
        let (identity, snapshot_bytes) = snapshot.identity_and_size()?;
        let index_identity = blake3::hash(format!("{software_id}:{identity}").as_bytes())
            .to_hex()
            .to_string();
        ensure!(
            identity == source.snapshot_identity
                && source.index.hash == identity
                && app.index_identity.as_deref() == Some(index_identity.as_str())
                && snapshot.counts()? == (source.file_count, source.logical_bytes)
                && snapshot
                    .nodes
                    .values()
                    .filter(|node| node.directory)
                    .count() as u64
                    == source.directory_count
                && snapshot
                    .nodes
                    .values()
                    .filter(|node| node.link.is_some())
                    .count() as u64
                    == source.symlink_count
                && matches!(
                    source.content_state.as_str(),
                    "metadata_indexed" | "content_verified"
                )
                && (source.content_state == "content_verified") == snapshot.content_verified(),
            "cached native index does not match its authenticated materialized reference"
        );
        ensure!(
            snapshot.nodes.values().all(|node| node.metadata.is_some()
                && node
                    .stamp
                    .as_ref()
                    .is_some_and(|stamp| stamp.modified_nanoseconds < 1_000_000_000
                        && stamp.changed_nanoseconds < 1_000_000_000)),
            "actual native index nodes require complete metadata and write/change stamps"
        );
        ensure!(
            app.record
                .roots
                .iter()
                .filter(|root| root.allowed_files.is_none())
                .all(|root| snapshot.root_metadata.contains_key(&root.id)
                    && snapshot.root_stamps.contains_key(&root.id)),
            "native full-root index lacks genuine root metadata/stamps"
        );
        let checkpoints = snapshot
            .nodes
            .keys()
            .step_by(MAX_PAGE)
            .cloned()
            .collect::<Vec<_>>();
        let header = json!({
            "version": 1, "softwareId": app.record.id, "appId": canonical, "instanceId": instance,
            "revisionId": source.revision_id, "snapshotIdentity": identity,
            "trackingScopeHash": source.tracking_scope_hash, "nodeCount": snapshot.nodes.len(),
            "metadataOnly": true, "fileStateTrust": "VERIFY_REQUIRED",
            "payloadReadability": "not_established",
            "reconciliationRequired": true, "coverageTrusted": false,
            "complete": false, "saved": false, "cloudWrite": false,
        });
        model::bounded_json(&header, 64 * 1024)?;
        let binding_bytes = model::serialized_size(
            &(
                &tracking_scope,
                &app.record.tracking_grant,
                source,
                &enrollment_grants,
                &header,
                &checkpoints,
                &index_identity,
            ),
            MAX_BASELINE_BYTES,
        )?;
        let mut retained = RetentionBudget::default();
        retained.charge(0, binding_bytes, 0)?;
        let mut snapshots = BTreeSet::new();
        for existing in &live {
            retained.charge(0, existing.binding_bytes, 0)?;
            if snapshots.insert(Arc::as_ptr(&existing.snapshot) as usize) {
                retained.charge(
                    existing.snapshot.nodes.len(),
                    existing.snapshot_bytes,
                    existing.path_bytes,
                )?;
            }
        }
        let path_bytes = snapshot.path_bytes()?;
        if snapshots.insert(Arc::as_ptr(snapshot) as usize) {
            retained.charge(snapshot.nodes.len(), snapshot_bytes, path_bytes)?;
        }
        let index = Arc::new(NativeMetadataIndex {
            shared: Arc::downgrade(&self.shared),
            snapshot: snapshot.clone(),
            source: source.clone(),
            tracking_scope,
            tracking_grant: app.record.tracking_grant.clone(),
            enrollment_grants,
            index_identity,
            header,
            checkpoints,
            snapshot_bytes,
            binding_bytes,
            path_bytes,
        });
        index.verify_current(&self.shared, app)?;
        self.shared.check_running()?;
        registry.owners.push(Arc::downgrade(&index));
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_retention_accounting_never_raises_persisted_node_byte_or_path_limits() {
        // Pure quota arithmetic, NOT a fabricated index or native node count.
        let mut exact = RetentionBudget::default();
        exact
            .charge(MAX_FILES, MAX_BASELINE_BYTES, MAX_PATH_BYTES)
            .unwrap();
        for (nodes, bytes, paths) in [
            (MAX_FILES + 1, 0, 0),
            (0, MAX_BASELINE_BYTES + 1, 0),
            (0, 0, MAX_PATH_BYTES + 1),
        ] {
            assert!(RetentionBudget::default()
                .charge(nodes, bytes, paths)
                .is_err());
        }
        assert!(exact.charge(0, 1, 0).is_err()); // Binding bytes count as well.
        let mut overflow = RetentionBudget {
            nodes: 0,
            bytes: u64::MAX,
            paths: 0,
        };
        assert!(overflow.charge(0, 1, 0).is_err());
    }
}
