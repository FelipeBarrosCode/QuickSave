// SPDX-License-Identifier: GPL-3.0-only
//! Durable original native work, not reconstruction from today's source tree.
//! All JSON deserialization stays behind authenticated private-file loading.

use crate::{
    bundle, expected_files,
    model::{self, Snapshot, TrackedSoftware, MAX_BASELINE_BYTES, MAX_FILES, MAX_PAGE},
    receipt::{self, NativeCaptureReceipt},
    scan,
    scheduler::Flight,
    Pending, Runtime, Shared, Tracker, TrackingStore,
};
use anyhow::{ensure, Context, Result};
use quicksave_platform::{FileStamp, SafeRoot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::{atomic::Ordering, Arc, Weak},
};

const FRAME_KIND: &str = "tracking_frozen_work";
const MAX_FRAMES: usize = 64;

#[derive(Default)]
pub(crate) struct FrameQuota {
    active: BTreeMap<String, u64>,
    loaded: BTreeMap<String, Weak<NativeFrozenWork>>,
}

impl FrameQuota {
    fn check(&self, software: &str, bytes: u64) -> Result<()> {
        let count = self.active.len() + usize::from(!self.active.contains_key(software));
        let total = self
            .active
            .iter()
            .filter(|(id, _)| id.as_str() != software)
            .try_fold(bytes, |sum, (_, bytes)| {
                sum.checked_add(*bytes)
                    .context("native frame byte count overflow")
            })?;
        ensure!(
            count <= MAX_FRAMES && total <= MAX_BASELINE_BYTES,
            "active native frozen work exceeds 64 frames / 128 MiB; resolve original work first"
        );
        Ok(())
    }
    pub(crate) fn install(&mut self, software: &str, reference: &Value) -> Result<()> {
        let bytes = reference["bytes"]
            .as_u64()
            .context("native frame byte size is missing")?;
        self.check(software, bytes)?;
        self.active.insert(software.to_owned(), bytes);
        Ok(())
    }
}

mod snapshot_arc {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &Arc<Snapshot>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.as_ref().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Arc<Snapshot>, D::Error> {
        Ok(Arc::new(Snapshot::deserialize(deserializer)?))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrozenFrame {
    version: u32,
    origin_token: String,
    instance_nonce: String,
    request: Value,
    record: TrackedSoftware,
    #[serde(with = "snapshot_arc")]
    metadata: Arc<Snapshot>,
    event_epoch: u64,
    uncertainty_epoch: u64,
    unknown_generation: u64,
    original_reference: Option<Value>,
    accepted_receipt: Option<Value>,
    #[serde(default)]
    source_expected_manifest_auth: Option<Value>,
}

/// Native capability: no public fields, Deserialize, Default or JSON constructor.
/// The loader authenticates the frame once. Paging never rereads a file/vault or
/// invents new content hashes. Revalidate explicitly at source admission and
/// publication; callbacks must not reenter their owning source engine.
pub struct NativeFrozenWork {
    shared: Weak<Shared>,
    frame: Arc<FrozenFrame>,
    reference: Value,
    baseline: Option<Arc<Snapshot>>,
}

fn selected(frame: &FrozenFrame) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for key in ["fileIds", "deletedFileIds"] {
        let values = frame.request[key]
            .as_array()
            .context("original selection is missing")?;
        ensure!(
            values.len() <= MAX_FILES,
            "original selection exceeds node bound"
        );
        for value in values {
            let id = value
                .as_str()
                .context("invalid original selected node ID")?;
            model::validate_id(id)?;
            ensure!(
                result.insert(id.to_owned()),
                "duplicate original selected/deleted ID"
            );
        }
    }
    ensure!(
        result.len() <= MAX_FILES,
        "original selection exceeds node bound"
    );
    Ok(result)
}

fn canonical_optional_object(value: &Option<Value>) -> Result<Value> {
    ensure!(
        value.as_ref().is_none_or(Value::is_object),
        "native optional authority must be an object or None, never Some(null)"
    );
    Ok(json!(value))
}

fn frame_scope(frame: &FrozenFrame, name: &str, hash: &str, bytes: u64) -> Result<Value> {
    let original_reference = canonical_optional_object(&frame.original_reference)?;
    let accepted_receipt = canonical_optional_object(&frame.accepted_receipt)?;
    Ok(json!({
        "version":1, "softwareId":frame.record.id, "workId":frame.request["workId"],
        "generation":frame.request["generation"], "originToken":frame.origin_token,
        "appId":frame.record.app_id, "providerId":frame.record.provider_id,
        "trackingScopeHash":bundle::digest(&frame.record.tracking_scope())?,
        "trackingGrantHash":bundle::digest(&frame.record.tracking_grant)?,
        "sourceIdentityHash":bundle::digest(&json!(frame.record.source_identity))?,
        "autosaveScopeHash":bundle::digest(&frame.record.autosave_scope())?,
        "authorizationHash":bundle::digest(&frame.request["authorization"])?,
        "automatic":frame.request["automatic"], "unknownGeneration":frame.unknown_generation,
        "metadataIdentity":frame.request["captureSource"]["snapshotIdentity"],
        "fullScopeProofHash":bundle::digest(&frame.request["captureSource"]["expectedFullScope"])?,
        "baselineReferenceHash":bundle::digest(&json!(frame.record.baseline))?,
        "selectedIdsHash":bundle::digest(&frame.request["fileIds"])?,
        "deletedIdsHash":bundle::digest(&frame.request["deletedFileIds"])?,
        "originalReferenceHash":bundle::digest(&original_reference)?,
        "captureReceiptHash":bundle::digest(&accepted_receipt)?,
        "frameHash":hash, "name":name, "bytes":bytes,
        "stage":if frame.accepted_receipt.is_some() {"source_receipt_accepted"} else {"metadata_frozen"},
    }))
}

pub(crate) fn verify_reference(store: &dyn TrackingStore, reference: &Value) -> Result<()> {
    model::bounded_json(reference, 64 * 1024)?;
    let name = reference["name"]
        .as_str()
        .context("native frame name is missing")?;
    model::validate_relative(name)?;
    let hash = reference["hash"]
        .as_str()
        .context("native frame hash is missing")?;
    let bytes = reference["bytes"]
        .as_u64()
        .context("native frame size is missing")?;
    ensure!(
        reference["version"] == 1
            && !name.contains('/')
            && name.starts_with("work-")
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            && bytes > 0
            && bytes <= MAX_BASELINE_BYTES
            && reference["scope"]["name"] == name
            && reference["scope"]["frameHash"] == hash
            && reference["scope"]["bytes"] == bytes
            && store.verify_grant(FRAME_KIND, &reference["scope"], &reference["grant"])?,
        "original native work frame reference is invalid or revoked"
    );
    Ok(())
}

fn read_private(shared: &Shared, reference: &Value, max: u64) -> Result<Vec<u8>> {
    let name = reference["name"]
        .as_str()
        .context("private native reference name is missing")?;
    model::validate_relative(name)?;
    ensure!(
        !name.contains('/'),
        "private native reference must be a single safe leaf"
    );
    let root = SafeRoot::open(&shared.policy.bundle_dir())?;
    let (file, stamp) = root.read_file(name)?;
    ensure!(
        stamp.size <= max,
        "private native document exceeds recovery bound"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.size
            && blake3::hash(&bytes).to_hex().as_str() == reference["hash"].as_str().unwrap_or(""),
        "private native document failed exact hash/length verification"
    );
    if let Some(expected) = reference["bytes"].as_u64() {
        ensure!(
            stamp.size == expected,
            "private native document reference length changed"
        );
    }
    root.verify_file(name, &stamp)?;
    Ok(bytes)
}

fn write_frame(shared: &Shared, frame: &FrozenFrame) -> Result<Value> {
    let bytes = model::serialized_size(frame, MAX_BASELINE_BYTES)?;
    shared
        .frozen_frames
        .lock()
        .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
        .check(&frame.record.id, bytes)?;
    let safe = SafeRoot::open(&shared.policy.bundle_dir())?;
    let name = format!("work-{}.json", uuid::Uuid::new_v4());
    let hash = bundle::write_local_json_bounded(&safe, &name, frame, MAX_BASELINE_BYTES)?;
    let scope = frame_scope(frame, &name, &hash, bytes)?;
    let grant = shared.store.issue_grant(FRAME_KIND, &scope)?;
    let reference =
        json!({"version":1,"name":name,"hash":hash,"bytes":bytes,"scope":scope,"grant":grant});
    verify_reference(shared.store.as_ref(), &reference)?;
    // Actual durable private-file readback, not a prediction of what was written.
    read_private(shared, &reference, MAX_BASELINE_BYTES)?;
    Ok(reference)
}

pub(crate) fn readback_reference(
    store: &dyn TrackingStore,
    record: &TrackedSoftware,
) -> Result<()> {
    let actual = store
        .read_record(&record.id)?
        .context("native work record readback is missing")?;
    model::bounded_json(&actual, 3 * 1024 * 1024)?;
    let actual: TrackedSoftware = serde_json::from_value(actual)?;
    actual.validate()?;
    ensure!(
        actual.pending_work == record.pending_work
            && actual.tracking_scope() == record.tracking_scope()
            && actual.tracking_grant == record.tracking_grant
            && actual.autosave_scope() == record.autosave_scope()
            && actual.autosave_grant == record.autosave_grant
            && actual.unknown_generation == record.unknown_generation
            && actual.dirty_generation == record.dirty_generation
            && actual.baseline.as_ref().map(|reference| (
                &reference.name,
                &reference.hash,
                &reference.grant
            )) == record.baseline.as_ref().map(|reference| (
                &reference.name,
                &reference.hash,
                &reference.grant
            ))
            && actual.baseline_full_scope == record.baseline_full_scope,
        "durable original native work reference was not preserved by state persistence"
    );
    Ok(())
}

pub(crate) fn persist_initial(shared: &Shared, app: &mut Runtime, request: &Value) -> Result<()> {
    let pending = app
        .pending
        .as_ref()
        .context("original native work is missing")?;
    let source = app
        .record
        .bundle_index_source
        .as_ref()
        .context("original native work requires a materialized current index")?;
    ensure!(
        app.record.tracked
            && source.snapshot_identity == pending.frozen_metadata_identity
            && source.index.hash == pending.frozen_metadata_identity,
        "original native work metadata does not match its materialized index"
    );
    // Check CURRENT-index authority before issuing the independent work-frame
    // grant. Later reindexing may legitimately rotate these index nonces; the
    // original frame must not depend on their continued validity.
    source.verify_reference_grants(&app.record.tracking_scope(), shared.store.as_ref())?;
    let mut record = app.record.clone();
    record.pending_work = None;
    let frame = Arc::new(FrozenFrame {
        version: 1,
        origin_token: uuid::Uuid::new_v4().to_string(),
        instance_nonce: shared.instance_nonce.clone(),
        request: request.clone(),
        record,
        metadata: pending.captured.clone(),
        event_epoch: pending.event_epoch,
        uncertainty_epoch: pending.uncertainty_epoch,
        unknown_generation: pending.unknown_generation,
        original_reference: None,
        accepted_receipt: None,
        source_expected_manifest_auth: None,
    });
    let reference = write_frame(shared, &frame)?;
    app.record.pending_work = Some(reference);
    app.pending.as_mut().unwrap().original_frame = Some(frame);
    Ok(())
}

pub(crate) fn persist_accepted(
    shared: &Shared,
    app: &Runtime,
    record: &mut TrackedSoftware,
    sealed: &Value,
    source_auth: &Value,
) -> Result<Option<Arc<FrozenFrame>>> {
    ensure!(
        sealed.is_object() && sealed["scope"].is_object(),
        "accepted source receipt must not be null or untyped JSON"
    );
    let Some(original) = app
        .pending
        .as_ref()
        .and_then(|pending| pending.original_frame.as_ref())
    else {
        return Ok(None); // Existing legacy non-native capture API has no frame.
    };
    let mut frame = (**original).clone(); // Snapshot Arc, not a duplicated tree.
    if frame.original_reference.is_none() {
        frame.original_reference = app.record.pending_work.clone();
    }
    frame.accepted_receipt = Some(sealed.clone());
    ensure!(
        sealed["scope"]["sourceExpectedManifestAuthHash"] == bundle::digest(source_auth)?,
        "compact source envelope does not match the actual accepted receipt"
    );
    frame.source_expected_manifest_auth = Some(source_auth.clone());
    let frame = Arc::new(frame);
    record.pending_work = Some(write_frame(shared, &frame)?);
    Ok(Some(frame))
}

fn verify_authority(shared: &Shared, app: &Runtime, frame: &FrozenFrame) -> Result<()> {
    ensure!(
        !app.scheduler.paused
            && app.record.tracking_scope() == frame.record.tracking_scope()
            && app.record.tracking_grant == frame.record.tracking_grant
            && app.record.autosave_scope() == frame.record.autosave_scope()
            && shared.store.verify_grant(
                "tracking",
                &frame.record.tracking_scope(),
                &frame.record.tracking_grant
            )?,
        "original root/provider/instance/source authority was changed or revoked"
    );
    if let Some(enrollment) = &frame.record.auto_enrollment {
        enrollment.verify_record(&frame.record, shared.store.as_ref(), &shared.policy)?;
    }
    if let Some(reference) = &frame.record.baseline {
        ensure!(
            shared.store.verify_grant(
                "tracking_baseline",
                &frame
                    .record
                    .baseline_scope(&reference.name, &reference.hash),
                &reference.grant
            )?,
            "original baseline reference was revoked"
        );
    }
    if frame.request["automatic"] == true {
        ensure!(
            app.record.autosave
                && app.record.autosave_grant == frame.record.autosave_grant
                && frame
                    .record
                    .autosave_grant
                    .as_ref()
                    .is_some_and(|grant| shared
                        .store
                        .verify_grant("autosave", &frame.record.autosave_scope(), grant)
                        .unwrap_or(false)),
            "original automatic source authority was revoked"
        );
    }
    let provider = frame
        .record
        .provider_id
        .as_deref()
        .context("original provider is missing")?;
    ensure!(
        shared.store.provider_writable(provider)?,
        "original provider is no longer writable"
    );
    let current = app
        .record
        .pending_work
        .as_ref()
        .context("original work is no longer pending")?;
    ensure!(
        current["scope"]["originToken"] == frame.origin_token
            && current["scope"]["workId"] == frame.request["workId"]
            && current["scope"]["generation"] == frame.request["generation"],
        "original native work reference was replaced or retired"
    );
    for root in &frame.record.roots {
        scan::PinnedRoot::open(root)?.check()?; // Metadata-only no-follow identity, no walk.
    }
    shared.check_running()
}

fn validate_frame(shared: &Shared, frame: &FrozenFrame) -> Result<()> {
    ensure!(
        frame.version == 1 && frame.record.pending_work.is_none(),
        "invalid recursive native work frame"
    );
    frame.record.validate()?;
    ensure!(
        frame.record.tracked && frame.record.bundle_index_source.is_some(),
        "original work was not materialized by an actual authenticated index"
    );
    // This function is called only AFTER verify_reference(), exact private-file
    // hash/length verification (or reuse of an already authenticated in-process
    // frame), and frame_scope() equality. Its original metadata/record are
    // authenticated by tracking_frozen_work, NOT by a still-current index nonce.
    // A newer real scan must not force re-signing/replacing the original work.
    let source = frame.record.bundle_index_source.as_ref().unwrap();
    let metadata_identity = frame.metadata.identity()?;
    ensure!(
        source.version == 1
            && source.tracking_scope_hash == bundle::digest(&frame.record.tracking_scope())?
            && source.snapshot_identity == metadata_identity
            && source.index.hash == metadata_identity,
        "authenticated original frame index/metadata binding was altered"
    );
    ensure!(
        frame
            .original_reference
            .as_ref()
            .is_none_or(Value::is_object)
            && frame.accepted_receipt.as_ref().is_none_or(Value::is_object)
            && frame
                .source_expected_manifest_auth
                .as_ref()
                .is_none_or(Value::is_object),
        "original native reference/accepted receipt cannot be Some(null)"
    );
    if let Some(source) = &frame.source_expected_manifest_auth {
        model::bounded_serialized(source, 128 * 1024)?;
        let source_hash = bundle::digest(source)?;
        let sealed = frame
            .accepted_receipt
            .as_ref()
            .context("frozen compact source envelope has no accepted receipt")?;
        ensure!(
            sealed["scope"]["sourceExpectedManifestAuthHash"] == source_hash,
            "frozen compact source envelope is not bound to its authenticated accepted receipt"
        );
    }
    frame.metadata.validate(&frame.record.roots)?;
    let request = &frame.request;
    model::validate_id(
        request["workId"]
            .as_str()
            .context("original work ID is missing")?,
    )?;
    let generation = request["generation"]
        .as_u64()
        .context("original generation is missing")?;
    ensure!(
        generation <= frame.record.dirty_generation
            && request["softwareId"] == frame.record.id
            && request["appId"] == json!(frame.record.app_id)
            && request["providerId"] == json!(frame.record.provider_id)
            && request["sourceIdentity"] == json!(frame.record.source_identity)
            && request["roots"]
                == json!(frame
                    .record
                    .roots
                    .iter()
                    .map(scan::root_request)
                    .collect::<Vec<_>>())
            && request["authorization"]["trackingScope"] == frame.record.tracking_scope()
            && request["authorization"]["trackingGrant"] == frame.record.tracking_grant
            && request["captureSource"]["snapshotIdentity"] == metadata_identity,
        "original native work payload no longer matches its frozen metadata/authority"
    );
    let ids = selected(frame)?;
    let current = request["fileIds"].as_array().unwrap();
    ensure!(
        current.iter().all(|id| id
            .as_str()
            .is_some_and(|id| frame.metadata.nodes.contains_key(id)))
            && request["deletedFileIds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|id| id
                    .as_str()
                    .is_some_and(|id| !frame.metadata.nodes.contains_key(id))),
        "original node/deletion selection was altered"
    );
    let full = request["captureSource"]["selectionKind"] == "full_scope";
    if full {
        ensure!(
            current.len() == frame.metadata.nodes.len(),
            "original full scope omits indexed nodes"
        );
        let proof = &request["captureSource"]["expectedFullScope"];
        ensure!(
            proof["scope"]["workId"] == request["workId"]
                && proof["scope"]["generation"] == generation
                && proof["scope"]["metadataIdentity"]
                    == request["captureSource"]["snapshotIdentity"]
                && proof["scope"]["trackingScopeHash"]
                    == bundle::digest(&frame.record.tracking_scope())?
                && proof["scope"]["deletedNodeIdsHash"]
                    == bundle::digest(&request["deletedFileIds"])?
                && proof["scope"]["expectedNodeIdsHash"] == bundle::digest(&request["fileIds"])?
                && shared.store.verify_grant(
                    "tracking_full_capture",
                    &proof["scope"],
                    &proof["grant"]
                )?,
            "original full-scope omission authority is invalid or revoked"
        );
    } else {
        ensure!(
            request["captureSource"]["selectionKind"] == "selected_nodes"
                && request["deletedFileIds"].as_array().unwrap().is_empty()
                && !ids.is_empty()
                && request["captureSource"]["expectedFullScope"].is_null(),
            "original partial work cannot authorize omissions or widen to full scope"
        );
    }
    Ok(())
}

impl NativeFrozenWork {
    /// Exact original private materialized record, including original policy
    /// bindings. Source registration only; never an IPC/UI DTO.
    pub fn record(&self) -> Result<Value> {
        Ok(serde_json::to_value(&self.frame.record)?)
    }
    /// Native-only exact queued request; no renderer may receive this authority.
    pub fn work(&self) -> Result<Value> {
        Ok(self.frame.request.clone())
    }
    /// Locator/authentication for the prior ACTUAL source receipt. This alone
    /// cannot instantiate a receipt or prove a COMMITTED source operation.
    pub fn accepted_receipt(&self) -> Result<Option<Value>> {
        Ok(self.frame.accepted_receipt.clone())
    }
    pub fn header(&self) -> Result<Value> {
        Ok(json!({
            "softwareId":self.frame.record.id, "workId":self.frame.request["workId"],
            "generation":self.frame.request["generation"],
            "metadataIdentity":self.frame.request["captureSource"]["snapshotIdentity"],
            "trackingScopeHash":self.reference["scope"]["trackingScopeHash"],
            "unknownGeneration":self.frame.unknown_generation,
            "fullScope":self.frame.request["captureSource"]["selectionKind"] == "full_scope",
            "nodeCount":self.frame.request["fileIds"].as_array().unwrap().len(),
            "frameReference":self.reference, "hasAcceptedReceipt":self.frame.accepted_receipt.is_some(),
            "historicalOnly":true, "reconciliationRequired":true, "saved":false,
        }))
    }
    pub fn node_page(&self, offset: usize, limit: usize) -> Result<Value> {
        ensure!(
            limit > 0 && limit <= MAX_PAGE,
            "original node page limit must be 1..=500"
        );
        let ids = self.frame.request["fileIds"].as_array().unwrap();
        ensure!(offset <= ids.len(), "original node page exceeds selection");
        let end = offset
            .checked_add(limit)
            .context("original node offset overflow")?
            .min(ids.len());
        let nodes = ids[offset..end]
            .iter()
            .map(|id| {
                let id = id.as_str().context("original node ID is missing")?;
                let node = self
                    .frame
                    .metadata
                    .nodes
                    .get(id)
                    .context("original frozen node disappeared")?;
                receipt::indexed_metadata_node(id, node)
            })
            .collect::<Result<Vec<_>>>()?;
        let page = json!({"nodes":nodes,"offset":offset,"nextOffset":if end < ids.len() {Some(end)} else {None},
            "metadataIdentity":self.frame.request["captureSource"]["snapshotIdentity"],
            "workId":self.frame.request["workId"]});
        model::bounded_serialized(&page, 32 * 1024 * 1024)?;
        Ok(page)
    }
    pub fn full_scope_evidence(&self) -> Result<Value> {
        ensure!(
            self.frame.request["captureSource"]["selectionKind"] == "full_scope",
            "selected original work is not full-scope authority"
        );
        let record = &self.frame.record;
        let deleted = self.frame.request["deletedFileIds"].as_array().unwrap().iter().map(|id| {
            let id = id.as_str().context("original deleted ID is missing")?;
            let node = self.baseline.as_ref().and_then(|baseline| baseline.nodes.get(id))
                .context("original omission was not in the authenticated original baseline")?;
            Ok(json!({"id":id,"rootId":node.root_id,"path":node.path,"kind":node.kind(),"size":node.size,
                "stamp":node.stamp,"metadata":node.metadata,"fileHash":node.hash,
                "linkTargetHash":node.link.as_ref().map(|link|blake3::hash(link.target.as_bytes()).to_hex().to_string())}))
        }).collect::<Result<Vec<_>>>()?;
        let value = json!({
            "version":1,"workId":self.frame.request["workId"],"generation":self.frame.request["generation"],
            "softwareId":record.id,"providerId":record.provider_id,"sourceIdentity":record.source_identity,
            "metadataIdentity":self.frame.request["captureSource"]["snapshotIdentity"],
            "fullScope":true,"completeFileList":true,"keepsVersionHistory":true,
            "coverageScope":"approved_evidenced_roots_only",
            "coverage":record.bundle_index_source.as_ref().map(|source|&source.coverage),
            "expectedFullScope":self.frame.request["captureSource"]["expectedFullScope"],
            "authorization":self.frame.request["authorization"],"roots":self.frame.request["roots"],
            "rootMetadata":self.frame.metadata.root_metadata,"rootStamps":self.frame.metadata.root_stamps,
            "deletedFileIds":self.frame.request["deletedFileIds"],"deletedNodes":deleted,
            "baseline":{"kind":if self.baseline.is_none() {"none"} else if record.baseline_full_scope {"full"} else {"partial"},
                "snapshotIdentity":self.baseline.as_ref().map(|baseline|baseline.identity()).transpose()?,
                "reference":record.baseline,"scope":record.baseline.as_ref().map(|reference|record.baseline_scope(&reference.name,&reference.hash))},
            "autoEnrollment":record.auto_enrollment.as_ref().map(|enrollment|json!({
                "policyScope":enrollment.policy_scope,"policyGrant":enrollment.policy_grant,
                "discoveryScope":enrollment.discovery_scope,"discoveryGrant":enrollment.discovery_grant})),
        });
        model::bounded_serialized(&value, MAX_BASELINE_BYTES)?;
        Ok(value)
    }
    pub fn revalidate(&self) -> Result<()> {
        let shared = self
            .shared
            .upgrade()
            .context("original work tracker is unavailable")?;
        shared.check_running()?;
        let mut apps = shared.apps()?;
        let app = apps
            .get_mut(&self.frame.record.id)
            .context("original software is missing")?;
        shared.validate_tracking(app)?;
        verify_authority(&shared, app, &self.frame)
    }
}

impl Tracker {
    pub fn original_work(
        &self,
        software_id: &str,
        work_id: &str,
        generation: u64,
        tracking_scope_hash: &str,
    ) -> Result<Arc<NativeFrozenWork>> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software_id)
            .context("original software is missing")?;
        self.shared.validate_tracking(app)?;
        let reference = app
            .record
            .pending_work
            .as_ref()
            .context(
                "legacy/original work has no durable native frame; reconciliation is required",
            )?
            .clone();
        verify_reference(self.shared.store.as_ref(), &reference)?;
        ensure!(
            reference["scope"]["softwareId"] == software_id
                && reference["scope"]["workId"] == work_id
                && reference["scope"]["generation"] == generation
                && reference["scope"]["trackingScopeHash"] == tracking_scope_hash,
            "original frame is not the exact requested work/generation/root authority"
        );
        readback_reference(self.shared.store.as_ref(), &app.record)?;
        let cached = self
            .shared
            .frozen_frames
            .lock()
            .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
            .loaded
            .get(software_id)
            .and_then(Weak::upgrade);
        if let Some(cached) = cached {
            if cached.reference == reference {
                verify_authority(&self.shared, app, &cached.frame)?;
                return Ok(cached);
            }
        }
        let frame = if let Some(frame) = app
            .pending
            .as_ref()
            .and_then(|pending| pending.original_frame.as_ref())
        {
            frame.clone()
        } else {
            Arc::new(serde_json::from_slice::<FrozenFrame>(&read_private(
                &self.shared,
                &reference,
                MAX_BASELINE_BYTES,
            )?)?)
        };
        ensure!(
            frame_scope(
                &frame,
                reference["name"].as_str().unwrap(),
                reference["hash"].as_str().unwrap(),
                reference["bytes"].as_u64().unwrap()
            )? == reference["scope"],
            "original frame signature binding changed"
        );
        validate_frame(&self.shared, &frame)?;
        verify_authority(&self.shared, app, &frame)?;
        let same_original_baseline = app
            .record
            .baseline
            .as_ref()
            .map(|reference| (&reference.name, &reference.hash))
            == frame
                .record
                .baseline
                .as_ref()
                .map(|reference| (&reference.name, &reference.hash));
        let baseline = match (same_original_baseline, &app.baseline) {
            (true, Some(baseline)) => Some(baseline.clone()),
            _ => scan::load_baseline(
                &frame.record,
                self.shared.store.as_ref(),
                &self.shared.policy,
            )?
            .map(Arc::new),
        };
        ensure!(
            frame.record.baseline.is_none() || baseline.is_some(),
            "authenticated original baseline is missing"
        );
        let handle = Arc::new(NativeFrozenWork {
            shared: Arc::downgrade(&self.shared),
            frame,
            reference,
            baseline,
        });
        // Verify actual original omission membership before admitting a source owner.
        if handle.frame.request["captureSource"]["selectionKind"] == "full_scope" {
            let evidence = handle.full_scope_evidence()?;
            let proof = &handle.frame.request["captureSource"]["expectedFullScope"]["scope"];
            ensure!(
                proof["baselineKind"] == evidence["baseline"]["kind"]
                    && proof["baselineIdentity"] == evidence["baseline"]["snapshotIdentity"],
                "original full-scope baseline proof was altered"
            );
        }
        self.shared
            .frozen_frames
            .lock()
            .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
            .loaded
            .insert(software_id.to_owned(), Arc::downgrade(&handle));
        Ok(handle)
    }

    /// Restore ONLY the original native work and an actual immutable source
    /// receipt. Caller drains its source owner before entering this method.
    /// This is not a new upload admission, capture, or JSON recovery protocol.
    pub fn resume_pending(
        &self,
        original: Arc<NativeFrozenWork>,
        receipt: Arc<dyn NativeCaptureReceipt>,
    ) -> Result<Value> {
        ensure!(
            original.shared.ptr_eq(&Arc::downgrade(&self.shared)),
            "original native work belongs to another tracker instance"
        );
        original.revalidate()?;
        ensure!(
            receipt.immutable_prepared_capture(),
            "original recovery requires a real authenticated immutable source checkpoint"
        );
        receipt.revalidate()?; // Actual source/key/preparation proof, never Tracker predictions.
        let evidence = receipt.evidence()?;
        let source_auth = receipt::compact_source_auth(&evidence)?;
        model::bounded_serialized(&evidence, MAX_BASELINE_BYTES)?;
        let frame = &original.frame;
        let captured = capture_from_original(frame, &evidence)?;
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(&frame.record.id)
            .context("original software is missing")?;
        self.shared.validate_tracking(app)?;
        verify_authority(&self.shared, app, frame)?;
        if let Some(pending) = &app.pending {
            ensure!(
                pending.work_id == frame.request["workId"].as_str().unwrap()
                    && pending.generation == frame.request["generation"].as_u64().unwrap(),
                "another native work/source owner is still active"
            );
        } else {
            ensure!(
                app.scheduler.flight.is_none(),
                "another native scheduler flight is active"
            );
        }
        let selected = selected(frame)?;
        let files = expected_files(&selected, &captured)?;
        let sealed = if let Some(sealed) = &frame.accepted_receipt {
            authenticate_receipt(&self.shared, frame, &evidence, &captured, sealed)?;
            if let Some(original_auth) = &frame.source_expected_manifest_auth {
                ensure!(
                    original_auth == &source_auth
                        && sealed["scope"]["sourceExpectedManifestAuthHash"]
                            == bundle::digest(original_auth)?,
                    "authenticated original compact source envelope was altered"
                );
            }
            sealed.clone()
        } else {
            let scope = capture_scope(frame, &evidence, &captured)?;
            let grant = self
                .shared
                .store
                .issue_grant("tracking_capture_receipt", &scope)?;
            ensure!(
                self.shared
                    .store
                    .verify_grant("tracking_capture_receipt", &scope, &grant)?,
                "actual recovered source receipt could not be authenticated"
            );
            let reference = receipt::persist_receipt(
                &evidence,
                &scope,
                &frame.record,
                self.shared.store.as_ref(),
                &self.shared.policy,
            )?;
            json!({"scope":scope,"grant":grant,"reference":reference})
        };
        // A prior acknowledgement may have persisted the historical baseline
        // before losing its terminal response. Accept only that EXACT outcome,
        // not an unrelated/newer baseline or a plaintext DB completion flag.
        let same_original_baseline = app
            .record
            .baseline
            .as_ref()
            .map(|reference| (&reference.name, &reference.hash))
            == frame
                .record
                .baseline
                .as_ref()
                .map(|reference| (&reference.name, &reference.hash));
        if !same_original_baseline {
            let expected = historical_snapshot(
                frame.request["captureSource"]["selectionKind"] == "full_scope",
                original.baseline.as_deref(),
                &captured,
                &selected,
            )?;
            let baseline = app
                .baseline
                .as_ref()
                .context("current historical baseline is unavailable")?;
            let reference = app
                .record
                .baseline
                .as_ref()
                .context("current historical baseline reference is missing")?;
            ensure!(baseline.identity()? == expected.identity()?
                && app.record.capture_receipt.as_ref() == Some(&sealed)
                && self.shared.store.verify_grant("tracking_baseline",
                    &app.record.baseline_scope(&reference.name,&reference.hash),&reference.grant)?,
                "current baseline is neither the original nor this exact authenticated historical result");
        }
        receipt.revalidate()?;
        let mut record = app.record.clone();
        let mut accepted = (**frame).clone();
        if accepted.original_reference.is_none() {
            accepted.original_reference = Some(original.reference.clone());
        }
        accepted.accepted_receipt = Some(sealed.clone());
        accepted.source_expected_manifest_auth = Some(source_auth.clone());
        let accepted = Arc::new(accepted);
        if frame.accepted_receipt.is_none() {
            record.pending_work = Some(write_frame(&self.shared, &accepted)?);
        }
        record.capture_receipt = Some(sealed.clone());
        // Updating authenticated local sidecars may use only the actual cached
        // current index. Never replace today's current index with the old work.
        if let Some(current) = &app.current {
            record.bundle_index_source = Some(bundle::write_index(
                current,
                &record,
                self.shared.store.as_ref(),
                &self.shared.policy,
            )?);
        }
        let unknown = app
            .record
            .unknown_generation
            .checked_add(1)
            .context("native recovery unknown generation exhausted")?;
        let dirty = app
            .scheduler
            .dirty_generation
            .max(frame.request["generation"].as_u64().unwrap())
            .checked_add(1)
            .context("native recovery dirty generation exhausted")?;
        record.unknown_generation = unknown;
        record.dirty_generation = dirty;
        record.dirty = true;
        record.status = "uploading".into();
        record.error = None;
        // Readback MUST precede installing a runnable recovered Pending.
        self.shared
            .store
            .save_record(&serde_json::to_value(&record)?)?;
        readback_reference(self.shared.store.as_ref(), &record)?;
        let pins = frame
            .record
            .roots
            .iter()
            .map(scan::PinnedRoot::open)
            .collect::<Result<Vec<_>>>()?;
        for pin in &pins {
            pin.check()?;
        }
        let generation = frame.request["generation"].as_u64().unwrap();
        let work_id = frame.request["workId"].as_str().unwrap().to_owned();
        app.scheduler.dirty_generation = dirty;
        app.scheduler.require_reconcile();
        app.scheduler.content_dirty = true;
        app.scheduler.flight = Some(Flight {
            work_id: work_id.clone(),
            generation,
        });
        app.force_hash = true;
        app.record = record;
        app.pending = Some(Pending {
            work_id: work_id.clone(),
            generation,
            captured: Arc::new(captured),
            selected,
            full_scope: frame.request["captureSource"]["selectionKind"] == "full_scope",
            event_epoch: frame.event_epoch,
            uncertainty_epoch: frame.uncertainty_epoch,
            scope: frame.record.autosave_scope(),
            receipt: Some(receipt),
            receipt_evidence: Some(sealed.clone()),
            source_expected_manifest_auth: Some(source_auth),
            awaiting_receipt: false,
            frozen_metadata_identity: frame.request["captureSource"]["snapshotIdentity"]
                .as_str()
                .unwrap()
                .to_owned(),
            full_scope_proof: frame.request["captureSource"]["expectedFullScope"]
                .as_object()
                .map(|_| frame.request["captureSource"]["expectedFullScope"].clone()),
            source_pins: pins,
            automatic: frame.request["automatic"] == true,
            deleted: frame.request["deletedFileIds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect(),
            immutable_prepared_capture: true,
            frozen_authorization: frame.request["authorization"].clone(),
            frozen_baseline: original.baseline.clone(),
            frozen_baseline_reference: frame.record.baseline.clone(),
            frozen_baseline_scope: frame.record.baseline.as_ref().map(|reference| {
                frame
                    .record
                    .baseline_scope(&reference.name, &reference.hash)
            }),
            frozen_baseline_full_scope: frame.record.baseline_full_scope,
            unknown_generation: frame.unknown_generation,
            original_frame: Some(accepted),
            recovered: true,
        });
        self.shared
            .frozen_frames
            .lock()
            .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?
            .install(&app.record.id, app.record.pending_work.as_ref().unwrap())?;
        Ok(json!({
            "workId":work_id,"generation":generation,"originalWorkRestored":true,
            "historicalOnly":true,"reconciliationRequired":true,
            "captureSource":{
                "stage":"native_capture_receipt_accepted",
                "snapshotIdentity":frame.request["captureSource"]["snapshotIdentity"],
                "expectedFiles":files,"captureReceipt":sealed,
                "sourceExpectedManifestAuth":evidence["sourceExpectedManifestAuth"],
                "expectedFullScope":frame.request["captureSource"]["expectedFullScope"],
                "consistency":"validated_stable_files_not_application_atomic","keepsLocalCopy":true,
            },
        }))
    }
}

fn capture_from_original(frame: &FrozenFrame, evidence: &Value) -> Result<Snapshot> {
    ensure!(
        evidence["workId"] == frame.request["workId"]
            && evidence["metadataIdentity"] == frame.request["captureSource"]["snapshotIdentity"],
        "actual source receipt is not for the exact original work/metadata"
    );
    model::validate_id(
        evidence["sourceSnapshotId"]
            .as_str()
            .context("actual source snapshot ID is missing")?,
    )?;
    ensure!(
        evidence["sourceExpectedManifestAuth"]
            .as_object()
            .is_some_and(|value| !value.is_empty()),
        "actual source manifest authentication is missing"
    );
    let nodes = evidence["nodes"]
        .as_array()
        .context("actual source captured nodes are missing")?;
    let ids = selected(frame)?;
    ensure!(
        nodes.len() == frame.request["fileIds"].as_array().unwrap().len(),
        "actual source did not prepare the exact original selected file list"
    );
    let mut captured = (*frame.metadata).clone();
    captured.content_captured = true;
    let mut seen = BTreeSet::new();
    for actual in nodes {
        let id = actual["id"]
            .as_str()
            .context("actual source node ID is missing")?;
        ensure!(
            ids.contains(id) && seen.insert(id),
            "actual source widened or duplicated original nodes"
        );
        let node = captured
            .nodes
            .get_mut(id)
            .context("actual source captured a deleted/unselected node")?;
        let stamp: FileStamp = serde_json::from_value(actual["stamp"].clone())?;
        ensure!(
            actual["rootId"] == node.root_id
                && actual["path"] == node.path
                && actual["kind"] == node.kind()
                && actual["size"] == node.size
                && node.stamp.as_ref() == Some(&stamp),
            "actual source metadata differs from the original frozen native node"
        );
        if let Some(link) = &node.link {
            ensure!(
                actual["linkTargetHash"]
                    == blake3::hash(link.target.as_bytes()).to_hex().to_string(),
                "actual source link differs from original confined link metadata"
            );
        } else if !node.directory {
            let hash = actual["fileHash"]
                .as_str()
                .context("actual source captured hash is missing")?;
            let hash = hash.strip_prefix("blake3:").unwrap_or(hash);
            ensure!(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    && node.hash.as_deref().is_none_or(|known| known == hash),
                "actual source changed an original known hash or supplied an invalid hash"
            );
            node.hash = Some(hash.to_owned());
        }
    }
    if frame.request["captureSource"]["selectionKind"] == "full_scope" {
        captured.validate_content(&frame.record.roots)?;
    } else {
        captured.validate(&frame.record.roots)?;
    }
    Ok(captured)
}

fn capture_scope(frame: &FrozenFrame, evidence: &Value, captured: &Snapshot) -> Result<Value> {
    let files = expected_files(&selected(frame)?, captured)?;
    Ok(json!({
        "version":1,"workId":frame.request["workId"],"generation":frame.request["generation"],
        "softwareId":frame.record.id,"providerId":frame.record.provider_id,
        "trackingScopeHash":bundle::digest(&frame.record.tracking_scope())?,
        "metadataIdentity":frame.request["captureSource"]["snapshotIdentity"],
        "unknownGeneration":frame.unknown_generation,"capturedSnapshotIdentity":captured.identity()?,
        "expectedFilesHash":bundle::digest(&files)?,"sourceSnapshotId":evidence["sourceSnapshotId"],
        "sourceExpectedManifestAuthHash":bundle::digest(&evidence["sourceExpectedManifestAuth"])?,
        "fullScopeProofHash":bundle::digest(&frame.request["captureSource"]["expectedFullScope"])?,
        "immutablePreparedCapture":true,
    }))
}

fn authenticate_receipt(
    shared: &Shared,
    frame: &FrozenFrame,
    evidence: &Value,
    captured: &Snapshot,
    sealed: &Value,
) -> Result<()> {
    ensure!(
        sealed["scope"] == capture_scope(frame, evidence, captured)?
            && shared.store.verify_grant(
                "tracking_capture_receipt",
                &sealed["scope"],
                &sealed["grant"]
            )?,
        "original actual source receipt scope/hash authentication changed"
    );
    let reference = &sealed["reference"];
    let scope = json!({"version":1,"tracking":frame.record.tracking_scope(),"captureScope":sealed["scope"],
        "name":reference["name"],"hash":reference["hash"]});
    ensure!(
        reference["scope"] == scope
            && shared.store.verify_grant(
                "tracking_capture_receipt_sidecar",
                &scope,
                &reference["grant"]
            )?,
        "original actual source receipt sidecar authentication changed"
    );
    let actual: Value =
        serde_json::from_slice(&read_private(shared, reference, MAX_BASELINE_BYTES)?)?;
    ensure!(
        &actual == evidence,
        "reloaded native source receipt does not match original authenticated preparation"
    );
    Ok(())
}

fn historical_snapshot(
    full_scope: bool,
    original: Option<&Snapshot>,
    captured: &Snapshot,
    selected: &BTreeSet<String>,
) -> Result<Snapshot> {
    let mut baseline = if full_scope {
        captured.clone()
    } else {
        original.cloned().unwrap_or_default()
    };
    baseline.content_captured = true;
    if !full_scope {
        for id in selected {
            if let Some(node) = captured.nodes.get(id) {
                ensure!(
                    baseline.nodes.contains_key(id) || baseline.nodes.len() < MAX_FILES,
                    "historical partial baseline exceeds native node bounds"
                );
                baseline.nodes.insert(id.clone(), node.clone());
            } else {
                baseline.nodes.remove(id);
            }
        }
    }
    baseline.identity()?; // Persisted metadata ceiling before any state mutation.
    Ok(baseline)
}

/// Retire authority, never files/history. Revoke both lineage references after
/// the record no longer points at them, so completed work is not replayable.
pub(crate) fn retire_reference(shared: &Shared, app: &mut Runtime) -> Result<()> {
    let Some(reference) = app.record.pending_work.clone() else {
        return Ok(());
    };
    // Do not retire a cached preparation if persistence actually advanced to a
    // different accepted frame (or another authority) during a failed handoff.
    readback_reference(shared.store.as_ref(), &app.record)?;
    let original = app
        .pending
        .as_ref()
        .and_then(|pending| pending.original_frame.as_ref())
        .and_then(|frame| frame.original_reference.clone());
    app.record.pending_work = None;
    if let Err(error) = shared
        .persist(app)
        .and_then(|()| readback_reference(shared.store.as_ref(), &app.record))
    {
        app.record.pending_work = Some(reference);
        return Err(error).context("retire exact native frame reference durably");
    }
    shared.store.revoke_grant(FRAME_KIND, &reference["scope"])?;
    if let Some(original) = original {
        shared.store.revoke_grant(FRAME_KIND, &original["scope"])?;
    }
    let mut quota = shared
        .frozen_frames
        .lock()
        .map_err(|_| anyhow::anyhow!("native frame quota poisoned"))?;
    quota.active.remove(&app.record.id);
    quota.loaded.remove(&app.record.id);
    Ok(())
}

pub(crate) fn complete_recovered(
    shared: &Shared,
    app: &mut Runtime,
    work_id: &str,
    generation: u64,
    success: bool,
) -> Result<Value> {
    let pending = app
        .pending
        .as_ref()
        .context("original recovered work is missing")?;
    ensure!(
        pending.work_id == work_id && pending.generation == generation,
        "original completion identity changed"
    );
    if !success {
        app.scheduler
            .complete(work_id, generation, false, false, shared.now())?;
        app.pending = None;
        app.force_hash = true;
        shared.persist(app)?;
        return Ok(
            json!({"workId":work_id,"generation":generation,"sourceConfirmed":false,
            "originalWorkRetained":true,"reconciliationRequired":true,"software":app.record.sanitized()}),
        );
    }
    let frame = pending
        .original_frame
        .as_ref()
        .context("original native frame is missing")?;
    verify_authority(shared, app, frame)?;
    receipt::verify_pending_receipt(shared, app, pending)?;
    pending
        .receipt
        .as_ref()
        .unwrap()
        .verify_committed()
        .context("recovered completion requires actual source COMMITTED cryptographic receipt")?;
    let baseline = historical_snapshot(
        pending.full_scope,
        pending.frozen_baseline.as_deref(),
        &pending.captured,
        &pending.selected,
    )?;
    let total = shared
        .baseline_entries
        .load(Ordering::Acquire)
        .checked_sub(
            app.baseline
                .as_ref()
                .map_or(0, |baseline| baseline.nodes.len()),
        )
        .and_then(|total| total.checked_add(baseline.nodes.len()))
        .context("historical baseline node count overflow")?;
    let paths = shared
        .baseline_path_bytes
        .load(Ordering::Acquire)
        .checked_sub(
            app.baseline
                .as_ref()
                .map(|baseline| baseline.path_bytes())
                .transpose()?
                .unwrap_or(0),
        )
        .and_then(|bytes| bytes.checked_add(baseline.path_bytes().ok()?))
        .context("historical baseline path count overflow")?;
    ensure!(
        total <= MAX_FILES && paths <= model::MAX_PATH_BYTES,
        "historical baseline exceeds global metadata bounds"
    );
    let mut record = app.record.clone();
    record.baseline_full_scope = pending.full_scope || pending.frozen_baseline_full_scope;
    record.baseline = Some(scan::save_baseline(
        &baseline,
        &record,
        shared.store.as_ref(),
        &shared.policy,
    )?);
    // This is historical cloud confirmation only. Current/confirmed counters,
    // lastSavedAt and today's actual index are NOT replaced or acknowledged.
    shared.store.save_record(&serde_json::to_value(&record)?)?;
    app.record = record;
    app.baseline = Some(Arc::new(baseline));
    shared.baseline_entries.store(total, Ordering::Release);
    shared.baseline_path_bytes.store(paths, Ordering::Release);
    app.scheduler
        .complete(work_id, generation, true, false, shared.now())?;
    app.scheduler.require_reconcile();
    app.scheduler.content_dirty = true;
    app.force_hash = true;
    retire_reference(shared, app)?; // Pending retained until both original grants retire.
    app.pending = None;
    shared.persist(app)?;
    shared.wake();
    Ok(
        json!({"workId":work_id,"generation":generation,"sourceConfirmed":true,
        "historicalBaselineConfirmed":true,"currentGenerationConfirmed":false,
        "reconciliationRequired":true,"software":app.record.sanitized()}),
    )
}

#[cfg(test)]
mod quota_tests {
    use super::*;
    #[test]
    fn native_frame_quota_and_optional_mac_domains_are_bounded_and_canonical() {
        // Quota arithmetic only, not invented native files or cloud counts.
        let mut quota = FrameQuota::default();
        for index in 0..MAX_FRAMES {
            quota.active.insert(format!("scope-{index}"), 1);
        }
        assert!(quota.check("one-too-many", 1).is_err());
        assert!(quota.check("scope-0", 1).is_ok());
        assert!(FrameQuota::default()
            .check("oversize", MAX_BASELINE_BYTES + 1)
            .is_err());
        assert_eq!(canonical_optional_object(&None).unwrap(), Value::Null);
        assert_eq!(
            bundle::digest(&canonical_optional_object(&None).unwrap()).unwrap(),
            bundle::digest(&Value::Null).unwrap()
        );
        assert!(canonical_optional_object(&Some(Value::Null)).is_err());
        assert!(canonical_optional_object(&Some(json!({"scope":{}}))).is_ok());
    }
}
