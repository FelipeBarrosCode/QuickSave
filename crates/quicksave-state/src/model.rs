// SPDX-License-Identifier: GPL-3.0-only

use crate::{bounded_json, validate_id, validate_text};
use anyhow::{ensure, Context, Result};
use quicksave_platform::FileStamp;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROVIDERS: usize = 256;
pub const MAX_SOFTWARE: usize = 4096;
pub const MAX_ROOTS: usize = 64;
const MAX_PENDING_WORK_REFERENCE_BYTES: usize = 64 * 1024;
const MAX_PENDING_WORK_FRAMES: usize = 64;
const MAX_PENDING_WORK_FRAME_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFileStampID {
    pub device: u64,
    #[serde(alias = "file_id")]
    pub file_id: [u64; 2],
}

impl From<&FileStamp> for NativeFileStampID {
    fn from(stamp: &FileStamp) -> Self {
        Self {
            device: stamp.device,
            file_id: stamp.file_id,
        }
    }
}

/// Native IDs must come from a caller's pinned handles, never from a webview.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateRoot {
    pub id: String,
    pub path: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub identity: NativeFileStampID,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<FileStamp>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub directory: bool,
    #[serde(default, alias = "fileAllowlist")]
    pub allowed_files: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

fn default_true() -> bool {
    true
}
fn is_true(value: &bool) -> bool {
    *value
}
fn default_software_status() -> String {
    "needs_backup".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateSoftware {
    pub id: String,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<Value>,
    pub name: String,
    #[serde(default)]
    pub tracked: bool,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default = "default_software_status")]
    pub status: String,
    #[serde(default)]
    pub autosave: bool,
    #[serde(default)]
    pub autosave_grant: Option<Value>,
    #[serde(default)]
    pub tracking_grant: Option<Value>,
    #[serde(default = "default_true")]
    pub dirty: bool,
    #[serde(default)]
    pub dirty_generation: u64,
    /// Tracker's native uncertainty partition; never tracking/write authority.
    #[serde(default)]
    pub unknown_generation: u64,
    /// Current clean-state projection, not historical upload or source authority.
    #[serde(default)]
    pub confirmed_generation: Option<u64>,
    #[serde(default)]
    pub last_confirmed_uploaded_generation: u64,
    #[serde(default)]
    pub last_confirmed_version: Option<String>,
    #[serde(default)]
    pub last_saved_at: Option<String>,
    #[serde(default)]
    pub file_count: Option<u64>,
    #[serde(default)]
    pub logical_bytes: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub roots: Vec<StateRoot>,
    /// Bounded tracker hashes/receipts, not arbitrary application settings.
    #[serde(default)]
    pub baseline: Option<Value>,
    #[serde(default)]
    pub reconciliation_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_index_source: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_index_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_index_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_root_roles: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_permissions: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_enrollment_policy: Option<Value>,
    #[serde(default)]
    pub baseline_full_scope: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_bundle_manifest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_enrollment: Option<StateAutoEnrollment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_receipt: Option<Value>,
    /// Private native-frame locator, never a source capability or a UI field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_work: Option<Value>,
}

impl StateSoftware {
    pub fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            app_id: None,
            source_identity: None,
            tracked: false,
            provider_id: None,
            status: default_software_status(),
            autosave: false,
            autosave_grant: None,
            tracking_grant: None,
            dirty: true,
            dirty_generation: 0,
            unknown_generation: 0,
            confirmed_generation: None,
            last_confirmed_uploaded_generation: 0,
            last_confirmed_version: None,
            last_saved_at: None,
            file_count: None,
            logical_bytes: None,
            error: None,
            roots: Vec::new(),
            baseline: None,
            reconciliation_required: true,
            revision_id: None,
            bundle_index_source: None,
            bundle_index_ref: None,
            bundle_index_hash: None,
            native_root_roles: None,
            coverage: None,
            missing_permissions: None,
            global_enrollment_policy: None,
            baseline_full_scope: false,
            previous_bundle_manifest: None,
            auto_enrollment: None,
            app_running: None,
            capture_receipt: None,
            pending_work: None,
        }
    }

    /// A native Tracker result supplies the status and reconciliation state.
    /// This projection never verifies or replaces its source index/receipt.
    pub(crate) fn current_confirmation(&self) -> Option<u64> {
        (self.tracked
            && self.status == "saved"
            && !self.dirty
            && !self.reconciliation_required
            && self.last_confirmed_uploaded_generation != 0
            && self.last_confirmed_uploaded_generation == self.dirty_generation)
            .then_some(self.last_confirmed_uploaded_generation)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(reference) = &self.pending_work {
            validate_pending_work_reference(reference, &self.id)?;
        }
        if let Some(identity) = &self.source_identity {
            bounded_json(identity, 16 * 1024)?;
            reject_secret_keys(identity)?;
            let app = identity["app_id"]
                .as_str()
                .context("native source identity lacks app_id")?;
            validate_text(app, 512, "native source app identity")?;
            // Canonical product identity (e.g. steam:480) is distinct from
            // app_id's installation binding (steam:480@native-installation).
            // Tracking MACs bind BOTH appId and the full unchanged sourceIdentity;
            // native enrollment, not equality here, verifies their relationship.
        }
        if let Some(enrollment) = &self.auto_enrollment {
            enrollment.validate()?;
        }
        for value in [&self.previous_bundle_manifest, &self.capture_receipt]
            .into_iter()
            .flatten()
        {
            bounded_json(value, 128 * 1024)?;
            reject_secret_keys(value)?;
        }
        if let Some(revision) = &self.revision_id {
            validate_id(revision)?;
        }
        if let Some(reference) = &self.bundle_index_ref {
            validate_text(
                reference,
                quicksave_platform::MAX_PATH_BYTES,
                "bundle index reference",
            )?;
        }
        if let Some(hash) = &self.bundle_index_hash {
            ensure!(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "bundle index hash must be lowercase 256-bit hex"
            );
        }
        for value in [
            &self.bundle_index_source,
            &self.native_root_roles,
            &self.coverage,
            &self.missing_permissions,
            &self.global_enrollment_policy,
        ]
        .into_iter()
        .flatten()
        {
            bounded_json(value, 512 * 1024)?;
            reject_secret_keys(value)?;
        }
        validate_id(&self.id)?;
        validate_text(&self.name, 512, "software name")?;
        if let Some(id) = &self.app_id {
            validate_text(id, 1024, "application ID")?;
        }
        if let Some(id) = &self.provider_id {
            validate_id(id)?;
        }
        ensure!(
            matches!(
                self.status.as_str(),
                "needs_backup" | "saved" | "checking" | "uploading" | "error" | "not_tracked"
            ),
            "invalid software status"
        );
        ensure!(self.roots.len() <= MAX_ROOTS, "too many tracked roots");
        let mut ids = BTreeSet::new();
        for root in &self.roots {
            validate_id(&root.id)?;
            ensure!(ids.insert(&root.id), "duplicate root ID");
            validate_text(&root.path, quicksave_platform::MAX_PATH_BYTES, "root path")?;
            let path = std::path::Path::new(&root.path);
            ensure!(path.is_absolute(), "tracked root path must be absolute");
            ensure!(
                !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
                "tracked root path contains parent traversal"
            );
            if let Some(role) = &root.role {
                validate_text(role, 128, "root role")?;
            }
            if let Some(stamp) = &root.stamp {
                ensure!(
                    NativeFileStampID::from(stamp) == root.identity,
                    "root stamp identity mismatch"
                );
            }
            if let Some(files) = &root.allowed_files {
                ensure!(
                    !files.is_empty() && files.len() <= 4096,
                    "invalid manual file allowlist"
                );
                for file in files {
                    validate_text(file, 255, "manual file leaf")?;
                    ensure!(
                        !file.contains(['/', '\\', ':']) && file != "." && file != "..",
                        "manual file allowlist must contain ordinary leaves only"
                    );
                }
            }
            if let Some(source) = &root.source {
                bounded_json(source, 4096)?;
                reject_secret_keys(source)?;
            }
        }
        if self.tracked {
            ensure!(
                !self.roots.is_empty(),
                "tracked software requires native roots"
            );
        }
        if let Some(error) = &self.error {
            validate_text(error, 1024, "software error")?;
        }
        for value in [&self.last_saved_at, &self.last_confirmed_version]
            .into_iter()
            .flatten()
        {
            validate_text(value, 1024, "saved version metadata")?;
        }
        if let Some(value) = &self.baseline {
            bounded_json(value, 2 * 1024 * 1024)?;
            reject_secret_keys(value)?;
        }
        if let Some(grant) = &self.autosave_grant {
            bounded_json(grant, 128 * 1024)?;
        }
        if let Some(grant) = &self.tracking_grant {
            bounded_json(grant, 128 * 1024)?;
        }
        ensure!(
            self.last_confirmed_uploaded_generation <= self.dirty_generation,
            "confirmed upload generation is in the future"
        );
        if let Some(confirmed) = self.confirmed_generation {
            ensure!(
                confirmed <= self.dirty_generation,
                "confirmed generation is in the future"
            );
        }
        if self.unknown_generation != 0 && (self.dirty || self.reconciliation_required) {
            ensure!(
                self.confirmed_generation.is_none() && self.status != "saved",
                "unknown-dirty data cannot have a current saved confirmation"
            );
        }
        Ok(())
    }

    pub fn sanitized(&self, autosave_verified: bool) -> Value {
        let bundle = self.bundle_index_source.as_ref().map(|source| {
            let mut projection = serde_json::Map::new();
            for key in [
                "revisionId",
                "snapshotIdentity",
                "indexedAt",
                "contentState",
                "fileCount",
                "logicalBytes",
                "directoryCount",
                "symlinkCount",
                "coverage",
            ] {
                if let Some(value) = source.get(key) {
                    projection.insert(key.into(), value.clone());
                }
            }
            if let Some(roots) = source.get("roots").and_then(Value::as_array) {
                projection.insert(
                    "roots".into(),
                    Value::Array(
                        roots
                            .iter()
                            .take(MAX_ROOTS)
                            .map(|root| {
                                let mut projected = serde_json::Map::new();
                                for key in [
                                    "rootId",
                                    "role",
                                    "roles",
                                    "fileCount",
                                    "logicalBytes",
                                    "directoryCount",
                                    "symlinkCount",
                                    "scope",
                                ] {
                                    if let Some(value) = root.get(key) {
                                        projected.insert(key.into(), value.clone());
                                    }
                                }
                                Value::Object(projected)
                            })
                            .collect(),
                    ),
                );
            }
            projection.insert(
                "coverageScope".into(),
                json!("approved_evidenced_roots_only"),
            );
            projection.insert(
                "consistency".into(),
                json!("validated_stable_files_not_application_atomic"),
            );
            projection.insert("cloudCommitted".into(), json!(false));
            Value::Object(projection)
        });
        json!({
            "id": self.id, "appId": self.app_id, "name": self.name,
            "tracked": self.tracked, "providerId": self.provider_id,
            "status": self.status, "autosave": self.autosave && autosave_verified,
            "dirty": self.dirty, "lastSavedAt": self.last_saved_at,
            "unknownGeneration": self.unknown_generation,
            "fileCount": self.file_count, "logicalBytes": self.logical_bytes,
            "error": self.error,
            "appRunning":self.app_running,"bundle":bundle,
        })
    }
}

/// These borrowed schemas are validation-only. Keep the original Value byte
/// semantics; never reserialize a typed scope to change a native MAC payload.
/// Shape validation is NOT authentication: Tracker still checks the actual
/// tracking_frozen_work MAC, nonce, parent grants and private no-follow file.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingWorkReference<'a> {
    version: u32,
    name: &'a str,
    hash: &'a str,
    bytes: u64,
    #[serde(borrow)]
    scope: PendingWorkScope<'a>,
    #[serde(borrow)]
    grant: PendingWorkGrant<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingWorkScope<'a> {
    version: u32,
    software_id: &'a str,
    work_id: &'a str,
    generation: u64,
    origin_token: &'a str,
    // Presence is checked separately: explicit null must never normalize into
    // an absent field in the retained MAC payload.
    #[serde(borrow)]
    app_id: Option<&'a str>,
    #[serde(borrow)]
    provider_id: Option<&'a str>,
    tracking_scope_hash: &'a str,
    tracking_grant_hash: &'a str,
    source_identity_hash: &'a str,
    autosave_scope_hash: &'a str,
    authorization_hash: &'a str,
    automatic: bool,
    unknown_generation: u64,
    metadata_identity: &'a str,
    full_scope_proof_hash: &'a str,
    baseline_reference_hash: &'a str,
    selected_ids_hash: &'a str,
    deleted_ids_hash: &'a str,
    original_reference_hash: &'a str,
    capture_receipt_hash: &'a str,
    frame_hash: &'a str,
    name: &'a str,
    bytes: u64,
    stage: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingWorkGrant<'a> {
    version: u32,
    algorithm: &'a str,
    mac: &'a str,
    kind: &'a str,
    nonce: &'a str,
    authority_ref: &'a str,
}

fn validate_pending_work_hash(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native work reference requires a raw lowercase 256-bit hex value"
    );
    Ok(())
}

pub(crate) fn validate_pending_work_reference(value: &Value, software_id: &str) -> Result<()> {
    bounded_json(value, MAX_PENDING_WORK_REFERENCE_BYTES)?;
    ensure!(
        value["scope"].get("appId").is_some() && value["scope"].get("providerId").is_some(),
        "native work reference is missing nullable scope fields"
    );
    let reference = PendingWorkReference::deserialize(value)
        .map_err(|_| anyhow::anyhow!("native work reference contains invalid or unknown fields"))?;
    let scope = &reference.scope;
    ensure!(
        reference.version == 1 && scope.version == 1,
        "unsupported native work reference version"
    );
    validate_id(reference.name)?;
    ensure!(
        reference.name.len() <= 255
            && reference.name.starts_with("work-")
            && reference.name.ends_with(".json"),
        "native work reference must name one private work-file leaf"
    );
    ensure!(
        reference.bytes > 0 && reference.bytes <= MAX_PENDING_WORK_FRAME_BYTES,
        "native work reference exceeds its frame byte bound"
    );
    ensure!(
        scope.software_id == software_id
            && scope.name == reference.name
            && scope.frame_hash == reference.hash
            && scope.bytes == reference.bytes,
        "native work reference header differs from its frozen scope"
    );
    validate_id(scope.software_id)?;
    validate_id(scope.work_id)?;
    validate_id(scope.origin_token)?;
    if let Some(id) = scope.app_id {
        validate_text(id, 1024, "native work application ID")?;
        let bytes = id.as_bytes();
        ensure!(
            !id.starts_with(['/', '\\'])
                && !(bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'/' | b'\\')),
            "native work reference cannot contain an absolute application path"
        );
    }
    if let Some(id) = scope.provider_id {
        validate_id(id)?;
    }
    ensure!(
        matches!(scope.stage, "metadata_frozen" | "source_receipt_accepted"),
        "invalid native work frame stage"
    );
    for hash in [
        reference.hash,
        scope.tracking_scope_hash,
        scope.tracking_grant_hash,
        scope.source_identity_hash,
        scope.autosave_scope_hash,
        scope.authorization_hash,
        scope.metadata_identity,
        scope.full_scope_proof_hash,
        scope.baseline_reference_hash,
        scope.selected_ids_hash,
        scope.deleted_ids_hash,
        scope.original_reference_hash,
        scope.capture_receipt_hash,
    ] {
        validate_pending_work_hash(hash)?;
    }
    // Read the scalar fields without comparing them to CURRENT state. Original
    // generation/unknown counters must remain lossless u64 historical values;
    // only Tracker authenticates their relationship to the original private work.
    let _ = (scope.generation, scope.unknown_generation, scope.automatic);
    let grant = &reference.grant;
    ensure!(
        grant.version == 1
            && grant.algorithm == "hmac-sha256"
            && grant.kind == "tracking_frozen_work",
        "invalid native work reference grant schema"
    );
    validate_pending_work_hash(grant.mac)?;
    validate_pending_work_hash(grant.nonce)?;
    // Pure deterministic account-name derivation only: no device key, vault
    // access, grant verification/issuance, registry write or nonce rotation.
    ensure!(
        grant.authority_ref == crate::authority_account(grant.kind, &value["scope"])?,
        "native work reference has an invalid authority slot"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAutoEnrollment {
    pub policy_scope: Value,
    pub policy_grant: Value,
    pub discovery_scope: Value,
    pub discovery_grant: Value,
    pub app_evidence_hash: String,
    pub identity_evidence: Value,
    pub unresolved_roots: Value,
    pub unresolved_reasons: Value,
    pub roots_complete: bool,
    #[serde(default)]
    pub candidate_hash: String,
}
impl StateAutoEnrollment {
    pub(crate) fn validate(&self) -> Result<()> {
        bounded_json(&self.policy_scope, 512 * 1024)?;
        bounded_json(&self.discovery_scope, 64 * 1024)?;
        bounded_json(&self.policy_grant, 4096)?;
        bounded_json(&self.discovery_grant, 4096)?;
        let parsed: AppTrackingPolicyScope = serde_json::from_value(self.policy_scope.clone())
            .map_err(|_| anyhow::anyhow!("invalid native auto-enrollment policy schema"))?;
        AppTrackingSettings {
            policy_scope: parsed,
            policy_grant: self.policy_grant.clone(),
        }
        .validate()?;
        let policy_hash = blake3::hash(&serde_json::to_vec(&self.policy_scope)?)
            .to_hex()
            .to_string();
        ensure!(
            self.discovery_scope["version"] == 1
                && self.discovery_scope["source"] == "verified_native_discovery"
                && self.discovery_scope["policyHash"].as_str() == Some(policy_hash.as_str()),
            "native discovery attestation does not bind the enrollment policy"
        );
        for value in [
            &self.identity_evidence,
            &self.unresolved_roots,
            &self.unresolved_reasons,
        ] {
            bounded_json(value, 512 * 1024)?;
            reject_secret_keys(value)?;
        }
        for hash in [&self.app_evidence_hash, &self.candidate_hash] {
            ensure!(
                hash.is_empty()
                    || hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "native enrollment digest is invalid"
            );
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> Result<Value> {
        self.validate()?;
        Ok(json!({
            "policyHash":blake3::hash(&serde_json::to_vec(&self.policy_scope)?).to_hex().to_string(),
            "discoveryHash":blake3::hash(&serde_json::to_vec(&self.discovery_scope)?).to_hex().to_string(),
            "appEvidenceHash":self.app_evidence_hash, "candidateHash":self.candidate_hash,
            "coverageHash":blake3::hash(&serde_json::to_vec(&json!({
                "rootsComplete":self.roots_complete,
                "unresolvedRoots":self.unresolved_roots,
                "unresolvedReasons":self.unresolved_reasons,
            }))?).to_hex().to_string(),
        }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub origin: String,
    pub read_only: bool,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    /// Non-secret destination metadata for native consent, not a UI settings
    /// editor. Access rebinds this exact projection to protected provider fields.
    #[serde(default)]
    pub public_scope: BTreeMap<String, String>,
    /// Opaque QuickSave-native account references, never source-vault references.
    pub credential_ref: String,
    pub repository_key_ref: String,
    #[serde(default)]
    pub source_profile_id: Option<String>,
    /// Explicit reauthorization/account boundary, NOT token rotation revision.
    #[serde(default)]
    pub authority_revision: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl ProviderRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        validate_text(&self.name, 512, "provider name")?;
        let kind = noland_rclone_adapter::ProviderKind::parse(&self.kind)
            .context("unknown provider kind")?;
        ensure!(
            kind != noland_rclone_adapter::ProviderKind::Local,
            "local provider is test-only"
        );
        ensure!(
            self.kind == kind.as_str(),
            "provider kind must use its canonical identifier"
        );
        ensure!(
            matches!(
                self.status.as_str(),
                "connecting" | "connected" | "disconnected" | "error"
            ),
            "invalid provider status"
        );
        ensure!(
            matches!(self.origin.as_str(), "quicksave" | "noland"),
            "invalid provider origin"
        );
        ensure!(
            self.credential_ref == format!("provider.{}", self.id),
            "invalid credential reference"
        );
        ensure!(
            self.repository_key_ref == crate::REPOSITORY_KEY_ACCOUNT
                || self.repository_key_ref == format!("repository.import.{}", self.id),
            "invalid repository key reference"
        );
        for value in [&self.bucket, &self.prefix].into_iter().flatten() {
            ensure!(
                value.len() <= 4096 && !value.chars().any(char::is_control),
                "invalid provider root"
            );
        }
        crate::validate_provider_root(self.bucket.as_deref(), self.prefix.as_deref())?;
        crate::provider::validate_public_scope(&self.public_scope)?;
        if let Some(id) = &self.source_profile_id {
            validate_id(id)?;
        }
        if let Some(error) = &self.error {
            validate_text(error, 1024, "provider error")?;
        }
        Ok(())
    }

    pub fn sanitized(&self) -> Value {
        json!({
            "id": self.id, "name": self.name, "kind": self.kind,
            "status": self.status, "origin": self.origin, "readOnly": self.read_only,
            "error": self.error,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceSettings {
    #[serde(default)]
    pub launch_at_login: bool,
    #[serde(default = "default_true")]
    pub keep_local_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_tracking: Option<AppTrackingSettings>,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            keep_local_data: true,
            app_tracking: None,
        }
    }
}

/// Mirrors Tracker's policyScope exactly, not a plaintext boolean enrollment
/// authority. The grant remains native-private and is verified before use.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppTrackingSettings {
    pub policy_scope: AppTrackingPolicyScope,
    pub policy_grant: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppTrackingPolicyScope {
    pub version: u32,
    pub policy_id: String,
    pub role_policy_version: u32,
    pub source: String,
    pub enabled: bool,
    pub base_directories: Vec<AppTrackingBaseDirectory>,
    pub app_identity_policy: AppTrackingIdentityPolicy,
    pub excluded_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "ScopeProviderId::is_absent")]
    pub provider_id: ScopeProviderId,
}

/// Preserve absent versus explicit null in Tracker's authenticated raw scope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ScopeProviderId {
    #[default]
    Absent,
    Null,
    Id(String),
}
impl ScopeProviderId {
    fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
    pub fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Id(id) => Some(id),
            _ => None,
        }
    }
}
impl Serialize for ScopeProviderId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Id(id) => serializer.serialize_str(id),
            _ => serializer.serialize_none(),
        }
    }
}
impl<'de> Deserialize<'de> for ScopeProviderId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(deserializer)? {
            Some(id) => Self::Id(id),
            None => Self::Null,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppTrackingBaseDirectory {
    pub id: String,
    pub path: String,
    pub identity: NativeFileStampID,
    pub allowed_roles: Vec<String>,
    pub ownership_rules: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppTrackingIdentityPolicy {
    pub allowed_app_ids: Vec<String>,
    pub allow_new_verified_apps: bool,
    pub allowed_evidence_kinds: Vec<String>,
    pub allow_native_installation_only: bool,
}

impl AppTrackingSettings {
    pub(crate) fn validate(&self) -> Result<()> {
        let scope = &self.policy_scope;
        ensure!(
            scope.version == 1
                && scope.role_policy_version == 1
                && scope.source == "verified_native_discovery",
            "unrecognized app-tracking policy"
        );
        validate_id(&scope.policy_id)?;
        ensure!(
            !scope.base_directories.is_empty() && scope.base_directories.len() <= MAX_ROOTS,
            "app-tracking policy needs a bounded native base set"
        );
        let mut ids = BTreeSet::new();
        for base in &scope.base_directories {
            validate_id(&base.id)?;
            ensure!(ids.insert(&base.id), "duplicate app-tracking base ID");
            validate_native_policy_path(&base.path)?;
            ensure!(
                !base.allowed_roles.is_empty() && base.allowed_roles.len() <= 10,
                "app-tracking role set is invalid"
            );
            for role in &base.allowed_roles {
                ensure!(
                    matches!(
                        role.as_str(),
                        "installation"
                            | "save"
                            | "config"
                            | "container"
                            | "group_container"
                            | "data"
                            | "runtime"
                            | "installer"
                    ),
                    "unsupported app-tracking root role"
                );
            }
            ensure!(
                !base.ownership_rules.is_empty() && base.ownership_rules.len() <= 64,
                "app-tracking ownership rules are missing or oversized"
            );
            for rule in &base.ownership_rules {
                validate_text(rule, 128, "native ownership rule")?;
            }
        }
        let policy = &scope.app_identity_policy;
        ensure!(
            policy.allowed_app_ids.len() <= MAX_SOFTWARE
                && !policy.allowed_evidence_kinds.is_empty()
                && policy.allowed_evidence_kinds.len() <= 64,
            "app identity policy is outside its bounds"
        );
        for app in &policy.allowed_app_ids {
            validate_text(app, 1024, "approved app ID")?;
        }
        for evidence in &policy.allowed_evidence_kinds {
            validate_text(evidence, 128, "native identity evidence kind")?;
        }
        ensure!(
            scope.excluded_paths.len() <= 128,
            "too many app-tracking exclusions"
        );
        for path in &scope.excluded_paths {
            validate_native_policy_path(path)?;
        }
        if let Some(provider) = scope.provider_id.as_deref() {
            validate_id(provider)?;
        }
        bounded_json(&serde_json::to_value(scope)?, 512 * 1024)?;
        bounded_json(&self.policy_grant, 4096)?;
        Ok(())
    }
}

fn validate_native_policy_path(path: &str) -> Result<()> {
    validate_text(
        path,
        quicksave_platform::MAX_PATH_BYTES,
        "native policy path",
    )?;
    let path = std::path::Path::new(path);
    ensure!(
        path.is_absolute()
            && path.parent().is_some()
            && !path.components().any(|part| matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )),
        "native policy paths must be absolute non-root paths without traversal"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceDocument {
    pub version: u32,
    pub generation: u64,
    pub providers: Vec<ProviderRecord>,
    pub software: Vec<StateSoftware>,
    pub settings: WorkspaceSettings,
}

impl Default for WorkspaceDocument {
    fn default() -> Self {
        Self {
            version: 2,
            generation: 0,
            providers: Vec::new(),
            software: Vec::new(),
            settings: WorkspaceSettings::default(),
        }
    }
}

impl WorkspaceDocument {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.version == 2, "unsupported workspace state version");
        ensure!(
            self.providers.len() <= MAX_PROVIDERS,
            "too many provider profiles"
        );
        if let Some(policy) = &self.settings.app_tracking {
            policy.validate()?;
            if let Some(id) = policy.policy_scope.provider_id.as_deref() {
                ensure!(
                    self.providers.iter().any(|provider| provider.id == id),
                    "app-tracking default provider does not exist"
                );
            }
        }
        ensure!(
            self.software.len() <= MAX_SOFTWARE,
            "too many software records"
        );
        ensure!(
            self.settings.keep_local_data,
            "QuickSave never authorizes automatic local deletion"
        );
        let mut ids = BTreeSet::new();
        for provider in &self.providers {
            provider.validate()?;
            ensure!(ids.insert(&provider.id), "duplicate provider ID");
        }
        let mut ids = BTreeSet::new();
        let mut pending_frames = 0_usize;
        let mut pending_bytes = 0_u64;
        for software in &self.software {
            software.validate()?;
            if let Some(reference) = &software.pending_work {
                pending_frames += 1;
                pending_bytes = pending_bytes
                    .checked_add(
                        reference["bytes"]
                            .as_u64()
                            .context("invalid native frame size")?,
                    )
                    .context("native frame aggregate byte count overflow")?;
                ensure!(
                    pending_frames <= MAX_PENDING_WORK_FRAMES
                        && pending_bytes <= MAX_PENDING_WORK_FRAME_BYTES,
                    "pending native work exceeds 64 frames / 128 MiB"
                );
            }
            ensure!(ids.insert(&software.id), "duplicate software ID");
            if let Some(id) = &software.provider_id {
                ensure!(
                    self.providers.iter().any(|provider| &provider.id == id),
                    "software provider does not exist"
                );
            }
        }
        Ok(())
    }
}

pub(crate) fn reject_secret_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase().replace(['_', '-'], "");
                ensure!(
                    ![
                        "password",
                        "secret",
                        "privatekey",
                        "accesstoken",
                        "refreshtoken",
                        "repositorykey",
                        "credentials",
                        "configini"
                    ]
                    .iter()
                    .any(|needle| lower.contains(needle)),
                    "secret-bearing fields cannot be stored in workspace settings"
                );
                reject_secret_keys(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
