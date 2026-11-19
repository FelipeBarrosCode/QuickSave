// SPDX-License-Identifier: GPL-3.0-only
//! Real immutable local bundle indexes. Discovery plans are never bundle DTOs.

use crate::{
    diagnostics::{self, RootContext, RootFailures},
    model::{
        self, validate_absolute, validate_id, validate_name, validate_relative, ApprovedRoot,
        RootIdentity, Snapshot, TrackedSoftware, TrackingPolicy, MAX_BASELINE_BYTES, MAX_FILES,
        MAX_ROOTS, MAX_SOFTWARE,
    },
    scan, Runtime, Scheduler, Tracker, TrackingStore,
};
use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::SafeRoot;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const MAX_BASES: usize = 64;
const MAX_DIAGNOSTICS: usize = 256;
const MAX_DIAGNOSTIC_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityPolicy {
    allowed_app_ids: BTreeSet<String>,
    allow_new_verified_apps: bool,
    allowed_evidence_kinds: BTreeSet<String>,
    allow_native_installation_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaseDirectory {
    id: String,
    path: PathBuf,
    identity: RootIdentity,
    allowed_roles: BTreeSet<String>,
    ownership_rules: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentPolicy {
    version: u32,
    policy_id: String,
    role_policy_version: u32,
    source: String,
    enabled: bool,
    base_directories: Vec<BaseDirectory>,
    app_identity_policy: IdentityPolicy,
    excluded_paths: Vec<PathBuf>,
    #[serde(default)]
    provider_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AutoEnrollment {
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

impl AutoEnrollment {
    pub(crate) fn has_failed_roots(&self) -> bool {
        self.failed_roots().next().is_some()
    }

    fn failed_roots(&self) -> impl Iterator<Item = &Value> {
        self.unresolved_roots
            .as_array()
            .into_iter()
            .flatten()
            .filter(|root| {
                root["preventsFullScopeCapture"] == true
                    || root["code"] == "native_root_index_unavailable"
                    || root["code"] == "container_boundary_indexed_via_verified_children"
            })
    }

    fn unavailable_roots(&self) -> impl Iterator<Item = &Value> {
        self.failed_roots()
            .filter(|root| !intentional_omission(root))
    }

    pub(crate) fn root_failure_message(&self) -> Option<String> {
        // A signed policy omission still prevents complete-application capture,
        // but is not a native permission/integrity error.
        let first = self.unavailable_roots().next()?;
        Some(diagnostics::bounded_message(format_args!(
            "{} native application root scope(s) unresolved; explicitly partial coverage. {}",
            self.unavailable_roots().count(),
            first["message"]
                .as_str()
                .unwrap_or("Native root indexing failed.")
        )))
    }

    pub(crate) fn binding(&self) -> Value {
        json!({
            "policyHash": digest(&self.policy_scope).unwrap_or_default(),
            "discoveryHash": digest(&self.discovery_scope).unwrap_or_default(),
            "appEvidenceHash": self.app_evidence_hash,
            "candidateHash": self.candidate_hash,
            "coverageHash": digest(&json!({
                "rootsComplete": self.roots_complete,
                "unresolvedRoots": self.unresolved_roots,
                "unresolvedReasons": self.unresolved_reasons,
            })).unwrap_or_default(),
        })
    }

    pub(crate) fn verify(&self, store: &dyn TrackingStore, policy: &TrackingPolicy) -> Result<()> {
        model::bounded_json(&self.policy_scope, 512 * 1024)?;
        ensure!(
            store.verify_grant(
                "app_tracking_policy",
                &self.policy_scope,
                &self.policy_grant
            )? && store.verify_grant(
                "bundle_discovery",
                &self.discovery_scope,
                &self.discovery_grant
            )?,
            "automatic enrollment policy/discovery authority is invalid or revoked"
        );
        ensure!(
            self.discovery_scope["version"] == 1
                && self.discovery_scope["source"] == "verified_native_discovery"
                && self.discovery_scope["policyHash"] == digest(&self.policy_scope)?,
            "discovery attestation does not bind this native policy"
        );
        let parsed: EnrollmentPolicy = serde_json::from_value(self.policy_scope.clone())?;
        ensure!(
            parsed.version == 1
                && parsed.role_policy_version == 1
                && parsed.enabled
                && parsed.source == "verified_native_discovery",
            "automatic tracking policy is disabled/unsupported"
        );
        let _ = policy; // UI authority checks do no source I/O.
        Ok(())
    }

    pub(crate) fn revalidate_native(
        &self,
        store: &dyn TrackingStore,
        policy: &TrackingPolicy,
    ) -> Result<()> {
        self.verify(store, policy)?;
        let parsed: EnrollmentPolicy = serde_json::from_value(self.policy_scope.clone())?;
        parsed.pin(policy)?;
        Ok(())
    }

    pub(crate) fn verify_record(
        &self,
        record: &TrackedSoftware,
        store: &dyn TrackingStore,
        policy: &TrackingPolicy,
    ) -> Result<()> {
        self.verify(store, policy)?;
        ensure!(
            self.app_evidence_hash
                == digest(&json!({
                    "appId": record.app_id,
                    "identityEvidence": self.identity_evidence,
                    "roots": record.roots.iter().map(scan::root_request).collect::<Vec<_>>(),
                }))?,
            "automatic source-root/evidence proofs were altered"
        );
        Ok(())
    }
}

fn intentional_omission(root: &Value) -> bool {
    matches!(
        root["code"].as_str(),
        Some(
            "unselected_role"
                | "data_only_container_boundary_omitted"
                | "container_boundary_indexed_via_verified_children"
        )
    )
}

impl EnrollmentPolicy {
    fn pin(&self, policy: &TrackingPolicy) -> Result<Vec<(BaseDirectory, scan::PinnedRoot)>> {
        ensure!(
            self.version == 1
                && self.role_policy_version == 1
                && self.enabled
                && self.source == "verified_native_discovery",
            "unsupported or disabled automatic tracking policy"
        );
        validate_id(&self.policy_id)?;
        ensure!(
            !self.base_directories.is_empty() && self.base_directories.len() <= MAX_BASES,
            "invalid automatic enrollment base count"
        );
        ensure!(
            self.excluded_paths.len() <= 128,
            "too many native policy exclusions"
        );
        for path in &self.excluded_paths {
            validate_absolute(path)?;
        }
        let identities = &self.app_identity_policy;
        ensure!(
            identities.allowed_app_ids.len() <= MAX_SOFTWARE,
            "too many allowed app identities"
        );
        for id in &identities.allowed_app_ids {
            validate_id(id)?;
        }
        validate_rules(&identities.allowed_evidence_kinds)?;
        let mut ids = BTreeSet::new();
        let mut native_ids = BTreeSet::new();
        let mut pinned = Vec::new();
        for base in &self.base_directories {
            validate_id(&base.id)?;
            validate_absolute(&base.path)?;
            ensure!(
                !wide_home_base(&base.path),
                "a filesystem/home root is not an automatic enrollment base"
            );
            ensure!(
                ids.insert(base.id.clone())
                    && native_ids.insert((base.identity.device, base.identity.file_id)),
                "duplicate automatic enrollment base identity"
            );
            ensure!(
                !base.allowed_roles.is_empty() && base.allowed_roles.len() <= 10,
                "automatic enrollment has no bounded role policy"
            );
            for role in &base.allowed_roles {
                ensure!(is_role(role), "unsupported automatic enrollment role");
            }
            validate_rules(&base.ownership_rules)?;
            // Bases are authority anchors, not whole-tree read permission.
            // Opening/checking them never enumerates unapproved siblings.
            let root = ApprovedRoot {
                id: base.id.clone(),
                path: base.path.clone(),
                role: "manual".into(),
                identity: base.identity.clone(),
                allowed_files: None,
                source: None,
            };
            for component in base.path.components() {
                if let std::path::Component::Normal(name) = component {
                    ensure!(
                        !model::is_secret_component(
                            name.to_str().context("non-UTF8 base component")?
                        ),
                        "an enrollment base is excluded"
                    );
                }
            }
            for excluded in std::iter::once(&policy.data_dir)
                .chain(policy.excluded_paths.iter())
                .chain(self.excluded_paths.iter())
            {
                ensure!(
                    !base.path.starts_with(excluded),
                    "automatic enrollment base is inside protected state"
                );
            }
            pinned.push((base.clone(), scan::PinnedRoot::open(&root)?));
        }
        if let Some(provider) = &self.provider_id {
            validate_id(provider)?;
        }
        Ok(pinned)
    }
}

pub(crate) fn wide_home_base(path: &Path) -> bool {
    // Count normal components, not "/" or Windows drive/UNC prefixes. In
    // particular /Applications is a valid pinned BASE, never a whole-root grant.
    let names: Vec<_> = path
        .components()
        .filter_map(|component| {
            if let std::path::Component::Normal(name) = component {
                name.to_str()
            } else {
                None
            }
        })
        .collect();
    names.is_empty()
        || (names
            .first()
            .is_some_and(|name| matches!(*name, "Users" | "home"))
            && names.len() <= 2)
        || matches!(
            path.to_str(),
            Some("/root" | "/var/root" | "/private/var/root")
        )
        || std::env::var_os("HOME").is_some_and(|home| path == Path::new(&home))
}

fn validate_rules(rules: &BTreeSet<String>) -> Result<()> {
    ensure!(
        !rules.is_empty() && rules.len() <= 64,
        "invalid identity/ownership rule count"
    );
    for rule in rules {
        validate_id(rule)?;
        ensure!(
            known_evidence(rule),
            "unknown evidence rule cannot authorize automatic roots"
        );
    }
    Ok(())
}

fn known_evidence(kind: &str) -> bool {
    matches!(
        kind,
        "native_installation_handle"
            | "native_mapping_root_handle"
            | "native_approved_learned_association"
            | "native_executable_handle"
            | "cf_bundle_identifier"
            | "cf_bundle_executable_native_handle"
            | "validated_signed_bundle_identifier"
            | "exact_cf_bundle_identifier_path"
            | "cf_bundle_identifier_and_executable_handle"
            | "container_metadata_identifier"
            | "validated_signed_application_group"
            | "xdg_desktop_file_id"
            | "exact_flatpak_desktop_identifier"
            | "exact_namespaced_desktop_id_path"
            | "xdg_desktop_or_flatpak_identifier"
            | "exact_numeric_steam_app_id"
            | "exact_steam_appmanifest_id_and_installdir"
            | "inventory_approved_exact_steam_app_id_userdata_path"
            | "windows_registry_or_package_identity"
            | "reviewed_exact_windows_product_mapping"
            | "reviewed_exact_product_mapping"
    )
}

fn is_role(role: &str) -> bool {
    matches!(
        role,
        "installation"
            | "runtime"
            | "save"
            | "config"
            | "container"
            | "group_container"
            | "data"
            | "installer"
    )
}

fn role(classification: &str) -> Result<&str> {
    match classification {
        "install" => Ok("installation"),
        role if is_role(role) => Ok(role),
        _ => bail!("unresolved/unknown root classification cannot be indexed"),
    }
}

fn native_role(classification: &str) -> &str {
    match classification {
        "container" | "group_container" | "data" => "save",
        "installer" => "installation",
        other => other,
    }
}

/// Coverage decisions operate on authenticated declarations only. They neither
/// inspect the filesystem nor turn an omitted root into native authority.
struct RootDeclaration {
    classification: String,
    roles: BTreeSet<String>,
}

impl RootDeclaration {
    fn parse(root: &Value) -> Result<Self> {
        ensure!(root.is_object(), "invalid candidate root declaration");
        ensure!(
            root["status"] == "verified_candidate",
            "a proposed/unresolved root is not native authority"
        );
        validate_id(
            root["rootId"]
                .as_str()
                .context("candidate root ID is missing")?,
        )?;
        validate_absolute(Path::new(
            root["path"]
                .as_str()
                .context("candidate root path is missing")?,
        ))?;
        let classification = role(
            root["classification"]
                .as_str()
                .context("root classification is missing")?,
        )?;
        let roles = match root.get("roles") {
            None => BTreeSet::from([native_role(classification).to_owned()]),
            Some(value) => {
                let values = value
                    .as_array()
                    .context("invalid source roles declaration")?;
                ensure!(
                    !values.is_empty() && values.len() <= 10,
                    "invalid source role count"
                );
                values
                    .iter()
                    .map(|value| {
                        role(value.as_str().context("invalid source role")?)
                            .map(|role| native_role(role).to_owned())
                    })
                    .collect::<Result<BTreeSet<_>>>()?
            }
        };
        candidate_identity(&root["nativeIdentity"])?;
        evidence_kinds(&root["evidence"])?;
        let ownership = root["ownership"]
            .as_str()
            .context("source root lacks native ownership evidence")?;
        ensure!(
            !matches!(
                ownership,
                "" | "unresolved" | "excluded" | "unknown" | "user_review"
            ),
            "unowned root cannot be automatically enrolled"
        );
        Ok(Self {
            classification: classification.into(),
            roles,
        })
    }

    fn unselected(&self, selected: &BTreeSet<String>) -> bool {
        !selected.contains(native_role(&self.classification)) && self.roles.is_disjoint(selected)
    }
}

enum RootOmission {
    UnselectedRole,
    DataOnlyContainerBoundary,
}

impl RootOmission {
    fn diagnostic(&self, root: &Value) -> Value {
        let (code, message) = match self {
            Self::UnselectedRole => ("unselected_role",
                "This known root role was not selected by native policy; it was not opened or indexed."),
            Self::DataOnlyContainerBoundary => ("data_only_container_boundary_omitted",
                "Data-only policy does not capture a whole macOS container; only independently verified selected child roots may be indexed."),
        };
        json!({
            "rootId":root["rootId"], "path":root["path"],
            "classification":root["classification"], "roles":root["roles"],
            "code":code, "message":message, "omitted":true,
            "preventsFullScopeCapture":true, "complete":false,
            "trackingAuthorized":false, "uploadAuthorized":false,
        })
    }
}

fn has_data_ownership(kinds: &BTreeSet<String>) -> bool {
    kinds.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "exact_cf_bundle_identifier_path"
                | "container_metadata_identifier"
                | "validated_signed_application_group"
                | "exact_flatpak_desktop_identifier"
                | "exact_namespaced_desktop_id_path"
                | "inventory_approved_exact_steam_app_id_userdata_path"
                | "reviewed_exact_windows_product_mapping"
                | "reviewed_exact_product_mapping"
                | "native_approved_learned_association"
        )
    })
}

pub(crate) fn digest(value: &Value) -> Result<String> {
    serialized_digest(value, 512 * 1024 * 1024)
}

fn serialized_digest<T: Serialize + ?Sized>(value: &T, max: u64) -> Result<String> {
    struct HashWriter {
        hash: blake3::Hasher,
        written: u64,
        max: u64,
    }
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written = self
                .written
                .checked_add(bytes.len() as u64)
                .filter(|size| *size <= self.max)
                .ok_or_else(|| std::io::Error::other("native authority exceeds metadata limit"))?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter {
        hash: blake3::Hasher::new(),
        written: 0,
        max,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.hash.finalize().to_hex().to_string())
}

/// Converts only genuine native directory/file identities; no path hash or
/// display-name fallback. Foreign-platform IDs cannot authorize local roots.
fn candidate_identity(value: &Value) -> Result<(RootIdentity, bool)> {
    let directory = match value["kind"].as_str() {
        Some("directory") => true,
        Some("regular_file") => false,
        _ => bail!("candidate kind is not a no-follow native directory/regular file"),
    };
    let identity = match value["platform"].as_str() {
        Some("unix") => {
            ensure!(cfg!(unix), "Unix identities cannot authorize Windows roots");
            RootIdentity {
                device: value["device"]
                    .as_u64()
                    .context("candidate device identity is missing")?,
                file_id: [
                    value["inode"]
                        .as_u64()
                        .context("candidate inode identity is missing")?,
                    0,
                ],
            }
        }
        Some("windows") => {
            ensure!(
                cfg!(windows),
                "Windows identities cannot authorize Unix roots"
            );
            decode_windows_identity(value)?
        }
        _ => bail!("candidate has no supported actual native identity"),
    };
    Ok((identity, directory))
}

/// Exact FILE_ID_128 byte layout used by both Windows native adapters. Pure
/// decoding is portable; using it as native authority is Windows-host-only.
pub(crate) fn decode_windows_identity(value: &Value) -> Result<RootIdentity> {
    let device = value["volume_serial"]
        .as_u64()
        .context("Windows volume identity is missing")?;
    let bytes = value["file_id"]
        .as_array()
        .context("Windows 128-bit file ID is missing")?;
    ensure!(
        bytes.len() == 16,
        "Windows identity must retain all 128 bits"
    );
    let mut id = [0_u8; 16];
    for (index, byte) in bytes.iter().enumerate() {
        id[index] = u8::try_from(byte.as_u64().context("invalid Windows file ID byte")?)?;
    }
    ensure!(
        id != [0; 16],
        "Windows native file ID cannot be fabricated as zero"
    );
    Ok(RootIdentity {
        device,
        file_id: [
            u64::from_le_bytes(id[..8].try_into()?),
            u64::from_le_bytes(id[8..].try_into()?),
        ],
    })
}

fn evidence_kinds(value: &Value) -> Result<BTreeSet<String>> {
    let entries = value
        .as_array()
        .context("native identity evidence is missing")?;
    ensure!(
        !entries.is_empty() && entries.len() <= 64,
        "invalid native evidence count"
    );
    let mut kinds = BTreeSet::new();
    for entry in entries {
        model::bounded_json(entry, 8192)?;
        let kind = entry["kind"]
            .as_str()
            .context("identity evidence kind is missing")?;
        ensure!(
            known_evidence(kind),
            "unknown evidence is diagnostic, not root authority"
        );
        let identifier = entry["identifier"]
            .as_str()
            .context("identity evidence identifier is missing")?;
        validate_id(identifier)?;
        kinds.insert(kind.to_owned());
    }
    Ok(kinds)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Sidecar {
    pub name: String,
    pub hash: String,
    pub grant: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleIndexSource {
    pub version: u32,
    pub revision_id: String,
    pub snapshot_identity: String,
    pub indexed_at: String,
    pub content_state: String,
    pub file_count: u64,
    pub logical_bytes: u64,
    pub directory_count: u64,
    pub symlink_count: u64,
    pub roots: Vec<Value>,
    pub coverage: String,
    pub tracking_scope_hash: String,
    #[serde(default)]
    pub capture_receipt_hash: Option<String>,
    pub index: Sidecar,
    pub manifest: Sidecar,
}

impl BundleIndexSource {
    /// Authenticate the cached native references without reading source files
    /// or rereading/rehashing whole persisted index/manifest documents per page.
    pub(crate) fn verify_reference_grants(
        &self,
        tracking: &Value,
        store: &dyn TrackingStore,
    ) -> Result<()> {
        ensure!(
            self.version == 1 && self.tracking_scope_hash == digest(tracking)?,
            "native index reference no longer binds this tracking scope"
        );
        for (kind, reference) in [("index", &self.index), ("manifest", &self.manifest)] {
            validate_relative(&reference.name)?;
            ensure!(
                !reference.name.contains('/')
                    && reference.hash.len() == 64
                    && reference.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && store.verify_grant(
                        &format!("bundle_{kind}"),
                        &self.scope(tracking, kind, &reference.name, &reference.hash),
                        &reference.grant,
                    )?,
                "native index/manifest reference is invalid or revoked"
            );
        }
        Ok(())
    }

    pub(crate) fn sanitized(&self) -> Value {
        json!({
            "revisionId": self.revision_id, "snapshotIdentity": self.snapshot_identity,
            "indexedAt": self.indexed_at, "contentState": self.content_state,
            "fileCount": self.file_count, "logicalBytes": self.logical_bytes,
            "directoryCount": self.directory_count, "symlinkCount": self.symlink_count,
            "roots": self.roots, "coverage": self.coverage,
            "coverageScope": "approved_evidenced_roots_only",
            "consistency": "validated_stable_files_not_application_atomic",
            "payloadReadability": "not_established",
            "cloudCommitted": false
        })
    }

    fn scope(&self, tracking: &Value, kind: &str, name: &str, hash: &str) -> Value {
        json!({
            "version": 1, "tracking": tracking, "revisionId": self.revision_id,
            "snapshotIdentity": self.snapshot_identity, "kind": kind,
            "name": name, "hash": hash,
        })
    }

    pub(crate) fn certificate(&self, record: &TrackedSoftware) -> Value {
        json!({
            "revisionId": self.revision_id,
            "scope": self.scope(&record.tracking_scope(), "manifest", &self.manifest.name, &self.manifest.hash),
            "reference": self.manifest,
        })
    }
}

pub(crate) fn write_index(
    snapshot: &Snapshot,
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
    policy: &TrackingPolicy,
) -> Result<BundleIndexSource> {
    snapshot.validate(&record.roots)?;
    ensure!(
        snapshot
            .nodes
            .values()
            .all(|node| node.metadata.is_some() && node.stamp.is_some()),
        "real bundle index lacks required native metadata"
    );
    ensure!(
        record
            .roots
            .iter()
            .filter(|root| root.allowed_files.is_none())
            .all(|root| snapshot.root_metadata.contains_key(&root.id)
                && snapshot.root_stamps.contains_key(&root.id)),
        "real bundle index lacks empty/full native root metadata"
    );
    let identity = snapshot.identity()?;
    let scope_hash = digest(&record.tracking_scope())?;
    let receipt_hash = record.capture_receipt.as_ref().map(digest).transpose()?;
    if let Some(previous) = &record.bundle_index_source {
        if previous.snapshot_identity == identity
            && previous.tracking_scope_hash == scope_hash
            && previous.capture_receipt_hash == receipt_hash
        {
            return Ok(previous.clone());
        }
    }
    quicksave_platform::ensure_private_directory(&policy.bundle_dir())?;
    let safe = SafeRoot::open(&policy.bundle_dir())?;
    let counts = snapshot.counts()?;
    let roots = record.roots.iter().map(|root| {
        let nodes = snapshot.nodes.values().filter(|node| node.root_id == root.id);
        let mut files = 0_u64;
        let mut bytes = 0_u64;
        let mut directories = 0_u64;
        let mut links = 0_u64;
        for node in nodes {
            if node.directory { directories += 1; }
            else if node.link.is_some() { links += 1; }
            else {
                files += 1;
                bytes = bytes.checked_add(node.size).context("root logical byte count overflow")?;
            }
        }
        Ok(json!({
            "rootId": root.id, "role": root.role,
            "roles": root.source.as_ref().and_then(|s| s.get("roles")).cloned().unwrap_or_else(|| json!([root.role])),
            "fileCount": files, "logicalBytes": bytes, "directoryCount": directories,
            "symlinkCount": links, "scope": if root.allowed_files.is_some() { "selected_files" } else { "full_root" },
        }))
    }).collect::<Result<Vec<_>>>()?;
    let coverage = record
        .auto_enrollment
        .as_ref()
        .map_or("partial", |enrollment| {
            if enrollment.roots_complete
                && enrollment
                    .unresolved_roots
                    .as_array()
                    .is_some_and(Vec::is_empty)
                && enrollment
                    .unresolved_reasons
                    .as_array()
                    .is_some_and(Vec::is_empty)
            {
                "complete"
            } else {
                "partial"
            }
        });
    let content_state = if snapshot.content_verified() {
        "content_verified"
    } else {
        "metadata_indexed"
    };
    let revision_id = format!(
        "bundle-revision-{}",
        digest(&json!({
            "version": 1, "tracking": scope_hash, "snapshot": identity, "coverage": coverage,
            "source": record.auto_enrollment.as_ref().map(AutoEnrollment::binding),
            "receipt": receipt_hash,
        }))?
    );
    let mut source = BundleIndexSource {
        version: 1,
        revision_id,
        snapshot_identity: identity,
        indexed_at: chrono::Utc::now().to_rfc3339(),
        content_state: content_state.into(),
        file_count: counts.0,
        logical_bytes: counts.1,
        directory_count: snapshot
            .nodes
            .values()
            .filter(|node| node.directory)
            .count() as u64,
        symlink_count: snapshot
            .nodes
            .values()
            .filter(|node| node.link.is_some())
            .count() as u64,
        roots,
        coverage: coverage.into(),
        tracking_scope_hash: scope_hash,
        capture_receipt_hash: receipt_hash,
        index: Sidecar {
            name: String::new(),
            hash: String::new(),
            grant: Value::Null,
        },
        manifest: Sidecar {
            name: String::new(),
            hash: String::new(),
            grant: Value::Null,
        },
    };
    source.index = write_sidecar(&safe, snapshot, "index", &source, record, store)?;
    let previous = record
        .bundle_index_source
        .as_ref()
        .map(|old| old.certificate(record))
        .or_else(|| record.previous_bundle_manifest.clone());
    let manifest = json!({
        "schemaVersion": 1, "kind": "quicksave_local_bundle_manifest",
        "softwareId": record.id, "appId": record.app_id, "name": record.name,
        "sourceIdentity": record.source_identity,
        "revisionId": source.revision_id, "snapshotIdentity": source.snapshot_identity,
        "trackingScope": record.tracking_scope(), "contentState": source.content_state,
        "indexedAt": source.indexed_at, "index": source.index,
        "roots": record.roots, "rootMetadata": snapshot.root_metadata, "rootStamps": snapshot.root_stamps,
        "rootSummary": source.roots,
        "fileCount": source.file_count, "logicalBytes": source.logical_bytes,
        "directoryCount": source.directory_count, "symlinkCount": source.symlink_count,
        "coverage": source.coverage, "coverageScope": "approved_evidenced_roots_only",
        "identityEvidence": record.auto_enrollment.as_ref().map(|e| &e.identity_evidence),
        "unresolvedRoots": record.auto_enrollment.as_ref().map(|e| &e.unresolved_roots),
        "unresolvedReasons": record.auto_enrollment.as_ref().map(|e| &e.unresolved_reasons),
        "autoEnrollment": record.auto_enrollment.as_ref().map(AutoEnrollment::binding),
        "captureReceipt": record.capture_receipt,
        "previousRevision": previous,
        "applicationAtomic": false, "cloudCommitted": false,
        "payloadReadability": "not_established",
    });
    source.manifest = write_sidecar(&safe, &manifest, "manifest", &source, record, store)?;
    Ok(source)
}

fn write_sidecar<T: Serialize>(
    safe: &SafeRoot,
    value: &T,
    kind: &str,
    source: &BundleIndexSource,
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
) -> Result<Sidecar> {
    let name = format!("{kind}-{}.json", uuid::Uuid::new_v4());
    let hash = write_local_json(safe, &name, value)?;
    let scope = source.scope(&record.tracking_scope(), kind, &name, &hash);
    let grant_kind = format!("bundle_{kind}");
    let grant = store.issue_grant(&grant_kind, &scope)?;
    ensure!(
        store.verify_grant(&grant_kind, &scope, &grant)?,
        "store did not issue an authenticated bundle sidecar"
    );
    Ok(Sidecar { name, hash, grant })
}

pub(crate) fn write_local_json<T: Serialize>(
    safe: &SafeRoot,
    name: &str,
    value: &T,
) -> Result<String> {
    write_local_json_bounded(safe, name, value, MAX_BASELINE_BYTES)
}

pub(crate) fn write_local_json_bounded<T: Serialize>(
    safe: &SafeRoot,
    name: &str,
    value: &T,
    max: u64,
) -> Result<String> {
    let mut hash = blake3::Hasher::new();
    safe.write_new(name, |file| {
        serde_json::to_writer(
            IndexWriter {
                file,
                hash: &mut hash,
                written: 0,
                max,
            },
            value,
        )?;
        Ok(())
    })?;
    Ok(hash.finalize().to_hex().to_string())
}

struct IndexWriter<'a> {
    file: &'a mut File,
    hash: &'a mut blake3::Hasher,
    written: u64,
    max: u64,
}
impl Write for IndexWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|size| *size <= self.max)
            .ok_or_else(|| {
                std::io::Error::other("bundle metadata exceeds bounded sidecar limit")
            })?;
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.written = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn read_sidecar(
    safe: &SafeRoot,
    reference: &Sidecar,
    kind: &str,
    source: &BundleIndexSource,
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
) -> Result<Vec<u8>> {
    validate_relative(&reference.name)?;
    ensure!(!reference.name.contains('/'), "invalid bundle sidecar name");
    let scope = source.scope(
        &record.tracking_scope(),
        kind,
        &reference.name,
        &reference.hash,
    );
    ensure!(
        store.verify_grant(&format!("bundle_{kind}"), &scope, &reference.grant)?,
        "bundle sidecar authority is invalid or revoked"
    );
    let (file, stamp) = safe.read_file(&reference.name)?;
    ensure!(
        stamp.size <= MAX_BASELINE_BYTES,
        "bundle sidecar exceeds bounded size"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BASELINE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == stamp.size
            && blake3::hash(&bytes).to_hex().as_str() == reference.hash,
        "bundle sidecar content failed authentication"
    );
    safe.verify_file(&reference.name, &stamp)?;
    Ok(bytes)
}

pub(crate) fn load_index(
    record: &TrackedSoftware,
    store: &dyn TrackingStore,
    policy: &TrackingPolicy,
) -> Result<Option<Snapshot>> {
    let Some(source) = &record.bundle_index_source else {
        return Ok(None);
    };
    ensure!(
        source.version == 1 && source.tracking_scope_hash == digest(&record.tracking_scope())?,
        "bundle index was rebound to another native scope"
    );
    let safe = SafeRoot::open(&policy.bundle_dir())?;
    let bytes = read_sidecar(&safe, &source.manifest, "manifest", source, record, store)?;
    let manifest: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest["revisionId"] == source.revision_id
            && manifest["snapshotIdentity"] == source.snapshot_identity
            && manifest["index"] == serde_json::to_value(&source.index)?
            && manifest["trackingScope"] == record.tracking_scope(),
        "bundle manifest/index binding changed"
    );
    ensure!(
        manifest["fileCount"] == source.file_count
            && manifest["logicalBytes"] == source.logical_bytes
            && manifest["directoryCount"] == source.directory_count
            && manifest["symlinkCount"] == source.symlink_count
            && manifest["rootSummary"] == json!(source.roots)
            && manifest["coverage"] == source.coverage
            && manifest["contentState"] == source.content_state
            && manifest["captureReceipt"] == json!(record.capture_receipt)
            && source.capture_receipt_hash
                == record.capture_receipt.as_ref().map(digest).transpose()?,
        "bundle summary was altered outside its authenticated manifest"
    );
    let bytes = read_sidecar(&safe, &source.index, "index", source, record, store)?;
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    snapshot.validate(&record.roots)?;
    ensure!(
        snapshot.identity()? == source.snapshot_identity
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
            && (source.content_state == "content_verified") == snapshot.content_verified(),
        "bundle index does not match actual snapshot/counts"
    );
    Ok(Some(snapshot))
}

impl Tracker {
    /// Native-only: both grants must originate after consent/trusted discovery.
    /// Each failed candidate is a diagnostic, never an empty synthetic bundle.
    pub fn materialize_bundles(&self, candidates: &[Value], authority: &Value) -> Result<Value> {
        self.materialize_bundles_impl(candidates, authority, false)
    }

    /// Only the native service's spent explicit refresh ticket may enter here.
    /// Background discovery/status must not clear a persisted authorization gap.
    pub fn refresh_bundles(&self, candidates: &[Value], authority: &Value) -> Result<Value> {
        self.materialize_bundles_impl(candidates, authority, true)
    }

    fn materialize_bundles_impl(
        &self,
        candidates: &[Value],
        authority: &Value,
        explicit_recheck: bool,
    ) -> Result<Value> {
        self.shared.check_running()?;
        ensure!(
            candidates.len() <= MAX_SOFTWARE,
            "too many native bundle candidates"
        );
        model::bounded_json(authority, 1024 * 1024)?;
        let candidates_hash = serialized_digest(candidates, 64 * 1024 * 1024)?;
        let enrollment = AutoEnrollment {
            policy_scope: authority["policyScope"].clone(),
            policy_grant: authority["policyGrant"].clone(),
            discovery_scope: authority["discoveryScope"].clone(),
            discovery_grant: authority["discoveryGrant"].clone(),
            app_evidence_hash: String::new(),
            identity_evidence: json!([]),
            unresolved_roots: json!([]),
            unresolved_reasons: json!([]),
            roots_complete: false,
            candidate_hash: String::new(),
        };
        enrollment.verify(self.shared.store.as_ref(), &self.shared.policy)?;
        ensure!(
            enrollment.discovery_scope["candidatesHash"] == candidates_hash,
            "native discovery attestation does not cover this exact candidate batch"
        );
        let parsed: EnrollmentPolicy = serde_json::from_value(enrollment.policy_scope.clone())?;
        let bases = parsed.pin(&self.shared.policy)?;
        if let Some(provider) = &parsed.provider_id {
            ensure!(
                self.shared.store.provider_known(provider)?,
                "automatic tracking provider is unknown"
            );
        }
        let mut diagnostics = Vec::new();
        let mut diagnostic_bytes = 0_u64;
        let mut omitted = 0_u64;
        let mut indexed = Vec::new();
        let mut partial = 0_u64;
        let mut seen = BTreeSet::new();
        for candidate in candidates {
            let app = candidate["appId"].as_str().unwrap_or("");
            let result = if !seen.insert(app.to_owned()) {
                Err(anyhow::anyhow!("duplicate native application candidate"))
            } else {
                self.materialize_candidate(
                    candidate,
                    &parsed,
                    &bases,
                    &enrollment,
                    explicit_recheck,
                )
            };
            match result {
                Ok((bundle, root_diagnostics)) => {
                    if bundle["bundle"]["coverage"] == "partial" {
                        partial += 1;
                    }
                    indexed.push(bundle);
                    if !root_diagnostics.is_empty() {
                        push_diagnostic(
                            &mut diagnostics,
                            &mut diagnostic_bytes,
                            &mut omitted,
                            json!({
                                "appId":app,"displayName":candidate["displayName"],
                                "code":"bundle_materialization_partial",
                                "materialized":true,"rootDiagnostics":root_diagnostics,
                                "message":if root_diagnostics.iter().all(intentional_omission) {
                                    "Selected independently verified roots were indexed; other roles were intentionally omitted. Coverage remains partial."
                                } else {
                                    "Only complete independently verified roots were indexed; unavailable roots remain unresolved."
                                },
                            }),
                        );
                    }
                }
                Err(error) => {
                    if !app.is_empty() && app.len() <= 512 {
                        let id = format!("software-{}", blake3::hash(app.as_bytes()).to_hex());
                        if let Some(old) = self.shared.apps()?.get_mut(&id) {
                            old.scheduler.require_reconcile();
                            old.force_hash = true;
                            old.record.error = Some(bounded_error(&error));
                            self.shared.persist(old)?;
                        }
                    }
                    push_diagnostic(
                        &mut diagnostics,
                        &mut diagnostic_bytes,
                        &mut omitted,
                        json!({
                            "appId": if app.len() <= 512 { app } else { "" },
                            "displayName":candidate["displayName"],
                            "code": if error.is::<diagnostics::NoSelectedRoots>() {
                                "no_selected_source_roots"
                            } else { "bundle_materialization_rejected" },
                            "message": bounded_error(&error),
                            "materialized": false,
                            "rootDiagnostics":diagnostics::failures(&error),
                        }),
                    );
                }
            }
        }
        self.shared.wake();
        Ok(json!({"bundles": indexed, "diagnostics": diagnostics,
            "partialBundles": partial, "omittedDiagnostics": omitted,
            "incomplete": !diagnostics.is_empty() || omitted > 0 || partial > 0}))
    }

    fn materialize_candidate(
        &self,
        candidate: &Value,
        policy: &EnrollmentPolicy,
        bases: &[(BaseDirectory, scan::PinnedRoot)],
        template: &AutoEnrollment,
        explicit_recheck: bool,
    ) -> Result<(Value, Vec<Value>)> {
        model::bounded_json(candidate, 512 * 1024)?;
        let app_id = candidate["appId"]
            .as_str()
            .context("candidate app identity is missing")?;
        validate_id(app_id)?;
        let name = candidate["displayName"]
            .as_str()
            .context("candidate display name is missing")?;
        validate_name(name)?;
        let kinds = evidence_kinds(&candidate["identityEvidence"])?;
        ensure!(
            !kinds.is_disjoint(&policy.app_identity_policy.allowed_evidence_kinds),
            "app identity evidence is outside the approved policy"
        );
        ensure!(
            policy.app_identity_policy.allowed_app_ids.contains(app_id)
                || policy.app_identity_policy.allow_new_verified_apps,
            "new application identity was not approved by the sealed policy"
        );
        let native_only = candidate.get("productId").is_none_or(Value::is_null)
            || app_id.starts_with("unresolved-")
            || app_id.starts_with("quicksave.observed:");
        ensure!(
            !native_only || policy.app_identity_policy.allow_native_installation_only,
            "unsigned/unknown identity requires explicit native-installation-only policy"
        );
        let id = format!("software-{}", blake3::hash(app_id.as_bytes()).to_hex());
        let candidate_hash = digest(candidate)?;
        let mut renew_deferred_metadata = false;
        {
            let mut apps = self.shared.apps()?;
            if let Some(old) = apps.get_mut(&id) {
                if explicit_recheck {
                    let replacement = old
                        .record
                        .auto_enrollment
                        .as_ref()
                        .filter(|previous| {
                            previous.policy_scope == template.policy_scope
                                && previous.discovery_scope == template.discovery_scope
                                && previous.candidate_hash == candidate_hash
                                && (previous.policy_grant != template.policy_grant
                                    || previous.discovery_grant != template.discovery_grant)
                        })
                        .cloned();
                    if let Some(mut replacement) = replacement {
                        // A fresh explicit discovery can renew the certificate
                        // for the SAME bound scope, never tracking/root/history
                        // authority. Its nonce is deliberately not in binding().
                        if matches!(
                            self.shared.store.verify_grant(
                                "tracking",
                                &old.record.tracking_scope(),
                                &old.record.tracking_grant
                            ),
                            Ok(true)
                        ) {
                            replacement.policy_grant = template.policy_grant.clone();
                            replacement.discovery_grant = template.discovery_grant.clone();
                            ensure!(
                                replacement.binding()
                                    == old.record.auto_enrollment.as_ref().unwrap().binding(),
                                "fresh discovery cannot change an enrolled scope"
                            );
                            replacement.verify_record(
                                &old.record,
                                self.shared.store.as_ref(),
                                &self.shared.policy,
                            )?;
                            self.shared.pause_authorization(old)?;
                            old.record.auto_enrollment = Some(replacement);
                        }
                    }
                }
                if explicit_recheck && old.authorization_paused {
                    let result = self
                        .shared
                        .verify_paused_authority(old)
                        .and_then(|_| self.shared.reconcile_mode(old, false, false));
                    if result.is_err() && old.record.authorization_pending {
                        let _ = self.shared.pause_authorization(old);
                    }
                    if let Err(error) = result {
                        if error.is::<crate::DeferredLegacyAuthority>()
                            && pristine_metadata_enrollment(old)
                        {
                            renew_deferred_metadata = true;
                        } else {
                            return Err(error);
                        }
                    }
                }
                if !renew_deferred_metadata {
                    match self.shared.validate_tracking(old) {
                        Ok(()) => {}
                        Err(error)
                            if explicit_recheck
                                && error.is::<crate::DeferredLegacyAuthority>()
                                && pristine_metadata_enrollment(old) =>
                        {
                            renew_deferred_metadata = true;
                        }
                        Err(error) => return Err(error),
                    }
                }
                let same_policy_candidate =
                    old.record.auto_enrollment.as_ref().is_some_and(|old| {
                        old.policy_scope == template.policy_scope
                            && old.candidate_hash == candidate_hash
                    });
                if !renew_deferred_metadata
                    && !old.scheduler.paused
                    && same_policy_candidate
                    && old
                        .record
                        .auto_enrollment
                        .as_ref()
                        .is_none_or(|enrollment| enrollment.unavailable_roots().next().is_none())
                    && old.record.tracked
                    && old.current.is_some()
                    && old.record.bundle_index_source.is_some()
                {
                    let unchanged_proof = !old.scheduler.needs_reconcile
                        && !old.force_hash
                        && old.watch_ok
                        && old.event_epoch.load(Ordering::Acquire) == old.observation_event_epoch
                        && self.shared.uncertainty_epoch.load(Ordering::Acquire)
                            == old.observation_uncertainty_epoch;
                    if old.pending.is_none() && !unchanged_proof {
                        self.shared.reconcile_mode(old, false, false)?;
                    }
                    crate::sync_record(old);
                    return Ok((old.record.sanitized(), Vec::new()));
                }
            }
        }
        let roots_input = candidate["sourceRoots"]
            .as_array()
            .context("candidate has no verified source roots")?;
        ensure!(
            !roots_input.is_empty() && roots_input.len() <= MAX_ROOTS,
            "invalid candidate source-root count"
        );
        let mut effective = self.shared.policy.clone();
        effective
            .excluded_paths
            .extend(policy.excluded_paths.iter().cloned());
        ensure!(
            effective.excluded_paths.len() <= 256,
            "too many effective protected paths"
        );
        let policy_hash = digest(&template.policy_scope)?;
        let mut roots = Vec::new();
        let mut pins = Vec::new();
        let mut native_ids = BTreeMap::new();
        let mut normalization_notes = Vec::new();
        let mut root_errors = Vec::new();
        let mut root_omissions = Vec::new();
        let selected_roles = policy
            .base_directories
            .iter()
            .flat_map(|base| {
                base.allowed_roles
                    .iter()
                    .map(|role| native_role(role).to_owned())
            })
            .collect::<BTreeSet<_>>();
        // Platform::MacOs serializes as "mac_os" in the native planner.
        // Retain the earlier internal "macos" spelling for authenticated legacy
        // candidates; both receive the same strictly narrower data-only policy.
        let mac_data_only = matches!(candidate["platform"].as_str(), Some("mac_os" | "macos"))
            && !selected_roles.is_empty()
            && selected_roles
                .iter()
                .all(|role| matches!(role.as_str(), "save" | "config"));
        let refreshing = self.shared.apps()?.contains_key(&id);
        for root in roots_input {
            let declaration = RootDeclaration::parse(root)
                .with_context(|| RootContext::candidate(root, "validate_root_declaration"))?;
            if declaration.unselected(&selected_roles) {
                let omission = RootOmission::UnselectedRole.diagnostic(root);
                normalization_notes.push(omission.clone());
                root_omissions.push(omission);
                continue;
            }
            let prepared: Result<(ApprovedRoot,scan::PinnedRoot)> =
                RootContext::candidate(root,"prepare_native_root").run(&effective,|| {
            ensure!(
                root["status"] == "verified_candidate",
                "a proposed/unresolved root is not native authority"
            );
            let root_id = root["rootId"]
                .as_str()
                .context("candidate root ID is missing")?;
            validate_id(root_id)?;
            let path = PathBuf::from(
                root["path"]
                    .as_str()
                    .context("candidate root path is missing")?,
            );
            validate_absolute(&path)?;
            let classification = role(
                root["classification"]
                    .as_str()
                    .context("root classification is missing")?,
            )?;
            let roles = root
                .get("roles")
                .and_then(Value::as_array)
                .map(|roles| {
                    roles
                        .iter()
                        .map(|value| {
                            role(value.as_str().context("invalid source role")?)
                                .map(|role| native_role(role).to_owned())
                        })
                        .collect::<Result<BTreeSet<_>>>()
                })
                .transpose()?
                .unwrap_or_else(|| BTreeSet::from([native_role(classification).to_owned()]));
            ensure!(
                !native_only || matches!(classification, "installation" | "runtime"),
                "native-only unknown identity cannot authorize guessed application data roots"
            );
            let root_kinds = evidence_kinds(&root["evidence"])?;
            ensure!(
                matches!(classification, "installation" | "runtime" | "installer")
                    || has_data_ownership(&root_kinds),
                "a native install/root handle alone does not prove ownership of application data"
            );
            let ownership = root["ownership"]
                .as_str()
                .context("source root lacks native ownership evidence")?;
            ensure!(
                !matches!(
                    ownership,
                    "unresolved" | "excluded" | "unknown" | "user_review"
                ),
                "unowned root cannot be automatically enrolled"
            );
            if classification == "group_container" {
                ensure!(
                    root_kinds.contains("validated_signed_application_group"),
                    "shared group root lacks validated signed ownership evidence"
                );
            }
            // Necessary policy checks precede native I/O. A denied/outside
            // candidate is not an availability failure that can be skipped.
            // Positive containment is still proved by pinned native handles.
            ensure!(
                bases.iter().any(|(base,_)|
                    path != base.path && path.starts_with(&base.path)
                        && base.allowed_roles.contains(native_role(classification))
                        && roles.is_subset(&base.allowed_roles)
                        && !root_kinds.is_disjoint(&base.ownership_rules)),
                "native root is not granted by an approved base/ownership/role policy"
            );
            let (identity, directory) = candidate_identity(&root["nativeIdentity"])?;
            ensure!(
                native_ids
                    .get(&(identity.device, identity.file_id))
                    .is_none_or(|previous| previous == &path),
                "source root aliases another path; native authority is ambiguous"
            );
            native_ids.insert((identity.device, identity.file_id), path.clone());
            let (root_path, allowlist, actual_identity) = if directory {
                (
                    path.clone(),
                    None,
                    RootContext::candidate(root,"approve_directory_identity")
                        .run(&effective,||scan::pin_candidate_identity(&path,&effective,scan::CandidateScope::Tree))?,
                )
            } else {
                let parent = path
                    .parent()
                    .context("candidate file lacks a parent")?
                    .to_owned();
                let leaf = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("candidate file lacks UTF-8 name")?;
                validate_relative(leaf)?;
                ensure!(
                    !model::is_secret_component(leaf),
                    "candidate file is credential/vault material"
                );
                let parent_id = RootContext::candidate(root,"approve_file_parent")
                    .run(&effective,||scan::pin_candidate_identity(&parent,&effective,scan::CandidateScope::SelectedLeaves))?;
                let safe = RootContext::candidate(root,"pin_file_parent")
                    .run(&effective,||SafeRoot::open(&parent))?;
                let stamp = RootContext::candidate(root,"observe_candidate_file_metadata")
                    .run(&effective,||safe.file_metadata(leaf))?;
                ensure!(
                    identity.device == stamp.device && identity.file_id == stamp.file_id,
                    "verified candidate file identity changed"
                );
                RootContext::candidate(root,"verify_candidate_file_metadata").run(&effective,|| {
                    ensure!(safe.file_metadata(leaf)? == stamp,"verified candidate file metadata changed");
                    Ok(())
                })?;
                (parent, Some(BTreeSet::from([leaf.to_owned()])), parent_id)
            };
            if directory {
                ensure!(
                    actual_identity == identity,
                    "verified candidate directory identity changed"
                );
            }
            let stable_root = digest(&json!([
                app_id,
                classification,
                &actual_identity,
                &root_path,
                &allowlist
            ]))?;
            let mut approved = ApprovedRoot {
                id: format!("bundle-root-{stable_root}"),
                path: root_path,
                role: native_role(classification).into(),
                identity: actual_identity,
                allowed_files: allowlist,
                source: None,
            };
            let pin = RootContext::approved(&approved,None,"pin_approved_root")
                .run(&effective,||scan::PinnedRoot::open(&approved))?;
            let mut granting_base = None;
            for (base, base_pin) in bases {
                if path != base.path
                    && path.starts_with(&base.path)
                    && base.allowed_roles.contains(native_role(classification))
                    && roles.is_subset(&base.allowed_roles)
                    && !root_kinds.is_disjoint(&base.ownership_rules)
                    && pin.is_inside(base_pin)?
                {
                    granting_base = Some(base);
                    break;
                }
            }
            let base = granting_base
                .context("native root is not granted by an approved base/ownership/role policy")?;
            approved.source = Some(json!({
                "provider": "verified_native_discovery", "candidateRootId": root_id,
                "sourceRoot": path, "sourceNativeIdentity": root["nativeIdentity"],
                "policyId": policy.policy_id, "policyHash": policy_hash,
                "baseId": base.id, "baseIdentity": base.identity,
                "evidenceHash": digest(&root["evidence"])?,
                "roles": roles,
                "classification": root["classification"],
                "classifications": root.get("roles").cloned().unwrap_or_else(|| json!([root["classification"]])),
                "ownership": ownership,
            }));
            approved.validate()?;
            Ok((approved,pin))
            });
            let (approved, pin) = match prepared {
                Ok(prepared) => prepared,
                Err(error) if !refreshing && diagnostics::unavailable(&error) => {
                    root_errors.extend(diagnostics::root_failure(&error));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if mac_data_only
                && matches!(
                    declaration.classification.as_str(),
                    "container" | "group_container"
                )
            {
                // A selected boundary still passes base, protected-path and
                // native identity checks above. It never receives a tree audit,
                // index, or grant, even when no independently owned child exists.
                let omission = RootOmission::DataOnlyContainerBoundary.diagnostic(root);
                normalization_notes.push(omission.clone());
                root_omissions.push(omission);
                continue;
            }
            normalize_root(
                &mut roots,
                &mut pins,
                approved,
                pin,
                &mut normalization_notes,
            )
            .with_context(|| RootContext::candidate(root, "normalize_approved_roots"))?;
        }
        if roots.is_empty() {
            if root_errors.is_empty() {
                return Err(diagnostics::NoSelectedRoots(root_omissions).into());
            }
            root_errors.extend(root_omissions);
            return Err(RootFailures(root_errors).into());
        }
        let approved_pins = roots
            .iter()
            .map(|root| root.id.clone())
            .zip(pins)
            .collect::<BTreeMap<_, _>>();
        // Normalization has issued no capture/index/tracking authority. Only
        // retained roots now receive complete protected-root and mutual alias
        // audits; discarded broad container scaffolds are never content walks.
        let mut audited_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let audit = RootContext::approved(&root, None, "audit_normalized_root_policy").run(
                &effective,
                || {
                    scan::check_policy(&root.path, &effective, root.allowed_files.is_some())?;
                    approved_pins
                        .get(&root.id)
                        .context("normalized root has no native pin")?
                        .check()
                },
            );
            match audit {
                Ok(()) => audited_roots.push(root),
                Err(error) if !refreshing && diagnostics::unavailable(&error) => {
                    root_errors.extend(diagnostics::root_failure(&error));
                }
                Err(error) => return Err(error),
            }
        }
        let roots = audited_roots;
        if roots.is_empty() {
            if root_errors.is_empty() {
                return Err(diagnostics::NoSelectedRoots(root_omissions).into());
            }
            root_errors.extend(root_omissions);
            return Err(RootFailures(root_errors).into());
        }
        for (index, root) in roots.iter().enumerate() {
            for other in &roots[..index] {
                RootContext::approved(root,None,"audit_normalized_root_aliases").run(&effective,|| {
                    ensure!(!roots_overlap(other,root)?,
                        diagnostics::ScopeGrantViolation("incompatible native root aliases/overlaps require explicit reviewed scopes"));
                    Ok(())
                })?;
            }
        }
        let mut enrollment = template.clone();
        enrollment.identity_evidence = candidate["identityEvidence"].clone();
        enrollment.unresolved_roots = candidate
            .get("unresolvedRoots")
            .cloned()
            .unwrap_or_else(|| json!([]));
        enrollment.unresolved_reasons = candidate
            .get("unresolvedReasons")
            .cloned()
            .unwrap_or_else(|| json!([]));
        enrollment.roots_complete = candidate["rootsComplete"].as_bool().unwrap_or(false);
        if !root_errors.is_empty() {
            enrollment.roots_complete = false;
        }
        if !normalization_notes.is_empty() {
            enrollment
                .unresolved_roots
                .as_array_mut()
                .context("invalid unresolved root coverage")?
                .extend(normalization_notes);
            enrollment.roots_complete = false;
        }
        enrollment.candidate_hash = candidate_hash;
        ensure!(
            enrollment.unresolved_roots.is_array() && enrollment.unresolved_reasons.is_array(),
            "invalid coverage diagnostics"
        );
        enrollment.app_evidence_hash = digest(&json!({
            "appId": app_id, "identityEvidence": enrollment.identity_evidence,
            "roots": roots.iter().map(scan::root_request).collect::<Vec<_>>(),
        }))?;
        let mut apps = self.shared.apps()?;
        ensure!(
            apps.contains_key(&id) || apps.len() < MAX_SOFTWARE,
            "software tracking limit reached"
        );
        let old = apps.get(&id);
        if let Some(old) = old {
            ensure!(
                old.pending.is_none() && old.record.pending_work.is_none(),
                "bundle has active or durable original work; recover/finalize it before changing authority"
            );
            ensure!(
                old.record.auto_enrollment.is_some(),
                "automatic discovery cannot replace manual software authority"
            );
            if renew_deferred_metadata {
                ensure!(pristine_metadata_enrollment(old)
                    && roots.len() == old.record.roots.len()
                    && candidate.get("sourceIdentity").filter(|value| !value.is_null())
                        == old.record.source_identity.as_ref(),
                    "deferred metadata reapproval cannot replace history or widen/change source identity");
            }
            for old_root in &old.record.roots {
                ensure!(roots.iter().any(|root| root.id == old_root.id
                    && root.identity == old_root.identity && root.allowed_files == old_root.allowed_files),
                    "discovery omitted a previously approved root; cannot silently shrink full scope");
            }
        }
        // Never authenticate/reuse a deferred old index as a capture receipt or
        // historical baseline. Its immutable file remains untouched. Renewal is
        // permitted only when there is no capture/history/flight to replace.
        let previous = old.filter(|_| !renew_deferred_metadata).and_then(|old| {
            old.record
                .bundle_index_source
                .as_ref()
                .map(|source| source.certificate(&old.record))
        });
        let mut record = TrackedSoftware {
            authorization_pending: false,
            id: id.clone(),
            app_id: Some(app_id.into()),
            source_identity: candidate
                .get("sourceIdentity")
                .filter(|value| !value.is_null())
                .cloned(),
            name: name.into(),
            tracked: false,
            provider_id: old
                .and_then(|old| old.record.provider_id.clone())
                .or_else(|| policy.provider_id.clone()),
            autosave: false,
            dirty: true,
            status: "needs_backup".into(),
            last_saved_at: None,
            file_count: None,
            logical_bytes: None,
            error: enrollment.root_failure_message(),
            roots,
            dirty_generation: old
                .map_or(0, |old| old.scheduler.dirty_generation)
                .checked_add(1)
                .context("dirty generation exhausted")?,
            unknown_generation: old.map_or(0, |old| old.record.unknown_generation),
            last_confirmed_uploaded_generation: old
                .map_or(0, |old| old.scheduler.last_confirmed_uploaded_generation),
            tracking_grant: Value::Null,
            autosave_grant: None,
            baseline: None,
            baseline_full_scope: false,
            bundle_index_source: None,
            previous_bundle_manifest: previous,
            auto_enrollment: Some(enrollment),
            app_running: old.and_then(|old| old.record.app_running),
            capture_receipt: None,
            pending_work: None,
        };
        record.validate()?;
        // Only native metadata is read here. App installations are not hashed to
        // paint a dashboard; the engine's actual capture supplies content later.
        let mut snapshot = Snapshot::default();
        let mut readable_roots = Vec::new();
        let mut total_path_bytes = 0_usize;
        for root in &record.roots {
            let capture = RootContext::approved(root, None, "index_complete_root")
                .run(&effective, || {
                    scan::capture_index(
                        std::slice::from_ref(root),
                        None,
                        true,
                        false,
                        &effective,
                        &self.shared.stop,
                        &self.shared.io,
                    )
                })
                .and_then(|index| {
                    ensure!(
                        root.allowed_files.as_ref().is_none_or(|leaves| leaves
                            .iter()
                            .all(|leaf| index.nodes.contains_key(&crate::file_id(&root.id, leaf)))),
                        "new verified source file disappeared during initial metadata indexing"
                    );
                    Ok(index)
                });
            match capture {
                Ok(index) => {
                    ensure!(
                        index.nodes.len() <= MAX_FILES.saturating_sub(snapshot.nodes.len()),
                        "normalized bundle index exceeds bounded entry count"
                    );
                    total_path_bytes = total_path_bytes
                        .checked_add(index.path_bytes()?)
                        .context("bundle path size overflow")?;
                    ensure!(
                        total_path_bytes <= model::MAX_PATH_BYTES,
                        "bundle index exceeds bounded path memory"
                    );
                    for (id, node) in index.nodes {
                        ensure!(
                            snapshot.nodes.insert(id, node).is_none(),
                            "normalized bundle indexed a file twice"
                        );
                    }
                    snapshot.root_metadata.extend(index.root_metadata);
                    snapshot.root_stamps.extend(index.root_stamps);
                    readable_roots.push(root.clone());
                }
                Err(error) => {
                    if old.is_some() {
                        return Err(error).context(
                            "root refresh failed; prior authority, index and baseline are retained",
                        );
                    }
                    // An unsupported link layout rejects this WHOLE independent
                    // root, never just a troublesome leaf or its target. Only
                    // initial automatic enrollment may retain other roots.
                    // Refresh/manual scopes cannot silently shrink authority.
                    if !diagnostics::unavailable(&error)
                        && !error.is::<quicksave_platform::LinkOutsideLogicalRoot>()
                    {
                        return Err(error);
                    }
                    root_errors.extend(diagnostics::root_failure(&error));
                }
            }
        }
        if readable_roots.is_empty() || (!root_errors.is_empty() && snapshot.nodes.is_empty()) {
            return Err(RootFailures(root_errors).into());
        }
        if !root_errors.is_empty() {
            record.roots = readable_roots;
            let enrollment = record
                .auto_enrollment
                .as_mut()
                .context("native enrollment is missing")?;
            enrollment.roots_complete = false;
            enrollment
                .unresolved_roots
                .as_array_mut()
                .context("invalid unresolved native roots")?
                .extend(root_errors.iter().cloned());
            enrollment.app_evidence_hash = digest(&json!({
                "appId": app_id, "identityEvidence": enrollment.identity_evidence,
                "roots": record.roots.iter().map(scan::root_request).collect::<Vec<_>>(),
            }))?;
            record.error = enrollment.root_failure_message();
        }
        snapshot.validate(&record.roots)?;
        snapshot.identity()?;
        record.validate()?;
        let previous_count = old
            .and_then(|old| old.current.as_ref())
            .map_or(0, |s| s.nodes.len());
        let total = self
            .shared
            .index_entries
            .load(Ordering::Acquire)
            .checked_sub(previous_count)
            .and_then(|n| n.checked_add(snapshot.nodes.len()))
            .context("invalid workspace index accounting")?;
        ensure!(
            total <= MAX_FILES,
            "workspace real index exceeds bounded entry count"
        );
        let previous_paths = old
            .and_then(|old| old.current.as_ref())
            .map(|s| s.path_bytes())
            .transpose()?
            .unwrap_or(0);
        let total_paths = self
            .shared
            .index_path_bytes
            .load(Ordering::Acquire)
            .checked_sub(previous_paths)
            .and_then(|bytes| bytes.checked_add(snapshot.path_bytes().ok()?))
            .context("invalid workspace native path accounting")?;
        ensure!(
            total_paths <= model::MAX_PATH_BYTES,
            "workspace native path/link memory exceeds bounded limit"
        );
        for root in &record.roots {
            RootContext::approved(root, None, "verify_materialized_root_identity").run(
                &effective,
                || {
                    approved_pins
                        .get(&root.id)
                        .context("materialized root lost its native authority handle")?
                        .check()
                },
            )?;
        }
        template.verify(self.shared.store.as_ref(), &self.shared.policy)?;
        record.tracking_grant = self
            .shared
            .store
            .issue_grant("tracking", &record.tracking_scope())?;
        ensure!(
            self.shared.store.verify_grant(
                "tracking",
                &record.tracking_scope(),
                &record.tracking_grant
            )?,
            "native tracking grant could not be authenticated"
        );
        let source = write_index(
            &snapshot,
            &record,
            self.shared.store.as_ref(),
            &self.shared.policy,
        )?;
        record.file_count = Some(source.file_count);
        record.logical_bytes = Some(source.logical_bytes);
        record.bundle_index_source = Some(source);
        record.previous_bundle_manifest = None;
        record.tracked = true;
        for root in &record.roots {
            RootContext::approved(root, None, "verify_persisted_root_identity").run(
                &effective,
                || {
                    approved_pins
                        .get(&root.id)
                        .context("persisted root lost its native authority handle")?
                        .check()
                },
            )?;
        }
        self.shared
            .store
            .save_record(&serde_json::to_value(&record)?)?;
        // Publish only after every sidecar, grant and final record is durable.
        let identity = snapshot.identity()?;
        let value = record.sanitized();
        let generation = record.dirty_generation;
        let confirmed = record.last_confirmed_uploaded_generation;
        let runtime = Runtime {
            authorization_paused: false,
            record,
            scheduler: Scheduler::new(generation, confirmed, self.shared.now())?,
            baseline: None,
            current: Some(Arc::new(snapshot)),
            pending: None,
            event_epoch: Arc::new(AtomicU64::new(0)),
            force_hash: true,
            watch_ok: false,
            index_identity: Some(
                blake3::hash(format!("{id}:{identity}").as_bytes())
                    .to_hex()
                    .to_string(),
            ),
            observation_event_epoch: 0,
            observation_uncertainty_epoch: 0,
            policy_pending: false,
        };
        if let Some(previous) = apps.insert(id, runtime) {
            self.shared.baseline_path_bytes.fetch_sub(
                previous
                    .baseline
                    .as_ref()
                    .map(|s| s.path_bytes())
                    .transpose()?
                    .unwrap_or(0),
                Ordering::AcqRel,
            );
            self.shared.baseline_entries.fetch_sub(
                previous.baseline.as_ref().map_or(0, |s| s.nodes.len()),
                Ordering::AcqRel,
            );
        }
        self.shared.index_entries.store(total, Ordering::Release);
        self.shared
            .index_path_bytes
            .store(total_paths, Ordering::Release);
        self.shared.reconfigure.store(true, Ordering::Release);
        root_errors.extend(root_omissions);
        Ok((value, root_errors))
    }

    /// Sanitized cached real bundle revisions. No source scans or content I/O.
    pub fn bundles(&self) -> Result<Vec<Value>> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let mut bundles = Vec::new();
        for app in apps.values_mut() {
            if self.shared.validate_tracking(app).is_err() {
                // A quarantined app is not a verified bundle; it must not
                // prevent independent applications from being listed.
                continue;
            }
            crate::sync_record(app);
            if !app.scheduler.paused
                && app.record.tracked
                && app.record.bundle_index_source.is_some()
                && app.current.is_some()
            {
                bundles.push(app.record.sanitized());
            }
        }
        Ok(bundles)
    }

    /// Native-only private record. List/UI roots expose approved display paths
    /// and roles, never native identities, grants, leaf allowlists or sidecars.
    pub fn bundle_record(&self, software_id: &str) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let app = apps.get_mut(software_id).context("unknown real bundle")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused
                && app.record.tracked
                && app.current.is_some()
                && app.record.bundle_index_source.is_some(),
            "software does not have an authenticated materialized index"
        );
        crate::sync_record(app);
        Ok(serde_json::to_value(&app.record)?)
    }

    /// Revision-bound bounded page for all-app dashboards. No source I/O and no
    /// giant file-tree copies. A changed bundle generation invalidates cursors.
    pub fn bundle_listing(&self, cursor: Option<&str>, limit: usize) -> Result<Value> {
        self.shared.check_running()?;
        ensure!(
            limit > 0 && limit <= model::MAX_PAGE,
            "bundle page limit must be 1..=500"
        );
        let mut apps = self.shared.apps()?;
        let mut hash = blake3::Hasher::new();
        for (id, app) in apps.iter_mut() {
            self.shared.validate_tracking(app)?;
            if !app.scheduler.paused && app.record.tracked && app.current.is_some() {
                if let Some(source) = &app.record.bundle_index_source {
                    hash.update(id.as_bytes());
                    hash.update(source.revision_id.as_bytes());
                }
            }
        }
        let identity = hash.finalize().to_hex().to_string();
        let offset = if let Some(cursor) = cursor {
            ensure!(cursor.len() <= 1024, "oversized bundle cursor");
            let (snapshot, offset) = cursor.rsplit_once(':').context("invalid bundle cursor")?;
            ensure!(
                snapshot == identity,
                "bundle revisions changed; restart pagination"
            );
            offset
                .parse::<usize>()
                .context("invalid bundle page offset")?
        } else {
            0
        };
        let mut values = Vec::with_capacity(limit);
        let mut index = 0_usize;
        let mut more = false;
        for app in apps.values_mut() {
            if app.scheduler.paused
                || !app.record.tracked
                || app.current.is_none()
                || app.record.bundle_index_source.is_none()
            {
                continue;
            }
            if index >= offset {
                if values.len() == limit {
                    more = true;
                    break;
                }
                crate::sync_record(app);
                values.push(app.record.sanitized());
            }
            index += 1;
        }
        ensure!(offset <= index, "bundle cursor exceeds indexed revisions");
        Ok(json!({"bundles": values,
            "nextCursor": if more { Some(format!("{identity}:{}", offset + limit)) } else { None }}))
    }

    /// Native ownership callback. A signed observation is a hint, never a clean
    /// bit, a content grant or permission to contact a provider.
    pub fn observe_application(&self, event: &Value) -> Result<Value> {
        self.shared.check_running()?;
        model::bounded_json(event, 64 * 1024)?;
        let software = event["softwareId"]
            .as_str()
            .context("observation software ID is missing")?;
        let app_id = event["appId"]
            .as_str()
            .context("observation app ID is missing")?;
        let kind = event["kind"]
            .as_str()
            .context("observation kind is missing")?;
        ensure!(
            matches!(kind, "app_open" | "app_close" | "change_hint"),
            "unsupported application observation"
        );
        let roots = event["rootIds"]
            .as_array()
            .context("observation exact root IDs are missing")?;
        ensure!(
            !roots.is_empty() && roots.len() <= MAX_ROOTS,
            "invalid observation root count"
        );
        let mut ids = BTreeSet::new();
        for root in roots {
            let id = root.as_str().context("invalid observed root ID")?;
            validate_id(id)?;
            ensure!(ids.insert(id.to_owned()), "duplicate observed root");
        }
        let mut apps = self.shared.apps()?;
        let app = apps
            .get_mut(software)
            .context("observation software is not indexed")?;
        self.shared.validate_tracking(app)?;
        ensure!(
            !app.scheduler.paused
                && app.record.app_id.as_deref() == Some(app_id)
                && ids
                    .iter()
                    .all(|id| app.record.roots.iter().any(|root| &root.id == id)),
            "native observation identity/root ownership does not match indexed authority"
        );
        let scope = json!({
            "version": 1, "softwareId": software, "appId": app_id, "kind": kind,
            "rootIds": ids,
            "trackingScopeHash": digest(&app.record.tracking_scope())?,
        });
        ensure!(
            event["scope"] == scope
                && self.shared.store.verify_grant(
                    "tracking_observation",
                    &scope,
                    &event["grant"]
                )?,
            "application observation was not authenticated by the native owner"
        );
        app.event_epoch.fetch_add(1, Ordering::AcqRel);
        app.scheduler.hint(self.shared.now())?;
        // Normal lifecycle/use hints are not filesystem proof gaps. A qualified
        // native metadata reconciliation can still prove an unchanged baseline;
        // overflow/watch-error epochs independently force uncertain capture.
        if kind == "app_open" {
            app.record.app_running = Some(true);
        }
        if kind == "app_close" {
            app.record.app_running = Some(false);
        }
        self.shared.persist(app)?;
        self.shared.wake();
        Ok(
            json!({"softwareId": software, "reconciliationRequired": true,
            "dirtyGeneration": app.scheduler.dirty_generation, "cloudWrite": false}),
        )
    }

    /// Native-only revocation. Keeps every source byte, index, immutable local
    /// manifest and engine/cloud revision; disables only future authority.
    pub fn disable_automatic_tracking(&self) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let mut policies = BTreeSet::new();
        let mut disabled = Vec::new();
        // Revoke every global scope before any fallible record write, so a
        // persistence failure cannot leave other auto-enrolled apps authorized.
        for app in apps.values() {
            if let Some(enrollment) = &app.record.auto_enrollment {
                if policies.insert(digest(&enrollment.policy_scope)?) {
                    self.shared
                        .store
                        .revoke_grant("app_tracking_policy", &enrollment.policy_scope)?;
                }
            }
        }
        for app in apps.values_mut() {
            let Some(_) = &app.record.auto_enrollment else {
                continue;
            };
            self.shared.revoke_autosave(app)?;
            self.shared
                .store
                .revoke_grant("tracking", &app.record.tracking_scope())?;
            app.scheduler.revoke();
            app.watch_ok = false;
            app.record.tracked = false;
            app.record.error = Some(
                "Automatic tracking is disabled; saved local/cloud history is retained.".into(),
            );
            self.shared.persist(app)?;
            disabled.push(json!({"softwareId": app.record.id,
                "revisionId": app.record.bundle_index_source.as_ref().map(|source| &source.revision_id)}));
        }
        self.shared.reconfigure.store(true, Ordering::Release);
        self.shared.wake();
        Ok(json!({"disabled": disabled, "keepsLocalData": true, "keepsVersionHistory": true}))
    }

    /// Counts refer to authenticated actual records, never discovery-plan rows.
    /// The service owns whether a global policy is enabled before any app exists.
    pub fn automatic_tracking_status(&self) -> Result<Value> {
        self.shared.check_running()?;
        let mut apps = self.shared.apps()?;
        let mut indexed = 0_u64;
        let mut inactive = 0_u64;
        let mut dirty = 0_u64;
        let mut diagnostics = Vec::new();
        for app in apps
            .values_mut()
            .filter(|app| app.record.auto_enrollment.is_some())
        {
            if self.shared.validate_tracking(app).is_err() {
                inactive += 1;
                dirty += 1;
                if diagnostics.len() < MAX_DIAGNOSTICS {
                    diagnostics.push(json!({"softwareId":app.record.id,
                        "code":"tracking_authorization_unavailable",
                        "message":"Tracking authorization is unavailable; approvals and history are retained. This app is not counted as verified or Saved."}));
                }
                continue;
            }
            crate::sync_record(app);
            if app.record.tracked
                && !app.scheduler.paused
                && app.current.is_some()
                && app.record.bundle_index_source.is_some()
            {
                indexed += 1;
            } else {
                inactive += 1;
            }
            if app.record.dirty {
                dirty += 1;
            }
            if let Some(error) = &app.record.error {
                if diagnostics.len() < MAX_DIAGNOSTICS {
                    diagnostics.push(json!({"softwareId": app.record.id, "message": error}));
                }
            }
        }
        Ok(json!({
            "policyOwner": "native_service", "indexedApplications": indexed,
            "inactiveApplications": inactive, "dirtyApplications": dirty,
            "diagnostics": diagnostics, "io": self.shared.io.value(),
        }))
    }
}

fn pristine_metadata_enrollment(app: &crate::Runtime) -> bool {
    app.record.auto_enrollment.is_some()
        && app.record.last_saved_at.is_none()
        && app.record.last_confirmed_uploaded_generation == 0
        && app.record.baseline.is_none()
        && !app.record.baseline_full_scope
        && app.baseline.is_none()
        && app.record.capture_receipt.is_none()
        && app.record.pending_work.is_none()
        && app.pending.is_none()
        && app.scheduler.flight.is_none()
        && app.record.previous_bundle_manifest.is_none()
}

fn container_boundary(root: &ApprovedRoot) -> bool {
    matches!(
        root.source
            .as_ref()
            .and_then(|source| source["classification"].as_str()),
        Some("container" | "group_container")
    )
}

fn normalization_note(root: &ApprovedRoot) -> Value {
    json!({
        "rootId": root.id, "path": root.path,
        "classification": root.source.as_ref().and_then(|source| source.get("classification")),
        "code": "container_boundary_indexed_via_verified_children",
        "preventsFullScopeCapture":true,"complete":false,
        "message": "Only independently verified child scopes are indexed; the enclosing container is not claimed as fully captured.",
    })
}

fn merge_root_provenance(parent: &mut ApprovedRoot, child: &ApprovedRoot) -> Result<()> {
    let source = parent
        .source
        .as_mut()
        .context("normalized root has no native provenance")?;
    let mut roles = BTreeSet::from([parent.role.clone()]);
    let empty = Value::Null;
    for value in [
        &source["roles"],
        child
            .source
            .as_ref()
            .map(|source| &source["roles"])
            .unwrap_or(&empty),
    ] {
        if let Some(values) = value.as_array() {
            for value in values {
                roles.insert(
                    value
                        .as_str()
                        .context("invalid normalized native role")?
                        .to_owned(),
                );
            }
        }
    }
    source["roles"] = json!(roles);
    let proof = json!({
        "rootId": child.id, "path": child.path, "identity": child.identity,
        "allowedFiles": child.allowed_files, "role": child.role,
        "candidateRootId": child.source.as_ref().and_then(|s| s.get("candidateRootId")),
        "classification": child.source.as_ref().and_then(|s| s.get("classification")),
        "evidenceHash": child.source.as_ref().and_then(|s| s.get("evidenceHash")),
        "baseId": child.source.as_ref().and_then(|s| s.get("baseId")),
        "baseIdentity": child.source.as_ref().and_then(|s| s.get("baseIdentity")),
    });
    if source.get("normalizedRootProofs").is_none() {
        source["normalizedRootProofs"] = json!([]);
    }
    let proofs = source["normalizedRootProofs"]
        .as_array_mut()
        .context("invalid normalized root proofs")?;
    proofs.push(proof);
    if let Some(previous) = child
        .source
        .as_ref()
        .and_then(|s| s["normalizedRootProofs"].as_array())
    {
        proofs.extend(previous.iter().cloned());
    }
    ensure!(
        proofs.len() <= MAX_ROOTS,
        "normalized root proofs exceed bound"
    );
    parent.validate()
}

/// These are native candidate pins, not grants or disjointness proofs. A
/// parent may subsume a verified child only on positive native containment;
/// retained roots receive full policy/alias audits after normalization.
/// Container boundaries instead yield to independently evidenced
/// children, preserving partial coverage rather than claiming caches/vaults or
/// unselected container siblings. No bytes are counted twice.
fn normalize_root(
    roots: &mut Vec<ApprovedRoot>,
    pins: &mut Vec<scan::PinnedRoot>,
    mut root: ApprovedRoot,
    pin: scan::PinnedRoot,
    notes: &mut Vec<Value>,
) -> Result<()> {
    let mut index = 0;
    while index < roots.len() {
        if roots[index].path == root.path
            && roots[index].identity == root.identity
            && roots[index].allowed_files == root.allowed_files
        {
            merge_root_provenance(&mut roots[index], &root)?;
            return Ok(());
        }
        let previous_contains = roots[index].allowed_files.is_none()
            && root.path.starts_with(&roots[index].path)
            && pin.is_inside(&pins[index])?;
        if previous_contains {
            if container_boundary(&roots[index]) {
                notes.push(normalization_note(&roots[index]));
                roots.remove(index);
                pins.remove(index);
                continue;
            }
            merge_root_provenance(&mut roots[index], &root)?;
            return Ok(());
        }
        let new_contains = root.allowed_files.is_none()
            && roots[index].path.starts_with(&root.path)
            && pins[index].is_inside(&pin)?;
        if new_contains {
            if container_boundary(&root) {
                notes.push(normalization_note(&root));
                return Ok(());
            }
            merge_root_provenance(&mut root, &roots[index])?;
            roots.remove(index);
            pins.remove(index);
            continue;
        }
        // Lack of native containment is NOT disjointness. Preserve both
        // candidates for the mandatory final anti-alias audit.
        index += 1;
    }
    roots.push(root);
    pins.push(pin);
    Ok(())
}

fn roots_overlap(left: &ApprovedRoot, right: &ApprovedRoot) -> Result<bool> {
    if left.path == right.path && left.identity == right.identity {
        return Ok(match (&left.allowed_files, &right.allowed_files) {
            (Some(a), Some(b)) => !a.is_disjoint(b),
            _ => true,
        });
    }
    if left.allowed_files.is_some() && right.allowed_files.is_some() {
        return Ok(false);
    }
    // Handle-based overlap includes aliases; no positive path-prefix fallback.
    let left_pin = scan::PinnedRoot::open(left)?;
    let right_pin = scan::PinnedRoot::open(right)?;
    // Anti-alias approval is not a capture/link-readability walk. The actual
    // independent root indexes still apply strict link confinement afterwards.
    left_pin.safe.overlaps_for_approval(&right_pin.safe)
}

fn bounded_error(error: &anyhow::Error) -> String {
    // Native diagnostics only. Never format grants, keys or source file bytes.
    diagnostics::message(error)
}

fn push_diagnostic(output: &mut Vec<Value>, bytes: &mut u64, omitted: &mut u64, diagnostic: Value) {
    let size = model::serialized_size(&diagnostic, MAX_DIAGNOSTIC_BYTES);
    if output.len() < MAX_DIAGNOSTICS {
        if let Ok(size) = size {
            if let Some(total) = bytes
                .checked_add(size)
                .filter(|total| *total <= MAX_DIAGNOSTIC_BYTES)
            {
                *bytes = total;
                output.push(diagnostic);
                return;
            }
        }
    }
    *omitted = omitted.saturating_add(1);
}
