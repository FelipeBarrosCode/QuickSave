// SPDX-License-Identifier: GPL-3.0-only
//! Backend-only bridge from actual Tracker::bundle_record/root_authority values.
//! No discovery row, renderer JSON, unsealed base directory or display name is
//! materialization authority. No content/index payload is read by this bridge.
use crate::*;
use anyhow::{ensure, Context, Result};
use quicksave_platform::{RootIdentity, SafeRoot};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub trait GrantVerifier: Send + Sync {
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool>;
}
impl<F: Fn(&str, &Value, &Value) -> Result<bool> + Send + Sync> GrantVerifier for F {
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
        self(kind, scope, grant)
    }
}

/// Captured only from an approved immutable scope, never from incoming JSON.
#[derive(Clone)]
pub struct ObservationContext {
    pub(crate) fingerprint: String,
    pub(crate) uid: u32,
}

/// Native ownership binding, not a public UI DTO or a new tracking grant.
#[derive(Clone)]
pub struct TrackerBundleBinding {
    software_id: String,
    app_id: String,
    source_app_id: String,
    tracking_scope_hash: String,
    roots: Vec<RootSpec>,
    application: NativeApplicationSpec,
}

impl TrackerBundleBinding {
    /// Call only with private records just returned by Tracker::bundle_record
    /// and Tracker::root_authority. Verifies the native enrollment policy,
    /// discovery/tracking grants and signed index/manifest headers BEFORE
    /// opening the selected executable's metadata handle. Does not open/parse
    /// payloads, enumerate a tree, resolve PATH, guess an exe, or expand a parent.
    pub fn from_native_records(
        record: &Value,
        authority: &Value,
        executable: &Path,
        verifier: &dyn GrantVerifier,
    ) -> Result<Self> {
        bounded(record)?;
        bounded(authority)?;
        let software_id = text(&record["id"])?;
        let app_id = text(&record["appId"])?;
        let source = record
            .get("sourceIdentity")
            .filter(|value| value.is_object())
            .context("materialized bundle has no native sourceIdentity")?;
        let source_app_id = text(&source["app_id"])?;
        if let Some(id) = source["steam_app_id"].as_u64() {
            ensure!(
                id > 0 && id <= u32::MAX as u64 && source_app_id == format!("steam:{id}"),
                "Steam sourceIdentity is not an exact canonical app ID"
            );
        }
        if let Some(id) = source["desktop_entry_id"].as_str() {
            ensure!(
                source_app_id == format!("desktop:{id}"),
                "XDG sourceIdentity case/ID changed"
            );
        }
        ensure!(
            !source_app_id.starts_with("quicksave.observed:")
                && !app_id.starts_with("quicksave.observed:"),
            "unknown observed app IDs remain diagnostics, not native enrollment"
        );
        ensure!(
            record["tracked"] == true
                && authority["softwareId"] == software_id
                && authority["id"] == software_id
                && authority["appId"] == app_id
                && authority["sourceIdentity"] == *source,
            "private native records disagree"
        );
        let scope = &authority["scope"];
        ensure!(
            scope["version"] == 1
                && scope["softwareId"] == software_id
                && scope["appId"] == app_id
                && scope["sourceIdentity"] == *source,
            "native tracking scope identity changed"
        );
        ensure!(
            record["trackingGrant"] == authority["grant"]
                && verifier.verify_grant("tracking", scope, &authority["grant"])?,
            "native tracking authority is invalid or revoked"
        );

        // An approved base is not permission to observe all siblings. The
        // actual enrollment and materialized record must already exist.
        let enrollment = &record["autoEnrollment"];
        let policy = &enrollment["policyScope"];
        let discovery = &enrollment["discoveryScope"];
        ensure!(
            policy["version"] == 1
                && policy["enabled"] == true
                && policy["source"] == "verified_native_discovery"
                && verifier.verify_grant(
                    "app_tracking_policy",
                    policy,
                    &enrollment["policyGrant"]
                )?,
            "an explicit enabled native app tracking policy is required"
        );
        let policy_hash = digest(policy)?;
        ensure!(
            scope.pointer("/autoEnrollment/policyHash") == Some(&json!(policy_hash))
                && discovery["version"] == 1
                && discovery["source"] == "verified_native_discovery"
                && discovery["policyHash"] == policy_hash
                && scope.pointer("/autoEnrollment/discoveryHash")
                    == Some(&json!(digest(discovery)?))
                && verifier.verify_grant(
                    "bundle_discovery",
                    discovery,
                    &enrollment["discoveryGrant"]
                )?,
            "native discovery is not bound to the approved enrollment policy"
        );
        let tracking_scope_hash = digest(scope)?;
        let index = &record["bundleIndexSource"];
        ensure!(
            index["version"] == 1 && index["trackingScopeHash"] == tracking_scope_hash,
            "bundle has no authenticated materialized index for this exact scope"
        );
        text(&index["revisionId"])?;
        text(&index["snapshotIdentity"])?;
        for kind in ["index", "manifest"] {
            let sidecar = &index[kind];
            let name = text(&sidecar["name"])?;
            crate::scope::validate_relative(&name)?;
            ensure!(
                !name.contains('/'),
                "invalid materialized sidecar reference"
            );
            let hash = text(&sidecar["hash"])?;
            ensure!(
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid materialized sidecar hash"
            );
            let signed = json!({
                "version":1, "tracking":scope, "revisionId":index["revisionId"],
                "snapshotIdentity":index["snapshotIdentity"], "kind":kind, "name":name, "hash":hash
            });
            ensure!(
                verifier.verify_grant(&format!("bundle_{kind}"), &signed, &sidecar["grant"])?,
                "materialized native index/manifest attestation is invalid or revoked"
            );
        }
        let record_roots = root_array(&record["roots"])?;
        let authority_roots = root_array(&authority["roots"])?;
        let signed_roots = root_array(&scope["roots"])?;
        ensure!(
            record_roots.len() == authority_roots.len() && record_roots.len() == signed_roots.len(),
            "materialized root selection changed"
        );
        let mut roots = Vec::new();
        let mut ids = BTreeSet::new();
        for input in record_roots {
            let id = text(&input["id"])?;
            ensure!(ids.insert(id.clone()), "duplicate materialized root ID");
            let compare = |other: &&Value| other["id"] == id;
            let authoritative = authority_roots
                .iter()
                .find(compare)
                .context("root authority is missing")?;
            let signed = signed_roots
                .iter()
                .find(compare)
                .context("root was not signed")?;
            for key in ["id", "path", "role", "identity", "allowedFiles"] {
                ensure!(
                    input[key] == authoritative[key] && input[key] == signed[key],
                    "native root, file selection or identity changed"
                );
            }
            let role = input["role"]
                .as_str()
                .context("materialized root role missing")?;
            let kind = match role {
                "installation" | "runtime" => ObservationRootKind::Installation,
                "save" | "config" | "manual" | "container" | "group_container" | "data"
                | "installer" => ObservationRootKind::Data,
                _ => anyhow::bail!("unsupported native observation root role"),
            };
            let path = PathBuf::from(input["path"].as_str().context("native root path missing")?);
            crate::scope::validate_absolute(&path)?;
            ensure!(
                !crate::scope::private_path(&path),
                "private native source root is excluded"
            );
            let native = &input["identity"];
            let file_id: [u64; 2] = serde_json::from_value(native["fileId"].clone())?;
            let identity = RootIdentity {
                device: native["device"]
                    .as_u64()
                    .context("native root device missing")?,
                file_id,
            };
            let allowed_files = if input["allowedFiles"].is_null() {
                None
            } else {
                let leaves = input["allowedFiles"]
                    .as_array()
                    .context("invalid exact-file observation scope")?;
                ensure!(
                    !leaves.is_empty() && leaves.len() <= 4096,
                    "invalid native leaf count"
                );
                let mut files = BTreeSet::new();
                for leaf in leaves {
                    let leaf = leaf.as_str().context("invalid native file leaf")?;
                    crate::scope::validate_relative(leaf)?;
                    ensure!(
                        !leaf.contains('/')
                            && !crate::scope::private_path(Path::new(leaf))
                            && files.insert(leaf.to_owned()),
                        "unsafe, duplicate or widened file scope"
                    );
                }
                Some(files)
            };
            roots.push(RootSpec {
                id,
                path,
                identity,
                kind,
                allowed_files,
            });
        }
        crate::scope::validate_absolute(executable)?;
        ensure!(
            !crate::scope::private_path(executable),
            "private executable is excluded"
        );
        if let Some(exclusions) = policy["excludedPaths"].as_array() {
            ensure!(exclusions.len() <= 256, "too many native policy exclusions");
            for exclusion in exclusions {
                let path = Path::new(
                    exclusion
                        .as_str()
                        .context("invalid native policy exclusion")?,
                );
                crate::scope::validate_absolute(path)?;
                ensure!(
                    !executable.starts_with(path),
                    "selected native executable is policy-excluded"
                );
            }
        }
        if let Some(known) = source["canonical_executable"].as_str() {
            ensure!(
                Path::new(known) == executable,
                "selected executable differs from sourceIdentity"
            );
        }
        // Pick from the actual signed install/runtime roots only. Never derive
        // or approve executable.parent() and never promote an exact-file root.
        let (root, relative) = roots.iter().filter(|root| root.kind.allows(ObservationRootKind::Executable))
            .filter_map(|root| {
                let relative = crate::scope::portable_relative(executable.strip_prefix(&root.path).ok()?)?;
                if crate::scope::validate_relative(&relative).is_err()
                    || root.allowed_files.as_ref().is_some_and(|files| !files.contains(&relative)) { return None; }
                Some((root, relative))
            }).max_by_key(|(root, _)| root.path.as_os_str().len())
            .context("exact executable is not in a materialized, approved install/runtime file selection")?;
        let pinned = SafeRoot::open(&root.path)?;
        ensure!(
            pinned.identity()? == root.identity,
            "materialized executable root identity changed"
        );
        let (_metadata, executable_stamp) = pinned.read_file(&relative)?;
        ensure!(
            pinned.identity()? == root.identity,
            "executable root changed during metadata pinning"
        );
        let mac_bundle = if let Some(identifier) = source_app_id.strip_prefix("mac-bundle:") {
            let bundle = roots
                .iter()
                .filter(|root| {
                    root.kind == ObservationRootKind::Installation
                        && root.allowed_files.is_none()
                        && executable.starts_with(root.path.join("Contents/MacOS"))
                })
                .max_by_key(|root| root.path.as_os_str().len())
                .context(
                    "native Mac bundle metadata needs its exact materialized installation root",
                )?;
            Some(MacBundleBinding {
                identifier: identifier.into(),
                path: bundle.path.clone(),
            })
        } else {
            None
        };
        let application = NativeApplicationSpec {
            app_id: app_id.clone(),
            source_app_id: source_app_id.clone(),
            executable: executable.into(),
            executable_stamp,
            root_ids: ids,
            mac_bundle,
        };
        Ok(Self {
            software_id,
            app_id,
            source_app_id,
            tracking_scope_hash,
            roots,
            application,
        })
    }

    pub fn software_id(&self) -> &str {
        &self.software_id
    }
    pub fn app_id(&self) -> &str {
        &self.app_id
    }
    pub fn source_app_id(&self) -> &str {
        &self.source_app_id
    }
    pub fn roots(&self) -> &[RootSpec] {
        &self.roots
    }
    pub fn application(&self) -> &NativeApplicationSpec {
        &self.application
    }

    pub fn append_to_scope(&self, request: &mut ScopeRequest) -> Result<()> {
        // Roll back only this bounded append on failure. Cloning the entire
        // accumulated 4096-app scope for every binding is quadratic in retained
        // allowlist size and is unnecessary for atomic native construction.
        let original_roots = request.roots.len();
        for root in &self.roots {
            if let Err(error) = request.add_exact_root(root.clone()) {
                request.roots.truncate(original_roots);
                return Err(error);
            }
        }
        if let Err(error) = request.add_native_application(self.application.clone()) {
            request.roots.truncate(original_roots);
            return Err(error);
        }
        Ok(())
    }

    /// Re-read private native records before signing; a changed index revision
    /// alone is allowed, but identity, roots, file leaves, policy and executable
    /// must still match. The constructor rechecks current signed attestations.
    pub fn validate_current(
        &self,
        record: &Value,
        authority: &Value,
        verifier: &dyn GrantVerifier,
    ) -> Result<()> {
        let current =
            Self::from_native_records(record, authority, &self.application.executable, verifier)?;
        ensure!(
            current.software_id == self.software_id
                && current.app_id == self.app_id
                && current.source_app_id == self.source_app_id
                && current.tracking_scope_hash == self.tracking_scope_hash
                && current.application.executable_stamp == self.application.executable_stamp
                && current.roots.len() == self.roots.len()
                && current.roots.iter().all(|root| self
                    .roots
                    .iter()
                    .any(|old| crate::scope::same_root_spec(old, root))),
            "native observation binding changed; rebuild and reapprove the exact scope"
        );
        Ok(())
    }

    /// Returns at most one compact hint. Persistent polling limitations do not
    /// cause a new hint, and unknown IDs are never matched/enrolled here.
    pub fn hint(
        &self,
        snapshot: &ObservationSnapshot,
        context: &ObservationContext,
    ) -> Result<Option<TrackerObservationHint>> {
        let Some(app) = snapshot
            .applications
            .iter()
            .find(|app| app.app_id == self.app_id && app.registered_identity)
        else {
            return Ok(None);
        };
        if app.capture_triggers.is_empty() {
            return Ok(None);
        }
        let sessions: Vec<_> = app
            .active_sessions
            .iter()
            .chain(app.ended_sessions.iter())
            .collect();
        // No session-generation proof means a source-permission diagnostic,
        // not a fabricated app_open/app_close or an ownership grant.
        if sessions.is_empty() {
            return Ok(None);
        }
        let mut generation = blake3::Hasher::new();
        for session in sessions {
            let proof = &session.process;
            ensure!(
                proof.scope_fingerprint() == context.fingerprint
                    && proof.app_id() == self.app_id
                    && proof.executable() == self.application.executable
                    && proof.executable_stamp() == &self.application.executable_stamp
                    && proof.image_binding() == ImageIdentityBinding::MappedImageNativeFile
                    && proof.generation().uid == context.uid
                    && proof.generation().pid != 0
                    && proof.observed_at_ms() <= snapshot.observed_at_ms,
                "native session generation/executable binding does not match this bundle"
            );
            generation.update(session.id.as_bytes());
            generation.update(serde_json::to_string(proof.generation())?.as_bytes());
        }
        for file in snapshot
            .files
            .iter()
            .filter(|file| file.process().app_id() == self.app_id)
        {
            let root = self
                .roots
                .iter()
                .find(|root| root.id == file.root_id())
                .context("observed native file root is not owned by this materialized bundle")?;
            crate::scope::validate_relative(file.relative_path())?;
            ensure!(
                root.allowed_files
                    .as_ref()
                    .is_none_or(|files| files.contains(file.relative_path())),
                "observed file widened the materialized exact-file selection"
            );
        }
        let kind = if app.execution_state == ExecutionState::NotObservedRunning
            && app
                .capture_triggers
                .contains(&CaptureTrigger::ObservedRunClose)
        {
            "app_close"
        } else if app.execution_state == ExecutionState::Running
            && app.capture_triggers.contains(&CaptureTrigger::ObservedRun)
        {
            "app_open"
        } else {
            "change_hint"
        };
        let roots: BTreeSet<_> = self.roots.iter().map(|root| root.id.clone()).collect();
        let scope = json!({
            "version":1, "softwareId":self.software_id, "appId":self.app_id, "kind":kind,
            "rootIds":roots, "trackingScopeHash":self.tracking_scope_hash,
        });
        Ok(Some(TrackerObservationHint {
            scope,
            software_id: self.software_id.clone(),
            app_id: self.app_id.clone(),
            root_ids: roots,
            kind,
            epoch: snapshot.epoch,
            generation_hash: generation.finalize().to_hex().to_string(),
        }))
    }
}

pub struct TrackerObservationHint {
    scope: Value,
    software_id: String,
    app_id: String,
    root_ids: BTreeSet<String>,
    kind: &'static str,
    epoch: u64,
    generation_hash: String,
}
impl TrackerObservationHint {
    pub fn scope(&self) -> &Value {
        &self.scope
    }
    pub fn into_event(self, native_owner_grant: Value) -> Value {
        json!({
            "softwareId":self.software_id, "appId":self.app_id, "rootIds":self.root_ids, "kind":self.kind,
            "scope":self.scope, "grant":native_owner_grant,
            "nativeObservation":{"epoch":self.epoch, "sessionGenerationHash":self.generation_hash,
                "completeness":"unknown", "applicationAtomic":false, "clean":false},
        })
    }
}

fn root_array(value: &Value) -> Result<&[Value]> {
    let roots = value.as_array().context("materialized roots missing")?;
    ensure!(
        !roots.is_empty() && roots.len() <= 48,
        "invalid materialized root count"
    );
    Ok(roots)
}
fn text(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .context("native identity/reference string missing")?;
    crate::scope::valid_id(text)?;
    Ok(text.into())
}
fn digest(value: &Value) -> Result<String> {
    bounded(value)?;
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}
fn bounded(value: &Value) -> Result<()> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize, bytes: &mut usize) -> Result<()> {
        ensure!(
            depth <= 32 && *nodes > 0,
            "native observation metadata exceeds structural bounds"
        );
        *nodes -= 1;
        let charge = match value {
            Value::String(value) => value.len().saturating_mul(6).saturating_add(2),
            Value::Array(values) => values.len().saturating_add(2),
            Value::Object(values) => values.keys().fold(2usize, |sum, key| {
                sum.saturating_add(key.len().saturating_mul(6) + 4)
            }),
            _ => 32,
        };
        *bytes = bytes
            .checked_sub(charge)
            .context("native observation metadata exceeds byte bounds")?;
        match value {
            Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, nodes, bytes)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    visit(value, depth + 1, nodes, bytes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(value, 0, &mut 65536usize, &mut (4 * 1024 * 1024usize))
}
