// SPDX-License-Identifier: GPL-3.0-only
//! Production adapters; tests inject their own boundaries instead.

use crate::{
    boundary as dto,
    interfaces::{
        Enqueue, NativeDiscovery, NativeFuture, PublishGuard, ServiceEngine, ServiceStore,
        ServiceTracking, SourceGuard,
    },
    root_guard, Queue, WorkspaceService,
};
use anyhow::{anyhow, bail, ensure, Result};
use quicksave_noland::NativeEngine;
use quicksave_state::{ProviderAccess, WorkspaceStore};
use quicksave_tracking::{Tracker, TrackingPolicy, TrackingStore};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[cfg(all(test, unix))]
#[path = "native/capture_integration_tests.rs"]
mod capture_integration_tests;

pub(super) async fn open(
    data_dir: &Path,
    home: &Path,
    isolated: bool,
) -> Result<Arc<WorkspaceService>> {
    let discovery = Arc::new(NativeDiscovery::new(home, data_dir, isolated)?);
    let import_dirs = isolated.then(|| quicksave_state::KnownDataDirs {
        bases: vec![home_application_data(home)],
    });
    let data = data_dir.to_path_buf();
    let home = home.to_path_buf();
    let (store, engine, policy) = tokio::task::spawn_blocking(move || {
        let store = if isolated {
            WorkspaceStore::open_with_vault(
                &data,
                Arc::new(quicksave_state::MemoryVault::default()),
            )?
        } else {
            WorkspaceStore::open(&data)?
        };
        let engine = NativeEngine::open(&data, &home)?.with_workspace(store.clone())?;
        let mut policy = TrackingPolicy::new(&data);
        // These capabilities are implemented by the actual source capture
        // coordinator and publication receipt, including authenticated empty
        // roots and additive omission history. They are not folder-copy flags.
        policy.supports_metadata_snapshots = cfg!(any(unix, windows));
        policy.supports_deletion_snapshots = cfg!(any(unix, windows));
        // This compile-time workspace path is an exclusion, never a capture
        // candidate. Also reject native credential locations even if absent.
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow!("QuickSave repository exclusion is unavailable"))?;
        policy.excluded_paths.push(repository.to_path_buf());
        for relative in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".config/rclone",
            "Library/Keychains",
        ] {
            policy.excluded_paths.push(home.join(relative));
        }
        Ok::<_, anyhow::Error>((store, engine, policy))
    })
    .await
    .map_err(|_| anyhow!("The native workspace initialization worker failed"))?
    .map_err(|error| {
        let category = dto::engine_error(&error);
        if category == dto::NATIVE_FAILURE {
            anyhow!("The native QuickSave workspace could not be opened safely")
        } else {
            anyhow!(category)
        }
    })?;
    let queue = Queue::new();
    let callback = queue.enqueue();
    let adapter = Arc::new(StoreAdapter(store.clone(), import_dirs));
    let tracking_store: Arc<dyn TrackingStore> = adapter.clone();
    let resume_autosave = store.document()?.software.iter().any(|software| {
        software.autosave && software.autosave_grant.is_some() && software.tracking_grant.is_some()
    });
    let resume_index = store
        .document()?
        .software
        .iter()
        .any(|software| software.tracking_grant.is_some() && !software.roots.is_empty());
    let resume_tracking = store
        .document()?
        .settings
        .app_tracking
        .as_ref()
        .is_some_and(|settings| settings.policy_scope.enabled);
    let engine = Arc::new(engine);
    let tracking = Arc::new(TrackingAdapter {
        tracker: Mutex::new(None),
        store: store.clone(),
        engine: Some(engine.clone()),
        observation: Mutex::new(None),
        observation_enabled: !isolated,
        bootstrap: Some(TrackingBootstrap {
            store: tracking_store,
            enqueue: callback,
            policy,
        }),
    });
    if resume_autosave || resume_index {
        let startup = tracking.clone();
        tokio::task::spawn_blocking(move || startup.tracker())
            .await
            .map_err(|_| anyhow!("The autosave initialization worker failed"))?
            .map_err(|_| anyhow!("Persisted autosave authority could not be validated safely"))?;
    }
    let service = WorkspaceService::assemble(
        adapter,
        Arc::new(EngineAdapter(engine.clone())),
        tracking.clone(),
        discovery,
        if isolated {
            Arc::new(crate::interfaces::UnavailableOAuth)
        } else {
            Arc::new(crate::oauth::NativeOAuth)
        },
        queue,
    )?;
    #[cfg(unix)]
    if !isolated {
        let adapters = Arc::new(crate::batch_adapter::NativeBatchAdapters::new(
            store.clone(),
            engine,
            tracking,
        ));
        let signer = Arc::new(crate::native_plans::WorkspaceOperationSigner::new(store));
        let runtime = crate::batch::NativeBatchRuntime::open(
            &service,
            &data_dir.join("native-batches"),
            signer,
            adapters.clone(),
            adapters,
        )?;
        runtime.confirm_core_hooks_installed();
        service
            .batch
            .set(runtime)
            .map_err(|_| anyhow!("Native batch ownership was already installed"))?;
    }
    if resume_tracking {
        // Plain settings only schedule verification; they never authorize
        // inventory/content access until the native-vault policy MAC is valid.
        if service
            .tracking_call("verify_app_tracking_policy", json!({}))
            .await
            .is_ok()
        {
            service.start_app_tracking(json!({}), false)?;
        }
    }
    Ok(service)
}

struct StoreAdapter(WorkspaceStore, Option<quicksave_state::KnownDataDirs>);

impl ServiceStore for StoreAdapter {
    fn snapshot(&self) -> Result<Value> {
        Ok(serde_json::to_value(self.0.document()?)?)
    }
    fn provider_types(&self) -> Value {
        self.0.provider_types()
    }
    fn connect_provider(&self, input: &Value) -> Result<Value> {
        ensure!(
            self.1.is_none(),
            "Isolated development workspaces cannot connect live storage accounts"
        );
        let before = self
            .0
            .document()?
            .providers
            .into_iter()
            .map(|p| p.id)
            .collect::<std::collections::BTreeSet<_>>();
        self.0.connect_provider(input)?;
        let after = self.0.document()?;
        let created = after
            .providers
            .iter()
            .filter(|provider| !before.contains(&provider.id))
            .collect::<Vec<_>>();
        ensure!(
            created.len() == 1,
            "Native provider creation did not produce exactly one profile"
        );
        Ok(json!({"id":created[0].id}))
    }
    fn disconnect_provider(&self, id: &str) -> Result<()> {
        self.0.disconnect_provider(id)
    }
    fn import_noland(&self, input: &Value) -> Result<Value> {
        self.0.import_noland(input)
    }
    fn discover_noland_sources(&self) -> Result<Value> {
        match &self.1 {
            Some(dirs) => self.0.discover_noland_sources_in(dirs),
            None => self.0.discover_noland_sources(),
        }
    }
    fn noland_source_scope(&self, source_id: &str) -> Result<Value> {
        let proof = self.0.noland_source_proof(source_id)?;
        Ok(json!({
            "sourceId":source_id, "path":proof.state_file(),
            "file":proof.approved_path_handoff()?,
        }))
    }
    fn provider_access(&self, id: &str, operation_id: &str) -> Result<ProviderAccess> {
        ensure!(
            self.1.is_none(),
            "Isolated development workspaces cannot access live storage accounts"
        );
        self.0.provider_access(id, operation_id)
    }
    fn record_provider_health(&self, id: &str, report: &Value) -> Result<()> {
        self.0.record_provider_health(id, report)
    }
    fn grant_provider_write(&self, id: &str) -> Result<()> {
        self.0.grant_provider_write(id)
    }
    fn provider_writable(&self, id: &str) -> Result<bool> {
        self.0.provider_writable(id)
    }
    fn oauth_reauthorization_profile(
        &self,
        id: &str,
    ) -> Result<quicksave_state::NativeOAuthProfile> {
        ensure!(
            self.1.is_none(),
            "Isolated development cannot reauthorize live storage accounts"
        );
        self.0.oauth_reauthorization_profile(id)
    }
    fn provider_credential_generation(&self, id: &str) -> Result<u64> {
        ensure!(
            self.1.is_none(),
            "Isolated development cannot reauthorize live storage accounts"
        );
        self.0.provider_credential_generation(id)
    }
    fn complete_provider_reauthorization(
        &self,
        id: &str,
        expected: u64,
        credentials: &Value,
    ) -> Result<()> {
        ensure!(
            self.1.is_none(),
            "Isolated development cannot reauthorize live storage accounts"
        );
        self.0
            .complete_provider_reauthorization(id, expected, credentials)
            .map(|_| ())
    }
    fn export_recovery_key(&self, input: &Value) -> Result<Value> {
        let destination = Path::new(dto::text(input, "destination", 4096)?);
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow!("Recovery export needs a parent directory"))?;
        let proofs = input["_approvedPaths"]
            .as_array()
            .ok_or_else(|| anyhow!("Native recovery export proofs are missing"))?;
        let proof = proofs
            .iter()
            .find(|proof| proof["path"].as_str() == parent.to_str() && proof["kind"] == "directory")
            .ok_or_else(|| anyhow!("Native recovery export parent was not approved"))?;
        let parent_identity = serde_json::from_value(proof["identity"].clone())?;
        self.0
            .export_recovery_key(&quicksave_state::NativeRecoveryExport {
                provider_id: Some(dto::id(input, "providerId")?.into()),
                destination: destination.to_path_buf(),
                parent_identity,
            })
    }
}

impl TrackingStore for StoreAdapter {
    fn load_records(&self) -> Result<Vec<Value>> {
        Ok(self
            .0
            .software()?
            .into_iter()
            .filter(|record| {
                record["trackingGrant"].is_object()
                    && record["roots"]
                        .as_array()
                        .is_some_and(|roots| !roots.is_empty())
            })
            .collect())
    }
    fn save_record(&self, record: &Value) -> Result<()> {
        // Tracker writes a complete native record. State's public patch API
        // preserves omitted fields, so retirement must explicitly clear this
        // opaque pointer rather than resurrect the previous pending frame.
        if record.get("pendingWork").is_none() {
            let mut complete = record.clone();
            complete["pendingWork"] = Value::Null;
            self.0.update_software(&complete)?;
        } else {
            self.0.update_software(record)?;
        }
        Ok(())
    }
    fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
        self.0.issue_grant(kind, scope)
    }
    fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
        self.0.verify_grant(kind, scope, grant)
    }
    fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
        self.0.revoke_grant(kind, scope)
    }
    fn provider_writable(&self, provider_id: &str) -> Result<bool> {
        self.0.provider_writable(provider_id)
    }
    fn provider_known(&self, provider_id: &str) -> Result<bool> {
        Ok(self
            .0
            .document()?
            .providers
            .iter()
            .any(|provider| provider.id == provider_id))
    }
}

fn home_application_data(home: &Path) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else if cfg!(windows) {
        home.join("AppData/Roaming")
    } else {
        home.join(".local/share")
    }
}

struct TrackingBootstrap {
    store: Arc<dyn TrackingStore>,
    enqueue: Enqueue,
    policy: TrackingPolicy,
}
struct TrackingAdapter {
    tracker: Mutex<Option<Arc<Tracker>>>,
    store: WorkspaceStore,
    bootstrap: Option<TrackingBootstrap>,
    engine: Option<Arc<NativeEngine>>,
    observation: Mutex<Option<crate::observation::ObservationSession>>,
    observation_enabled: bool,
}
impl TrackingAdapter {
    fn stop_observation(&self) -> Result<()> {
        // Never hold the Tracker/store locks while joining a callback that uses
        // them. The observer's only owner stays retained if draining fails.
        let mut session = self
            .observation
            .lock()
            .map_err(|_| anyhow!("Native observation ownership lock failed"))?;
        if let Some(active) = &*session {
            active.shutdown()?;
        }
        session.take();
        Ok(())
    }

    fn refresh_observation(&self) -> Result<Value> {
        self.stop_observation()?;
        if !self.observation_enabled {
            return Ok(json!({"state":"disabled","sourceIndexMaterialized":false}));
        }
        #[cfg(unix)]
        {
            let engine = self
                .engine
                .as_ref()
                .ok_or_else(|| anyhow!("The native source graph owner is unavailable"))?;
            let tracker = self.tracker()?;
            let bootstrap = self
                .bootstrap
                .as_ref()
                .ok_or_else(|| anyhow!("Native observation policy is unavailable"))?;
            // This explicit materialization uses the already authenticated
            // immutable metadata index, never a new content walk or hashing.
            let graph = crate::observation::materialize_source_indices(
                self.store.clone(),
                tracker.clone(),
                engine.clone(),
                vec![],
            )?;
            let session = crate::observation::ObservationSession::start_with_source_engine(
                self.store.clone(),
                tracker,
                bootstrap.policy.clone(),
                bootstrap.policy.excluded_paths.clone(),
                vec![],
                engine.clone(),
            )?;
            let mut status = session.status()?;
            status["sourceGraph"] = dto::copy_fields(
                &graph,
                &[
                    "indexedBundles",
                    "sourceIndexedInstances",
                    "sourceCanonicalApps",
                    "sourceIndexedNodes",
                    "diagnostics",
                    "omittedDiagnostics",
                    "incomplete",
                    "fileStateTrust",
                    "coverageTrusted",
                    "complete",
                    "saved",
                    "cloudWrite",
                ],
            );
            *self
                .observation
                .lock()
                .map_err(|_| anyhow!("Native observation ownership lock failed"))? = Some(session);
            Ok(status)
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("Native source graph observation is unavailable on this platform")
        }
    }

    fn tracker(&self) -> Result<Arc<Tracker>> {
        let mut slot = self
            .tracker
            .lock()
            .map_err(|_| anyhow!("Native tracker ownership lock failed"))?;
        if let Some(tracker) = &*slot {
            return Ok(tracker.clone());
        }
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or_else(|| anyhow!("Native tracker initialization is unavailable"))?;
        let tracker = Arc::new(Tracker::open(
            bootstrap.store.clone(),
            bootstrap.enqueue.clone(),
            bootstrap.policy.clone(),
        )?);
        *slot = Some(tracker.clone());
        Ok(tracker)
    }

    fn verified(&self, software: &str) -> Result<Value> {
        ensure!(
            self.store.verify_tracking_grant(software)?,
            "Persisted manual tracking authority is invalid or revoked"
        );
        let record = self.store.software_record(software)?;
        let authority = self.tracker()?.root_authority(software)?;
        ensure!(
            authority["roots"] == authority_roots(&record)?,
            "Tracker/persisted root or individual-file scope mismatch"
        );
        Ok(record)
    }

    fn verify_work(&self, work: &Value) -> Result<()> {
        self.tracker()?.verify_autosave_work(work)?;
        let software = dto::id(work, "softwareId")?;
        let provider = dto::id(work, "providerId")?;
        let record = self.verified(software)?;
        ensure!(
            work["roots"] == authority_roots(&record)? && record["providerId"] == provider,
            "Autosave work scope changed"
        );
        self.verify_autosave_authorization(software, provider, &record, work)
    }

    fn verify_autosave_authorization(
        &self,
        software: &str,
        provider: &str,
        record: &Value,
        work: &Value,
    ) -> Result<()> {
        let authorization = work
            .get("authorization")
            .ok_or_else(|| anyhow!("Autosave work lacks signed authority"))?;
        ensure!(
            record["trackingGrant"] == authorization["trackingGrant"]
                && record["autosaveGrant"] == authorization["autosaveGrant"],
            "The original native autosave authority was replaced"
        );
        ensure!(
            self.store.verify_grant(
                "tracking",
                &authorization["trackingScope"],
                &authorization["trackingGrant"]
            )?,
            "Autosave tracking authority was revoked"
        );
        ensure!(
            self.store.verify_autosave_grant(software, provider)?,
            "Persistent autosave authority was revoked or changed"
        );
        ensure!(
            self.store.verify_grant(
                "autosave",
                &authorization["autosaveScope"],
                &authorization["autosaveGrant"]
            )?,
            "Autosave work no longer matches the native grant"
        );
        Ok(())
    }

    fn verify_upload_scope(
        &self,
        software: &str,
        provider: &str,
        automatic: bool,
        work: &Value,
    ) -> Result<()> {
        let record = self.verified(software)?;
        ensure!(
            record["providerId"] == provider && self.store.provider_writable(provider)?,
            "Provider write authority was revoked"
        );
        if automatic {
            ensure!(
                record["autosave"] == true,
                "Persistent autosave was disabled"
            );
            // Revocation polling checks fresh small authority only. Exact node
            // inventories are verified at admission; the actual source receipt
            // is revalidated at COMMITTED/catalog publication barriers. Do not
            // rewalk 250k original IDs on every 250 ms progress tick.
            self.verify_autosave_authorization(software, provider, &record, work)?;
        }
        Ok(())
    }
}

impl TrackingAdapter {
    fn call_inner(&self, method: &str, input: &Value) -> Result<Value> {
        match method {
            "app_discovery_authority" => crate::enrollment::discovery_authority(&self.store, input),
            "materialize_bundles" => {
                let mut result =
                    crate::enrollment::materialize(&self.store, self.tracker()?.as_ref(), input)?;
                match self.refresh_observation() {
                    Ok(status) => {
                        if status["sourceGraph"]["incomplete"] == true {
                            result["incomplete"] = json!(true);
                            if let Some(diagnostics) = result["diagnostics"].as_array_mut() {
                                if diagnostics.len() < 256 {
                                    diagnostics.push(json!({"code":"native_source_graph_incomplete",
                                        "message":"Some native source indices could not be imported. Existing data is retained and coverage remains unconfirmed."}));
                                }
                            }
                        }
                        result["observation"] = status;
                    }
                    Err(_) => {
                        result["incomplete"] = json!(true);
                        result["observation"] = json!({"state":"reconciliation_required","sourceIndexMaterialized":false});
                        if let Some(diagnostics) = result["diagnostics"].as_array_mut() {
                            if diagnostics.len() < 256 {
                                diagnostics.push(json!({"code":"native_source_graph_reconciliation_required",
                                    "message":"Native source index or process evidence could not be admitted. Indexed local roots remain available; coverage is not confirmed."}));
                            }
                        }
                    }
                }
                Ok(result)
            }
            "disable_app_tracking" => {
                self.store.clear_app_tracking_policy()?;
                self.stop_observation()?;
                if let Some(tracker) = self
                    .tracker
                    .lock()
                    .map_err(|_| anyhow!("Native tracker ownership lock failed"))?
                    .clone()
                {
                    tracker.disable_automatic_tracking()?;
                }
                Ok(json!({}))
            }
            "mark_unknown_dirty" => {
                let software = dto::id(input, "softwareId")?;
                let before = self.store.software_record(software)?;
                ensure!(
                    self.store.verify_tracking_grant(software)?,
                    "Unknown-state recovery needs the original signed tracking authority"
                );
                ensure!(
                    before["appId"] == input["appId"]
                        && before["providerId"] == input["providerId"]
                        && before["trackingGrant"] == input["record"]["trackingGrant"]
                        && before["sourceIdentity"] == input["record"]["sourceIdentity"]
                        && authority_roots(&before)? == authority_roots(&input["record"])?
                        && crate::native_plans::root_authority_revision(&before)?
                            == dto::text(input, "rootAuthorityRevision", 64)?,
                    "The frozen native root/instance authority changed"
                );
                let unknown = self.tracker()?.mark_unknown_dirty(software)?;
                let persisted = self.store.software_record(software)?;
                ensure!(
                    persisted["dirty"] == true
                        && persisted["reconciliationRequired"] == true
                        && persisted["dirtyGeneration"] == unknown["dirtyGeneration"]
                        && persisted["unknownGeneration"] == unknown["unknownGeneration"]
                        && persisted["status"] != "saved"
                        && persisted["confirmedGeneration"].is_null(),
                    "Unknown native state was not durably retained"
                );
                let message = serde_json::to_vec(&json!({
                    "domain":"QuickSave/native-batch-unknown/v1",
                    "softwareId":software,"rootAuthorityRevision":input["rootAuthorityRevision"],
                    "sourceId":input["sourceId"],"workId":input["workId"],"reason":input["reason"],
                    "dirtyGeneration":persisted["dirtyGeneration"],"unknownGeneration":persisted["unknownGeneration"],
                }))?;
                let mac = self.store.operation_mac_existing(&message)?;
                Ok(
                    json!({"softwareId":software,"rootAuthorityRevision":input["rootAuthorityRevision"],
                    "persisted":true,"state":"unknown_dirty",
                    "proofDigest":blake3::hash(&mac).to_hex().to_string(),
                    "dirtyGeneration":persisted["dirtyGeneration"],"unknownGeneration":persisted["unknownGeneration"],
                    "acknowledgement":unknown}),
                )
            }
            "verify_app_tracking_policy" => {
                ensure!(
                    self.store.app_tracking_policy()?.is_some(),
                    "Native application tracking policy is disabled or revoked"
                );
                Ok(json!({}))
            }
            "app_tracking" => {
                // Pure startup/status projection; signed policy verification
                // occurs in the owned tracking worker, not on each UI poll.
                let status = self.store.sanitized()?;
                Ok(status
                    .pointer("/settings/appTracking")
                    .cloned()
                    .unwrap_or(Value::Null))
            }
            "software" => {
                // Idle/dashboard startup must not unlock a vault or start
                // watchers for unverified manual records. Explicit source
                // browsing/mutation initializes and validates the tracker.
                let ready = self
                    .tracker
                    .lock()
                    .map_err(|_| anyhow!("Native tracker ownership lock failed"))?
                    .is_some();
                if !ready {
                    return Ok(self.store.sanitized()?["software"].clone());
                }
                // Tracker validates each signed scope/policy before returning a
                // real indexed DTO. Re-reading and parsing the entire state file
                // once again for every app would turn this into quadratic I/O.
                Ok(json!(self.tracker()?.software()?))
            }
            "approve_software" => self.tracker()?.approve_software(input),
            "add_files" => {
                let added = self.tracker()?.add_files(input)?;
                let id = dto::id(&added, "id")?;
                let record = self.store.software_record(id)?;
                if record["appId"].is_null() {
                    let mut roots = authority_roots(&record)?;
                    for root in roots.as_array_mut().unwrap() {
                        // null is whole tree in persisted state, while the
                        // native approval API uses an omitted allowlist.
                        if root["allowedFiles"].is_null() {
                            root.as_object_mut().unwrap().remove("allowedFiles");
                        }
                        root.as_object_mut().unwrap().remove("identity");
                    }
                    // This is the same already-native-consented pinned scope;
                    // only a durable software identity is assigned. Reapproval
                    // rechecks native handles and signs the exact new app ID.
                    let mut approval = json!({
                        "softwareId":id,"appId":format!("quicksave.manual.{}",uuid::Uuid::new_v4()),
                        "name":record["name"],"providerId":record["providerId"],"roots":roots,
                    });
                    if let Some(proofs) = input.get("_approvedPaths") {
                        approval["_approvedPaths"] = proofs.clone();
                    }
                    self.tracker()?.approve_software(&approval)
                } else {
                    Ok(added)
                }
            }
            "set_provider" => self.tracker()?.set_provider(
                dto::id(input, "softwareId")?,
                Some(dto::id(input, "providerId")?),
            ),
            "configure_autosave" => self.tracker()?.configure_autosave(
                dto::id(input, "softwareId")?,
                dto::id(input, "providerId")?,
                dto::boolean(input, "enabled")?,
            ),
            "file_listing" => {
                let software = dto::id(input, "softwareId")?;
                let record = self.verified(software)?;
                let cursor = input.get("cursor").and_then(Value::as_str);
                let mut listing =
                    self.tracker()?
                        .file_listing(software, cursor, dto::limit(input)?)?;
                if let Some(files) = listing["files"].as_array_mut() {
                    for file in files {
                        if let Some(root) = record["roots"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|root| root["id"] == file["rootId"])
                        {
                            file["role"] = root["role"].clone();
                        }
                    }
                }
                Ok(listing)
            }
            "scan_metadata" => {
                let software = dto::id(input, "softwareId")?;
                self.verified(software)?;
                self.tracker()?.scan_metadata(software)
            }
            "begin_upload" | "prepare_upload_scope" => {
                let software = dto::id(input, "softwareId")?;
                self.verified(software)?;
                let ids = input
                    .get("fileIds")
                    .filter(|value| !value.is_null())
                    .map(|value| {
                        let values = value
                            .as_array()
                            .ok_or_else(|| anyhow!("Retry selection is invalid"))?;
                        ensure!(
                            !values.is_empty() && values.len() <= 250_000,
                            "Retry selection exceeds the bounded exact scope"
                        );
                        values
                            .iter()
                            .map(|value| {
                                value
                                    .as_str()
                                    .map(str::to_owned)
                                    .ok_or_else(|| anyhow!("Invalid file identity"))
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                let tracker = self.tracker()?;
                if method == "prepare_upload_scope" {
                    tracker.prepare_upload_scope(
                        software,
                        dto::id(input, "providerId")?,
                        ids.as_deref(),
                    )
                } else {
                    tracker.begin_upload(software, dto::id(input, "providerId")?, ids.as_deref())
                }
            }
            "prepared_node_listing" => self.tracker()?.prepared_node_listing(
                dto::id(input, "workId")?,
                input.get("cursor").and_then(Value::as_str),
                dto::limit(input)?,
            ),
            "verify_capture_receipt" => self
                .tracker()?
                .verify_capture_receipt(dto::id(input, "workId")?),
            "capture_reuse_epoch" => {
                Ok(json!({"epoch":self.tracker()?.capture_reuse_epoch(dto::id(input,"workId")?)?}))
            }
            "full_scope_evidence" => self
                .tracker()?
                .full_scope_evidence(dto::id(input, "workId")?),
            "capture_completion_binding" => self
                .tracker()?
                .capture_completion_binding(dto::id(input, "workId")?),
            "complete_upload" => self.tracker()?.complete_upload(
                dto::id(input, "workId")?,
                input["generation"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("Missing captured generation"))?,
                dto::boolean(input, "success")?,
            ),
            "verify_autosave_work" => {
                self.verify_work(input)?;
                Ok(json!({}))
            }
            "verify_upload_authority" => {
                self.verify_upload_scope(
                    dto::id(input, "softwareId")?,
                    dto::id(input, "providerId")?,
                    input["automatic"] == true,
                    &input["work"],
                )?;
                Ok(json!({}))
            }
            "disconnect_provider" => {
                let provider = dto::id(input, "providerId")?;
                let tracker = self
                    .tracker
                    .lock()
                    .map_err(|_| anyhow!("Native tracker ownership lock failed"))?
                    .clone();
                let Some(tracker) = tracker else {
                    return Ok(json!({}));
                };
                for software in tracker.software()? {
                    if software["providerId"] == provider {
                        tracker.configure_autosave(dto::id(&software, "id")?, provider, false)?;
                    }
                }
                Ok(json!({}))
            }
            _ => bail!("This native tracker operation is not supported"),
        }
    }
}
impl ServiceTracking for TrackingAdapter {
    fn call(&self, method: &str, input: &Value) -> Result<Value> {
        if matches!(method, "software" | "file_listing") {
            // One synchronous, request-scoped document view. Grant MACs and
            // vault revocation checks remain real, and a fresh end-of-read
            // comparison discards projections that raced a state mutation.
            // Never apply this frame to capture, workers, or publication.
            let first = self
                .store
                .with_metadata_verification_snapshot(|| self.call_inner(method, input));
            match first {
                Err(error) if error.is::<quicksave_state::MetadataProjectionChanged>() => self
                    .store
                    .with_metadata_verification_snapshot(|| self.call_inner(method, input)),
                result => result,
            }
        } else {
            self.call_inner(method, input)
        }
    }
    fn pin_scope(&self, record: &Value) -> Result<Arc<dyn SourceGuard>> {
        let verified = self.verified(dto::id(record, "id")?)?;
        ensure!(
            authority_roots(&verified)? == authority_roots(record)?,
            "Native source approval changed"
        );
        root_guard::pin(&verified)
    }
    fn accept_capture_receipt(
        &self,
        work_id: &str,
        receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<Value> {
        self.tracker()?.accept_capture_receipt(work_id, receipt)
    }
    fn original_work(
        &self,
        record: &Value,
        work_id: &str,
        generation: u64,
    ) -> Result<Arc<quicksave_tracking::NativeFrozenWork>> {
        let software = dto::id(record, "id")?;
        let current = self.verified(software)?;
        ensure!(
            authority_roots(&current)? == authority_roots(record)?
                && current["appId"] == record["appId"]
                && current["providerId"] == record["providerId"]
                && current["sourceIdentity"] == record["sourceIdentity"]
                && current["trackingGrant"] == record["trackingGrant"],
            "Original native root/provider/instance authority changed"
        );
        let authority = self.tracker()?.root_authority(software)?;
        self.tracker()?.original_work(
            software,
            work_id,
            generation,
            &dto::fingerprint(&authority["scope"])?,
        )
    }
    fn resume_pending(
        &self,
        original: Arc<quicksave_tracking::NativeFrozenWork>,
        receipt: Arc<dyn quicksave_tracking::NativeCaptureReceipt>,
    ) -> Result<Value> {
        self.tracker()?.resume_pending(original, receipt)
    }
    fn verify_upload_authority(
        &self,
        software: &str,
        provider: &str,
        automatic: bool,
        work: &Value,
    ) -> Result<()> {
        self.verify_upload_scope(software, provider, automatic, work)
    }
    fn shutdown(&self) -> Result<()> {
        self.stop_observation()?;
        let tracker = self
            .tracker
            .lock()
            .map_err(|_| anyhow!("Native tracker ownership lock failed"))?
            .clone();
        if let Some(tracker) = tracker {
            tracker.shutdown()?;
        }
        Ok(())
    }
}

/// Lossless authority projection shared by service comparisons and the tracker.
/// Source/display metadata is deliberately not part of filesystem authority.
pub(super) fn authority_roots(record: &Value) -> Result<Value> {
    let roots = record["roots"]
        .as_array()
        .ok_or_else(|| anyhow!("Approved native roots are missing"))?;
    Ok(Value::Array(roots.iter().map(|root| json!({
        "id":root["id"],"path":root["path"],"role":root["role"],
        "identity":root["identity"],"allowedFiles":root.get("allowedFiles").unwrap_or(&Value::Null),
    })).collect()))
}

struct EngineAdapter(Arc<NativeEngine>);
impl ServiceEngine for EngineAdapter {
    #[cfg(any(unix, windows))]
    fn verify_capture_completion<'a>(
        &'a self,
        operation_id: &'a str,
        binding: Value,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.0
                .verify_capture_completion(operation_id, binding)
                .await
        })
    }
    #[cfg(any(unix, windows))]
    fn recover_restore_local<'a>(
        &'a self,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            // Local recovery is synchronous and fully owned. Keep its native
            // filesystem work off the async/GUI executor and await its drain.
            let engine = self.0.clone();
            tokio::task::spawn_blocking(move || engine.recover_restore_local(selection, guard))
                .await
                .map_err(|_| anyhow!("Native restore recovery worker failed"))?
        })
    }
    fn shutdown<'a>(&'a self) -> NativeFuture<'a, ()> {
        Box::pin(async move { self.0.shutdown().await })
    }
    #[cfg(unix)]
    fn delete_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move { self.0.delete_guarded(access, selection, guard).await })
    }
    fn rich_catalog_supported(&self) -> bool {
        cfg!(any(unix, windows))
    }
    fn native_capture_supported(&self) -> bool {
        cfg!(any(unix, windows))
    }
    #[cfg(any(unix, windows))]
    fn download_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move { self.0.download_guarded(access, selection, guard).await })
    }
    #[cfg(any(unix, windows))]
    fn upload_captured_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
        capture: Arc<dyn quicksave_noland::capture_control::NativeCaptureController>,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            self.0
                .upload_captured_guarded(access, selection, guard, capture)
                .await
        })
    }
    fn upload_guarded<'a>(
        &'a self,
        access: ProviderAccess,
        selection: Value,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move { self.0.upload_guarded(access, selection, guard).await })
    }
    fn retry_guarded<'a>(
        &'a self,
        operation_id: &'a str,
        guard: PublishGuard,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move { self.0.retry_guarded(operation_id, guard).await })
    }
    fn call<'a>(
        &'a self,
        method: &'a str,
        access: Option<ProviderAccess>,
        input: Value,
    ) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            match method {
                "preflight" => self.0.preflight().await,
                "register" => {
                    self.0.register(&input).await?;
                    Ok(json!({}))
                }
                "catalog" => {
                    #[cfg(windows)]
                    return self.0.catalog_projection(
                        &access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                    ).await;
                    #[cfg(not(windows))]
                    self.0
                        .catalog(
                            &access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                        )
                        .await
                }
                "files" => {
                    self.0
                        .files(
                            &access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                            &input,
                        )
                        .await
                }
                "health_check" => {
                    let report = self
                        .0
                        .health(
                            &access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                        )
                        .await?;
                    // Empty-root list + absent-head evidence is distinct from
                    // a read/authenticated encrypted catalog. Never invent
                    // authenticated/canRead/keyVerified flags.
                    let output = dto::copy_fields(
                        &report,
                        &[
                            "canList",
                            "canRead",
                            "repositoryAccessible",
                            "repositoryEmpty",
                            "keyVerified",
                            "evidence",
                            "observedAt",
                            "providerId",
                        ],
                    );
                    Ok(output)
                }
                "upload" => {
                    self.0
                        .upload(
                            access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                            input,
                        )
                        .await
                }
                #[cfg(any(unix, windows))]
                "preview_restore" => {
                    self.0
                        .preview_restore(
                            access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                            input,
                        )
                        .await
                }
                #[cfg(any(unix, windows))]
                "restore_preview_scope" => self
                    .0
                    .restore_preview_scope(dto::id(&input, "restorePreviewId")?),
                #[cfg(any(unix, windows))]
                "restore_recovery_scope" => self
                    .0
                    .restore_recovery_scope(dto::id(&input, "operationId")?),
                #[cfg(not(any(unix, windows)))]
                "preview_restore" | "restore_preview_scope" | "restore_recovery_scope" => bail!(
                    "Authenticated frozen restore controls are unsupported on this native backend"
                ),
                "download" => {
                    bail!("A native restore needs its frozen preview and publication authority")
                }
                "preview_delete" => {
                    self.0
                        .preview_delete(
                            &access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                            input,
                        )
                        .await
                }
                "delete" => {
                    bail!("Native cloud deletion needs exact frozen provider/publication authority")
                }
                "status" => self.0.status(dto::id(&input, "operationId")?).await,
                "recent" => Ok(json!(self.0.recent().await?)),
                "cancel" => self.0.cancel(dto::id(&input, "operationId")?).await,
                "retry" => self.0.retry(dto::id(&input, "operationId")?).await,
                "reattach" => {
                    self.0
                        .reattach(
                            access.ok_or_else(|| anyhow!("Native provider access is required"))?,
                            dto::id(&input, "operationId")?,
                        )
                        .await?;
                    Ok(json!({}))
                }
                _ => bail!("This native engine operation is not supported"),
            }
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct AuditedStore(StoreAdapter, std::sync::mpsc::SyncSender<()>);
    impl TrackingStore for AuditedStore {
        fn load_records(&self) -> Result<Vec<Value>> {
            self.0.load_records()
        }
        fn save_record(&self, record: &Value) -> Result<()> {
            TrackingStore::save_record(&self.0, record)?;
            if std::thread::current().name() == Some("quicksave-tracking")
                && record["status"] == "needs_backup"
                && record["dirty"] == true
                && record["bundleIndexSource"]["contentState"] == "metadata_indexed"
            {
                let _ = self.1.try_send(());
            }
            Ok(())
        }
        fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
            TrackingStore::issue_grant(&self.0, kind, scope)
        }
        fn verify_grant(&self, kind: &str, scope: &Value, grant: &Value) -> Result<bool> {
            TrackingStore::verify_grant(&self.0, kind, scope, grant)
        }
        fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
            TrackingStore::revoke_grant(&self.0, kind, scope)
        }
        fn provider_writable(&self, id: &str) -> Result<bool> {
            TrackingStore::provider_writable(&self.0, id)
        }
        fn provider_known(&self, id: &str) -> Result<bool> {
            TrackingStore::provider_known(&self.0, id)
        }
    }

    #[tokio::test]
    async fn native_enrollment_persists_real_index_and_polling_never_hashes_app_data() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().canonicalize().unwrap();
        let data = base.join("private-data");
        let home = base.join("fixture-home");
        std::fs::create_dir(&home).unwrap();
        let applications = home.join("Applications");
        std::fs::create_dir(&applications).unwrap();
        let app = applications.join("Synthetic.app");
        std::fs::create_dir(&app).unwrap();
        std::fs::write(
            app.join("application.bin"),
            b"real isolated fixture payload",
        )
        .unwrap();
        let store = WorkspaceStore::open_with_vault(
            &data,
            Arc::new(quicksave_state::MemoryVault::default()),
        )
        .unwrap();
        let (audit, audited) = std::sync::mpsc::sync_channel(1);
        let mut policy = TrackingPolicy::new(&data);
        policy.audit_interval = std::time::Duration::from_secs(3600);
        let tracker = Tracker::open(
            Arc::new(AuditedStore(StoreAdapter(store.clone(), None), audit)),
            Arc::new(|_| bail!("synthetic autosave is not enabled")),
            policy,
        )
        .unwrap();
        let app_identity = quicksave_platform::SafeRoot::open(&app)
            .unwrap()
            .identity()
            .unwrap();
        let base_identity = quicksave_platform::SafeRoot::open(&applications)
            .unwrap()
            .identity()
            .unwrap();
        let source_identity = json!({"app_id":"mac-bundle:synthetic.fixture","display_name":"Synthetic",
            "canonical_executable":null,"desktop_entry_id":null,"steam_app_id":null,"launcher":"native",
            "aliases":[],"identity_confidence":1.0,"icon_path":null});
        let report = json!({"bundlePlans":[{
            "appId":"mac-bundle:synthetic.fixture","productId":"synthetic.fixture","displayName":"Synthetic",
            "sourceIdentity":source_identity,
            "identityEvidence":[{"kind":"native_installation_handle","identifier":"synthetic.fixture"}],
            "sourceRoots":[{"rootId":"fixture-install","path":app,"classification":"install","roles":["install"],
                "nativeIdentity":{"platform":"unix","device":app_identity.device,"inode":app_identity.file_id[0],"kind":"directory"},
                "status":"verified_candidate","ownership":"exclusive_native_installation",
                "evidence":[{"kind":"native_installation_handle","identifier":"synthetic.fixture"}]}],
            "rootsComplete":true,"unresolvedRoots":[],"unresolvedReasons":[],
        }],"diagnostics":[],"unresolvedApplications":[],"inventoryIncomplete":false});
        let result = crate::enrollment::materialize(&store, &tracker, &json!({
            "report":report,"replacePolicy":true,
            "nativeScope":{"baseDirectories":[applications],"excludedPaths":[data]},
            "_approvedPaths":[{"path":applications,"kind":"directory","identity":base_identity}],
        })).unwrap();
        assert_eq!(result["bundles"].as_array().unwrap().len(), 1, "{result}");
        let id = result["bundles"][0]["id"].as_str().unwrap();
        let record = store.software_record(id).unwrap();
        assert!(store.verify_tracking_grant(id).unwrap());
        assert_eq!(record["sourceIdentity"], source_identity);
        assert_eq!(record["fileCount"], 1);
        assert_eq!(record["logicalBytes"], 29);
        assert!(record["bundleIndexSource"].is_object());
        assert_ne!(record["status"], "saved");
        // The real mandatory initial audit is not UI polling. Wait for its
        // durable native metadata result before measuring cached requests.
        audited
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the real initial metadata audit must finish within the fixture bound");
        let before = tracker.performance_counters();
        for _ in 0..20 {
            tracker.software().unwrap();
            tracker.file_listing(id, None, 20).unwrap();
        }
        let after = tracker.performance_counters();
        assert_eq!(before["bytesRead"], after["bytesRead"]);
        assert_eq!(before["filesHashed"], after["filesHashed"]);
        assert_eq!(before["fsWalks"], after["fsWalks"]);
        assert_eq!(after["bytesRead"], 0);
        let engine = NativeEngine::open(&data, &home).unwrap();
        engine.register(&record).await.unwrap();
        tracker.shutdown().unwrap();
    }

    #[test]
    fn production_tracking_adapter_preserves_signed_individual_file_scope_in_memory_vault() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().canonicalize().unwrap();
        let data = base.join("private-data");
        let source = base.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("approved.txt"), b"synthetic selected data").unwrap();
        std::fs::write(
            source.join("not-approved.txt"),
            b"synthetic unselected data",
        )
        .unwrap();
        let store = WorkspaceStore::open_with_vault(
            &data,
            Arc::new(quicksave_state::MemoryVault::default()),
        )
        .unwrap();
        let persistence = Arc::new(StoreAdapter(store.clone(), None));
        let tracker = Tracker::open(
            persistence,
            Arc::new(|_| bail!("synthetic autosave is not enabled")),
            TrackingPolicy::new(&data),
        )
        .unwrap();
        let adapter = TrackingAdapter {
            tracker: Mutex::new(Some(Arc::new(tracker))),
            store: store.clone(),
            bootstrap: None,
            engine: None,
            observation: Mutex::new(None),
            observation_enabled: false,
        };
        let parent = quicksave_platform::SafeRoot::open(&source).unwrap();
        let (_, stamp) = parent.read_file("approved.txt").unwrap();
        let result = adapter
            .call(
                "add_files",
                &json!({
                    "paths":[source.join("approved.txt")],
                    "_approvedPaths":[{
                        "path":source.join("approved.txt"),"kind":"file",
                        "identity":quicksave_state::NativeFileStampID::from(&stamp),
                        "stamp":stamp,"parentIdentity":parent.identity().unwrap(),
                    }],
                }),
            )
            .unwrap();
        let id = dto::id(&result, "id").unwrap();
        let record = store.software_record(id).unwrap();
        assert_eq!(record["roots"][0]["allowedFiles"], json!(["approved.txt"]));
        assert!(store.verify_tracking_grant(id).unwrap());
        assert!(record["appId"]
            .as_str()
            .is_some_and(|id| id.starts_with("quicksave.manual.")));
        let guard = adapter.pin_scope(&record).unwrap();
        guard.verify().unwrap();
        let loaded = StoreAdapter(store.clone(), None).load_records().unwrap();
        assert_eq!(loaded[0]["trackingGrant"], record["trackingGrant"]);
        assert_eq!(
            loaded[0]["roots"][0]["allowedFiles"],
            json!(["approved.txt"])
        );
        adapter.shutdown().unwrap();
    }

    #[test]
    fn lazy_manual_dashboard_does_not_read_vault_or_grant_edited_state() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().canonicalize().unwrap();
        let data = base.join("private-data");
        let source = base.join("unapproved-source");
        std::fs::create_dir(&source).unwrap();
        let vault = Arc::new(quicksave_state::MemoryVault::default());
        let store = WorkspaceStore::open_with_vault(&data, vault.clone()).unwrap();
        let native = quicksave_platform::SafeRoot::open(&source).unwrap();
        store.update_software(&json!({
            "id":"synthetic-edited-record","name":"Unverified manual record","tracked":true,
            "roots":[{"id":"synthetic-root","path":source,"role":"manual","identity":native.identity().unwrap(),"allowedFiles":null}],
        })).unwrap();
        vault.deny_access(true).unwrap();
        let adapter = TrackingAdapter {
            tracker: Mutex::new(None),
            store: store.clone(),
            engine: None,
            observation: Mutex::new(None),
            observation_enabled: false,
            bootstrap: Some(TrackingBootstrap {
                store: Arc::new(StoreAdapter(store, None)),
                enqueue: Arc::new(|_| bail!("no synthetic autosave authority")),
                policy: TrackingPolicy::new(&data),
            }),
        };
        let software = adapter.call("software", &json!({})).unwrap();
        assert_eq!(software[0]["tracked"], false);
        assert_eq!(software[0]["autosave"], false);
        assert!(adapter.tracker.lock().unwrap().is_none());
        assert!(vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .is_empty());
        adapter.shutdown().unwrap();
    }
}
