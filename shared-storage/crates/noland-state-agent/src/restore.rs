use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use noland_crypto::MasterKey;
use noland_rclone_adapter::{
    EphemeralRcloneSession, ProviderKind, TransferTuning, TransferWorkload, WorkerResources,
};
use noland_restore::{
    recover_native_restore, restore_pipelined, DownloadJournal, NativeRestoreControl,
    NativeRestoreRecoveryReport, PipelineOptions, RestorePlan, RestorePrerequisite, RestoreTarget,
};
use noland_state_core::*;
use noland_storage::{write_guarded_ephemeral_session, RcloneStorage, SharedStorageProvider};

use crate::StateAgent;

// In-process native capabilities are not accepted from RPC or reconstructed
// from operation JSON. The host reattaches the device-vault authority and the
// original MAC-authenticated plan after a restart.
type NativeControls = BTreeMap<(uuid::Uuid, uuid::Uuid), Arc<NativeRestoreControl>>;
static NATIVE_RESTORE_CONTROLS: OnceLock<Mutex<NativeControls>> = OnceLock::new();

impl StateAgent {
    pub fn native_install_restore_control(
        &self,
        operation_id: uuid::Uuid,
        control: Arc<NativeRestoreControl>,
    ) -> Result<()> {
        if !self.config.native_host
            || self.operations.is_running(operation_id)
            || control.preview().job_id != operation_id
        {
            return Err(StateError::Conflict(
                "native restore authority cannot change during execution or bind another job"
                    .into(),
            ));
        }
        control.check_gate()?;
        let db = self.db.clone();
        let plan_digest = control.preview().digest()?;
        control.set_attempt_recorder(Arc::new(move |attempt_id| {
            let mut operation = db
                .get_operation(operation_id)?
                .ok_or_else(|| StateError::NotFound(operation_id.to_string()))?;
            if operation.kind != "restore" {
                return Err(StateError::Integrity(
                    "native restore attempt has no restore operation".into(),
                ));
            }
            let fields = operation.detail_json.as_object_mut().ok_or_else(|| {
                StateError::Integrity("native restore operation detail is invalid".into())
            })?;
            let attempts = fields
                .entry("native_restore_attempts")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
                .ok_or_else(|| StateError::Integrity("invalid native restore attempts".into()))?;
            if attempts.len() >= 64 {
                return Err(StateError::Conflict(
                    "native restore retained-attempt limit reached".into(),
                ));
            }
            attempts.push(serde_json::json!(attempt_id));
            fields.insert(
                "native_restore_plan_digest".into(),
                serde_json::json!(plan_digest),
            );
            db.upsert_operation(&operation)
        }))?;
        let db = self.db.clone();
        control.set_commit_recorder(Arc::new(move |restore_id| {
            let mut operation = db
                .get_operation(operation_id)?
                .ok_or_else(|| StateError::NotFound(operation_id.to_string()))?;
            let fields = operation.detail_json.as_object_mut().ok_or_else(|| {
                StateError::Integrity("invalid native restore completion record".into())
            })?;
            fields.insert("native_restore_filesystem_committed".into(), true.into());
            fields.insert(
                "native_restore_committed_attempt".into(),
                serde_json::json!(restore_id),
            );
            db.upsert_operation(&operation)
        }))?;
        if let Some(operation) = self.db.get_operation(operation_id)? {
            if operation.state == "COMPLETED"
                || operation.detail_json["native_restore_filesystem_committed"].as_bool()
                    == Some(true)
            {
                control.require_committed_recovery();
            }
            if operation.kind != "restore"
                || operation.app_id.as_ref() != Some(&control.preview().app_id)
                || operation.detail_json["bundle_id"]
                    .as_str()
                    .and_then(|id| uuid::Uuid::parse_str(id).ok())
                    != Some(control.preview().bundle_id)
                || operation
                    .detail_json
                    .get("native_restore_plan_digest")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|digest| {
                        control.preview().digest().ok().as_deref() != Some(digest)
                    })
            {
                return Err(StateError::Conflict(
                    "native restore reattachment differs from the frozen operation".into(),
                ));
            }
        }
        let mut controls = NATIVE_RESTORE_CONTROLS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| StateError::Storage("native restore authority lock poisoned".into()))?;
        // Completed capabilities can be reconstructed only from their original
        // device-authenticated durable plan. Do not retain huge historical
        // inventories forever in the in-process authority registry.
        controls.retain(|(instance, id), _| {
            *instance != self.config.instance_id
                || *id == operation_id
                || self.operations.is_running(*id)
                || self
                    .db
                    .get_operation(*id)
                    .ok()
                    .flatten()
                    .is_none_or(|operation| operation.state != "COMPLETED")
        });
        let metadata = controls
            .iter()
            .filter(|(key, _)| **key != (self.config.instance_id, operation_id))
            .try_fold(control.metadata_bytes(), |total, (_, control)| {
                total.checked_add(control.metadata_bytes()).ok_or_else(|| {
                    StateError::Invalid(
                        "native restore authority metadata accounting overflow".into(),
                    )
                })
            })?;
        if metadata > noland_restore::MAX_NATIVE_RESTORE_METADATA {
            return Err(StateError::Conflict("native restore authority registry exceeds its aggregate 512 MiB metadata budget; reattach only the operations being recovered".into()));
        }
        if controls.len() >= 256 && !controls.contains_key(&(self.config.instance_id, operation_id))
        {
            return Err(StateError::Conflict(
                "native restore authority capacity reached".into(),
            ));
        }
        controls.insert((self.config.instance_id, operation_id), control);
        Ok(())
    }

    pub fn native_restore_control(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Arc<NativeRestoreControl>> {
        NATIVE_RESTORE_CONTROLS.get_or_init(Mutex::default)
            .lock().map_err(|_| StateError::Storage("native restore authority lock poisoned".into()))?
            .get(&(self.config.instance_id, operation_id)).cloned()
            .ok_or_else(|| StateError::Conflict(
                "native restore needs the original approved plan and device-vault recovery authority".into(),
            ))
    }

    /// Explicit restart/cancel recovery, after the native controller has
    /// reattached the original plan. DB paths/attempt IDs are hints only; every
    /// workspace scope and intent is independently MAC-verified.
    pub fn native_recover_restore(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Vec<NativeRestoreRecoveryReport>> {
        if !self.config.native_host {
            return Err(StateError::Conflict(
                "native local recovery requires an owned native restore operation".into(),
            ));
        }
        let control = self.native_restore_control(operation_id)?;
        control.check_gate()?;
        let operation = self
            .db
            .get_operation(operation_id)?
            .ok_or_else(|| StateError::NotFound(operation_id.to_string()))?;
        if operation.kind != "restore" {
            return Err(StateError::Invalid(
                "operation is not a native restore".into(),
            ));
        }
        let attempts = operation.detail_json["native_restore_attempts"].as_array();
        if attempts.is_some_and(|attempts| attempts.len() > 64) {
            return Err(StateError::Invalid(
                "native restore attempt bound exceeded".into(),
            ));
        }
        let mut reports = Vec::new();
        for attempt in attempts.into_iter().flatten() {
            let id = attempt
                .as_str()
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .ok_or_else(|| {
                    StateError::Integrity("invalid native restore attempt identity".into())
                })?;
            let workspace = self.config.paths.restore_dir(&id.to_string());
            // A missing/replaced journal is not proof that its destination-side
            // artifacts were cleaned. Preserve every attempt's actual outcome,
            // rather than dropping earlier reports or treating absence as done.
            let report = match recover_native_restore(&workspace, Arc::clone(&control)) {
                Ok(report) => report,
                Err(error) => NativeRestoreRecoveryReport {
                    retained_artifacts: vec![error.to_string().chars().take(1024).collect()],
                    ..Default::default()
                },
            };
            reports.push(report);
        }
        Ok(reports)
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn persist_restore_progress(
    agent: &StateAgent,
    operation_id: uuid::Uuid,
    progress: &mut OperationProgress,
    phase: &str,
    completed_units: u64,
    message: &str,
) -> Result<()> {
    progress.phase = phase.into();
    progress.completed_units = completed_units;
    progress.message = Some(message.into());
    progress.updated_at = chrono::Utc::now();
    agent
        .db
        .set_operation_progress(operation_id, Some(progress))
}

fn persist_restore_failure(
    agent: &StateAgent,
    operation_id: uuid::Uuid,
    metrics: &OperationMetrics,
    error: &str,
) -> Result<()> {
    let Some(mut op) = agent.db.get_operation(operation_id)? else {
        return Ok(());
    };
    op.state = RestoreState::Failed.as_str().into();
    op.updated_at = chrono::Utc::now();
    op.last_error = Some(error.to_string());
    if !op.detail_json.is_object() {
        op.detail_json = serde_json::json!({});
    }
    op.detail_json
        .as_object_mut()
        .expect("operation detail is an object")
        .insert("metrics".into(), serde_json::to_value(metrics)?);
    crate::operation_diagnostics::retain(agent, &mut op)?;
    agent.db.set_operation_metrics(operation_id, metrics)?;
    agent.db.upsert_operation(&op)
}

fn persist_restore_operation(
    agent: &StateAgent,
    operation_id: uuid::Uuid,
    state: RestoreState,
    metrics: &OperationMetrics,
) -> Result<()> {
    let Some(mut op) = agent.db.get_operation(operation_id)? else {
        return Ok(());
    };
    op.state = state.as_str().into();
    op.updated_at = chrono::Utc::now();
    if !op.detail_json.is_object() {
        op.detail_json = serde_json::json!({});
    }
    op.detail_json
        .as_object_mut()
        .expect("operation detail is an object")
        .insert("metrics".into(), serde_json::to_value(metrics)?);
    if matches!(
        state,
        RestoreState::Completed | RestoreState::Failed | RestoreState::RolledBack
    ) {
        crate::operation_diagnostics::retain(agent, &mut op)?;
    }
    agent.db.set_operation_metrics(operation_id, metrics)?;
    agent.db.upsert_operation(&op)?;
    Ok(())
}

pub async fn run_restore_with_session(
    agent: &StateAgent,
    app_id: &AppId,
    bundle_id: uuid::Uuid,
    mode: RestoreMode,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
    operation_id: uuid::Uuid,
) -> Result<()> {
    let (config, session_guard) =
        write_guarded_ephemeral_session(&agent.config.paths.run_root, session)?;
    let result = async {
        let provider = Arc::new(RcloneStorage::try_from_session(session, &config)?);
        if agent.config.native_host {
            let checkpoint_provider = Arc::clone(&provider);
            agent
                .native_restore_control(operation_id)?
                .set_credential_checkpoint(Arc::new(move || {
                    checkpoint_provider.checkpoint_native_credentials()
                }))?;
        }
        run_restore_with_provider_unfinalized(
            agent,
            app_id,
            bundle_id,
            mode,
            session,
            master,
            operation_id,
            provider.as_ref(),
            |tuning| {
                Ok(RcloneStorage::try_from_session(session, &config)?.with_transfer_tuning(tuning))
            },
        )
        .await
    }
    .await;
    let _finalization = result
        .is_ok()
        .then(|| agent.operations.finalization_scope(operation_id));
    // Repository release has finished. Checked OAuth rotation precedes any
    // durable COMPLETED publication, including explicit error finalization.
    let credentials = session_guard.finish();
    let result = match (result, credentials) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(credentials)) => Err(StateError::Storage(format!(
            "restore failed: {error}; checked credential finalization also failed: {credentials}"
        ))),
    };
    if result.is_ok() {
        crate::operation_diagnostics::complete_after_repository_release(agent, operation_id)?;
    }
    result
}

pub(crate) async fn run_restore_with_provider<P: SharedStorageProvider>(
    agent: &StateAgent,
    app_id: &AppId,
    bundle_id: uuid::Uuid,
    mode: RestoreMode,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
    operation_id: uuid::Uuid,
    provider: &dyn SharedStorageProvider,
    create_storage: impl FnOnce(TransferTuning) -> Result<P>,
) -> Result<()> {
    let result = run_restore_with_provider_unfinalized(
        agent,
        app_id,
        bundle_id,
        mode,
        session,
        master,
        operation_id,
        provider,
        create_storage,
    )
    .await;
    let _finalization = result
        .is_ok()
        .then(|| agent.operations.finalization_scope(operation_id));
    if result.is_ok() {
        crate::operation_diagnostics::complete_after_repository_release(agent, operation_id)?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_restore_with_provider_unfinalized<P: SharedStorageProvider>(
    agent: &StateAgent,
    app_id: &AppId,
    bundle_id: uuid::Uuid,
    mode: RestoreMode,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
    operation_id: uuid::Uuid,
    provider: &dyn SharedStorageProvider,
    create_storage: impl FnOnce(TransferTuning) -> Result<P>,
) -> Result<()> {
    let guard = crate::repository::acquire_restore(agent, provider, master, operation_id).await?;
    let result = run_restore_inner(
        agent,
        app_id,
        bundle_id,
        mode,
        session,
        master,
        operation_id,
        create_storage,
    )
    .await;
    let _finalization = result
        .is_ok()
        .then(|| agent.operations.finalization_scope(operation_id));
    // The caller's single credential guard remains alive through remote
    // finalization, including failed transfers.
    guard.finish(result).await
}

async fn run_restore_inner<P: SharedStorageProvider>(
    agent: &StateAgent,
    app_id: &AppId,
    bundle_id: uuid::Uuid,
    mode: RestoreMode,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
    operation_id: uuid::Uuid,
    create_storage: impl FnOnce(TransferTuning) -> Result<P>,
) -> Result<()> {
    let total_started = Instant::now();
    let mut metrics = OperationMetrics::default();
    let mut progress = OperationProgress::new(RestoreState::FetchingManifest.as_str(), 0);
    progress.unit = Some("files".into());
    progress.detail_json = serde_json::json!({
        "bundle_id": bundle_id,
        "ready_to_launch_reached": false,
        "milestones": [],
    });
    persist_restore_operation(
        agent,
        operation_id,
        RestoreState::FetchingManifest,
        &metrics,
    )?;
    persist_restore_progress(
        agent,
        operation_id,
        &mut progress,
        RestoreState::FetchingManifest.as_str(),
        0,
        "Fetching and verifying the restore manifest",
    )?;
    let provider = ProviderKind::parse(&session.provider).unwrap_or(ProviderKind::Local);
    let baseline_workload = if agent.has_latency_sensitive_sessions()? {
        TransferWorkload::GameplaySafe
    } else {
        TransferWorkload::Throughput
    };
    let workload = baseline_workload.for_active_transfer();
    let resources = WorkerResources::detect();
    let tuning = TransferTuning::from_worker_resources(provider, workload, resources);
    let pipeline_options = PipelineOptions::for_transfer_tuning(resources, workload, &tuning);
    tracing::info!(
        provider = provider.as_str(),
        ?baseline_workload,
        ?workload,
        uploads = tuning.max_parallel_uploads,
        downloads = tuning.max_parallel_downloads,
        rclone_transfers = tuning.rclone_transfers,
        decoder_workers = pipeline_options.max_parallel_packs,
        verification_workers = pipeline_options.reconstruction_workers,
        buffered_chunks = pipeline_options.buffered_chunks,
        io_pressure = resources.io_pressure,
        "resolved automatic shared-storage restore parallelism"
    );
    let transfer_plan = serde_json::json!({
        "baseline_workload": format!("{baseline_workload:?}"),
        "workload": format!("{workload:?}"),
        "logical_cpus": resources.logical_cpus,
        "available_memory_bytes": resources.available_memory,
        "io_pressure": resources.io_pressure,
        "cpu_worker_budget": resources.cpu_workers(workload, 1),
        "requested_download_slots": tuning.max_parallel_downloads,
        "requested_parallel_packs": pipeline_options.max_parallel_packs,
        "requested_verification_workers": pipeline_options.reconstruction_workers,
        "requested_buffered_chunks": pipeline_options.buffered_chunks,
        "requested_inflight_pack_bytes": pipeline_options.max_inflight_pack_bytes,
        "max_parallel_packs": pipeline_options.max_parallel_packs,
        "verification_workers": pipeline_options.reconstruction_workers,
        "verification_pool_workers": 0,
        "buffered_chunks": pipeline_options.buffered_chunks,
        "max_inflight_pack_bytes": pipeline_options.max_inflight_pack_bytes,
    });
    let storage = create_storage(tuning)?;
    let storage = crate::session_storage::SessionStorage::new(storage, agent, session, master);
    let storage_before = storage.operation_metrics();
    let metadata_before = storage.metadata_read_metrics();

    // Dynamic roots such as Steam libraries may appear after the agent starts.
    // Refresh them before resolving the portable logical roots in the manifest.
    let discovery_started = Instant::now();
    if let Err(error) = agent.discover() {
        return Err(error);
    }
    metrics.discovery_duration_ms = elapsed_ms(discovery_started);

    let manifest_started = Instant::now();
    let plan = prepare_restore_with_metadata(
        agent,
        &storage,
        master,
        app_id,
        bundle_id,
        mode,
        operation_id,
    )
    .await;
    metrics.manifest_duration_ms = elapsed_ms(manifest_started);
    let result = match plan {
        Ok((plan, index, metadata_diagnostics)) => {
            let plan = plan.into_shared();
            if plan.manifest.files.is_empty()
                && (mode == RestoreMode::CompleteApplication || plan.manifest.tombstones.is_empty())
            {
                return Err(StateError::Invalid(format!(
                    "bundle {bundle_id} contains no restorable files"
                )));
            }
            let priority_plan = plan.priority_plan();
            let total_files = u64::try_from(priority_plan.entries.len()).unwrap_or(u64::MAX);
            let ready_to_launch_files = u64::try_from(
                priority_plan
                    .entries_for(RestoreTarget::ReadyToLaunch)
                    .count(),
            )
            .unwrap_or(u64::MAX);
            progress.total_units = Some(total_files);
            progress.detail_json = serde_json::json!({
                "bundle_id": bundle_id,
                "restore_id": plan.restore_id,
                "ready_to_launch_files": ready_to_launch_files,
                "total_files": total_files,
                "ready_to_launch_reached": false,
                "milestones": [],
                "target": "READY_TO_LAUNCH",
                "transfer_plan": transfer_plan,
                "remote_metadata": metadata_diagnostics,
            });
            persist_restore_operation(
                agent,
                operation_id,
                RestoreState::CheckingPrerequisites,
                &metrics,
            )?;
            persist_restore_progress(
                agent,
                operation_id,
                &mut progress,
                RestoreState::CheckingPrerequisites.as_str(),
                0,
                "Planning launch-critical and remaining restore work",
            )?;

            let restore_result = async {
                let roots = if agent.config.native_host {
                    agent.native_restore_control(operation_id)?.logical_roots()?
                } else { prepare_restore_roots(agent, &plan.manifest)? };
                let prerequisites = if agent.config.native_host { Vec::new() } else {
                    steam_restore_prerequisites(&plan.manifest, &roots, mode)
                };
                let local_plan = plan.clone().with_prerequisites(prerequisites);
                let local_plan = if agent.config.native_host {
                    local_plan.with_native_control(agent.native_restore_control(operation_id)?)
                } else {
                    local_plan
                };
                let manifest_app = &plan.manifest.app;
                if !agent.config.native_host { agent.db.upsert_app(&AppIdentity {
                    app_id: manifest_app.app_id.clone(),
                    display_name: manifest_app.display_name.clone(),
                    canonical_executable: manifest_app.canonical_executable.clone(),
                    desktop_entry_id: manifest_app.desktop_entry_id.clone(),
                    steam_app_id: manifest_app.steam_app_id,
                    launcher: manifest_app.launcher,
                    aliases: manifest_app.aliases.clone(),
                    identity_confidence: 1.0,
                    icon_path: manifest_app.icon_path.clone(),
                })?; }

                let index_cache_started = Instant::now();
                crate::backup::remember_remote_pack_index(
                    agent,
                    storage.storage_identity(),
                    master,
                    &index,
                )?;
                progress.detail_json["remote_index_cache_us"] = serde_json::json!(index_cache_started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
                // Restore retries reuse verified local pack/chunk caches directly. Their old
                // journal rows are not needed for resume and would pollute this attempt's totals.
                agent.db.delete_sync_journal_entries_for_kind_direction(
                    operation_id,
                    ContentObjectKind::Pack,
                    SyncDirection::Download,
                )?;
                let download_journal = Some(DownloadJournal {
                    db: &agent.db,
                    operation_id,
                });

                persist_restore_operation(agent, operation_id, RestoreState::Applying, &metrics)?;
                let report = restore_pipelined(
                    &storage,
                    master,
                    &local_plan,
                    &index,
                    &roots,
                    (!agent.config.native_host).then_some(&agent.db),
                    download_journal,
                    pipeline_options,
                    |sample| {
                        progress.total_units = Some(sample.total_entries);
                        progress.unit = Some("files".into());
                        progress.detail_json["ready_to_launch_reached"] =
                            serde_json::json!(sample.ready_to_launch && !agent.config.native_host);
                        if agent.config.native_host {
                            // Native restoration preserves the complete graph,
                            // but Linux/Wine launcher milestones are not proof
                            // that a foreign executable can launch on this OS.
                            progress.detail_json["critical_data_verified"] =
                                serde_json::json!(sample.critical_data_verified);
                            progress.detail_json["native_launch_assessment"] =
                                serde_json::json!("separate_native_prerequisite_validation_required");
                        }
                        // Admission can tighten explicit options if resources
                        // changed during manifest/index preparation. Keep legacy
                        // plan labels truthful as well as the requested/effective
                        // counts recorded in the pipeline's I/O diagnostics.
                        progress.detail_json["transfer_plan"]["max_parallel_packs"] =
                            serde_json::json!(sample.io.effective_parallel_packs);
                        progress.detail_json["transfer_plan"]["verification_workers"] =
                            serde_json::json!(sample.io.effective_verification_workers);
                        progress.detail_json["transfer_plan"]["verification_pool_workers"] =
                            serde_json::json!(sample.io.verification_pool_workers);
                        progress.detail_json["transfer_plan"]["buffered_chunks"] =
                            serde_json::json!(sample.io.effective_buffered_chunks);
                        progress.detail_json["transfer_plan"]["max_inflight_pack_bytes"] =
                            serde_json::json!(sample.io.max_inflight_pack_bytes);
                        progress.detail_json["pipeline"] = serde_json::json!({
                            "phase": sample.phase,
                            "checked_files": sample.checked_entries,
                            "rollback_files": sample.rollback_entries,
                            "preflight_duration_ms": sample.preflight_duration_ms,
                            "rollback_duration_ms": sample.rollback_duration_ms,
                            "version": 2,
                            "assembled_bytes": sample.assembled_bytes,
                            "verified_bytes": sample.verified_bytes,
                            "readback_bytes": sample.readback_bytes,
                            "published_bytes": sample.published_bytes,
                            "total_bytes": sample.total_bytes,
                            "reused_files": sample.reused_entries,
                            "elapsed_ms": sample.elapsed_ms,
                            "files_per_second": sample.completed_entries as f64 * 1000.0 / sample.elapsed_ms.max(1) as f64,
                            "assembled_bytes_per_second": sample.assembled_bytes as f64 * 1000.0 / sample.elapsed_ms.max(1) as f64,
                            "io": sample.io,
                        });
                        if sample.ready_to_launch || agent.config.native_host && sample.critical_data_verified {
                            progress.detail_json["milestones"] =
                                if agent.config.native_host { serde_json::json!(["CRITICAL_DATA_VERIFIED"]) }
                                else { serde_json::json!(["READY_TO_LAUNCH"]) };
                        }
                        persist_restore_progress(
                            agent,
                            operation_id,
                            &mut progress,
                            RestoreState::Applying.as_str(),
                            sample.completed_entries,
                            &format!("{} · {:.1} MiB assembled · {:.1} MiB verified · {:.1} MiB extra read-back", sample.phase,
                                sample.assembled_bytes as f64 / 1_048_576.0,
                                sample.verified_bytes as f64 / 1_048_576.0,
                                sample.readback_bytes as f64 / 1_048_576.0),
                        )
                    },
                )
                .await?;
                metrics.restore_apply_duration_ms = report.apply_duration_ms;
                metrics.download_duration_ms = report.pipeline_duration_ms;
                progress.detail_json["pipeline"]["io"] = serde_json::to_value(&report.io)?;
                if agent.config.native_host {
                    progress.detail_json["native_restore_cleanup_required"] =
                        serde_json::json!(report.io.commit.native_cleanup_required);
                    progress.detail_json["native_restore_filesystem_committed"] = true.into();
                    progress.detail_json["native_reconstruction"] =
                        serde_json::to_value(&report.io.commit.native_reconstruction)?;
                    progress.detail_json["native_restore_readiness"] =
                        serde_json::json!(report.io.commit.native_reconstruction.as_ref()
                            .map(|report| report.readiness.as_str()).unwrap_or("files_only"));
                }
                progress.detail_json["pipeline"]["elapsed_ms"] = serde_json::json!(report.pipeline_duration_ms);
                progress.detail_json["total_packs"] = serde_json::json!(report.packs_downloaded);
                progress.detail_json["complete_published_files"] =
                    serde_json::json!(report.restore.published_entries);
                progress.detail_json["complete_reused_files"] =
                    serde_json::json!(report.restore.reused_entries);
                progress.detail_json["milestones"] =
                    if agent.config.native_host { serde_json::json!(["DATA_RESTORED"]) }
                    else { serde_json::json!(["READY_TO_LAUNCH"]) };
                // A personal-state selection from a complete bundle is not a
                // complete local parent. Only a successful, fully selected
                // publication may enable backup's unchanged-parent shortcut.
                let restored_all_files = priority_plan.entries.len() == plan.manifest.files.len()
                    && report.restore.published_entries + report.restore.reused_entries
                        == plan.manifest.files.len()
                    && (!agent.config.native_host
                        || plan.manifest.environment["quicksave_native_download"]["whole_bundle"].as_bool() == Some(true));
                let cache_started = Instant::now();
                let cache_result = if restored_all_files && !agent.config.native_host {
                    crate::backup::remember_restored_parent(
                        agent,
                        storage.storage_identity(),
                        master,
                        &plan.manifest,
                        &index,
                    )
                } else {
                    Ok(())
                };
                progress.detail_json["post_commit_cache_us"] = serde_json::json!(cache_started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
                if let Err(error) = cache_result {
                        // The filesystem and index already committed. Cache
                        // failure must not relabel that durable restore failed.
                        tracing::warn!(%error, %bundle_id, "restored backup parent cache unavailable");
                        progress.detail_json["incremental_parent_cache_error"] =
                            serde_json::json!(error.to_string());
                }
                progress.detail_json["restored_all_manifest_files"] = serde_json::json!(restored_all_files);
                Ok(())
            }
            .await;

            let terminal_pack_release = if agent.config.native_host {
                // Native workspaces are never swept by an unsigned path list.
                // The streaming pipeline keeps no plaintext chunk cache.
                Ok(0)
            } else {
                plan.release_staged_pack_links()
            };
            // Streaming owns only this workspace's fallback scratch files. Do not
            // prune other operations' shared pack cache while releasing our links.
            let terminal_pack_cleanup = terminal_pack_release;
            match restore_result {
                Ok(()) => {
                    progress.detail_json["terminal_pack_cache_cleanup"] =
                        match terminal_pack_cleanup {
                            Ok(released) => serde_json::json!({
                                "staged_links_released": released,
                                "cleanup_required": false,
                            }),
                            Err(_) => serde_json::json!({
                                "status": "CLEANUP_REQUIRED",
                                "cleanup_required": true,
                                "reason": "staged_pack_link_release_failed",
                            }),
                        };
                    // Publication is already durable. Scratch/link cleanup is
                    // diagnostic, never evidence that files were rolled back.
                    Ok(())
                }
                Err(error) => {
                    if let Err(cleanup_error) = terminal_pack_cleanup {
                        progress.detail_json["terminal_pack_cache_cleanup"] = serde_json::json!({
                            "status": "CLEANUP_REQUIRED",
                            "cleanup_required": true,
                            "reason": "staged_pack_link_release_failed",
                        });
                        tracing::warn!(
                            restore_id = %plan.restore_id,
                            %cleanup_error,
                            "failed to clear restore pack cache after terminal failure"
                        );
                    }
                    Err(error)
                }
            }
        }
        Err(error) => Err(error),
    };
    let storage_metrics = storage.operation_metrics().saturating_sub(storage_before);
    metrics.bytes_downloaded = storage_metrics.bytes_downloaded;
    metrics.bytes_uploaded = storage_metrics.bytes_uploaded;
    metrics.num_rclone_invocations = storage_metrics.rclone_invocations;
    metrics.num_remote_stat_calls = storage_metrics.remote_stat_calls;
    metrics.num_remote_list_calls = storage_metrics.remote_list_calls;
    metrics.num_remote_mkdir_calls = storage_metrics.remote_mkdir_calls;
    metrics.num_remote_upload_calls = storage_metrics.remote_upload_calls;
    metrics.num_remote_download_calls = storage_metrics.remote_download_calls;
    metrics.total_duration_ms = elapsed_ms(total_started);
    progress.detail_json["remote_metadata"]["provider_io"] = serde_json::to_value(
        storage
            .metadata_read_metrics()
            .saturating_sub(metadata_before),
    )?;
    progress.detail_json["remote_metadata"]["catalog_cache"] = storage.metadata_metrics();
    match &result {
        Ok(()) => {
            let completed_units = progress.total_units.unwrap_or(progress.completed_units);
            persist_restore_progress(
                agent,
                operation_id,
                &mut progress,
                RestoreState::Validating.as_str(),
                completed_units,
                "Data restored; finalizing repository admission",
            )?;
            persist_restore_operation(agent, operation_id, RestoreState::Validating, &metrics)?;
            crate::operation_diagnostics::prepare_completion(
                agent,
                operation_id,
                RestoreState::Validating.as_str(),
                RestoreState::Completed.as_str(),
            )?;
        }
        Err(error) => {
            let completed_units = progress.completed_units;
            progress.detail_json["failed"] = serde_json::json!(true);
            if let Err(persist_error) = persist_restore_progress(
                agent,
                operation_id,
                &mut progress,
                RestoreState::Failed.as_str(),
                completed_units,
                &error.to_string(),
            ) {
                tracing::warn!(
                    %operation_id,
                    %persist_error,
                    "failed to persist restore failure progress"
                );
            }
            if let Err(persist_error) =
                persist_restore_failure(agent, operation_id, &metrics, &error.to_string())
            {
                tracing::warn!(
                    %operation_id,
                    %persist_error,
                    "failed to persist restore failure metrics"
                );
            }
        }
    }
    result
}

async fn prepare_restore_with_metadata(
    agent: &StateAgent,
    provider: &dyn SharedStorageProvider,
    master: &MasterKey,
    app_id: &AppId,
    bundle_id: uuid::Uuid,
    mode: RestoreMode,
    operation_id: uuid::Uuid,
) -> Result<(
    RestorePlan,
    Vec<noland_pack::PackIndexEntry>,
    serde_json::Value,
)> {
    let (mut manifest, index, diagnostics) = crate::backup::read_restore_metadata(
        agent,
        provider,
        master,
        app_id,
        bundle_id,
        operation_id,
    )
    .await?;
    if let Some(selection) = agent.native_selection_for_operation(operation_id)? {
        let destination = selection
            .destination
            .as_ref()
            .ok_or_else(|| StateError::Invalid("native download destination missing".into()))?;
        let source = noland_snapshot::SourcePath::new(destination)?;
        let metadata = source.metadata()?;
        if !metadata.is_dir()
            || metadata.is_symlink()
            || selection.destination_identity != Some((metadata.dev(), metadata.ino()))
            || agent
                .config
                .capture_exclusions
                .iter()
                .any(|root| destination.starts_with(root) || root.starts_with(destination))
        {
            return Err(StateError::Conflict(
                "native download destination changed".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for file in &manifest.files {
            crate::native_host::validate_native_relative(&file.relative_path)?;
            if !seen.insert(crate::native_host::NativeFileKey {
                logical_root: file.logical_root.clone(),
                relative_path: file.relative_path.clone(),
            }) {
                return Err(StateError::Integrity(
                    "duplicate native download file identity".into(),
                ));
            }
        }
        if selection
            .file_keys
            .as_ref()
            .is_some_and(|keys| keys.iter().any(|key| !seen.contains(key)))
        {
            return Err(StateError::Invalid(
                "selected download file is not in the authenticated manifest".into(),
            ));
        }
        noland_state_core::native_layout::native_root_layouts(&manifest)?;
        let original_native_file_count = manifest.files.len();
        manifest
            .files
            .retain(|file| selection.contains(&file.logical_root, &file.relative_path));
        // Selection never implies deletions. Explicit tombstones require their
        // own complete, native-approved plan; the normal download has none.
        manifest.tombstones.clear();
        manifest.environment["quicksave_native_download"] = serde_json::json!({
            "whole_bundle": original_native_file_count == manifest.files.len(),
        });
        noland_state_core::native_layout::project_native_root_layouts(&mut manifest)?;
        let control = agent.native_restore_control(operation_id)?;
        if control.preview().destination != *destination
            || control.preview().destination_identity
                != noland_restore::NativeObjectId::from(selection.destination_identity.ok_or_else(
                    || StateError::Invalid("native destination identity missing".into()),
                )?)
        {
            return Err(StateError::Conflict(
                "native restore destination differs from approval".into(),
            ));
        }
        // First recover the prior attempt with its exact signed created-file
        // IDs. Restored-original receipts permit the same plan to retry without
        // treating rename's ctime update as an unapproved replacement.
        let recoveries = agent.native_recover_restore(operation_id)?;
        if recoveries.iter().any(|report| {
            !(report.committed || report.rolled_back)
                || !report.retained_artifacts.is_empty()
                || !report.owned_artifacts_clean
                || !report.metadata_only_workspace
        }) {
            return Err(StateError::Conflict(
                "native restore retains unverified recovery artifacts; explicit local recovery is required before any retry".into(),
            ));
        }
        let roots = control.logical_roots()?;
        if !manifest.environment.is_object() && !manifest.environment.is_null() {
            return Err(StateError::Integrity(
                "native restore environment is not an object".into(),
            ));
        }
        manifest.environment["quicksave_native_download"] = serde_json::json!({
            "destination": destination, "identity": selection.destination_identity,
            "files_only": !control.preview().reconstruction_eligible(),
            "whole_bundle": original_native_file_count == manifest.files.len(),
            "source_entry_count": original_native_file_count,
            "selected_entry_count": manifest.files.len(),
            "no_overwrite": control.preview().conflict_mode == noland_restore::NativeConflictMode::CreateOnly,
            "approved_plan": control.preview().digest()?,
            "root_mapping_fingerprint": control.preview().root_mapping_digest()?,
            "reconstruction_readiness": if control.preview().reconstruction_eligible() {
                "reconstruction_unverified"
            } else {"files_only"},
        });
        control.validate_fresh(&manifest, mode, &roots)?;
    }
    let restore_id = uuid::Uuid::new_v4();
    let staging = agent.config.paths.restore_dir(&restore_id.to_string());
    for child in ["packs", "materialized/.chunks", "pre_restore", "logs"] {
        if let Err(error) = std::fs::create_dir_all(staging.join(child)) {
            // Only this newly allocated workspace, never the shared pack cache.
            if !agent.config.native_host {
                let _ = std::fs::remove_dir_all(&staging);
            }
            return Err(error.into());
        }
    }
    if agent.config.native_host {
        let control = agent.native_restore_control(operation_id)?;
        let mut operation = agent
            .db
            .get_operation(operation_id)?
            .ok_or_else(|| StateError::NotFound(operation_id.to_string()))?;
        if !operation.detail_json.is_object() {
            operation.detail_json = serde_json::json!({});
        }
        let fields = operation
            .detail_json
            .as_object_mut()
            .expect("object initialized");
        fields.insert(
            "native_restore_plan_digest".into(),
            serde_json::json!(control.preview().digest()?),
        );
        let attempts = fields
            .entry("native_restore_attempts")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .ok_or_else(|| StateError::Integrity("invalid native restore attempts".into()))?;
        if attempts.len() >= 64 {
            return Err(StateError::Conflict("native restore has 64 retained authenticated attempts; recover/archive its audit history before another retry".into()));
        }
        fields.insert("native_restore_cleanup_required".into(), false.into());
        agent.db.upsert_operation(&operation)?;
    }
    Ok((
        RestorePlan {
            restore_id,
            staging,
            pack_cache: agent.config.paths.cache.join("restore-packs"),
            manifest,
            mode,
        },
        index,
        diagnostics,
    ))
}

fn steam_restore_prerequisites(
    bundle: &BundleManifest,
    roots: &LogicalRootMap,
    mode: RestoreMode,
) -> Vec<RestorePrerequisite> {
    if mode != RestoreMode::CompleteApplication {
        return Vec::new();
    }
    let Some(steam_app_id) = bundle.app.steam_app_id.or_else(|| {
        bundle
            .app
            .app_id
            .as_str()
            .strip_prefix("steam:")
            .and_then(|value| value.parse::<u32>().ok())
    }) else {
        return Vec::new();
    };
    let Some((target_dir, install_dir)) = steam_install_location_from_manifest(bundle, roots)
    else {
        return Vec::new();
    };
    let manifest = format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{steam_app_id}\"\n\t\"name\"\t\t\"{}\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"installdir\"\t\t\"{}\"\n}}\n",
        escape_acf_value(&bundle.app.display_name),
        escape_acf_value(&install_dir),
    );
    vec![RestorePrerequisite {
        root: target_dir,
        relative_path: format!("appmanifest_{steam_app_id}.acf"),
        contents: manifest.into_bytes(),
    }]
}

fn prepare_restore_roots(agent: &StateAgent, bundle: &BundleManifest) -> Result<LogicalRootMap> {
    let mut roots = agent.roots.lock().clone();
    let Some(preferred_steamapps) = preferred_steamapps_dir(&roots) else {
        return Ok(roots);
    };

    for library_id in bundle.files.iter().filter_map(|file| {
        let LogicalRoot::SteamLibrary { id } = file.logical_root_parsed()? else {
            return None;
        };
        Some(id)
    }) {
        roots
            .steam_libraries
            .entry(library_id)
            .or_insert_with(|| preferred_steamapps.clone());
    }

    let steam_app_id = bundle.app.steam_app_id.or_else(|| {
        bundle
            .app
            .app_id
            .as_str()
            .strip_prefix("steam:")
            .and_then(|value| value.parse::<u32>().ok())
    });
    if let Some(steam_app_id) = steam_app_id {
        roots
            .proton_prefixes
            .entry(steam_app_id)
            .or_insert_with(|| {
                preferred_steamapps
                    .join("compatdata")
                    .join(steam_app_id.to_string())
                    .join("pfx")
            });
    }

    let mut live_roots = agent.roots.lock();
    for (id, path) in &roots.steam_libraries {
        live_roots
            .steam_libraries
            .entry(id.clone())
            .or_insert_with(|| path.clone());
    }
    for (id, path) in &roots.proton_prefixes {
        live_roots
            .proton_prefixes
            .entry(*id)
            .or_insert_with(|| path.clone());
    }
    drop(live_roots);

    Ok(roots)
}

fn preferred_steamapps_dir(roots: &LogicalRootMap) -> Option<PathBuf> {
    roots
        .steam_libraries
        .values()
        .next()
        .cloned()
        .or_else(|| roots.steam_root.as_ref().map(|root| root.join("steamapps")))
}

fn steam_install_location_from_manifest(
    bundle: &BundleManifest,
    roots: &LogicalRootMap,
) -> Option<(PathBuf, String)> {
    let logical_location = bundle.files.iter().find_map(|file| {
        let Some(LogicalRoot::SteamLibrary { id }) = file.logical_root_parsed() else {
            return None;
        };
        let install_dir = steam_install_dir_from_path(Path::new(&file.relative_path))?;
        Some((roots.steam_libraries.get(&id)?.clone(), install_dir))
    });
    if logical_location.is_some() {
        return logical_location;
    }

    let install_dir = bundle
        .files
        .iter()
        .find_map(|file| {
            file.source_path_hint
                .as_deref()
                .and_then(|path| steam_install_dir_from_path(Path::new(path)))
        })
        .or_else(|| {
            bundle
                .app
                .canonical_executable
                .as_deref()
                .and_then(steam_install_dir_from_path)
        })?;
    Some((preferred_steamapps_dir(roots)?, install_dir))
}

fn steam_install_dir_from_path(path: &Path) -> Option<String> {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components
        .windows(3)
        .find(|parts| {
            parts[0].eq_ignore_ascii_case("steamapps") && parts[1].eq_ignore_ascii_case("common")
        })
        .map(|parts| parts[2].to_string())
        .or_else(|| {
            components
                .first()
                .is_some_and(|component| component.eq_ignore_ascii_case("common"))
                .then(|| components.get(1).map(|component| (*component).to_string()))
                .flatten()
        })
        .filter(|install_dir| !install_dir.is_empty())
}

fn escape_acf_value(value: &str) -> String {
    value.replace('"', "'")
}

#[cfg(test)]
#[path = "restore_claim_tests.rs"]
mod claim_tests;

#[cfg(test)]
mod tests {
    use super::{
        preferred_steamapps_dir, prepare_restore_roots, steam_install_dir_from_path,
        steam_restore_prerequisites,
    };
    use crate::{AgentConfig, StateAgent};
    use chrono::Utc;
    use noland_state_core::{
        AppId, AppIdentity, BackupMode, BundleManifest, LogicalRootMap, ManifestApp,
        ManifestSource, RestoreMode,
    };
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    #[test]
    fn completed_restore_retains_final_pipeline_report_and_runtime_metrics() {
        use noland_state_core::{
            OperationMetrics, OperationProgress, OperationRecord, RestoreState,
        };
        let root = crate::index_test_support::root("restore-final-metrics");
        let agent = StateAgent::boot(AgentConfig::isolated(root.join("agent"))).unwrap();
        let id = Uuid::new_v4();
        agent
            .db
            .upsert_operation(&OperationRecord {
                operation_id: id,
                kind: "restore".into(),
                app_id: None,
                state: "APPLYING".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_error: None,
                detail_json: serde_json::json!({}),
            })
            .unwrap();
        let mut progress = OperationProgress::new("COMPLETED", 2);
        let io = noland_restore::PipelineIoMetrics {
            write_us: 42,
            ..Default::default()
        };
        progress.detail_json = serde_json::json!({
            "pipeline": {"readback_bytes":10, "verified_bytes":20, "io": io},
            "remote_metadata": {"fetch_duration_ms":30},
        });
        agent
            .db
            .set_operation_progress(id, Some(&progress))
            .unwrap();
        let metrics = OperationMetrics {
            total_duration_ms: 50,
            ..Default::default()
        };
        super::persist_restore_operation(&agent, id, RestoreState::Completed, &metrics).unwrap();
        let operation = agent.db.get_operation(id).unwrap().unwrap();
        assert_eq!(operation.detail_json["pipeline"]["readback_bytes"], 10);
        assert_eq!(
            operation.detail_json["pipeline"]["io"],
            serde_json::to_value(io).unwrap()
        );
        assert_eq!(
            operation.detail_json["remote_metadata"]["fetch_duration_ms"],
            30
        );
        assert_eq!(
            agent
                .db
                .get_operation_metrics(id)
                .unwrap()
                .unwrap()
                .total_duration_ms,
            50
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn steam_bundle(display_name: &str) -> BundleManifest {
        BundleManifest::new(
            ManifestApp::from(&AppIdentity::new(AppId::steam(3_241_660), display_name)),
            ManifestSource {
                instance_id: Uuid::new_v4(),
                image_id: "test".into(),
                captured_at: Utc::now(),
            },
            BackupMode::CompleteApplication,
        )
    }

    #[test]
    fn steam_install_dir_comes_from_install_path_not_display_name() {
        assert_eq!(
            steam_install_dir_from_path(Path::new(
                "/mnt/library/steamapps/common/RepoInstall_3241660/bin/game.exe"
            )),
            Some("RepoInstall_3241660".into())
        );
        assert_eq!(
            steam_install_dir_from_path(Path::new("common/RepoInstall_3241660/game.bin")),
            Some("RepoInstall_3241660".into())
        );
    }

    #[tokio::test]
    async fn restored_external_steam_save_survives_complete_backup_and_library_remapping() {
        use noland_crypto::MasterKey;
        use noland_restore::{prepare_restore, restore_pipelined, PipelineOptions};
        use noland_state_core::*;
        use noland_storage::{
            commit_bundle_with_index, read_committed_manifest, read_pack_index, LocalStorage,
            SharedStorageProvider,
        };
        let root = std::fs::canonicalize(std::env::current_dir().unwrap())
            .unwrap()
            .join(format!("target/noland-restore-parent-{}", Uuid::new_v4()));
        let agent = StateAgent::boot(AgentConfig::isolated(root.join("target"))).unwrap();
        let storage = LocalStorage::new(root.join("cloud"));
        let master = MasterKey::generate();
        let mut source = steam_bundle("TestGame");
        source.environment["capture_scope_version"] = serde_json::json!(1);
        let app = source.app.app_id.clone();
        agent
            .db
            .upsert_app(&AppIdentity::new(app.clone(), "TestGame"))
            .unwrap();
        let library = agent.config.home.join("SteamLibrary/steamapps");
        agent.roots.lock().steam_libraries.clear();
        agent
            .roots
            .lock()
            .steam_libraries
            .insert("0".into(), library.clone());
        let chunks = [
            (
                "$STEAM_LIBRARY:1",
                "common/TestGame/game.bin",
                b"game".as_slice(),
            ),
            (
                "$XDG_CONFIG_HOME",
                "external-save/save.dat",
                b"save".as_slice(),
            ),
        ];
        for (logical_root, relative_path, bytes) in chunks {
            let hash = noland_cas::blake3_hex(bytes);
            source.files.push(ManifestFile {
                logical_root: logical_root.into(),
                relative_path: relative_path.into(),
                source_path_hint: Some(format!("/source-pc/{relative_path}")),
                file_type: "file".into(),
                size: bytes.len() as u64,
                file_hash: hash.clone(),
                chunks: vec![ChunkRef {
                    hash,
                    size: bytes.len() as u64,
                }],
                mode: Some(0o600),
                mtime_ns: Some(1),
                uid: None,
                gid: None,
                symlink_target: None,
                persistence_class: if logical_root.starts_with("$STEAM") {
                    PersistenceClass::ReconstructableApp
                } else {
                    PersistenceClass::PersistentState
                },
                semantic_role: if logical_root.starts_with("$STEAM") {
                    SemanticRole::AppContent
                } else {
                    SemanticRole::UserState
                },
                association_confidence: 1.0,
                shared_app_ids: Vec::new(),
            });
        }
        let packs = noland_pack::pack_chunks(
            &root.join("packs"),
            &master,
            chunks
                .into_iter()
                .map(|(_, _, bytes)| (noland_cas::blake3_hex(bytes), bytes.to_vec())),
            |_| false,
        )
        .unwrap();
        let index = packs
            .iter()
            .flat_map(|pack| pack.entries.clone())
            .collect::<Vec<_>>();
        let pack_files = packs
            .iter()
            .map(|pack| (pack.pack_id.clone(), pack.path.clone()))
            .collect::<Vec<_>>();
        commit_bundle_with_index(
            &storage,
            &master,
            &source,
            &pack_files,
            Some(&serde_json::to_vec(&index).unwrap()),
            None,
        )
        .await
        .unwrap();
        let destination = agent.config.home.join(".config/external-save/save.dat");
        let path_id = agent.db.upsert_path(destination.to_str().unwrap()).unwrap();
        agent
            .db
            .upsert_association(&PathAssociation {
                app_id: app.clone(),
                path_id,
                confidence: 0.5,
                evidence: vec![Evidence::new(EvidenceKind::NameHeuristic)
                    .with_detail("preserve existing evidence")],
                persistence_class: PersistenceClass::PersistentState,
                semantic_role: SemanticRole::UserState,
                first_seen_at: Utc::now(),
                last_seen_at: Utc::now(),
            })
            .unwrap();
        let roots = prepare_restore_roots(&agent, &source).unwrap();
        let plan = prepare_restore(
            &storage,
            &master,
            &agent.config.paths,
            &app,
            source.bundle_id,
            RestoreMode::CompleteApplication,
        )
        .await
        .unwrap()
        .into_shared();
        restore_pipelined(
            &storage,
            &master,
            &plan,
            &index,
            &roots,
            Some(&agent.db),
            None,
            PipelineOptions::default(),
            |_| Ok(()),
        )
        .await
        .unwrap();
        crate::backup::remember_remote_pack_index(
            &agent,
            storage.storage_identity(),
            &master,
            &index,
        )
        .unwrap();
        crate::backup::remember_restored_parent(
            &agent,
            storage.storage_identity(),
            &master,
            &source,
            &index,
        )
        .unwrap();
        let associations = agent.db.associations_for_app(&app).unwrap();
        let evidence = &associations
            .iter()
            .find(|(path, _)| Path::new(&path.canonical_path) == destination)
            .unwrap()
            .1
            .evidence;
        assert!(evidence
            .iter()
            .any(|item| item.kind == EvidenceKind::ExplicitUserBinding));
        assert!(evidence
            .iter()
            .any(|item| item.detail.as_deref() == Some("preserve existing evidence")));
        assert!(agent
            .db
            .get_file_state(&app, "$STEAM_LIBRARY:0", "common/TestGame/game.bin")
            .unwrap()
            .is_some());
        assert!(agent
            .db
            .get_file_state(&app, "$STEAM_LIBRARY:1", "common/TestGame/game.bin")
            .unwrap()
            .is_none());
        let unchanged_operation = Uuid::new_v4();
        let unchanged = crate::backup::run_backup(
            &agent,
            &app,
            BackupMode::CompleteApplication,
            BackupPerformanceMode::Balanced,
            &storage,
            &master,
            Some(unchanged_operation),
        )
        .await
        .unwrap();
        assert_eq!(unchanged.files.len(), 2);
        assert!(unchanged.tombstones.is_empty());
        let metrics = agent
            .db
            .get_operation_metrics(unchanged_operation)
            .unwrap()
            .unwrap();
        assert_eq!(metrics.num_files_rehashed, 0);
        assert_eq!(metrics.num_files_skipped_fast_identity, 2);
        assert_eq!(metrics.bytes_uploaded, 0);
        std::fs::write(&destination, b"changed save").unwrap();
        agent
            .db
            .append_app_mutation(&AppMutationRecord::new(
                app.clone(),
                destination.to_str().unwrap(),
                AppMutationKind::Modify,
            ))
            .unwrap();
        agent.db.mark_dirty(&app, Some(path_id), false).unwrap();
        let changed_operation = Uuid::new_v4();
        let next = crate::backup::run_backup(
            &agent,
            &app,
            BackupMode::CompleteApplication,
            BackupPerformanceMode::Balanced,
            &storage,
            &master,
            Some(changed_operation),
        )
        .await
        .unwrap();
        let metrics = agent
            .db
            .get_operation_metrics(changed_operation)
            .unwrap()
            .unwrap();
        assert_eq!(metrics.num_files_rehashed, 1);
        assert_eq!(metrics.num_files_skipped_fast_identity, 1);
        assert_eq!(next.files.len(), 2);
        assert!(
            next.tombstones.is_empty(),
            "scope selection must not synthesize deletions"
        );
        assert!(next
            .files
            .iter()
            .any(|file| file.logical_root == "$STEAM_LIBRARY:0"));
        assert!(!next
            .files
            .iter()
            .any(|file| file.logical_root == "$STEAM_LIBRARY:1"));
        assert!(
            read_committed_manifest(&storage, &master, &app, source.bundle_id)
                .await
                .is_err(),
            "replacement retires the old cloud generation, not live saves"
        );
        assert!(
            read_committed_manifest(&storage, &master, &app, next.bundle_id)
                .await
                .is_ok()
        );
        let second = StateAgent::boot(AgentConfig::isolated(root.join("second"))).unwrap();
        second.roots.lock().steam_libraries.clear();
        second.roots.lock().steam_libraries.insert(
            "0".into(),
            second.config.home.join("SteamLibrary/steamapps"),
        );
        let second_roots = prepare_restore_roots(&second, &next).unwrap();
        let next_index = read_pack_index(&storage, &master, &app, next.bundle_id)
            .await
            .unwrap();
        let plan = prepare_restore(
            &storage,
            &master,
            &second.config.paths,
            &app,
            next.bundle_id,
            RestoreMode::CompleteApplication,
        )
        .await
        .unwrap();
        restore_pipelined(
            &storage,
            &master,
            &plan,
            &next_index,
            &second_roots,
            None,
            None,
            PipelineOptions::default(),
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(second.config.home.join(".config/external-save/save.dat")).unwrap(),
            b"changed save"
        );
        assert_eq!(
            std::fs::read(
                second
                    .config
                    .home
                    .join("SteamLibrary/steamapps/common/TestGame/game.bin")
            )
            .unwrap(),
            b"game"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preferred_steamapps_dir_uses_registered_library_first() {
        let mut roots = LogicalRootMap::default();
        roots.steam_root = Some(PathBuf::from("/steam/root"));
        roots
            .steam_libraries
            .insert("0".into(), PathBuf::from("/steam/library/steamapps"));

        assert_eq!(
            preferred_steamapps_dir(&roots),
            Some(PathBuf::from("/steam/library/steamapps"))
        );
    }

    #[test]
    fn clean_machine_restore_derives_proton_prefix_without_registering_scan_root() {
        let home = std::env::temp_dir().join(format!(
            "noland-restore-proton-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let agent = StateAgent::boot(AgentConfig::isolated(home.clone())).unwrap();
        let bundle = steam_bundle("Test Game");

        let roots = prepare_restore_roots(&agent, &bundle).unwrap();
        let expected = agent
            .config
            .home
            .join(".steam/steam/steamapps/compatdata/3241660/pfx");

        assert_eq!(roots.proton_prefixes.get(&3_241_660), Some(&expected));
        assert!(!agent
            .db
            .known_roots(Some(&AppId::steam(3_241_660)))
            .unwrap()
            .iter()
            .any(|(_, kind, _)| kind == "proton"));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn fallback_does_not_synthesize_manifest_from_display_name() {
        let home = std::env::temp_dir().join(format!(
            "noland-restore-steam-manifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let steamapps = home.join("steamapps");
        std::fs::create_dir_all(&steamapps).unwrap();

        let agent = StateAgent::boot(AgentConfig::isolated(home.clone())).unwrap();
        agent
            .roots
            .lock()
            .steam_libraries
            .insert("0".into(), steamapps.clone());
        let bundle = steam_bundle("Display Name Is Not The Install Directory");

        assert!(steam_restore_prerequisites(
            &bundle,
            &agent.roots.lock(),
            RestoreMode::CompleteApplication
        )
        .is_empty());

        assert!(!steamapps.join("appmanifest_3241660.acf").exists());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn prerequisite_planning_preserves_original_steam_manifest_and_personal_state() {
        let home = std::env::temp_dir().join(format!(
            "noland-restore-steam-pre-manifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let steamapps = home.join("steamapps");
        std::fs::create_dir_all(&steamapps).unwrap();
        let agent = StateAgent::boot(AgentConfig::isolated(home.clone())).unwrap();
        agent
            .roots
            .lock()
            .steam_libraries
            .insert("0".into(), steamapps.clone());
        let mut bundle = steam_bundle("Test Game");
        bundle.app.canonical_executable = Some(PathBuf::from(
            "/source/steamapps/common/TestGame/bin/game.exe",
        ));
        let manifest_path = steamapps.join("appmanifest_3241660.acf");
        std::fs::write(&manifest_path, "old manifest").unwrap();

        let roots = prepare_restore_roots(&agent, &bundle).unwrap();
        let prerequisites =
            steam_restore_prerequisites(&bundle, &roots, RestoreMode::CompleteApplication);
        assert_eq!(prerequisites.len(), 1);
        assert!(
            steam_restore_prerequisites(&bundle, &roots, RestoreMode::PersonalState).is_empty()
        );

        assert_eq!(std::fs::read(&manifest_path).unwrap(), b"old manifest");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn transaction_prerequisite_uses_source_install_directory() {
        let home = std::env::temp_dir().join(format!(
            "noland-restore-steam-source-manifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let steamapps = home.join("steamapps");
        std::fs::create_dir_all(&steamapps).unwrap();

        let agent = StateAgent::boot(AgentConfig::isolated(home.clone())).unwrap();
        agent
            .roots
            .lock()
            .steam_libraries
            .insert("0".into(), steamapps.clone());
        let mut bundle = steam_bundle("Unrelated Display Name");
        bundle.app.canonical_executable = Some(PathBuf::from(
            "/source/steamapps/common/ActualInstallDirectory/bin/game.exe",
        ));

        let prerequisites = steam_restore_prerequisites(
            &bundle,
            &agent.roots.lock(),
            RestoreMode::CompleteApplication,
        );

        let manifest = std::str::from_utf8(&prerequisites[0].contents).unwrap();
        assert!(manifest.contains("\"installdir\"\t\t\"ActualInstallDirectory\""));
        assert!(!manifest.contains("\"installdir\"\t\t\"Unrelated Display Name\""));
        std::fs::remove_dir_all(home).unwrap();
    }
}
