// SPDX-License-Identifier: GPL-3.0-only
//! Native source-operation observation and exact frozen-selection helpers.
//!
//! # Parent integration API
//!
//! `SourceOperationShadow::from_agent(Arc<StateAgent>, authenticator)` reads the ACTUAL source
//! DB and running-worker owner; it never creates a shadow DB or trusts UI status.
//! `observe(binding)` / `binding(binding)` expose bounded, non-secret projections only.
//! `SourceFrozenSelection::known_paths(&[SourceDeletionSelection])` produces
//! exact safe catalog paths; `pending_deletion(id)` retains the source plan ID.
//! Source admission, provider reattachment and guards belong to the native parent
//! adapter. This helper never enables unsafe native `*` batch RPCs.
//!
//! Provenance: inspected pinned No Land e81238a7536aae201540956ce76981364fd36595
//! `state-agent/crates/noland-state-core/src/operations.rs` and active-fork
//! `noland-state-agent/src/{native_host,operation_manager,rpc_handler/submission}.rs`.
//! New code is GPL-3.0-only. Actual source HMAC admission/replay remains mandatory:
//! the authenticator must call/verify that code using native reacquired provider
//! access, not bless an unsigned operation JSON or a matching display label.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub use crate::catalog_control::DeletionSelection as SourceDeletionSelection;

pub const MAX_CHILDREN_PER_JOB: usize = 128;
pub const MAX_SELECTED_APPS: usize = 4096;
pub const MAX_NATIVE_SELECTION_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFrozenSelection {
    selected_paths: Vec<String>,
}

impl SourceFrozenSelection {
    /// The result is passed only to source `PrepareDeletion`; source inventory,
    /// dependency expansion, repository ownership and authentication still run.
    pub fn known_paths(selected: &[SourceDeletionSelection]) -> Result<Self> {
        ensure!(
            !selected.is_empty() && selected.len() <= 1000,
            "Select 1–1000 exact source backups per deletion preview"
        );
        let mut paths = BTreeSet::new();
        let mut bundle_ids = BTreeSet::new();
        for item in selected {
            crate::catalog_control::safe_app_id(&item.app_id)?;
            canonical_uuid(&item.bundle_id)?;
            ensure!(
                bundle_ids.insert(&item.bundle_id),
                "A bundle identity occurs more than once in the deletion selection"
            );
            paths.insert(format!("/catalog/{}/{}", item.app_id, item.bundle_id));
        }
        Ok(Self {
            selected_paths: paths.into_iter().collect(),
        })
    }

    /// Resume exactly this authenticated pending source FullDeletionPlan. It is
    /// never translated back into "all current backups for these apps".
    pub fn pending_deletion(plan_id: &str) -> Result<Self> {
        canonical_uuid(plan_id)?;
        Ok(Self {
            selected_paths: vec![format!("/pending-deletions/{plan_id}")],
        })
    }

    pub fn paths(&self) -> &[String] {
        &self.selected_paths
    }

    pub fn prepare_params(&self) -> serde_json::Value {
        serde_json::json!({"target":"cloud","selected_paths":self.selected_paths})
    }
}

fn canonical_uuid(value: &str) -> Result<()> {
    ensure!(
        value.len() == 36
            && value.bytes().enumerate().all(|(i, byte)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                }
            }),
        "Expected a canonical source operation/bundle identity"
    );
    Ok(())
}

#[cfg(unix)]
mod source {
    use super::*;
    use noland_state_agent::{native_host::NativeSelection, StateAgent};
    use noland_state_core::{OperationMetrics, OperationRecord};
    use serde_json::{json, Value};
    use std::{sync::Arc, time::Duration};
    use uuid::Uuid;

    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum SourceOperationKind {
        Backup,
        Restore,
        DeleteCloud,
    }

    impl SourceOperationKind {
        pub fn source_kind(self) -> &'static str {
            match self {
                Self::Backup => "backup",
                Self::Restore => "restore",
                Self::DeleteCloud => "delete",
            }
        }
    }

    /// Native-private fixed binding. Never deserialize this from JS as authority.
    /// `native_selection_digest` is the canonical typed NativeSelection digest,
    /// not a hash of a UI file list. For deletion it is the FullDeletionPlan
    /// digest, verified by the mandatory authenticator.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct ParentNativeBinding {
        pub parent_id: Uuid,
        pub job_id: Uuid,
        pub source_operation_id: Uuid,
        pub native_plan_id: Uuid,
        pub provider_id: String,
        pub provider_scope: String,
        pub app_id: String,
        pub kind: SourceOperationKind,
        pub native_selection_digest: String,
        pub roots_fingerprint: String,
        pub source_revision: String,
        pub mode: Option<String>,
        pub bundle_id: Option<Uuid>,
    }

    impl ParentNativeBinding {
        pub fn validate(&self) -> Result<()> {
            crate::catalog_control::safe_app_id(&self.app_id)?;
            ensure!(
                !self.provider_id.is_empty()
                    && self.provider_id.len() <= 128
                    && !self.provider_id.chars().any(char::is_control)
                    && !self.source_revision.is_empty()
                    && self.source_revision.len() <= 512
                    && !self.source_revision.chars().any(char::is_control),
                "Invalid parent native provider/revision binding"
            );
            for digest in [
                &self.provider_scope,
                &self.native_selection_digest,
                &self.roots_fingerprint,
            ] {
                ensure!(
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "Invalid parent native scope digest"
                );
            }
            ensure!(
                self.kind != SourceOperationKind::Restore || self.bundle_id.is_some(),
                "Restore binding lacks its frozen bundle ID"
            );
            ensure!(
                self.kind == SourceOperationKind::DeleteCloud && self.mode.is_none()
                    || self.kind != SourceOperationKind::DeleteCloud
                        && matches!(
                            self.mode.as_deref(),
                            Some("complete_application" | "personal_state" | "custom")
                        ),
                "Parent binding lacks an exact source operation mode"
            );
            Ok(())
        }
    }

    /// No default/unsigned implementation exists. `verify_record` must verify the
    /// actual source's authenticated idempotent submission (or loaded deletion
    /// plan), in addition to the parent's signed fixed plan. `verify_observation`
    /// may reuse that pinned native authentication, never a DB JSON claim alone.
    /// It must check that the parent/provider/root authority remains valid.
    pub trait SourceBindingAuthenticator: Send + Sync + 'static {
        fn verify_record(
            &self,
            expected: &ParentNativeBinding,
            actual: &OperationRecord,
        ) -> Result<()>;
        fn verify_observation(
            &self,
            expected: &ParentNativeBinding,
            actual: &SourceRecordIdentity,
        ) -> Result<()>;
        fn verify_absence(&self, expected: &ParentNativeBinding) -> Result<()>;
        /// Validate the retained native exact-ID cancellation capability, not
        /// current provider write/root authority. Revocation must stop writes,
        /// not prevent us from draining the already-owned source worker.
        fn verify_cancellation(&self, expected: &ParentNativeBinding) -> Result<()>;
    }

    /// No detail_json, keys, token, source path list, hashes or provider session.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct SourceRecordIdentity {
        pub source_operation_id: Uuid,
        pub kind: String,
        pub app_id: Option<String>,
        pub state: String,
        pub updated_at: String,
    }

    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum SourceLifecycle {
        Queued,
        Running,
        Completed,
        Failed,
        Cancelled,
        Interrupted,
        Unknown,
    }

    impl SourceLifecycle {
        pub fn from_source(state: &str) -> Self {
            match state {
                "QUEUED" | "REQUESTED" => Self::Queued,
                "DISCOVERING"
                | "RECONCILING"
                | "SNAPSHOTTING"
                | "HASHING"
                | "CAPTURING_AND_UPLOADING"
                | "PACKING"
                | "UPLOADING"
                | "COMMITTING"
                | "CHECKPOINTING"
                | "FETCHING_MANIFEST"
                | "CHECKING_PREREQUISITES"
                | "DOWNLOADING"
                | "VERIFYING"
                | "MATERIALIZING"
                | "WAITING_FOR_QUIESCE"
                | "CREATING_ROLLBACK_POINT"
                | "APPLYING"
                | "VALIDATING"
                | "ROLLING_BACK"
                | "RUNNING"
                | "BACKING_UP_DIRTY_APPS"
                | "UPLOADING_SEAL"
                | "COMMITTING_SEAL" => Self::Running,
                "COMPLETED" | "SEALED" => Self::Completed,
                "FAILED" | "ROLLED_BACK" => Self::Failed,
                "CANCELLED" => Self::Cancelled,
                "INTERRUPTED" => Self::Interrupted,
                _ => Self::Unknown,
            }
        }
        pub fn terminal(self) -> bool {
            matches!(
                self,
                Self::Completed | Self::Failed | Self::Cancelled | Self::Interrupted
            )
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct SourceProgress {
        pub phase: String,
        pub completed_units: u64,
        pub total_units: Option<u64>,
        pub unit: Option<String>,
        /// Exact source metrics, not progress-derived percentages.
        pub metrics: Option<OperationMetrics>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct SourceOperationStatus {
        pub identity: SourceRecordIdentity,
        pub lifecycle: SourceLifecycle,
        pub worker_running: bool,
        pub cancel_requested: bool,
        pub progress: Option<SourceProgress>,
    }

    impl SourceOperationStatus {
        pub fn terminal_and_drained(&self) -> bool {
            self.lifecycle.terminal() && !self.worker_running
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "presence", rename_all = "snake_case")]
    pub enum SourceObservation {
        Absent { source_operation_id: Uuid },
        Present { status: Box<SourceOperationStatus> },
    }

    /// Borrowing the actual agent keeps its actual StateDb/worker owner alive.
    /// No separate SQLite file is opened and no production state is searched.
    pub struct SourceOperationShadow {
        agent: Arc<StateAgent>,
        authenticator: Arc<dyn SourceBindingAuthenticator>,
    }

    impl SourceOperationShadow {
        pub fn from_agent(
            agent: Arc<StateAgent>,
            authenticator: Arc<dyn SourceBindingAuthenticator>,
        ) -> Result<Self> {
            ensure!(
                agent.config.native_host && !agent.config.converge_complete_backups,
                "Operation control requires an additive-history native source agent"
            );
            Ok(Self {
                agent,
                authenticator,
            })
        }

        /// Explicit reattachment read only: full native selection stays native.
        /// Polling uses `projected_operation(false)` instead of loading 250k keys.
        pub fn binding(&self, expected: &ParentNativeBinding) -> Result<Value> {
            expected.validate()?;
            let record = self
                .agent
                .db
                .get_operation(expected.source_operation_id)?
                .context("Original source operation is unavailable")?;
            check_record(expected, &record)?;
            self.authenticator.verify_record(expected, &record)?;
            if expected.kind != SourceOperationKind::DeleteCloud {
                ensure!(
                    record.detail_json["mode"].as_str() == expected.mode.as_deref(),
                    "Original source mode is missing or differs from its frozen parent"
                );
                let selection = NativeSelection::parse(&record.detail_json["native_selection"])?;
                let bytes = selection_bytes(&selection)?;
                ensure!(
                    blake3::hash(&bytes).to_hex().as_str() == expected.native_selection_digest
                        && selection.roots_fingerprint == expected.roots_fingerprint,
                    "Source operation differs from the parent's frozen native selection"
                );
                if expected.kind == SourceOperationKind::Backup {
                    ensure!(
                        selection.snapshot_identity.as_deref()
                            == Some(expected.source_revision.as_str()),
                        "Source capture revision differs from the approved parent plan"
                    );
                }
            } else {
                ensure!(
                    record.detail_json["target"] == "cloud",
                    "Native cloud deletion cannot reattach local source deletion"
                );
            }
            // Allowlist only; never copy source detail_json/session/results.
            Ok(json!({
                "sourceOperationId":expected.source_operation_id,
                "parentId":expected.parent_id, "jobId":expected.job_id,
                "nativePlanId":expected.native_plan_id, "providerId":expected.provider_id,
                "appId":expected.app_id, "kind":expected.kind,
                "sourceRevision":expected.source_revision,
                "mode":expected.mode,
                "bundleId":expected.bundle_id,
            }))
        }

        pub fn observe(&self, expected: &ParentNativeBinding) -> Result<SourceObservation> {
            self.observe_inner(expected, false)
        }

        fn observe_inner(
            &self,
            expected: &ParentNativeBinding,
            cancellation_capability: bool,
        ) -> Result<SourceObservation> {
            expected.validate()?;
            let Some(record) = self
                .agent
                .db
                .projected_operation(expected.source_operation_id, false)?
            else {
                if cancellation_capability {
                    self.authenticator.verify_cancellation(expected)?;
                } else {
                    self.authenticator.verify_absence(expected)?;
                }
                ensure!(
                    !self
                        .agent
                        .operations
                        .is_running(expected.source_operation_id),
                    "Source worker exists without its durable operation row"
                );
                return Ok(SourceObservation::Absent {
                    source_operation_id: expected.source_operation_id,
                });
            };
            check_record(expected, &record)?;
            ensure!(
                record.state.len() <= 128 && !record.state.chars().any(char::is_control),
                "Invalid source operation lifecycle"
            );
            let identity = SourceRecordIdentity {
                source_operation_id: record.operation_id,
                kind: record.kind,
                app_id: record.app_id.map(|app| app.to_string()),
                state: record.state,
                updated_at: record.updated_at.to_rfc3339(),
            };
            if cancellation_capability {
                self.authenticator.verify_cancellation(expected)?;
            } else {
                self.authenticator.verify_observation(expected, &identity)?;
            }
            let progress = self
                .agent
                .db
                .get_operation_progress(expected.source_operation_id)?
                .map(|progress| {
                    ensure!(
                        progress.phase.len() <= 128
                            && !progress.phase.chars().any(char::is_control)
                            && progress.unit.as_ref().is_none_or(|unit| {
                                unit.len() <= 64 && !unit.chars().any(char::is_control)
                            }),
                        "Source progress is outside its non-secret bounds"
                    );
                    Ok::<_, anyhow::Error>(SourceProgress {
                        phase: progress.phase,
                        completed_units: progress.completed_units,
                        total_units: progress.total_units,
                        unit: progress.unit,
                        metrics: self
                            .agent
                            .db
                            .get_operation_metrics(expected.source_operation_id)?,
                    })
                })
                .transpose()?;
            Ok(SourceObservation::Present {
                status: Box::new(SourceOperationStatus {
                    lifecycle: SourceLifecycle::from_source(&identity.state),
                    worker_running: self
                        .agent
                        .operations
                        .is_running(expected.source_operation_id),
                    cancel_requested: self
                        .agent
                        .operations
                        .cancel_requested(expected.source_operation_id),
                    identity,
                    progress,
                }),
            })
        }

        pub fn observe_page(
            &self,
            expected: &[ParentNativeBinding],
        ) -> Result<Vec<SourceObservation>> {
            ensure!(
                !expected.is_empty() && expected.len() <= MAX_CHILDREN_PER_JOB,
                "Source operation observation page must contain 1–128 fixed children"
            );
            let mut ids = BTreeSet::new();
            for child in expected {
                ensure!(
                    ids.insert(child.source_operation_id),
                    "Duplicate source child ID"
                );
            }
            expected
                .iter()
                .map(|binding| self.observe(binding))
                .collect()
        }

        /// Sends cancellation to the ACTUAL source manager and waits for its
        /// joined worker/finalizer lease to disappear. Timeout is an error, never
        /// a terminal status or permission to release source handles.
        pub async fn cancel_and_drain(
            &self,
            expected: &ParentNativeBinding,
            timeout: Duration,
        ) -> Result<SourceObservation> {
            ensure!(
                !timeout.is_zero() && timeout <= Duration::from_secs(120),
                "Source drain timeout must be 1ns–120s"
            );
            expected.validate()?;
            self.authenticator.verify_cancellation(expected)?;
            let before = self.observe_inner(expected, true)?;
            if matches!(&before, SourceObservation::Absent { .. }) {
                return Ok(before);
            }
            self.agent.operations.cancel(expected.source_operation_id);
            tokio::time::timeout(timeout, async {
                while self
                    .agent
                    .operations
                    .is_running(expected.source_operation_id)
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("Source cancellation is still draining; retain native ownership")?;
            self.observe_inner(expected, true)
        }
    }

    fn check_record(expected: &ParentNativeBinding, record: &OperationRecord) -> Result<()> {
        ensure!(
            record.operation_id == expected.source_operation_id
                && record.kind == expected.kind.source_kind()
                && (expected.kind == SourceOperationKind::DeleteCloud
                    || record.app_id.as_ref().map(|app| app.as_str())
                        == Some(expected.app_id.as_str())),
            "Actual source record belongs to another native parent/child selection"
        );
        if expected.kind == SourceOperationKind::Restore
            && !record.detail_json.is_null()
            && record.detail_json.get("bundle_id").is_some()
        {
            ensure!(
                record.detail_json["bundle_id"]
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
                    == expected.bundle_id,
                "Actual restore record belongs to another frozen bundle"
            );
        }
        if expected.kind != SourceOperationKind::DeleteCloud
            && record.detail_json.get("mode").is_some()
        {
            ensure!(
                record.detail_json["mode"].as_str() == expected.mode.as_deref(),
                "Actual source operation mode differs from the frozen parent plan"
            );
        }
        Ok(())
    }

    fn selection_bytes(selection: &NativeSelection) -> Result<Vec<u8>> {
        // Source NativeSelection parsing already bounds file count; count the
        // serialized document before allocating another native-private buffer.
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::other("Native selection size overflow"))?;
                if self.0 > MAX_NATIVE_SELECTION_BYTES {
                    return Err(std::io::Error::other(
                        "Native selection exceeds its private bound",
                    ));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(&mut Count(0), selection)?;
        Ok(serde_json::to_vec(selection)?)
    }

    pub fn native_selection_digest(selection: &NativeSelection) -> Result<String> {
        let bytes = selection_bytes(selection)?;
        let value = serde_json::from_slice(&bytes)?;
        let validated = NativeSelection::parse(&value)?;
        Ok(blake3::hash(&selection_bytes(&validated)?)
            .to_hex()
            .to_string())
    }
}

#[cfg(unix)]
pub use source::*;

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn multi_bundle_paths_keep_original_app_and_exact_bundle_ids() {
        let selected = vec![
            SourceDeletionSelection {
                app_id: "desktop:one".into(),
                bundle_id: "00000000-0000-0000-0000-000000000001".into(),
            },
            SourceDeletionSelection {
                app_id: "steam:22".into(),
                bundle_id: "00000000-0000-0000-0000-000000000002".into(),
            },
        ];
        let frozen = SourceFrozenSelection::known_paths(&selected).unwrap();
        assert_eq!(frozen.paths().len(), 2);
        assert!(frozen.paths().contains(&format!(
            "/catalog/{}/{}",
            selected[0].app_id, selected[0].bundle_id
        )));
        assert_eq!(frozen.prepare_params()["target"], "cloud");
        let resume = SourceFrozenSelection::pending_deletion(&selected[0].bundle_id).unwrap();
        assert_eq!(
            resume.paths(),
            &[format!("/pending-deletions/{}", selected[0].bundle_id)]
        );
    }

    #[test]
    fn exact_selection_helper_never_enables_globs_traversal_or_duplicate_bundle_ids() {
        for app in ["*", "_all", "../escape", "game/*", "game\\child", "game?"] {
            assert!(
                SourceFrozenSelection::known_paths(&[SourceDeletionSelection {
                    app_id: app.into(),
                    bundle_id: "00000000-0000-0000-0000-000000000001".into(),
                }])
                .is_err()
            );
        }
        let item = SourceDeletionSelection {
            app_id: "desktop:one".into(),
            bundle_id: "00000000-0000-0000-0000-000000000001".into(),
        };
        assert!(SourceFrozenSelection::known_paths(&[item.clone(), item]).is_err());
        assert!(SourceFrozenSelection::pending_deletion("../other").is_err());
    }
}

#[cfg(all(test, unix))]
mod source_tests {
    use super::*;
    use chrono::Utc;
    use noland_state_agent::{
        native_host::{native_file_id, NativeSelection},
        AgentConfig, StateAgent,
    };
    use noland_state_core::{AppId, OperationProgress, OperationRecord};
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use uuid::Uuid;

    struct FixtureAuthenticator {
        allow: AtomicBool,
        expected: ParentNativeBinding,
    }
    impl FixtureAuthenticator {
        fn check(&self, binding: &ParentNativeBinding) -> Result<()> {
            ensure!(
                self.allow.load(Ordering::SeqCst) && binding == &self.expected,
                "Fixture native authentication rejected this exact binding"
            );
            Ok(())
        }
    }
    impl SourceBindingAuthenticator for FixtureAuthenticator {
        fn verify_record(
            &self,
            expected: &ParentNativeBinding,
            actual: &OperationRecord,
        ) -> Result<()> {
            self.check(expected)?;
            ensure!(
                actual.detail_json["submission_binding"] == "fixture-source-MAC",
                "Fixture source submission authentication is missing"
            );
            Ok(())
        }
        fn verify_observation(
            &self,
            expected: &ParentNativeBinding,
            _: &SourceRecordIdentity,
        ) -> Result<()> {
            self.check(expected)
        }
        fn verify_absence(&self, expected: &ParentNativeBinding) -> Result<()> {
            self.check(expected)
        }
        fn verify_cancellation(&self, expected: &ParentNativeBinding) -> Result<()> {
            ensure!(
                expected == &self.expected,
                "Fixture cancellation scope changed"
            );
            Ok(())
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        Arc<StateAgent>,
        ParentNativeBinding,
        NativeSelection,
        Arc<FixtureAuthenticator>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(temp.path()).unwrap();
        let mut config = AgentConfig::isolated(path);
        config.native_host = true;
        config.converge_complete_backups = false;
        // Match native-host initialization: AgentPaths::ensure_dirs alone uses
        // ordinary directory modes, which the native SQLite privacy gate must
        // reject. Create private fixture directories before boot, never relax
        // the database policy or repair permissions after opening it.
        for directory in [
            &config.paths.state_root,
            &config.paths.run_root,
            &config.paths.staging,
            &config.paths.snapshots,
            &config.paths.packs,
            &config.paths.restore,
            &config.paths.checkpoints,
            &config.paths.cache,
        ] {
            quicksave_platform::ensure_private_directory(directory).unwrap();
        }
        let agent = Arc::new(StateAgent::boot(config).unwrap());
        // Deliberately exercise a legacy selection with absent optional coverage;
        // source format extensions must not silently invent whole-app coverage.
        let selection: NativeSelection = serde_json::from_value(json!({
            "version":1, "file_keys":[{"logical_root":"$HOME","relative_path":"save.dat"}],
            "roots_fingerprint":"e".repeat(64),"destination":null,"destination_identity":null,
            "snapshot_identity":"fixture-index-revision-1",
            "expected_files":[{
                "id":native_file_id("$HOME","save.dat"),"size":3,
                "fileHash":format!("blake3:{}","a".repeat(64)),
            }],
            "capture_scope":null,
        }))
        .unwrap();
        let binding = ParentNativeBinding {
            parent_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            source_operation_id: Uuid::new_v4(),
            native_plan_id: Uuid::new_v4(),
            provider_id: "fixture-provider".into(),
            provider_scope: "b".repeat(64),
            app_id: "desktop:fixture".into(),
            kind: SourceOperationKind::Backup,
            native_selection_digest: native_selection_digest(&selection).unwrap(),
            roots_fingerprint: selection.roots_fingerprint.clone(),
            source_revision: selection.snapshot_identity.clone().unwrap(),
            mode: Some("complete_application".into()),
            bundle_id: None,
        };
        let auth = Arc::new(FixtureAuthenticator {
            allow: AtomicBool::new(true),
            expected: binding.clone(),
        });
        (temp, agent, binding, selection, auth)
    }

    fn persist(
        agent: &StateAgent,
        binding: &ParentNativeBinding,
        selection: &NativeSelection,
        state: &str,
    ) {
        agent
            .db
            .upsert_operation(&OperationRecord {
                operation_id: binding.source_operation_id,
                kind: "backup".into(),
                app_id: Some(AppId(binding.app_id.clone())),
                state: state.into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_error: None,
                detail_json: json!({
                    "app_id":binding.app_id,"mode":"complete_application",
                    "native_selection":selection,"submission_binding":"fixture-source-MAC",
                    "private_provider_output":"never-project-this",
                }),
            })
            .unwrap();
    }

    #[test]
    fn actual_source_db_projection_preserves_unknown_and_does_not_emit_private_details() {
        let (_temp, agent, binding, selection, auth) = fixture();
        persist(&agent, &binding, &selection, "FUTURE_SOURCE_STATE");
        let shadow = SourceOperationShadow::from_agent(Arc::clone(&agent), auth).unwrap();
        let SourceObservation::Present { status } = shadow.observe(&binding).unwrap() else {
            panic!("present source row");
        };
        assert_eq!(status.lifecycle, SourceLifecycle::Unknown);
        assert!(!status.terminal_and_drained());
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("native_selection"));
        assert!(!json.contains("never-project-this"));
        let attached = shadow.binding(&binding).unwrap();
        assert!(!attached.to_string().contains("submission_binding"));
        assert!(!attached.to_string().contains("save.dat"));
    }

    #[test]
    fn source_binding_and_authenticator_both_reject_changed_plans() {
        let (_temp, agent, binding, mut selection, auth) = fixture();
        persist(&agent, &binding, &selection, "INTERRUPTED");
        let shadow = SourceOperationShadow::from_agent(Arc::clone(&agent), auth.clone()).unwrap();
        shadow.binding(&binding).unwrap();
        selection.snapshot_identity = Some("late-added-index-generation".into());
        persist(&agent, &binding, &selection, "INTERRUPTED");
        assert!(shadow.binding(&binding).is_err());
        auth.allow.store(false, Ordering::SeqCst);
        assert!(shadow.observe(&binding).is_err());
    }

    #[test]
    fn native_observation_uses_real_source_progress_without_synthetic_percentages() {
        let (_temp, agent, binding, selection, auth) = fixture();
        persist(&agent, &binding, &selection, "UPLOADING");
        let mut progress = OperationProgress::new("uploading", 17);
        progress.unit = Some("bytes".into());
        progress.total_units = Some(33);
        progress.detail_json = json!({"private_secret":"fixture-only-never-project"});
        agent
            .db
            .set_operation_progress(binding.source_operation_id, Some(&progress))
            .unwrap();
        let shadow = SourceOperationShadow::from_agent(agent, auth).unwrap();
        let SourceObservation::Present { status } = shadow.observe(&binding).unwrap() else {
            panic!("present row");
        };
        let actual = status.progress.unwrap();
        assert_eq!(actual.completed_units, 17);
        assert_eq!(actual.total_units, Some(33));
        let text = serde_json::to_string(&actual).unwrap();
        assert!(!text.contains("percent"));
        assert!(!text.contains("private_secret"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_drains_the_actual_source_manager_even_after_write_authority_revocation() {
        use noland_state_agent::operation_manager::OperationLane;
        use std::time::Duration;
        let (_temp, agent, binding, selection, auth) = fixture();
        persist(&agent, &binding, &selection, "RUNNING");
        let cancelled = Arc::clone(&agent);
        let failed = Arc::clone(&agent);
        let id = binding.source_operation_id;
        assert!(agent.operations.spawn_cancellable_on_lane(
            id,
            OperationLane::Transfer,
            async { std::future::pending::<()>().await },
            move || {
                let mut row = cancelled.db.get_operation(id).unwrap().unwrap();
                row.state = "CANCELLED".into();
                cancelled.db.upsert_operation(&row).unwrap();
            },
            move |_| {
                let mut row = failed.db.get_operation(id).unwrap().unwrap();
                row.state = "FAILED".into();
                failed.db.upsert_operation(&row).unwrap();
            },
        ));
        let shadow = SourceOperationShadow::from_agent(Arc::clone(&agent), auth.clone()).unwrap();
        let SourceObservation::Present { status } = shadow.observe(&binding).unwrap() else {
            panic!("actual row");
        };
        assert!(status.worker_running);
        auth.allow.store(false, Ordering::SeqCst);
        assert!(
            shadow.observe(&binding).is_err(),
            "revoked write authority cannot authorize new work"
        );
        let SourceObservation::Present { status } = shadow
            .cancel_and_drain(&binding, Duration::from_secs(5))
            .await
            .unwrap()
        else {
            panic!("cancelled actual source row");
        };
        assert_eq!(status.lifecycle, SourceLifecycle::Cancelled);
        assert!(status.terminal_and_drained());
        assert!(!agent.operations.is_running(id));
    }
}
