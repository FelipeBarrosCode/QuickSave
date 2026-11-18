// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{ensure, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::*;

pub struct ObservationEngine {
    pub(crate) scope: ObservationScope,
    source: Box<dyn EvidenceSource>,
    limits: ObservationLimits,
    snapshot: Arc<ObservationSnapshot>,
    pending_gaps: BTreeSet<GapReason>,
    pending_hints: BTreeSet<String>,
    persistent_gaps: BTreeSet<GapReason>,
}

impl ObservationEngine {
    pub fn new(
        scope: ObservationScope,
        source: Box<dyn EvidenceSource>,
        limits: ObservationLimits,
    ) -> Result<Self> {
        limits.validate()?;
        ensure!(
            scope.roots().count() <= limits.max_roots
                && scope.applications().len() + scope.native_applications().len()
                    <= limits.max_applications,
            "approved scope exceeds engine bounds"
        );
        let capabilities = source.capabilities();
        let mut applications = Vec::new();
        for app_id in scope.application_ids()? {
            if applications
                .iter()
                .any(|existing: &AppObservation| existing.app_id == app_id)
            {
                continue;
            }
            applications.push(AppObservation {
                app_id,
                registered_identity: true,
                execution_state: ExecutionState::Unknown,
                open_file_state: OpenFileState::Unknown,
                active_sessions: Vec::new(),
                ended_sessions: Vec::new(),
                root_candidates: Vec::new(),
                dirty_generation: 1,
                uncertainty_epoch: 1,
                completeness: "unknown",
                capture_triggers: vec![CaptureTrigger::ReconciliationRequired],
            });
        }
        Ok(Self {
            scope,
            source,
            limits,
            snapshot: Arc::new(ObservationSnapshot {
                schema_version: 1,
                observed_at_ms: 0,
                epoch: 0,
                uncertainty_epoch: 1,
                source: capabilities,
                gaps: vec![ObservationGap::global(GapReason::Restart)],
                applications,
                files: Vec::new(),
                unattributed_root_hints: BTreeSet::new(),
                backup_authority: "not_granted",
                application_atomic: false,
                activity_observed: true,
            }),
            pending_gaps: BTreeSet::from([GapReason::Restart]),
            pending_hints: BTreeSet::new(),
            persistent_gaps: BTreeSet::new(),
        })
    }

    pub fn snapshot(&self) -> Arc<ObservationSnapshot> {
        self.snapshot.clone()
    }
    pub(crate) fn maximum_poll_interval_ms(&self) -> u64 {
        self.limits.max_poll_interval_ms
    }

    /// Watcher hints are deliberately PID-free; they never create ownership.
    pub fn root_hint(&mut self, hint: RootHint) -> Result<()> {
        ensure!(
            self.scope.roots.contains_key(&hint.root_id),
            "hint is outside approved observation roots"
        );
        if self.pending_hints.len() >= self.limits.max_hints {
            self.pending_gaps.insert(GapReason::BoundExceeded);
        } else {
            self.pending_hints.insert(hint.root_id);
        }
        Ok(())
    }

    pub fn signal_gap(&mut self, reason: GapReason) {
        self.pending_gaps.insert(reason);
    }
    pub(crate) fn persistent_gap(&mut self, reason: GapReason, present: bool) {
        if present {
            self.persistent_gaps.insert(reason);
        } else {
            self.persistent_gaps.remove(&reason);
        }
    }

    /// A callback/watch race can invalidate a just-collected snapshot without a
    /// second unbounded polling loop. Nothing can turn this fence into "clean".
    pub(crate) fn fence_current(&mut self, reason: GapReason) {
        self.pending_gaps.insert(reason);
        let snapshot = Arc::make_mut(&mut self.snapshot);
        if !snapshot.gaps.iter().any(|gap| gap.reason == reason) {
            snapshot.gaps.push(ObservationGap::global(reason));
        }
        snapshot.uncertainty_epoch = snapshot.uncertainty_epoch.saturating_add(1);
        snapshot.activity_observed = true;
        for app in &mut snapshot.applications {
            app.uncertainty_epoch = snapshot.uncertainty_epoch;
            app.dirty_generation = app.dirty_generation.saturating_add(1);
            app.completeness = "unknown";
            push_trigger(
                &mut app.capture_triggers,
                CaptureTrigger::ReconciliationRequired,
            );
            if reason == GapReason::WorkerStopped {
                app.execution_state = ExecutionState::Unknown;
                app.open_file_state = OpenFileState::Unknown;
                for session in &mut app.active_sessions {
                    session.currently_observed = false;
                }
                for candidate in &mut app.root_candidates {
                    candidate.currently_open = false;
                }
            }
        }
    }

    /// Reconciles observations, never capture cleanliness or cloud durability.
    /// A successful poll cannot clear short-lived-open / lost-lifecycle gaps.
    pub fn reconcile(&mut self, now_ms: u64) -> Result<Arc<ObservationSnapshot>> {
        if self.snapshot.epoch != 0 {
            if now_ms < self.snapshot.observed_at_ms {
                self.pending_gaps.insert(GapReason::ClockMovedBackwards);
            } else if now_ms - self.snapshot.observed_at_ms > self.limits.max_poll_interval_ms {
                self.pending_gaps.insert(GapReason::MissedPoll);
            }
        }
        let mut admission = if self.scope.authorized().is_err() {
            Some(GapReason::ConsentRevoked)
        } else {
            None
        };
        let mut polled = if admission.is_some() {
            Err(anyhow::anyhow!(
                "native observation authority is unavailable"
            ))
        } else {
            self.source.poll(&self.scope, now_ms, &self.limits)
        };
        if admission.is_none() && self.scope.authorized().is_err() {
            admission = Some(GapReason::ConsentRevoked);
            polled = Err(anyhow::anyhow!(
                "native consent was revoked during the observation batch"
            ));
        }
        let mut capabilities = self.source.capabilities();
        if let Some(reason) = admission {
            capabilities.state = CapabilityState::Unavailable;
            capabilities.complete_file_stream = false;
            capabilities.complete_lifecycle_stream = false;
            capabilities.reason = if reason == GapReason::ConsentRevoked {
                "The native observation consent is invalid or revoked."
            } else {
                "The approved native root identity is unavailable or changed."
            };
        }
        let mut batch = match polled {
            Ok(batch) => batch,
            Err(_) => EvidenceBatch {
                processes: Vec::new(),
                files: Vec::new(),
                gaps: vec![ObservationGap::global(if let Some(reason) = admission {
                    reason
                } else if capabilities.state == CapabilityState::NeedsNativePermission {
                    GapReason::SourcePermissionDenied
                } else {
                    GapReason::SourceUnavailable
                })],
                process_listing_complete: false,
                observed_at_ms: now_ms,
            },
        };
        if self.scope.verify_evidence_roots(&batch).is_err() {
            batch.processes.clear();
            batch.files.clear();
            batch.process_listing_complete = false;
            batch
                .gaps
                .push(ObservationGap::global(GapReason::RootIdentityChanged));
        }
        let valid = batch.observed_at_ms == now_ms
            && batch.processes.len() <= self.limits.max_processes
            && batch.files.len() <= self.limits.max_evidence
            && batch.gaps.len() <= 128
            && batch
                .processes
                .iter()
                .chain(batch.files.iter().map(|file| &file.process))
                .all(|proof| {
                    proof.scope_fingerprint() == self.scope.fingerprint()
                        && proof.observed_at_ms() == now_ms
                        && self
                            .scope
                            .locate(proof.executable(), ObservationRootKind::Executable)
                            .is_some()
                })
            && batch.files.iter().all(|file| {
                let Some(root) = self.scope.roots.get(file.root_id()) else {
                    return false;
                };
                if crate::scope::validate_relative(file.relative_path()).is_err() {
                    return false;
                }
                let absolute = root.spec.path.join(file.relative_path());
                self.scope
                    .locate_for_app(
                        &absolute,
                        ObservationRootKind::Data,
                        Some(file.process.app_id()),
                    )
                    .is_some_and(|(resolved, _)| resolved.spec.id == file.root_id)
            });
        if !valid {
            self.fence_current(GapReason::InvalidEvidence);
            anyhow::bail!(
                "native evidence is stale, outside its approved scope, or exceeds the bound"
            );
        }
        let mut gaps = batch.gaps.clone();
        for reason in &self.persistent_gaps {
            if !gaps
                .iter()
                .any(|gap| gap.reason == *reason && gap.root_id.is_none())
            {
                gaps.push(ObservationGap::global(*reason));
            }
        }
        let fresh_gap = self
            .pending_gaps
            .iter()
            .any(|reason| !intrinsic_poll_gap(*reason));
        let previous_losses: BTreeSet<_> = self
            .snapshot
            .gaps
            .iter()
            .map(|gap| gap.reason)
            .filter(|reason| !intrinsic_poll_gap(*reason) && *reason != GapReason::Restart)
            .collect();
        for reason in &self.pending_gaps {
            if !gaps
                .iter()
                .any(|gap| gap.reason == *reason && gap.root_id.is_none())
            {
                gaps.push(ObservationGap::global(*reason));
            }
        }
        self.pending_gaps.clear();
        let losses: BTreeSet<_> = gaps
            .iter()
            .map(|gap| gap.reason)
            .filter(|reason| !intrinsic_poll_gap(*reason) && *reason != GapReason::Restart)
            .collect();
        let actionable_loss = fresh_gap || losses != previous_losses;
        let uncertainty = self
            .snapshot
            .uncertainty_epoch
            .checked_add(1)
            .context("observation uncertainty epoch exhausted")?;
        let epoch = self
            .snapshot
            .epoch
            .checked_add(1)
            .context("observation epoch exhausted")?;
        let mut previous: BTreeMap<_, _> = self
            .snapshot
            .applications
            .iter()
            .map(|app| (app.app_id.clone(), app.clone()))
            .collect();
        let mut app_ids: BTreeSet<_> = previous.keys().cloned().collect();
        for process in &batch.processes {
            if app_ids.len() >= self.limits.max_applications && !app_ids.contains(process.app_id())
            {
                if !gaps
                    .iter()
                    .any(|gap| gap.reason == GapReason::BoundExceeded)
                {
                    gaps.push(ObservationGap::global(GapReason::BoundExceeded));
                }
                continue;
            }
            app_ids.insert(process.app_id().to_owned());
        }
        let mut applications = Vec::new();
        let mut sessions_left = self.limits.max_processes;
        let mut candidates_left = self.limits.max_evidence;
        for app_id in app_ids {
            let old = previous.remove(&app_id);
            let processes: Vec<_> = batch
                .processes
                .iter()
                .filter(|p| p.app_id() == app_id)
                .collect();
            let files: Vec<_> = batch
                .files
                .iter()
                .filter(|f| f.process.app_id() == app_id)
                .collect();
            let old_sessions = old
                .as_ref()
                .map(|app| app.active_sessions.as_slice())
                .unwrap_or(&[]);
            let mut active = Vec::new();
            let mut ended = Vec::new();
            let mut triggers = Vec::new();
            for process in &processes {
                let existing = old_sessions
                    .iter()
                    .find(|session| session.process.same_execution(process));
                let session = if let Some(existing) = existing {
                    AppSession {
                        last_observed_ms: now_ms,
                        process: (**process).clone(),
                        currently_observed: true,
                        ..existing.clone()
                    }
                } else {
                    let token = format!(
                        "{}:{:?}:{:?}:{now_ms}",
                        app_id,
                        process.generation(),
                        process.executable_stamp()
                    );
                    push_trigger(&mut triggers, CaptureTrigger::ObservedRun);
                    AppSession {
                        id: blake3::hash(token.as_bytes()).to_hex().to_string(),
                        process: (**process).clone(),
                        first_observed_ms: now_ms,
                        last_observed_ms: now_ms,
                        boundary: SessionBoundary::RunObserved,
                        currently_observed: true,
                    }
                };
                active.push(session);
            }
            // Do not synthesize run-close from a failed/incomplete process poll.
            // Preserve old sessions as unknown for later reconciliation instead.
            if batch.process_listing_complete {
                for session in old_sessions {
                    if !processes.iter().any(|p| session.process.same_execution(p)) {
                        let changed = batch.processes.iter().any(|p| {
                            p.generation().pid == session.process.generation().pid
                                && !p.same_execution(&session.process)
                        });
                        let mut ended_session = session.clone();
                        ended_session.last_observed_ms = now_ms;
                        ended_session.currently_observed = false;
                        ended_session.boundary = if changed {
                            SessionBoundary::ExecutionChanged
                        } else {
                            SessionBoundary::NoLongerObserved
                        };
                        ended.push(ended_session);
                        push_trigger(
                            &mut triggers,
                            if changed {
                                CaptureTrigger::ObservedExecutionChange
                            } else {
                                CaptureTrigger::ObservedRunClose
                            },
                        );
                    }
                }
            } else {
                for session in old_sessions {
                    if !active
                        .iter()
                        .any(|current| current.process.same_execution(&session.process))
                    {
                        let mut uncertain = session.clone();
                        uncertain.currently_observed = false;
                        active.push(uncertain);
                    }
                }
            }
            if active.len() + ended.len() > sessions_left {
                active.truncate(sessions_left);
                ended.truncate(sessions_left.saturating_sub(active.len()));
                if !gaps
                    .iter()
                    .any(|gap| gap.reason == GapReason::BoundExceeded)
                {
                    gaps.push(ObservationGap::global(GapReason::BoundExceeded));
                }
            }
            sessions_left -= active.len() + ended.len();
            let mut candidates = BTreeMap::new();
            // Keep already-observed candidates after close, but never turn them
            // into authority or claim the old native leaf is still present.
            if let Some(old) = &old {
                for candidate in &old.root_candidates {
                    if candidates.len() >= candidates_left {
                        break;
                    }
                    let mut candidate = candidate.clone();
                    candidate.currently_open = false;
                    candidates.insert(
                        (candidate.root_id.clone(), candidate.relative_path.clone()),
                        candidate,
                    );
                }
            }
            for file in &files {
                let key = (file.root_id.clone(), file.relative_path.clone());
                if !candidates.contains_key(&key) && candidates.len() >= candidates_left {
                    if !gaps
                        .iter()
                        .any(|gap| gap.reason == GapReason::BoundExceeded)
                    {
                        gaps.push(ObservationGap::global(GapReason::BoundExceeded));
                    }
                    continue;
                }
                candidates.insert(
                    key,
                    RootCandidate {
                        root_id: file.root_id.clone(),
                        relative_path: file.relative_path.clone(),
                        confidence: file.confidence,
                        last_observed_ms: now_ms,
                        currently_open: true,
                        relation: "app_uses_path_not_ownership",
                        requires_manual_review: !file.process.registered_identity,
                        requires_native_policy_validation: true,
                        grants_tracking_authority: false,
                    },
                );
            }
            candidates_left -= candidates.len();
            let candidates: Vec<_> = candidates.into_values().collect();
            let old_files: Vec<_> = self
                .snapshot
                .files
                .iter()
                .filter(|f| f.process.app_id() == app_id)
                .collect();
            if file_fingerprint(&files) != file_fingerprint(&old_files) {
                push_trigger(&mut triggers, CaptureTrigger::OpenFileEvidenceChanged);
            }
            // Root hints are merged only with evidence of use from a CURRENT or
            // previous stamped session. They cannot invent a process owner.
            let uses_hinted_root = candidates
                .iter()
                .any(|candidate| self.pending_hints.contains(&candidate.root_id))
                || old.as_ref().is_some_and(|app| {
                    app.root_candidates
                        .iter()
                        .any(|candidate| self.pending_hints.contains(&candidate.root_id))
                });
            if uses_hinted_root {
                push_trigger(&mut triggers, CaptureTrigger::ApprovedRootHint);
            }
            if actionable_loss {
                push_trigger(&mut triggers, CaptureTrigger::ReconciliationRequired);
            }
            let generation = old
                .as_ref()
                .map_or(1, |app| app.dirty_generation)
                .checked_add(u64::from(!triggers.is_empty()))
                .context("observation dirty generation exhausted")?;
            applications.push(AppObservation {
                app_id,
                registered_identity: processes.iter().any(|p| p.registered_identity)
                    || old.as_ref().is_some_and(|app| app.registered_identity),
                execution_state: if !processes.is_empty() {
                    ExecutionState::Running
                } else if batch.process_listing_complete {
                    ExecutionState::NotObservedRunning
                } else {
                    ExecutionState::Unknown
                },
                open_file_state: if !files.is_empty() {
                    OpenFileState::OpenFilesObserved
                } else if batch.process_listing_complete
                    && gaps.iter().all(|gap| {
                        matches!(
                            gap.reason,
                            GapReason::PollingCannotObserveShortLivedOpens
                                | GapReason::PollingCannotObserveExecAndBack
                                | GapReason::Restart
                        )
                    })
                {
                    OpenFileState::NoOpenFilesObserved
                } else {
                    OpenFileState::Unknown
                },
                active_sessions: active,
                ended_sessions: ended,
                root_candidates: candidates,
                dirty_generation: generation,
                uncertainty_epoch: uncertainty,
                completeness: "unknown",
                capture_triggers: triggers,
            });
        }
        let activity_observed = actionable_loss
            || !self.pending_hints.is_empty()
            || applications
                .iter()
                .any(|app| !app.capture_triggers.is_empty());
        self.snapshot = Arc::new(ObservationSnapshot {
            schema_version: 1,
            observed_at_ms: now_ms,
            epoch,
            uncertainty_epoch: uncertainty,
            source: capabilities,
            gaps,
            applications,
            files: batch.files,
            unattributed_root_hints: std::mem::take(&mut self.pending_hints),
            backup_authority: "not_granted",
            application_atomic: false,
            activity_observed,
        });
        Ok(self.snapshot())
    }
}

fn intrinsic_poll_gap(reason: GapReason) -> bool {
    matches!(
        reason,
        GapReason::PollingCannotObserveShortLivedOpens | GapReason::PollingCannotObserveExecAndBack
    )
}

fn push_trigger(triggers: &mut Vec<CaptureTrigger>, trigger: CaptureTrigger) {
    if !triggers.contains(&trigger) {
        triggers.push(trigger);
    }
}

fn file_fingerprint(
    files: &[&FileEvidence],
) -> BTreeSet<(String, String, NativeFileIdentity, u64, i64, u32, i64, u32)> {
    files
        .iter()
        .map(|file| {
            (
                file.root_id.clone(),
                file.relative_path.clone(),
                NativeFileIdentity::from(&file.stamp),
                file.stamp.size,
                file.stamp.modified_seconds,
                file.stamp.modified_nanoseconds,
                file.stamp.changed_seconds,
                file.stamp.changed_nanoseconds,
            )
        })
        .collect()
}
