// SPDX-License-Identifier: GPL-3.0-only
//! Shared reconciliation path for real native probes and injected fixtures.
use anyhow::{Context, Result};
use std::{collections::BTreeSet, path::PathBuf};

use crate::{
    CapabilityState, EvidenceBatch, EvidenceConfidence, EvidenceSource, FileEvidence, GapReason,
    NativeFileIdentity, ObservationGap, ObservationLimits, ObservationRootKind, ObservationScope,
    ProcessGeneration, ProcessProof, SourceCapabilities,
};

#[derive(Clone, Debug)]
pub struct ProbeListing<T> {
    pub items: Vec<T>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessDescriptor {
    pub generation: ProcessGeneration,
    pub executable: PathBuf,
    /// Identity of the running mapped image, NOT just a stat of its pathname.
    pub executable_identity: NativeFileIdentity,
    pub image_binding: crate::ImageIdentityBinding,
    /// Native signing identifier, verified against the approved bundle product.
    /// Not a filename, process comm value, or user-supplied environment variable.
    pub bundle_identifier: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorSample {
    pub path: PathBuf,
    pub identity: NativeFileIdentity,
}

/// Trusted native adapter interface. Public for deterministic fixture injection;
/// never implement by interpreting renderer-supplied PID/path JSON.
///
/// Native implementations must filter paths against scope BEFORE external
/// filesystem metadata calls. Kernel records may contain transient outside-path
/// metadata; such records must be discarded rather than retained or emitted.
pub trait ProcessProbe: Send + 'static {
    fn capabilities(&self) -> SourceCapabilities;
    fn processes(&mut self, scope: &ObservationScope, max: usize) -> Result<ProbeListing<u32>>;
    fn process(&mut self, scope: &ObservationScope, pid: u32) -> Result<Option<ProcessDescriptor>>;
    fn descriptors(&mut self, pid: u32, max: usize) -> Result<ProbeListing<u64>>;
    fn descriptor(
        &mut self,
        scope: &ObservationScope,
        pid: u32,
        descriptor: u64,
    ) -> Result<Option<DescriptorSample>>;
}

pub struct PollingSource<P: ProcessProbe> {
    probe: P,
    runtime_failure: Option<(CapabilityState, &'static str)>,
}

impl<P: ProcessProbe> PollingSource<P> {
    pub fn new(probe: P) -> Self {
        Self {
            probe,
            runtime_failure: None,
        }
    }

    fn note_error(&mut self, error: &anyhow::Error, unavailable: bool) -> bool {
        let permission = error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        });
        if permission {
            self.runtime_failure = Some((
                CapabilityState::NeedsNativePermission,
                "The native API denied part of this approved scope; available evidence is partial.",
            ));
        } else if unavailable && self.runtime_failure.is_none() {
            self.runtime_failure = Some((
                CapabilityState::Unavailable,
                "The native process source could not enumerate the approved scope.",
            ));
        }
        permission
    }
}

impl<P: ProcessProbe> EvidenceSource for PollingSource<P> {
    fn capabilities(&self) -> SourceCapabilities {
        let mut capabilities = self.probe.capabilities();
        if let Some((state, reason)) = self.runtime_failure {
            capabilities.state = state;
            capabilities.reason = reason;
        }
        capabilities
    }

    fn poll(
        &mut self,
        scope: &ObservationScope,
        now_ms: u64,
        limits: &ObservationLimits,
    ) -> Result<EvidenceBatch> {
        limits.validate()?;
        self.runtime_failure = None;
        let mut batch = EvidenceBatch {
            processes: Vec::new(),
            files: Vec::new(),
            gaps: vec![
                ObservationGap::global(GapReason::PollingCannotObserveShortLivedOpens),
                ObservationGap::global(GapReason::PollingCannotObserveExecAndBack),
            ],
            process_listing_complete: true,
            observed_at_ms: now_ms,
        };
        if scope.authorized().is_err() {
            batch
                .gaps
                .push(ObservationGap::global(GapReason::ConsentRevoked));
            batch.process_listing_complete = false;
            return Ok(batch);
        }
        let listing = match self.probe.processes(scope, limits.max_processes) {
            Ok(listing) => listing,
            Err(error) => {
                self.note_error(&error, true);
                return Err(error);
            }
        };
        if !listing.complete || listing.items.len() > limits.max_processes {
            batch.process_listing_complete = false;
            batch.gaps.push(ObservationGap::global(
                GapReason::ProcessEnumerationIncomplete,
            ));
        }
        let mut descriptors_left = limits.max_descriptors_total;
        let pids: BTreeSet<_> = listing
            .items
            .into_iter()
            .take(limits.max_processes)
            .collect();
        for pid in pids {
            let before = match self.probe.process(scope, pid) {
                Ok(Some(process)) if process.generation.uid == scope.uid() => process,
                Ok(_) => continue,
                Err(error) => {
                    batch.process_listing_complete = false;
                    let reason = if self.note_error(&error, false) {
                        GapReason::SourcePermissionDenied
                    } else {
                        GapReason::ProcessChangedDuringObservation
                    };
                    push_gap(&mut batch, reason);
                    continue;
                }
            };
            if before.generation.pid != pid
                || before
                    .bundle_identifier
                    .as_ref()
                    .is_some_and(|id| id.len() > 400 || id.chars().any(char::is_control))
            {
                push_gap(&mut batch, GapReason::InvalidEvidence);
                batch.process_listing_complete = false;
                continue;
            }
            if before.executable.as_os_str().len() > limits.max_path_bytes {
                push_gap(&mut batch, GapReason::BoundExceeded);
                batch.process_listing_complete = false;
                continue;
            }
            if scope
                .locate(&before.executable, ObservationRootKind::Executable)
                .is_none()
            {
                continue;
            }
            let (_, _, image_stamp) = match scope
                .stamp(&before.executable, ObservationRootKind::Executable)
            {
                Ok(stamp) if NativeFileIdentity::from(&stamp.2) == before.executable_identity => {
                    stamp
                }
                Ok(_) => {
                    push_gap(&mut batch, GapReason::ExecutableIdentityChanged);
                    batch.process_listing_complete = false;
                    continue;
                }
                Err(error) => {
                    let reason = if self.note_error(&error, false) {
                        GapReason::SourcePermissionDenied
                    } else {
                        GapReason::ExecutableIdentityChanged
                    };
                    push_gap(&mut batch, reason);
                    batch.process_listing_complete = false;
                    continue;
                }
            };
            let resolved = if !self.probe.capabilities().running_image_native_identity
                || before.image_binding != crate::ImageIdentityBinding::MappedImageNativeFile
            {
                // A pathname-only Windows observation cannot prove which image
                // section is running, so it cannot join a registered product or
                // prove that product absent. Keep it as manual-review evidence.
                if scope.has_registered_executable(&before.executable) {
                    batch.process_listing_complete = false;
                }
                Ok(None)
            } else {
                scope.resolve_app(
                    &before.executable,
                    &image_stamp,
                    before.bundle_identifier.as_deref(),
                )
            };
            let registered = match resolved {
                Ok(app) => app,
                Err(_) => {
                    push_gap(
                        &mut batch,
                        if scope.registered_stamp_changed(&before.executable, &image_stamp) {
                            GapReason::ExecutableIdentityChanged
                        } else {
                            GapReason::BundleIdentityUnverified
                        },
                    );
                    batch.process_listing_complete = false;
                    continue;
                }
            };
            let app_id = registered.clone().unwrap_or_else(|| {
                let token = format!(
                    "{}:{:?}:{:?}",
                    image_stamp.device, image_stamp.file_id, before.executable
                );
                format!(
                    "quicksave.observed:{}",
                    blake3::hash(token.as_bytes()).to_hex()
                )
            });
            let proof = ProcessProof {
                scope_fingerprint: scope.fingerprint().to_owned(),
                generation: before.generation.clone(),
                executable: before.executable.clone(),
                executable_stamp: image_stamp,
                image_binding: before.image_binding,
                bundle_identifier: before.bundle_identifier.clone(),
                app_id,
                registered_identity: registered.is_some(),
                observed_at_ms: now_ms,
                source: self.probe.capabilities().source,
            };
            let mut files = Vec::new();
            if !self.probe.capabilities().native_open_file_identity
                || !self.probe.capabilities().running_image_native_identity
                || before.image_binding != crate::ImageIdentityBinding::MappedImageNativeFile
            {
                push_gap(&mut batch, GapReason::NativeFileSourceUnavailable);
            } else if descriptors_left == 0 {
                push_gap(&mut batch, GapReason::BoundExceeded);
            } else {
                let max = descriptors_left.min(limits.max_descriptors_per_process);
                match self.probe.descriptors(pid, max) {
                    Ok(listing) => {
                        if !listing.complete || listing.items.len() > max {
                            push_gap(&mut batch, GapReason::DescriptorEnumerationIncomplete);
                        }
                        // Charge even skipped/outside descriptors: attacker-controlled
                        // paths cannot bypass the native-call and CPU budget.
                        for fd in listing.items.into_iter().take(max) {
                            descriptors_left -= 1;
                            if batch.files.len() + files.len() >= limits.max_evidence {
                                push_gap(&mut batch, GapReason::BoundExceeded);
                                break;
                            }
                            match observe_file(
                                &mut self.probe,
                                scope,
                                &proof,
                                pid,
                                fd,
                                limits.max_path_bytes,
                            ) {
                                Ok(Some(file)) => files.push(file),
                                Ok(None) => {}
                                Err(error) => {
                                    let reason = if self.note_error(&error, false) {
                                        GapReason::SourcePermissionDenied
                                    } else {
                                        GapReason::DescriptorChangedDuringObservation
                                    };
                                    push_gap(&mut batch, reason);
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let reason = if self.note_error(&error, false) {
                            GapReason::SourcePermissionDenied
                        } else {
                            GapReason::DescriptorEnumerationIncomplete
                        };
                        push_gap(&mut batch, reason);
                    }
                }
            }
            // Whole-process bracket: an exec or PID reuse during descriptor
            // collection invalidates ALL evidence for this process in this poll.
            let after = self.probe.process(scope, pid);
            if let Err(error) = &after {
                if self.note_error(error, false) {
                    push_gap(&mut batch, GapReason::SourcePermissionDenied);
                }
            }
            let stable = matches!(after, Ok(Some(ref after)) if after == &before)
                && scope
                    .stamp(&before.executable, ObservationRootKind::Executable)
                    .is_ok_and(|(_, _, stamp)| stamp == proof.executable_stamp);
            if !stable {
                batch.process_listing_complete = false;
                push_gap(&mut batch, GapReason::ProcessChangedDuringObservation);
                continue;
            }
            batch.processes.push(proof);
            batch.files.extend(files);
        }
        let invalidated = if scope.authorized().is_err() {
            Some(GapReason::ConsentRevoked)
        } else if scope.verify_evidence_roots(&batch).is_err() {
            Some(GapReason::RootIdentityChanged)
        } else {
            None
        };
        if let Some(reason) = invalidated {
            batch.processes.clear();
            batch.files.clear();
            batch.process_listing_complete = false;
            push_gap(&mut batch, reason);
        }
        Ok(batch)
    }
}

fn observe_file<P: ProcessProbe>(
    probe: &mut P,
    scope: &ObservationScope,
    proof: &ProcessProof,
    pid: u32,
    descriptor: u64,
    max_path_bytes: usize,
) -> Result<Option<FileEvidence>> {
    let Some(before) = probe.descriptor(scope, pid, descriptor)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        before.path.as_os_str().len() <= max_path_bytes,
        "descriptor path exceeds the bound"
    );
    if scope
        .locate_for_app(
            &before.path,
            ObservationRootKind::Data,
            Some(proof.app_id()),
        )
        .is_none()
    {
        return Ok(None);
    }
    let (root_id, relative_path, stamp) = scope.stamp_for_app(
        &before.path,
        ObservationRootKind::Data,
        Some(proof.app_id()),
    )?;
    anyhow::ensure!(
        NativeFileIdentity::from(&stamp) == before.identity,
        "descriptor points to another native file"
    );
    let after = probe
        .descriptor(scope, pid, descriptor)?
        .context("descriptor closed during observation")?;
    anyhow::ensure!(before == after, "descriptor was swapped during observation");
    let (_, _, verified) = scope.stamp_for_app(
        &before.path,
        ObservationRootKind::Data,
        Some(proof.app_id()),
    )?;
    anyhow::ensure!(stamp == verified, "native file changed during observation");
    Ok(Some(FileEvidence {
        process: proof.clone(),
        root_id,
        relative_path,
        stamp,
        descriptor,
        confidence: EvidenceConfidence::NativeIdentityMatchedUse,
    }))
}

fn push_gap(batch: &mut EvidenceBatch, reason: GapReason) {
    if !batch
        .gaps
        .iter()
        .any(|gap| gap.reason == reason && gap.root_id.is_none())
    {
        batch.gaps.push(ObservationGap::global(reason));
    }
}
