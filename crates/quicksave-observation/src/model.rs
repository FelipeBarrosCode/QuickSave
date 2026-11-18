// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{ensure, Result};
use quicksave_integrations::{profiles::ProductIdentity, AppIdentity};
use quicksave_platform::FileStamp;
use serde::Serialize;
use std::{collections::BTreeSet, path::PathBuf};

/// Matches integrations' SourceAppIdentity.app_id, not a display or plan ID.
/// An installation-specific Tracker appId must be supplied explicitly using
/// NativeApplicationSpec rather than reconstructed from this product identity.
pub fn stable_app_id(identity: &AppIdentity) -> Result<String> {
    let (kind, id) = match &identity.product {
        ProductIdentity::MacBundleIdentifier(id) => ("mac-bundle", id.clone()),
        ProductIdentity::SteamAppId(id) => {
            ensure!(*id > 0, "invalid zero Steam identity");
            ("steam", id.to_string())
        }
        ProductIdentity::DesktopEntryId(id) => ("desktop", id.clone()),
    };
    ensure!(
        !id.is_empty() && id.len() <= 400 && !id.chars().any(char::is_control),
        "invalid observed application identity"
    );
    Ok(format!("{kind}:{id}"))
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationLimits {
    pub max_roots: usize,
    pub max_applications: usize,
    pub max_processes: usize,
    pub max_descriptors_per_process: usize,
    pub max_descriptors_total: usize,
    pub max_evidence: usize,
    pub max_hints: usize,
    pub max_path_bytes: usize,
    pub max_poll_interval_ms: u64,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            max_roots: 64,
            max_applications: 1024,
            max_processes: 4096,
            max_descriptors_per_process: 1024,
            max_descriptors_total: 32768,
            max_evidence: 8192,
            max_hints: 512,
            max_path_bytes: 4096,
            max_poll_interval_ms: 60000,
        }
    }
}

impl ObservationLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.max_roots > 0
                && self.max_roots <= 4096
                && self.max_applications > 0
                && self.max_applications <= 4096
                && self.max_processes > 0
                && self.max_processes <= 16384
                && self.max_descriptors_per_process > 0
                && self.max_descriptors_per_process <= 8192
                && self.max_descriptors_total > 0
                && self.max_descriptors_total <= 131072
                && self.max_evidence > 0
                && self.max_evidence <= 32768
                && self.max_hints > 0
                && self.max_hints <= 4096
                && self.max_path_bytes > 0
                && self.max_path_bytes <= 4096
                && self.max_poll_interval_ms >= 10
                && self.max_poll_interval_ms <= 60000,
            "observation limits exceed the hard bounds"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    MacLibproc,
    LinuxProcfs,
    WindowsProcess,
    MacEndpointSecurity,
    LinuxEbpf,
    WindowsEtw,
    InjectedFixture,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    NeedsNativePermission,
    NeedsNativeEntitlement,
    Unavailable,
    Unsupported,
}

/// Describes the actual adapter, not a platform-wide marketing capability.
#[derive(Clone, Debug, Serialize)]
pub struct SourceCapabilities {
    pub source: SourceKind,
    pub state: CapabilityState,
    pub process_generations: bool,
    pub executable_stamps: bool,
    pub running_image_native_identity: bool,
    pub native_open_file_identity: bool,
    pub bundle_identifier_verification: bool,
    pub complete_lifecycle_stream: bool,
    pub complete_file_stream: bool,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    Restart,
    PollingCannotObserveShortLivedOpens,
    PollingCannotObserveExecAndBack,
    MissedPoll,
    ClockMovedBackwards,
    SourceUnavailable,
    SourcePermissionDenied,
    ConsentRevoked,
    ProcessEnumerationIncomplete,
    DescriptorEnumerationIncomplete,
    NativeFileSourceUnavailable,
    ProcessChangedDuringObservation,
    DescriptorChangedDuringObservation,
    NamespaceChanged,
    RootIdentityChanged,
    ExecutableIdentityChanged,
    BundleIdentityUnverified,
    BoundExceeded,
    WatcherUnavailable,
    WatcherOverflow,
    QueueOverflow,
    CallbackFailed,
    EventsDuringReconciliation,
    InvalidEvidence,
    WorkerStopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservationGap {
    pub reason: GapReason,
    pub root_id: Option<String>,
}

impl ObservationGap {
    pub fn global(reason: GapReason) -> Self {
        Self {
            reason,
            root_id: None,
        }
    }
}

/// Kernel generation token. No caller-supplied PID-only event can become proof.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProcessGeneration {
    pub pid: u32,
    pub uid: u32,
    /// macOS timeval / Linux boot-relative ticks / Windows FILETIME.
    pub start: [u64; 2],
    /// Linux procfs directory and mount namespace IDs. Zero on other hosts.
    pub namespace: [u64; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageIdentityBinding {
    MappedImageNativeFile,
    /// Windows process image path plus an approved native file handle. This is
    /// useful execution evidence, NOT proof of the image section's file ID.
    ProcessImagePathAndPinnedStampOnly,
}

/// Immutable event-time evidence. Deliberately Serialize-only and private fields:
/// never deserialize this from a webview or use it as filesystem authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessProof {
    pub(crate) scope_fingerprint: String,
    pub(crate) generation: ProcessGeneration,
    pub(crate) executable: PathBuf,
    pub(crate) executable_stamp: FileStamp,
    pub(crate) image_binding: ImageIdentityBinding,
    pub(crate) bundle_identifier: Option<String>,
    pub(crate) app_id: String,
    pub(crate) registered_identity: bool,
    pub(crate) observed_at_ms: u64,
    pub(crate) source: SourceKind,
}

impl ProcessProof {
    pub fn scope_fingerprint(&self) -> &str {
        &self.scope_fingerprint
    }
    pub fn generation(&self) -> &ProcessGeneration {
        &self.generation
    }
    pub fn executable(&self) -> &std::path::Path {
        &self.executable
    }
    pub fn executable_stamp(&self) -> &FileStamp {
        &self.executable_stamp
    }
    pub fn image_binding(&self) -> ImageIdentityBinding {
        self.image_binding
    }
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.bundle_identifier.as_deref()
    }
    pub fn app_id(&self) -> &str {
        &self.app_id
    }
    pub fn source(&self) -> SourceKind {
        self.source
    }
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub fn same_execution(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.scope_fingerprint == other.scope_fingerprint
            && self.executable == other.executable
            && self.executable_stamp == other.executable_stamp
            && self.image_binding == other.image_binding
            && self.bundle_identifier == other.bundle_identifier
            && self.app_id == other.app_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NativeFileIdentity {
    pub device: u64,
    pub file_id: [u64; 2],
}

impl From<&FileStamp> for NativeFileIdentity {
    fn from(stamp: &FileStamp) -> Self {
        Self {
            device: stamp.device,
            file_id: stamp.file_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    /// A generation, image stamp and descriptor native ID matched before/after.
    NativeIdentityMatchedUse,
    /// A root changed; the OS source cannot identify the responsible process.
    UnattributedRootHint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileEvidence {
    pub(crate) process: ProcessProof,
    pub(crate) root_id: String,
    pub(crate) relative_path: String,
    pub(crate) stamp: FileStamp,
    pub(crate) descriptor: u64,
    pub(crate) confidence: EvidenceConfidence,
}

impl FileEvidence {
    pub fn process(&self) -> &ProcessProof {
        &self.process
    }
    pub fn root_id(&self) -> &str {
        &self.root_id
    }
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    pub fn stamp(&self) -> &FileStamp {
        &self.stamp
    }
    pub fn confidence(&self) -> EvidenceConfidence {
        self.confidence
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RootHint {
    pub root_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceBatch {
    pub(crate) processes: Vec<ProcessProof>,
    pub(crate) files: Vec<FileEvidence>,
    pub(crate) gaps: Vec<ObservationGap>,
    pub(crate) process_listing_complete: bool,
    pub(crate) observed_at_ms: u64,
}

/// Trusted backend adapters only. Returning evidence is not an authorization
/// mechanism. Built-in polling sources perform all native proof validation.
pub trait EvidenceSource: Send + 'static {
    fn capabilities(&self) -> SourceCapabilities;
    fn poll(
        &mut self,
        scope: &crate::ObservationScope,
        now_ms: u64,
        limits: &ObservationLimits,
    ) -> Result<EvidenceBatch>;
}

impl EvidenceBatch {
    pub fn processes(&self) -> &[ProcessProof] {
        &self.processes
    }
    pub fn files(&self) -> &[FileEvidence] {
        &self.files
    }
    pub fn gaps(&self) -> &[ObservationGap] {
        &self.gaps
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Running,
    /// Not present in an otherwise successful poll; not a witnessed OS exit.
    NotObservedRunning,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenFileState {
    OpenFilesObserved,
    NoOpenFilesObserved,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBoundary {
    RunObserved,
    NoLongerObserved,
    ExecutionChanged,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppSession {
    pub id: String,
    pub process: ProcessProof,
    pub first_observed_ms: u64,
    pub last_observed_ms: u64,
    pub boundary: SessionBoundary,
    pub currently_observed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootCandidate {
    pub root_id: String,
    pub relative_path: String,
    pub confidence: EvidenceConfidence,
    pub last_observed_ms: u64,
    pub currently_open: bool,
    pub relation: &'static str,
    pub requires_manual_review: bool,
    pub requires_native_policy_validation: bool,
    pub grants_tracking_authority: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTrigger {
    ObservedRun,
    ObservedRunClose,
    ObservedExecutionChange,
    OpenFileEvidenceChanged,
    ApprovedRootHint,
    ReconciliationRequired,
}

/// Local evidence suitable for inclusion alongside an application bundle plan.
/// It never supplies a capture SourcePath, a backup grant, or a "clean" flag.
#[derive(Clone, Debug, Serialize)]
pub struct AppObservation {
    pub app_id: String,
    pub registered_identity: bool,
    pub execution_state: ExecutionState,
    pub open_file_state: OpenFileState,
    pub active_sessions: Vec<AppSession>,
    pub ended_sessions: Vec<AppSession>,
    pub root_candidates: Vec<RootCandidate>,
    pub dirty_generation: u64,
    pub uncertainty_epoch: u64,
    pub completeness: &'static str,
    pub capture_triggers: Vec<CaptureTrigger>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationSnapshot {
    pub schema_version: u32,
    pub observed_at_ms: u64,
    pub epoch: u64,
    pub uncertainty_epoch: u64,
    pub source: SourceCapabilities,
    pub gaps: Vec<ObservationGap>,
    pub applications: Vec<AppObservation>,
    pub files: Vec<FileEvidence>,
    pub unattributed_root_hints: BTreeSet<String>,
    pub backup_authority: &'static str,
    pub application_atomic: bool,
    /// New evidence/actionable loss, not a clean/unchanged-content statement.
    pub activity_observed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidencePage {
    pub epoch: u64,
    pub files: Vec<FileEvidenceSummary>,
    pub next_offset: Option<usize>,
}

/// UI metadata only, not a capture file ID, native stamp or process path proof.
#[derive(Clone, Debug, Serialize)]
pub struct FileEvidenceSummary {
    pub evidence_id: String,
    pub app_id: String,
    pub root_id: String,
    pub relative_path: String,
    pub logical_bytes: u64,
    pub confidence: EvidenceConfidence,
    pub source: SourceKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ObservationWatermark {
    pub event_epoch: u64,
    pub pending_loss: bool,
    pub stopped: bool,
}

impl ObservationSnapshot {
    /// Native revision-bound paging. Do not serialize the full native snapshot
    /// as a renderer inventory or accept its evidence as incoming authority.
    pub fn evidence_page(
        &self,
        expected_epoch: u64,
        offset: usize,
        limit: usize,
    ) -> Result<EvidencePage> {
        ensure!(
            expected_epoch == self.epoch,
            "observation revision changed; restart paging"
        );
        ensure!(
            limit > 0 && limit <= 256 && offset <= self.files.len(),
            "invalid observation evidence page"
        );
        let end = offset.saturating_add(limit).min(self.files.len());
        Ok(EvidencePage {
            epoch: self.epoch,
            files: self.files[offset..end]
                .iter()
                .map(|file| {
                    let id = format!(
                        "{}:{}:{}:{:?}:{:?}",
                        file.process.scope_fingerprint(),
                        file.root_id,
                        file.relative_path,
                        file.process.generation(),
                        NativeFileIdentity::from(&file.stamp)
                    );
                    FileEvidenceSummary {
                        evidence_id: format!(
                            "observation:{}",
                            blake3::hash(id.as_bytes()).to_hex()
                        ),
                        app_id: file.process.app_id.clone(),
                        root_id: file.root_id.clone(),
                        relative_path: file.relative_path.clone(),
                        logical_bytes: file.stamp.size,
                        confidence: file.confidence,
                        source: file.process.source,
                    }
                })
                .collect(),
            next_offset: if end < self.files.len() {
                Some(end)
            } else {
                None
            },
        })
    }
}
