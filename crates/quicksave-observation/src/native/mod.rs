// SPDX-License-Identifier: GPL-3.0-only
//! Runtime adapters. Construction never installs helpers or requests elevation.
use crate::{
    CapabilityState, EvidenceBatch, EvidenceSource, ObservationLimits, ObservationScope,
    SourceCapabilities, SourceKind,
};
use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Current native principal only, never process enumeration or vault access.
/// Call after trusted policy verification; fixtures supply their own UID.
pub fn native_user_id() -> Result<u32> {
    #[cfg(unix)]
    return Ok(unsafe { libc::geteuid() });
    #[cfg(windows)]
    return Ok(0); // WindowsProcesses binds the actual current native SID.
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("native process principal is unsupported")
}

pub fn native_source(scope: &ObservationScope) -> Result<Box<dyn EvidenceSource>> {
    scope.check()?;
    #[cfg(target_os = "macos")]
    return Ok(Box::new(crate::PollingSource::new(macos::MacLibproc::new(
        scope,
    )?)));
    #[cfg(target_os = "linux")]
    return Ok(Box::new(crate::PollingSource::new(
        linux::LinuxProcfs::new(scope)?,
    )));
    #[cfg(target_os = "windows")]
    return Ok(Box::new(crate::PollingSource::new(
        windows::WindowsProcesses::new(scope)?,
    )));
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = scope;
        Ok(Box::new(UnavailableSource::new(
            SourceKind::Unsupported,
            CapabilityState::Unsupported,
            "No native observer exists for this host.",
        )))
    }
}

/// Optional high-fidelity streams are NOT silently promoted from polling.
/// No helper/agent is installed or launched. A future native bridge must be
/// explicitly supplied by the consented service and implement EvidenceSource.
pub fn privileged_stream_status(source: SourceKind) -> SourceCapabilities {
    let (state, reason) = match source {
        SourceKind::MacEndpointSecurity => (
            CapabilityState::NeedsNativeEntitlement,
            "An entitled EndpointSecurity client with explicit user approval is required; no such client is bound.",
        ),
        SourceKind::LinuxEbpf => (
            CapabilityState::NeedsNativePermission,
            "A consented native eBPF bridge, CAP_BPF/CAP_PERFMON and a verified local object are required; no bridge is bound.",
        ),
        SourceKind::WindowsEtw => (
            CapabilityState::NeedsNativePermission,
            "A native Kernel-File/Process ETW session with permission and event-loss accounting is required; no session is bound.",
        ),
        _ => (CapabilityState::Unsupported, "This is not a supported privileged stream adapter."),
    };
    SourceCapabilities {
        source,
        state,
        process_generations: false,
        executable_stamps: false,
        running_image_native_identity: false,
        native_open_file_identity: false,
        bundle_identifier_verification: false,
        complete_lifecycle_stream: false,
        complete_file_stream: false,
        reason,
    }
}

/// Selecting a required privileged stream never silently falls back to polling.
/// Until an explicitly permissioned native binding exists, poll returns an
/// error and the engine publishes the corresponding unavailable/gap evidence.
pub fn privileged_source(source: SourceKind) -> Box<dyn EvidenceSource> {
    Box::new(UnavailableSource {
        capabilities: privileged_stream_status(source),
    })
}

/// An unavailable adapter returns an explicit error, never an empty successful
/// stream. The engine converts it into unknown execution state and a gap epoch.
pub struct UnavailableSource {
    capabilities: SourceCapabilities,
}

impl UnavailableSource {
    pub fn new(source: SourceKind, state: CapabilityState, reason: &'static str) -> Self {
        Self {
            capabilities: SourceCapabilities {
                source,
                state,
                reason,
                process_generations: false,
                executable_stamps: false,
                running_image_native_identity: false,
                native_open_file_identity: false,
                bundle_identifier_verification: false,
                complete_lifecycle_stream: false,
                complete_file_stream: false,
            },
        }
    }
}

impl EvidenceSource for UnavailableSource {
    fn capabilities(&self) -> SourceCapabilities {
        self.capabilities.clone()
    }
    fn poll(
        &mut self,
        _: &ObservationScope,
        _: u64,
        _: &ObservationLimits,
    ) -> Result<EvidenceBatch> {
        anyhow::bail!("{}", self.capabilities.reason)
    }
}
