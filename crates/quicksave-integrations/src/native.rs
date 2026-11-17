// SPDX-License-Identifier: GPL-3.0-only
//! Explicit roadmap contracts, with no fake native helper implementations.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::profiles::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeHelper {
    MacKeychain,
    WindowsCredentialManager,
    LinuxSecretService,
    MacFsEvents,
    WindowsReadDirectoryChanges,
    LinuxInotify,
    MacApfsSnapshot,
    WindowsVss,
    LinuxFilesystemSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    Planned,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeCapability {
    pub helper: NativeHelper,
    pub platform: Platform,
    pub status: NativeStatus,
    pub implemented: bool,
    pub detail: &'static str,
    pub reference: &'static str,
}

/// Consumers must fail before claiming credentials, observation or snapshots.
pub fn require_helper(_helper: NativeHelper) -> Result<()> {
    bail!("native integration helper is not implemented; no secret access, observer or snapshot was started")
}

pub fn capabilities() -> Vec<NativeCapability> {
    use NativeHelper::*;
    use Platform::*;
    [
        (MacKeychain, MacOs,
         "External recovery-key files remain required; Keychain storage is not implemented.",
         "https://developer.apple.com/documentation/security/keychain-services"),
        (WindowsCredentialManager, Windows,
         "External recovery-key files remain required; Credential Manager is not implemented.",
         "https://learn.microsoft.com/en-us/windows/win32/secauthn/credentials-management"),
        (LinuxSecretService, Linux,
         "External recovery-key files remain required; Secret Service integration is not implemented.",
         "https://specifications.freedesktop.org/secret-service-spec/latest/"),
        (MacFsEvents, MacOs,
         "No continuous observer; notifications would be hints, never proof of an unchanged tree.",
         "https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/"),
        (WindowsReadDirectoryChanges, Windows,
         "No continuous observer; full stable-file validation remains necessary.",
         "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw"),
        (LinuxInotify, Linux,
         "No continuous observer; overflow/reconciliation support is not implemented.",
         "https://man7.org/linux/man-pages/man7/inotify.7.html"),
        (MacApfsSnapshot, MacOs,
         "No APFS snapshot helper or application quiescence protocol. Folder copies are not atomic app snapshots.",
         "https://developer.apple.com/documentation/apfs"),
        (WindowsVss, Windows,
         "No VSS requester/writer integration or privileged helper.",
         "https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview"),
        (LinuxFilesystemSnapshot, Linux,
         "No Btrfs/LVM snapshot or application quiescence helper.",
         "https://docs.kernel.org/filesystems/btrfs.html"),
    ]
    .into_iter()
    .map(|(helper, platform, detail, reference)| NativeCapability {
        helper, platform, status: NativeStatus::Planned, implemented: false, detail, reference,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn roadmap_never_reports_a_running_or_available_helper() {
        for capability in super::capabilities() {
            assert!(!capability.implemented);
            assert!(super::require_helper(capability.helper).is_err());
        }
    }
}
