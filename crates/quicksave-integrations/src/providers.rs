// SPDX-License-Identifier: GPL-3.0-only
//! Configuration contracts only. This module does not implement cloud I/O or auth.

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use crate::profiles::ProfilePath;

/// No variant contains credentials, OAuth tokens or encryption keys. References
/// to future native-vault entries are opaque identifiers, not secret values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypedProviderConfig {
    LocalFilesystem {
        repository: PathBuf,
    },
    S3Compatible {
        endpoint: String,
        bucket: String,
        prefix: Option<ProfilePath>,
        credential_reference: String,
    },
    GoogleDrive {
        folder_id: String,
        account_reference: String,
    },
    OneDrive {
        drive_id: String,
        folder_id: String,
        account_reference: String,
    },
    OtherRclone {
        remote_name: String,
        relative_path: Option<ProfilePath>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    LocalFilesystem,
    S3Compatible,
    GoogleDrive,
    OneDrive,
    OtherRclone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Available,
    Planned,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderCapability {
    pub kind: ProviderKind,
    pub status: ProviderStatus,
    pub engine_transport_implemented: bool,
    pub credential_flow_implemented: bool,
    pub automatic_deletion_supported: bool,
    pub detail: &'static str,
}

/// Short alias retained for callers that prefer the provider module namespace.
pub type ProviderConfig = TypedProviderConfig;

impl TypedProviderConfig {
    pub fn kind(&self) -> ProviderKind {
        match self {
            Self::LocalFilesystem { .. } => ProviderKind::LocalFilesystem,
            Self::S3Compatible { .. } => ProviderKind::S3Compatible,
            Self::GoogleDrive { .. } => ProviderKind::GoogleDrive,
            Self::OneDrive { .. } => ProviderKind::OneDrive,
            Self::OtherRclone { .. } => ProviderKind::OtherRclone,
        }
    }

    pub fn status(&self) -> ProviderStatus {
        match self {
            Self::LocalFilesystem { .. } => ProviderStatus::Available,
            _ => ProviderStatus::Planned,
        }
    }

    /// Only checks the contract, not filesystem confinement or durability.
    /// Native engine validation must still open/pin the repository.
    pub fn validate_for_use(&self) -> Result<()> {
        if self.status() != ProviderStatus::Available {
            // Do not echo endpoint/account/credential reference input.
            bail!(
                "provider {:?} is planned; cloud transport and authentication are not implemented",
                self.kind()
            );
        }
        match self {
            Self::LocalFilesystem { repository } => validate_local_repository_path(repository),
            _ => bail!("provider transport is not implemented"),
        }
    }
}

fn validate_local_repository_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "local repository path must be absolute");
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("repository path must be UTF-8"))?;
    ensure!(text.len() <= 4096, "local repository path is too long");
    ensure!(
        !text.chars().any(char::is_control),
        "invalid repository path"
    );
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "repository path cannot contain dot components"
    );
    // Path::components normalizes interior '.' segments, so check those too.
    ensure!(
        !text
            .split(['/', '\\'])
            .any(|part| part == "." || part == ".."),
        "repository path cannot contain dot components"
    );
    ensure!(
        path.components()
            .any(|part| matches!(part, Component::Normal(_))),
        "filesystem root is not a repository path"
    );
    Ok(())
}

pub fn capabilities() -> Vec<ProviderCapability> {
    vec![
        ProviderCapability {
            kind: ProviderKind::LocalFilesystem,
            status: ProviderStatus::Available,
            engine_transport_implemented: true,
            credential_flow_implemented: false,
            automatic_deletion_supported: false,
            detail: "Native local engine only; external recovery-key file and explicit root approval are required. This config contract does not validate filesystem handles.",
        },
        ProviderCapability {
            kind: ProviderKind::S3Compatible,
            status: ProviderStatus::Planned,
            engine_transport_implemented: false,
            credential_flow_implemented: false,
            automatic_deletion_supported: false,
            detail: "Typed settings only. No S3 requests, credential loading or remote durability implementation.",
        },
        ProviderCapability {
            kind: ProviderKind::GoogleDrive,
            status: ProviderStatus::Planned,
            engine_transport_implemented: false,
            credential_flow_implemented: false,
            automatic_deletion_supported: false,
            detail: "Typed settings only. No OAuth flow or Drive transport.",
        },
        ProviderCapability {
            kind: ProviderKind::OneDrive,
            status: ProviderStatus::Planned,
            engine_transport_implemented: false,
            credential_flow_implemented: false,
            automatic_deletion_supported: false,
            detail: "Typed settings only. No OAuth flow or Microsoft Graph transport.",
        },
        ProviderCapability {
            kind: ProviderKind::OtherRclone,
            status: ProviderStatus::Planned,
            engine_transport_implemented: false,
            credential_flow_implemented: false,
            automatic_deletion_supported: false,
            detail: "Typed settings only. Rclone is not invoked; existing remote configuration is never inspected.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cloud_config_fails_explicitly_without_io() {
        let configs = [
            ProviderConfig::S3Compatible {
                endpoint: "https://example.invalid".into(),
                bucket: "test".into(),
                prefix: None,
                credential_reference: "vault-entry".into(),
            },
            ProviderConfig::GoogleDrive {
                folder_id: "id".into(),
                account_reference: "ref".into(),
            },
            ProviderConfig::OneDrive {
                drive_id: "drive".into(),
                folder_id: "id".into(),
                account_reference: "ref".into(),
            },
            ProviderConfig::OtherRclone {
                remote_name: "example".into(),
                relative_path: None,
            },
        ];
        for config in configs {
            assert_eq!(config.status(), ProviderStatus::Planned);
            assert!(config
                .validate_for_use()
                .unwrap_err()
                .to_string()
                .contains("not implemented"));
        }
    }

    #[test]
    fn local_config_validation_is_lexical_not_a_successful_open() {
        assert!(validate_local_repository_path(Path::new("relative")).is_err());
        #[cfg(unix)]
        {
            assert!(validate_local_repository_path(Path::new("/")).is_err());
            assert!(validate_local_repository_path(Path::new("/repo/../other")).is_err());
            assert!(validate_local_repository_path(Path::new("/repo/./other")).is_err());
            assert!(validate_local_repository_path(Path::new("/does-not-exist/quicksave")).is_ok());
        }
    }
}
