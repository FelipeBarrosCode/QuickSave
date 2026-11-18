// SPDX-License-Identifier: GPL-3.0-only
//! Public protocol constants, not embedded application registrations.
//! Official sources and redirect-registration limitations: ../PROVENANCE.md.

use anyhow::{bail, Result};

// These are public registered redirect coordinates, not authentication secrets.
// Registration policy is deliberately not supplied by the webview or caller.
pub(crate) const REGISTERED_PORT: u16 = 53682;
pub(crate) const REGISTERED_PATH: &str = "/quicksave/oauth/callback";
pub(crate) const REGISTERED_URI: &str = "http://127.0.0.1:53682/quicksave/oauth/callback";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provider {
    GoogleDrive,
    MicrosoftOneDrive,
    Dropbox,
    Box,
}

impl Provider {
    pub(crate) fn from_kind(kind: &str) -> Result<Self> {
        match kind {
            "google_drive" => Ok(Self::GoogleDrive),
            "microsoft_onedrive" | "microsoft_one_drive" => Ok(Self::MicrosoftOneDrive),
            "dropbox" => Ok(Self::Dropbox),
            "box" => Ok(Self::Box),
            _ => bail!("This provider does not support QuickSave native OAuth."),
        }
    }

    pub(crate) fn authorization_endpoint(self) -> &'static str {
        match self {
            Self::GoogleDrive => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::MicrosoftOneDrive => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            }
            Self::Dropbox => "https://www.dropbox.com/oauth2/authorize",
            Self::Box => "https://account.box.com/api/oauth2/authorize",
        }
    }

    pub(crate) fn token_endpoint(self) -> &'static str {
        match self {
            Self::GoogleDrive => "https://oauth2.googleapis.com/token",
            Self::MicrosoftOneDrive => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            Self::Dropbox => "https://api.dropboxapi.com/oauth2/token",
            Self::Box => "https://api.box.com/oauth2/token",
        }
    }

    pub(crate) fn scope(self) -> &'static str {
        match self {
            // Existing configured backup folders must remain accessible, not
            // merely files created by this registered OAuth client. This is a
            // restricted Google scope and requires explicit provider consent.
            Self::GoogleDrive => "https://www.googleapis.com/auth/drive",
            Self::MicrosoftOneDrive => "offline_access https://graph.microsoft.com/Files.ReadWrite",
            Self::Dropbox => {
                "account_info.read files.metadata.read files.content.read files.content.write"
            }
            // Box grants the scopes enabled on the user's explicit confidential
            // app registration; do not invent an undocumented scope parameter.
            Self::Box => "",
        }
    }

    pub(crate) fn required_scopes(self) -> &'static [&'static str] {
        match self {
            Self::GoogleDrive => &["https://www.googleapis.com/auth/drive"],
            // offline_access is requested, but is not an API permission in the
            // token's granted scope list.
            Self::MicrosoftOneDrive => &["Files.ReadWrite"],
            Self::Dropbox => &[
                "account_info.read",
                "files.metadata.read",
                "files.content.read",
                "files.content.write",
            ],
            Self::Box => &[],
        }
    }

    pub(crate) fn permits_client_secret(self) -> bool {
        matches!(self, Self::GoogleDrive | Self::Box)
    }

    pub(crate) fn uses_pkce(self) -> bool {
        self != Self::Box
    }

    pub(crate) fn listener_port(self) -> u16 {
        match self {
            Self::GoogleDrive => 0,
            Self::MicrosoftOneDrive | Self::Dropbox | Self::Box => REGISTERED_PORT,
        }
    }

    pub(crate) fn registered_redirect(self) -> Option<&'static str> {
        match self {
            Self::GoogleDrive => None,
            Self::MicrosoftOneDrive | Self::Dropbox | Self::Box => Some(REGISTERED_URI),
        }
    }

    pub(crate) fn registered_path(self) -> Option<&'static str> {
        self.registered_redirect().map(|_| REGISTERED_PATH)
    }

    pub(crate) fn is_static_token_endpoint(endpoint: &str) -> bool {
        [
            Self::GoogleDrive,
            Self::MicrosoftOneDrive,
            Self::Dropbox,
            Self::Box,
        ]
        .iter()
        .any(|provider| provider.token_endpoint() == endpoint)
    }
}
