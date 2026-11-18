// SPDX-License-Identifier: GPL-3.0-only
//! Concrete signed-in-user drive discovery, without a user-guessed drive ID.

use crate::{
    token_valid,
    transport::{HttpTransport, HttpsTransport, MAX_TOKEN_BODY, TOKEN_TIMEOUT},
};
use anyhow::{anyhow, bail, ensure, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use url::Url;

const FIRST: &str = "https://graph.microsoft.com/v1.0/me/drives?$select=id,name,driveType&$top=100";
const MAX_DRIVES: usize = 256;
const MAX_PAGES: usize = 8;

/// Native chooser metadata only. No bearer token, URLs, raw account properties,
/// or serialization/Debug implementation. Parent retains choices in Rust.
pub struct OneDriveChoice {
    pub drive_id: String,
    pub drive_type: String,
    pub name: String,
}

pub(crate) fn validate_endpoint(endpoint: &str) -> Result<()> {
    ensure!(
        endpoint.len() <= 8192,
        "The OneDrive continuation URL is oversized."
    );
    let url =
        Url::parse(endpoint).map_err(|_| anyhow!("The OneDrive continuation URL is invalid."))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("graph.microsoft.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path() == "/v1.0/me/drives",
        "The OneDrive continuation URL is not allowed."
    );
    ensure!(
        url.query_pairs().all(|(key, _)| matches!(
            key.as_ref(),
            "$select" | "$top" | "$skiptoken" | "$skipToken" | "$skip"
        )),
        "The OneDrive continuation query is not allowed."
    );
    Ok(())
}

#[derive(Deserialize)]
struct Drive {
    id: String,
    #[serde(rename = "driveType")]
    drive_type: String,
    #[serde(default)]
    name: String,
}
#[derive(Deserialize)]
struct Page {
    value: Vec<Drive>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}

pub async fn discover_onedrive_drives(access_token: &str) -> Result<Vec<OneDriveChoice>> {
    ensure!(
        token_valid(access_token),
        "The native OneDrive access token is invalid."
    );
    discover_with_transport(access_token, &HttpsTransport::new()?).await
}

/// Normal one-drive case is automatic. Multiple drives require a native-backed
/// chooser using discover_onedrive_drives; never ask users to type opaque IDs.
pub async fn discover_onedrive_drive(access_token: &str) -> Result<(String, String)> {
    let mut choices = discover_onedrive_drives(access_token).await?;
    ensure!(
        choices.len() == 1,
        "Multiple OneDrive drives are available; choose the drive in the native chooser."
    );
    let choice = choices.remove(0);
    Ok((choice.drive_id, choice.drive_type))
}

async fn discover_with_transport(
    access_token: &str,
    transport: &dyn HttpTransport,
) -> Result<Vec<OneDriveChoice>> {
    ensure!(
        token_valid(access_token),
        "The native OneDrive access token is invalid."
    );
    let mut endpoint = FIRST.to_owned();
    let mut visited = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut choices = Vec::new();
    for _ in 0..MAX_PAGES {
        validate_endpoint(&endpoint)?;
        ensure!(
            visited.insert(endpoint.clone()),
            "The OneDrive metadata continuation repeated."
        );
        let reply = tokio::time::timeout(TOKEN_TIMEOUT, transport.graph(&endpoint, access_token))
            .await
            .map_err(|_| anyhow!("The native OneDrive metadata request timed out."))?
            .map_err(|_| anyhow!("The native OneDrive metadata request failed."))?;
        ensure!(
            reply.status == 200,
            "OneDrive drive discovery was not authorized or is unavailable."
        );
        ensure!(
            reply.body.len() <= MAX_TOKEN_BODY,
            "The OneDrive metadata response exceeded its size limit."
        );
        let page: Page = serde_json::from_slice(&reply.body)
            .map_err(|_| anyhow!("OneDrive returned invalid drive metadata."))?;
        ensure!(
            page.value.len() <= MAX_DRIVES - choices.len(),
            "OneDrive returned too many drives."
        );
        for drive in page.value {
            ensure!(
                !drive.id.is_empty()
                    && drive.id.len() <= 1024
                    && drive.id.is_ascii()
                    && !drive
                        .id
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                    && !drive.id.contains(['/', '\\', '?', '#'])
                    && ids.insert(drive.id.clone()),
                "OneDrive returned an invalid or duplicate drive identity."
            );
            ensure!(
                matches!(
                    drive.drive_type.as_str(),
                    "personal" | "business" | "documentLibrary"
                ),
                "OneDrive returned an unsupported drive type."
            );
            ensure!(
                drive.name.len() <= 512 && !drive.name.chars().any(char::is_control),
                "OneDrive returned an invalid drive name."
            );
            choices.push(OneDriveChoice {
                drive_id: drive.id,
                drive_type: drive.drive_type,
                name: drive.name,
            });
        }
        match page.next {
            Some(next) => endpoint = next,
            None => {
                ensure!(
                    !choices.is_empty(),
                    "No accessible OneDrive drive was found; no provider was connected."
                );
                return Ok(choices);
            }
        }
    }
    bail!("OneDrive drive discovery exceeded its page limit; no partial selection was accepted.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TokenReply;
    use std::{future::Future, pin::Pin, sync::Mutex};
    use zeroize::Zeroizing;

    struct Fake {
        pages: Mutex<Vec<String>>,
        requests: Mutex<Vec<String>>,
    }
    impl HttpTransport for Fake {
        fn exchange<'a>(
            &'a self,
            _: &'static str,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
            Box::pin(async { bail!("token exchange must not run for metadata") })
        }
        fn graph<'a>(
            &'a self,
            endpoint: &'a str,
            bearer: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
            Box::pin(async move {
                assert_eq!(bearer, "synthetic-bearer");
                self.requests.lock().unwrap().push(endpoint.to_owned());
                let body = self.pages.lock().unwrap().remove(0);
                Ok(TokenReply {
                    status: 200,
                    body: Zeroizing::new(body.into_bytes()),
                })
            })
        }
    }

    #[tokio::test]
    async fn selects_real_discovered_identity_without_manual_ids_or_account_projection() {
        let fake = Fake { pages: Mutex::new(vec![r#"{"value":[{"id":"synthetic-drive","driveType":"personal","name":"Drive","owner":{"secret":"not projected"}}]}"#.into()]),
            requests: Mutex::default() };
        let choices = discover_with_transport("synthetic-bearer", &fake)
            .await
            .unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].drive_id, "synthetic-drive");
        assert_eq!(choices[0].drive_type, "personal");
        assert!(fake.requests.lock().unwrap()[0].contains("/me/drives"));
    }

    #[tokio::test]
    async fn empty_invalid_duplicates_and_external_continuations_fail_without_partial_success() {
        for body in [
            r#"{"value":[]}"#,
            r#"{"value":[{"id":"x","driveType":"unsupported"}]}"#,
            r#"{"value":[{"id":"x","driveType":"personal"},{"id":"x","driveType":"personal"}]}"#,
            r#"{"value":[{"id":"x","driveType":"business"}],"@odata.nextLink":"https://evil.invalid/collect"}"#,
        ] {
            let fake = Fake {
                pages: Mutex::new(vec![body.into()]),
                requests: Mutex::default(),
            };
            let error = discover_with_transport("synthetic-bearer", &fake)
                .await
                .err()
                .unwrap();
            assert!(!format!("{error:#}").contains("synthetic-bearer"));
            assert_eq!(fake.requests.lock().unwrap().len(), 1);
        }
    }
}
