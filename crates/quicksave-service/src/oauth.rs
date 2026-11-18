// SPDX-License-Identifier: GPL-3.0-only
//! Private native OAuth integration. No returned token is an IPC DTO.

#[cfg(feature = "native-oauth")]
use crate::boundary as dto;
use crate::interfaces::{NativeFuture, ServiceOAuth};
#[cfg(any(not(feature = "native-oauth"), not(windows)))]
use anyhow::bail;
use anyhow::Result;
#[cfg(any(feature = "native-oauth", target_os = "macos", target_os = "linux"))]
use anyhow::{anyhow, ensure};
#[cfg(feature = "native-oauth")]
use serde_json::json;
use serde_json::Value;
#[cfg(feature = "native-oauth")]
use std::sync::Arc;

pub(super) struct NativeOAuth;
impl ServiceOAuth for NativeOAuth {
    fn supports(&self, kind: &str) -> bool {
        cfg!(feature = "native-oauth")
            && matches!(
                kind,
                "google_drive" | "microsoft_onedrive" | "microsoft_one_drive" | "dropbox" | "box"
            )
    }

    fn authorize<'a>(&'a self, input: Value) -> NativeFuture<'a, Value> {
        Box::pin(async move {
            #[cfg(feature = "native-oauth")]
            {
                self.authorize_native(input).await
            }
            #[cfg(not(feature = "native-oauth"))]
            {
                let _ = input;
                bail!("This build does not include the native OAuth bridge");
            }
        })
    }
}

#[cfg(feature = "native-oauth")]
impl NativeOAuth {
    async fn authorize_native(&self, mut input: Value) -> Result<Value> {
        let kind = match dto::id(&input, "kind")? {
            "microsoft_one_drive" => "microsoft_onedrive",
            other => other,
        }
        .to_owned();
        input["kind"] = json!(kind);
        ensure!(
            self.supports(&kind),
            "This provider has no supported native OAuth flow"
        );
        let mut fields = input.get("fields").cloned().unwrap_or_else(|| json!({}));
        ensure!(fields.is_object(), "Provider fields must be an object");
        let client_id = input
            .get("clientId")
            .or_else(|| fields.get("client_id"))
            .and_then(Value::as_str)
            .filter(|value| {
                !value.trim().is_empty()
                    && value.len() <= 4096
                    && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| anyhow!("Use your registered native/public OAuth client ID"))?
            .to_owned();
        if let Some(existing) = fields.get("client_id").and_then(Value::as_str) {
            ensure!(
                existing == client_id,
                "Conflicting OAuth client IDs are not allowed"
            );
        }
        let client_secret = input
            .get("clientSecret")
            .or_else(|| fields.get("client_secret"))
            .filter(|value| !value.is_null())
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| {
                        value.len() <= 64 * 1024 && !value.chars().any(char::is_control)
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("Invalid native OAuth client secret"))
            })
            .transpose()?;
        if let (Some(existing), Some(secret)) = (
            fields.get("client_secret").and_then(Value::as_str),
            client_secret.as_deref(),
        ) {
            ensure!(
                existing == secret,
                "Conflicting OAuth client secrets are not allowed"
            );
        }
        fields["client_id"] = json!(client_id);
        if let Some(secret) = &client_secret {
            fields["client_secret"] = json!(secret);
        }
        let request = quicksave_oauth::OAuthRequest {
            kind,
            client_id,
            client_secret,
        };
        let authorization = if request.kind == "box" {
            quicksave_oauth::authorize_box_confidential(request, Arc::new(open_oauth_browser)).await
        } else {
            quicksave_oauth::authorize(request, Arc::new(open_oauth_browser)).await
        };
        let mut tokens = authorization
            .map_err(|_| anyhow!("Native OAuth did not complete. No provider was connected."))?;
        ensure!(
            !tokens.access_token.is_empty() && tokens.expires_at > 0,
            "The provider did not issue a usable OAuth token"
        );
        let credentials = json!({
            "type":"o_auth2",
            "value":{
                "access_token":std::mem::take(&mut tokens.access_token),
                "refresh_token":tokens.refresh_token.take(),
                "expires_at":tokens.expires_at,
            },
        });
        let object = input
            .as_object_mut()
            .ok_or_else(|| anyhow!("Invalid native connection input"))?;
        object.remove("clientId");
        object.remove("clientSecret");
        object.insert("fields".into(), fields);
        object.insert("credentials".into(), credentials);
        // The caller moves this directly into the native vault-backed store,
        // then runs actual provider health verification before connected.
        Ok(input)
    }
}

fn allowed_browser_url(url: &str) -> Result<()> {
    #[cfg(feature = "native-oauth")]
    return quicksave_oauth::validate_authorization_browser_url(url);
    #[cfg(not(feature = "native-oauth"))]
    {
        let _ = url;
        bail!("This build does not include native OAuth browser authorization")
    }
}

/// Only called with a generated allowlisted authorization URL, after native
/// approval. Windows delegates to the safe native platform boundary, which
/// independently revalidates origins. Unix retains its fixed OS-owned opener.
/// No command interpreter or URL/error logging; bounded caller launch wait.
pub fn open_oauth_browser(url: &str) -> Result<()> {
    allowed_browser_url(url)?;
    #[cfg(windows)]
    return quicksave_platform::open_oauth_browser(url);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use quicksave_platform::SafeRoot;
        use std::{
            os::unix::fs::MetadataExt,
            path::Path,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let executable = if cfg!(target_os = "macos") {
            "/usr/bin/open"
        } else {
            "/usr/bin/xdg-open"
        };
        let executable_path = Path::new(executable);
        let parent = SafeRoot::open(
            executable_path
                .parent()
                .ok_or_else(|| anyhow!("Native browser opener path is invalid"))?,
        )?;
        let leaf = executable_path
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or_else(|| anyhow!("Native browser opener path is invalid"))?;
        let (held, stamp) = parent
            .read_file(leaf)
            .map_err(|_| anyhow!("The trusted OS browser opener is unavailable"))?;
        let metadata = held
            .metadata()
            .map_err(|_| anyhow!("The trusted OS browser opener is unavailable"))?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0 && metadata.mode() & 0o111 != 0,
            "The OS browser opener is not trusted"
        );
        parent
            .verify_file(leaf, &stamp)
            .map_err(|_| anyhow!("The OS browser opener identity changed"))?;
        let mut child = Command::new(executable)
            .arg(url)
            .env_clear()
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| anyhow!("The OS could not open the authorization browser"))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    ensure!(
                        status.success(),
                        "The OS could not open the authorization browser"
                    );
                    parent
                        .verify_file(leaf, &stamp)
                        .map_err(|_| anyhow!("The OS browser opener identity changed"))?;
                    return Ok(());
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!(
                        "The OS browser opener did not finish within its bounded launch deadline"
                    );
                }
            }
        }
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        bail!("A trusted native OAuth browser opener is not supported on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "native-oauth")]
    fn browser_origin_validation_never_launches_a_browser() {
        assert!(allowed_browser_url(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic"
        )
        .is_ok());
        assert!(allowed_browser_url("https://accounts.google.com.attacker.invalid/oauth").is_err());
        assert!(allowed_browser_url("file:///synthetic/unsafe").is_err());
        assert!(allowed_browser_url("https://www.dropbox.com/oauth2/authorize\nsecret").is_err());
        assert!(allowed_browser_url(
            "https://account.box.com/api/oauth2/authorize?client_id=synthetic"
        )
        .is_ok());
        assert!(allowed_browser_url("https://account.box.com.attacker.invalid/").is_err());
        for url in [
            "https://account.box.com@attacker.invalid/",
            "https://attacker.invalid@account.box.com/",
            "https://account.box.com:444/",
            "https://account.box.com\\@attacker.invalid/",
            "https://account.box.com/#fragment",
            "https://%61ccount.box.com/",
            "https://account.box.com/ bad",
        ] {
            assert!(allowed_browser_url(url).is_err());
        }
    }

    #[cfg(not(feature = "native-oauth"))]
    #[test]
    fn disabled_oauth_has_no_browser_handoff_path() {
        assert!(!NativeOAuth.supports("box"));
        assert!(allowed_browser_url("https://account.box.com/api/oauth2/authorize").is_err());
    }
}
