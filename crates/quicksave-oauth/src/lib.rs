// SPDX-License-Identifier: GPL-3.0-only
//! Native-only OAuth: PKCE S256, explicit confidential Box, refresh and drive discovery.
//! No token, code or client secret is returned to a browser/webview or logged.
//! Registration constraints and unclaimed acceptance: ../PROVENANCE.md.
#![forbid(unsafe_code)]

mod callback;
mod onedrive;
mod providers;
mod transport;
pub use onedrive::{discover_onedrive_drive, discover_onedrive_drives, OneDriveChoice};

use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use providers::Provider;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpSocket},
    time::Instant,
};
use transport::{HttpTransport, HttpsTransport, TokenReply, MAX_TOKEN_BODY, TOKEN_TIMEOUT};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// User-supplied registered public/desktop application. Never Debug/Serialize.
pub struct OAuthRequest {
    pub kind: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl Zeroize for OAuthRequest {
    fn zeroize(&mut self) {
        self.kind.zeroize();
        self.client_id.zeroize();
        self.client_secret.zeroize();
    }
}
impl Drop for OAuthRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Native-only credentials. Caller persists directly into the QuickSave vault.
/// Obtaining these tokens is not a successful provider-health check.
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
}

impl Zeroize for OAuthTokens {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.expires_at.zeroize();
    }
}
impl Drop for OAuthTokens {
    fn drop(&mut self) {
        self.zeroize();
    }
}

type Opener = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
const MAX_UNEXPECTED_CALLBACKS: usize = 16;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INPUT: usize = 8192;

#[derive(Clone, Copy)]
struct Limits {
    total: Duration,
    connection: Duration,
    token: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            total: TOTAL_TIMEOUT,
            connection: CONNECTION_TIMEOUT,
            token: TOKEN_TIMEOUT,
        }
    }
}

struct FlowSecrets {
    verifier: Zeroizing<String>,
    state: Zeroizing<String>,
    callback_path: Zeroizing<String>,
}
fn random_secret() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut bytes[..])
        .map_err(|_| anyhow!("Native secure randomness is unavailable."))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(&bytes[..])))
}
impl FlowSecrets {
    fn new(provider: Provider) -> Result<Self> {
        Ok(Self {
            verifier: random_secret()?,
            state: random_secret()?,
            callback_path: Zeroizing::new(match provider.registered_path() {
                Some(path) => path.to_owned(),
                None => format!("/oauth/callback/{}", random_secret()?.as_str()),
            }),
        })
    }
    fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }
}

fn validate_request(request: &OAuthRequest) -> Result<Provider> {
    let provider = Provider::from_kind(&request.kind)?;
    ensure!(
        !request.client_id.is_empty()
            && request.client_id.len() <= 4096
            && request.client_id.is_ascii()
            && !request
                .client_id
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()),
        "A valid registered desktop OAuth client ID is required."
    );
    if let Some(secret) = request.client_secret.as_deref() {
        ensure!(
            !secret.is_empty()
                && secret.len() <= MAX_INPUT
                && !secret.chars().any(char::is_control),
            "The registered OAuth client secret is invalid."
        );
        ensure!(
            provider.permits_client_secret(),
            "This provider requires public-client PKCE without a client secret."
        );
    }
    ensure!(provider != Provider::Box || request.client_secret.is_some(),
        "Box requires your explicitly configured confidential OAuth client ID and secret; public PKCE is not assumed.");
    Ok(provider)
}

fn bind_loopback(provider: Provider) -> Result<TcpListener> {
    // Tokio's convenience bind enables SO_REUSEADDR on Unix. This dedicated
    // OAuth listener explicitly disables address reuse instead.
    let socket = TcpSocket::new_v4()
        .map_err(|_| anyhow!("The native OAuth loopback listener could not be opened."))?;
    socket
        .set_reuseaddr(false)
        .map_err(|_| anyhow!("The native OAuth loopback listener could not be secured."))?;
    socket
        .bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            provider.listener_port(),
        )))
        .map_err(|_| {
            if provider.registered_redirect().is_some() {
                anyhow!("The registered OAuth loopback port 53682 is unavailable. No browser was opened; no alternate redirect will be used.")
            } else {
                anyhow!("The native OAuth loopback listener could not be opened.")
            }
        })?;
    socket
        .listen(16)
        .map_err(|_| anyhow!("The native OAuth loopback listener could not be opened."))
}

fn authorization_url(
    provider: Provider,
    request: &OAuthRequest,
    redirect_uri: &str,
    secrets: &FlowSecrets,
) -> Result<Zeroizing<String>> {
    let mut url = Url::parse(provider.authorization_endpoint())
        .map_err(|_| anyhow!("The native OAuth authorization endpoint is invalid."))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &request.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", &secrets.state);
        if !provider.scope().is_empty() {
            query.append_pair("scope", provider.scope());
        }
        if provider.uses_pkce() {
            query
                .append_pair("code_challenge", &secrets.challenge())
                .append_pair("code_challenge_method", "S256");
        }
        match provider {
            Provider::GoogleDrive => {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            }
            Provider::MicrosoftOneDrive => {
                query
                    .append_pair("response_mode", "query")
                    .append_pair("prompt", "select_account");
            }
            Provider::Dropbox => {
                query
                    .append_pair("token_access_type", "offline")
                    .append_pair("prompt", "consent");
            }
            Provider::Box => {}
        }
    }
    Ok(Zeroizing::new(url.into()))
}

fn token_form(
    provider: Provider,
    request: &OAuthRequest,
    redirect_uri: &str,
    verifier: &str,
    code: &str,
) -> Zeroizing<String> {
    let mut form = url::form_urlencoded::Serializer::new(String::with_capacity(1024));
    form.append_pair("grant_type", "authorization_code")
        .append_pair("client_id", &request.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code", code);
    if provider.uses_pkce() {
        form.append_pair("code_verifier", verifier);
    }
    if let Some(secret) = request.client_secret.as_deref() {
        form.append_pair("client_secret", secret);
    }
    if provider == Provider::MicrosoftOneDrive {
        form.append_pair("scope", provider.scope());
    }
    Zeroizing::new(form.finish())
}

/// Open a generated HTTPS authorization URL in the native system browser.
///
/// The caller must first obtain native consent for the exact provider and user
/// registration. The opener must return promptly and must not log URLs/errors.
/// Cancellation by dropping this future closes the listener; started token HTTP
/// work is not retried. See README for caller-owned persistence/health checks.
pub async fn authorize(request: OAuthRequest, open: Opener) -> Result<OAuthTokens> {
    // Unsupported kinds fail before binding a socket or invoking any opener.
    ensure!(validate_request(&request)? != Provider::Box,
        "Box uses its documented confidential-client flow. Explicit native approval and authorize_box_confidential are required; no automatic PKCE downgrade occurs.");
    let transport = HttpsTransport::new()?;
    authorize_with_transport(request, open, &transport, Limits::default()).await
}

/// Box's documented confidential authorization-code flow, selected explicitly
/// after native consent. The user supplies BOTH registration fields; none are
/// embedded/reused from No Land. This does not claim public-client PKCE.
pub async fn authorize_box_confidential(
    request: OAuthRequest,
    open: Opener,
) -> Result<OAuthTokens> {
    ensure!(
        validate_request(&request)? == Provider::Box,
        "The explicitly configured confidential flow is only for Box."
    );
    let transport = HttpsTransport::new()?;
    authorize_with_transport(request, open, &transport, Limits::default()).await
}

/// Refresh directly in native Rust with an allowlisted HTTPS POST, no implicit
/// retry and no stale-token success fallback. Persist via vault CAS before use.
pub async fn refresh(request: OAuthRequest, refresh_token: &str) -> Result<OAuthTokens> {
    validate_request(&request)?;
    ensure!(
        token_valid(refresh_token),
        "The native OAuth refresh token is invalid."
    );
    let transport = HttpsTransport::new()?;
    refresh_with_transport(&request, refresh_token, &transport, TOKEN_TIMEOUT).await
}

async fn refresh_with_transport(
    request: &OAuthRequest,
    refresh_token: &str,
    transport: &dyn HttpTransport,
    timeout: Duration,
) -> Result<OAuthTokens> {
    let provider = validate_request(request)?;
    ensure!(
        token_valid(refresh_token),
        "The native OAuth refresh token is invalid."
    );
    let mut form = url::form_urlencoded::Serializer::new(String::with_capacity(1024));
    form.append_pair("grant_type", "refresh_token")
        .append_pair("client_id", &request.client_id)
        .append_pair("refresh_token", refresh_token);
    if let Some(secret) = request.client_secret.as_deref() {
        form.append_pair("client_secret", secret);
    }
    if provider == Provider::MicrosoftOneDrive {
        form.append_pair("scope", provider.scope());
    }
    let body = Zeroizing::new(form.finish());
    let issued_at = unix_seconds()?;
    let reply = tokio::time::timeout(
        timeout,
        transport.exchange(provider.token_endpoint(), &body),
    )
    .await
    .map_err(|_| anyhow!("The native OAuth refresh timed out."))?
    .map_err(|_| anyhow!("The native OAuth refresh request failed."))?;
    let mut tokens = parse_tokens(provider, reply, issued_at)?;
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_token.to_owned());
    }
    ensure!(
        tokens.expires_at > unix_seconds()?,
        "The refreshed token expired before handoff."
    );
    Ok(tokens)
}

/// Native protocol support, not credential-storage/refresh or provider-health
/// acceptance. The parent ServiceOAuth.supports implementation may delegate here;
/// its separate durable-refresh/vault readiness gate must remain authoritative.
pub fn supports(kind: &str) -> bool {
    Provider::from_kind(kind).is_ok()
}

/// Pure validation for the native OS browser boundary. No browser/account/vault
/// access. Parse the URL rather than trusting a string prefix alone.
pub fn validate_authorization_browser_url(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 16 * 1024 && !value.chars().any(|c| c.is_control() || c.is_whitespace()),
        "Invalid native OAuth authorization URL"
    );
    let url = Url::parse(value).map_err(|_| anyhow!("Invalid native OAuth authorization URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443)
            && matches!(
                url.host_str(),
                Some(
                    "accounts.google.com"
                        | "login.microsoftonline.com"
                        | "www.dropbox.com"
                        | "account.box.com"
                )
            ),
        "Native OAuth authorization origin is not allowed"
    );
    // The generator emits canonical URLs. Do not let the OS and URL parser
    // disagree about backslashes, encoded authorities, ports or normalization.
    ensure!(
        url.as_str() == value && !value.contains('\\'),
        "Native OAuth authorization URL is not canonical"
    );
    Ok(())
}

async fn authorize_with_transport(
    request: OAuthRequest,
    open: Opener,
    transport: &dyn HttpTransport,
    limits: Limits,
) -> Result<OAuthTokens> {
    let deadline = Instant::now() + limits.total;
    tokio::time::timeout_at(deadline, async {
        let provider = validate_request(&request)?;
        let listener = bind_loopback(provider)?;
        let address = listener
            .local_addr()
            .map_err(|_| anyhow!("The native OAuth loopback address is unavailable."))?;
        ensure!(
            address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                && address.port() != 0,
            "The native OAuth listener is not confined to loopback."
        );
        let secrets = FlowSecrets::new(provider)?;
        let host = format!("127.0.0.1:{}", address.port());
        let redirect_uri =
            Zeroizing::new(format!("http://{host}{}", secrets.callback_path.as_str()));
        if let Some(registered) = provider.registered_redirect() {
            ensure!(
                redirect_uri.as_str() == registered,
                "The native OAuth callback does not match the registered loopback redirect."
            );
        }
        let url = authorization_url(provider, &request, &redirect_uri, &secrets)?;

        // Never run a potentially blocking OS opener on the async executor. Its
        // errors (or panic payloads) must not cross this secret-handling boundary.
        // The caller's opener must return promptly; a running blocking OS call
        // cannot be forcibly interrupted by Rust when the outer deadline expires.
        let opening = tokio::task::spawn_blocking(move || open(url.as_str()).is_ok());
        let opened = opening
            .await
            .map_err(|_| anyhow!("The native authorization browser could not be opened."))?;
        ensure!(
            opened,
            "The native authorization browser could not be opened."
        );

        let expected = callback::Expected {
            path: &secrets.callback_path,
            host: &host,
            state: &secrets.state,
        };
        let mut rejected = 0;
        let code = loop {
            let (mut stream, peer) = listener
                .accept()
                .await
                .map_err(|_| anyhow!("The native OAuth callback listener failed."))?;
            if !peer.ip().is_loopback() {
                rejected += 1;
            } else {
                let connection_deadline = deadline.min(Instant::now() + limits.connection);
                let received = tokio::time::timeout_at(connection_deadline, async {
                    let result = callback::read(&mut stream, &expected).await;
                    let page = match &result {
                        Ok(callback::Callback::Code(_)) => callback::Page::Received,
                        Ok(callback::Callback::Denied) => callback::Page::Denied,
                        Err(_) => callback::Page::Rejected,
                    };
                    callback::write(&mut stream, page).await;
                    result
                })
                .await;
                match received {
                    Ok(Ok(callback::Callback::Code(code))) => break code,
                    Ok(Ok(callback::Callback::Denied)) => {
                        bail!("OAuth authorization was denied or failed. No account was connected.")
                    }
                    _ => rejected += 1,
                }
            }
            ensure!(
                rejected < MAX_UNEXPECTED_CALLBACKS,
                "Native OAuth stopped after too many unexpected callbacks."
            );
        };
        // Accept one authenticated callback only. No second code can be submitted
        // during token exchange, and the loopback port is closed immediately.
        drop(listener);
        let form = token_form(provider, &request, &redirect_uri, &secrets.verifier, &code);
        let issued_at = unix_seconds()?;
        let reply = tokio::time::timeout(
            limits.token,
            transport.exchange(provider.token_endpoint(), &form),
        )
        .await
        .map_err(|_| anyhow!("The native OAuth token exchange timed out."))?
        .map_err(|_| anyhow!("The native OAuth token exchange failed."))?;
        let tokens = parse_tokens(provider, reply, issued_at)?;
        ensure!(
            tokens.expires_at > unix_seconds()?,
            "The OAuth token expired before authorization completed."
        );
        Ok(tokens)
    })
    .await
    .map_err(|_| anyhow!("Native OAuth authorization timed out. Start a new sign-in."))?
}

fn unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("The system clock is not valid for native OAuth."))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| anyhow!("The system clock is not valid for native OAuth."))
}

struct SecretString(Zeroizing<String>);
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
#[derive(Deserialize)]
struct WireTokens {
    access_token: Option<SecretString>,
    refresh_token: Option<SecretString>,
    token_type: Option<SecretString>,
    expires_in: Option<u64>,
    scope: Option<SecretString>,
    error: Option<SecretString>,
}

fn token_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64 * 1024
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn parse_tokens(provider: Provider, reply: TokenReply, issued_at: i64) -> Result<OAuthTokens> {
    ensure!(
        reply.body.len() <= MAX_TOKEN_BODY,
        "The OAuth token response exceeded its size limit."
    );
    // Do not parse/reflect a provider's error description or raw failed body.
    ensure!(
        reply.status == 200,
        "The OAuth provider rejected the token exchange."
    );
    let mut wire: WireTokens = serde_json::from_slice(&reply.body)
        .map_err(|_| anyhow!("The OAuth token response was invalid."))?;
    ensure!(
        wire.error.is_none(),
        "The OAuth provider rejected the token exchange."
    );
    let token_type = wire
        .token_type
        .as_ref()
        .ok_or_else(|| anyhow!("The OAuth token type was not provided."))?;
    ensure!(
        token_type.0.eq_ignore_ascii_case("bearer"),
        "The OAuth token type is not supported."
    );
    let lifetime = wire
        .expires_in
        .filter(|value| *value > 0 && *value <= 365 * 24 * 60 * 60)
        .ok_or_else(|| anyhow!("The OAuth token lifetime is invalid."))?;
    if let Some(scope) = &wire.scope {
        for required in provider.required_scopes() {
            ensure!(
                scope.0.split_ascii_whitespace().any(|granted| {
                    let granted = if provider == Provider::MicrosoftOneDrive {
                        granted
                            .strip_prefix("https://graph.microsoft.com/")
                            .unwrap_or(granted)
                    } else {
                        granted
                    };
                    granted == *required
                }),
                "The OAuth provider did not grant the required file permissions."
            );
        }
    }
    let expires_at = issued_at
        .checked_add(lifetime as i64)
        .ok_or_else(|| anyhow!("The OAuth token expiry is invalid."))?;
    let mut access = wire
        .access_token
        .take()
        .ok_or_else(|| anyhow!("The OAuth provider did not return an access token."))?;
    ensure!(token_valid(&access.0), "The OAuth access token is invalid.");
    let refresh = if let Some(mut refresh) = wire.refresh_token.take() {
        ensure!(
            token_valid(&refresh.0),
            "The OAuth refresh token is invalid."
        );
        Some(std::mem::take(&mut *refresh.0))
    } else {
        None
    };
    Ok(OAuthTokens {
        access_token: std::mem::take(&mut *access.0),
        refresh_token: refresh,
        expires_at,
    })
}

#[cfg(test)]
mod tests;
