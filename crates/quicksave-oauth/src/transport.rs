// SPDX-License-Identifier: GPL-3.0-only
//! HTTPS-only, allowlisted token transport. Injection is private to crate tests.

use crate::providers::Provider;
use anyhow::{anyhow, bail, Result};
use std::{future::Future, pin::Pin, time::Duration};
use zeroize::Zeroizing;

pub(crate) const MAX_TOKEN_BODY: usize = 256 * 1024;
pub(crate) const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct TokenReply {
    pub(crate) status: u16,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

pub(crate) trait HttpTransport: Send + Sync {
    fn exchange<'a>(
        &'a self,
        endpoint: &'static str,
        body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>>;
    fn graph<'a>(
        &'a self,
        _endpoint: &'a str,
        _bearer: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
        Box::pin(async { bail!("Native OneDrive metadata transport is unavailable.") })
    }
}

pub(crate) struct HttpsTransport {
    client: reqwest::Client,
}

impl HttpsTransport {
    pub(crate) fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connection_verbose(false)
            .connect_timeout(Duration::from_secs(10))
            .timeout(TOKEN_TIMEOUT)
            .pool_max_idle_per_host(0)
            .user_agent("QuickSave-native-oauth/0.1")
            .build()
            .map_err(|_| anyhow!("The native OAuth HTTPS client could not be initialized."))?;
        Ok(Self { client })
    }
}

impl HttpTransport for HttpsTransport {
    fn exchange<'a>(
        &'a self,
        endpoint: &'static str,
        body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
        Box::pin(async move {
            if !Provider::is_static_token_endpoint(endpoint) {
                bail!("The OAuth token endpoint is not allowed.");
            }
            let mut response = self
                .client
                .post(endpoint)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CACHE_CONTROL, "no-store")
                .body(body.as_bytes().to_vec())
                .send()
                .await
                .map_err(|_| anyhow!("The OAuth token HTTPS request failed."))?;
            let status = response.status().as_u16();
            if response
                .content_length()
                .is_some_and(|length| length > MAX_TOKEN_BODY as u64)
            {
                bail!("The OAuth token response exceeded its size limit.");
            }
            let mut body = Zeroizing::new(Vec::with_capacity(4096));
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| anyhow!("The OAuth token response could not be read."))?
            {
                if chunk.len() > MAX_TOKEN_BODY - body.len() {
                    bail!("The OAuth token response exceeded its size limit.");
                }
                body.extend_from_slice(&chunk);
            }
            Ok(TokenReply { status, body })
        })
    }

    fn graph<'a>(
        &'a self,
        endpoint: &'a str,
        bearer: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenReply>> + Send + 'a>> {
        Box::pin(async move {
            crate::onedrive::validate_endpoint(endpoint)?;
            let mut response = self
                .client
                .get(endpoint)
                .bearer_auth(bearer)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CACHE_CONTROL, "no-store")
                .send()
                .await
                .map_err(|_| anyhow!("The native OneDrive metadata request failed."))?;
            let status = response.status().as_u16();
            if response
                .content_length()
                .is_some_and(|length| length > MAX_TOKEN_BODY as u64)
            {
                bail!("The native OneDrive metadata response exceeded its size limit.");
            }
            let mut body = Zeroizing::new(Vec::with_capacity(4096));
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| anyhow!("The native OneDrive metadata response could not be read."))?
            {
                if chunk.len() > MAX_TOKEN_BODY - body.len() {
                    bail!("The native OneDrive metadata response exceeded its size limit.");
                }
                body.extend_from_slice(&chunk);
            }
            Ok(TokenReply { status, body })
        })
    }
}
