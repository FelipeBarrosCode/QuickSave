// SPDX-License-Identifier: GPL-3.0-only
//! Provider/session wire formats are produced by the active No Land adapter.

use crate::{bounded_json, model::ProviderRecord, validate_text, zeroize_json};
use anyhow::{bail, ensure, Context, Result};
use noland_rclone_adapter::{
    session_from_input, AdapterCredential, AdapterInput, ProviderKind, TokenMode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub const ALL_PROVIDER_KINDS: [ProviderKind; 14] = [
    ProviderKind::AmazonS3,
    ProviderKind::BackblazeB2,
    ProviderKind::CloudflareR2,
    ProviderKind::Wasabi,
    ProviderKind::DigitalOceanSpaces,
    ProviderKind::GenericS3,
    ProviderKind::GoogleDrive,
    ProviderKind::GoogleCloudStorage,
    ProviderKind::MicrosoftOneDrive,
    ProviderKind::Dropbox,
    ProviderKind::Box,
    ProviderKind::AzureBlob,
    ProviderKind::Sftp,
    ProviderKind::Webdav,
];

const PUBLIC_SCOPE_FIELDS: &[&str] = &[
    "endpoint",
    "url",
    "host",
    "port",
    "host_keys",
    "remote_path",
    "folder",
    "drive_id",
    "drive_type",
    "region",
    "account_id",
    "bucket",
    "space_name",
    "container",
];

pub(crate) fn validate_public_scope(scope: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        scope.len() <= PUBLIC_SCOPE_FIELDS.len(),
        "public provider scope has too many fields"
    );
    let mut bytes = 0usize;
    for (key, value) in scope {
        ensure!(
            PUBLIC_SCOPE_FIELDS.contains(&key.as_str()),
            "public provider scope contains a forbidden field"
        );
        ensure!(
            value.len() <= 16 * 1024 && !value.chars().any(char::is_control),
            "public provider scope value is invalid or oversized"
        );
        bytes = bytes
            .checked_add(key.len() + value.len())
            .context("public provider scope length overflow")?;
        ensure!(
            bytes <= 64 * 1024,
            "public provider scope exceeds its bounded size"
        );
        if key == "endpoint" || key == "url" {
            ensure!(
                value.is_empty() || (value.starts_with("https://") && !value.contains(['@', '?', '#'])),
                "public provider endpoint must be HTTPS without credentials, query parameters, or fragments"
            );
        }
    }
    Ok(())
}

/// An explicit allowlist, never a scrubbed copy of arbitrary provider fields.
/// Client IDs/secrets, tokens, passwords and credential payloads stay private.
pub(crate) fn public_scope(fields: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let projection = fields
        .iter()
        .filter(|(key, _)| PUBLIC_SCOPE_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    validate_public_scope(&projection)?;
    Ok(projection)
}

/// This type is never exported. Serialization is exclusively for the OS vault.
/// The non-secret binding prevents editing state.json to redirect credentials,
/// widen a storage root, switch encryption keys, or remove read-only policy.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretProfile {
    pub version: u32,
    /// Vault-only monotonic CAS. Never put this or credential material in state.json.
    #[serde(default)]
    pub credential_generation: u64,
    #[serde(default)]
    pub authority_revision: u64,
    pub provider_id: String,
    pub kind: String,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub read_only: bool,
    pub repository_key_ref: String,
    pub credentials: Value,
    pub provider_fields: BTreeMap<String, String>,
}

impl Drop for SecretProfile {
    fn drop(&mut self) {
        zeroize_json(&mut self.credentials);
        for value in self.provider_fields.values_mut() {
            value.zeroize();
        }
    }
}

impl SecretProfile {
    pub fn verify_binding(&self, provider: &ProviderRecord) -> Result<()> {
        ensure!(
            self.version == 1
                && self.provider_id == provider.id
                && self.kind == provider.kind
                && self.bucket == provider.bucket
                && self.prefix == provider.prefix
                && self.read_only == provider.read_only
                && self.repository_key_ref == provider.repository_key_ref,
            "provider settings do not match native-vault authority; reconnect or reimport"
        );
        ensure!(
            self.authority_revision == provider.authority_revision,
            "provider reauthorization authority differs from the native vault"
        );
        ensure!(
            provider.public_scope == public_scope(&self.provider_fields)?,
            "public provider destination scope does not match native-vault authority; a native-consented reconnect is required"
        );
        Ok(())
    }

    pub fn session(&self, operation_id: &str) -> Result<Value> {
        let kind = ProviderKind::parse(&self.kind).context("unknown provider kind")?;
        ensure!(
            kind != ProviderKind::Local,
            "local adapter is not a production provider"
        );
        validate_credentials(kind, &self.credentials)?;
        validate_fields(kind, &self.provider_fields, false)?;
        let credential: AdapterCredential = serde_json::from_value(self.credentials.clone())
            .map_err(|_| anyhow::anyhow!("invalid provider credential format"))?;
        let input = GuardedInput(AdapterInput {
            provider: kind,
            remote_name: format!("quicksave_{}", self.provider_id.replace('-', "_")),
            credentials: credential,
            fields: self.provider_fields.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
        });
        // Refresh tokens remain operation-scoped, never persistent/global config.
        let mut session = session_from_input(&input.0, operation_id, TokenMode::Operation)
            .map_err(|_| {
                anyhow::anyhow!(
                    "provider session cannot be constructed from its credential and field schema"
                )
            })?;
        if let Some(value) = self.provider_fields.get("upload_concurrency") {
            session.upload_concurrency = Some(
                value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid native upload concurrency"))?,
            );
        }
        let result = serde_json::to_value(&session)
            .map(|mut value| {
                // Private facade metadata. Parent reads it before deserializing the
                // unchanged No Land session wire type and passes performance_mode
                // into the source operation, retaining original automatic tuning.
                value["native_transfer_policy"] = json!({
                        "performanceProfile":self.provider_fields.get("performance_profile"),
                        "uploadConcurrency":session.upload_concurrency,
                        "downloadConcurrency":self.provider_fields.get("download_concurrency")
                            .and_then(|value| value.parse::<usize>().ok()),
                });
                value["native_authority_revision"] = json!(self.authority_revision);
                value
            })
            .map_err(|_| anyhow::anyhow!("provider session serialization failed"));
        session.config_ini.zeroize();
        result
    }
}

struct GuardedInput(AdapterInput);
impl Drop for GuardedInput {
    fn drop(&mut self) {
        match &mut self.0.credentials {
            AdapterCredential::S3 {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                access_key_id.zeroize();
                secret_access_key.zeroize();
                session_token.zeroize();
            }
            AdapterCredential::BackblazeB2 {
                key_id,
                application_key,
            } => {
                key_id.zeroize();
                application_key.zeroize();
            }
            AdapterCredential::OAuth2 {
                access_token,
                refresh_token,
                expires_at,
            } => {
                access_token.zeroize();
                refresh_token.zeroize();
                expires_at.zeroize();
            }
            AdapterCredential::UsernamePassword { username, password } => {
                username.zeroize();
                password.zeroize();
            }
            AdapterCredential::SshKey {
                username,
                private_key,
                passphrase,
            } => {
                username.zeroize();
                private_key.zeroize();
                passphrase.zeroize();
            }
            AdapterCredential::ServiceAccount { json } => json.zeroize(),
            AdapterCredential::LocalPath { path } => path.zeroize(),
        }
        for value in self.0.fields.values_mut() {
            value.zeroize();
        }
    }
}

pub(crate) fn parse_kind(value: &str) -> Result<ProviderKind> {
    // The portable adapter's canonical spellings predate these two desktop
    // serde snake_case names; both wire forms refer to the exact same kinds.
    let kind = match value {
        "digital_ocean_spaces" => Some(ProviderKind::DigitalOceanSpaces),
        "microsoft_one_drive" => Some(ProviderKind::MicrosoftOneDrive),
        other => ProviderKind::parse(other),
    }
    .context("unsupported storage provider kind")?;
    ensure!(
        kind != ProviderKind::Local,
        "local test remotes cannot be connected as providers"
    );
    Ok(kind)
}

pub(crate) fn fields_from_value(value: Option<&Value>) -> Result<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    bounded_json(value, 1024 * 1024)?;
    let object = value
        .as_object()
        .context("provider fields must be an object")?;
    ensure!(object.len() <= 64, "too many provider fields");
    object
        .iter()
        .map(|(key, value)| {
            validate_text(key, 128, "provider field name")?;
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                _ => bail!("provider fields must be strings, numbers, or booleans"),
            };
            ensure!(
                value.len() <= 512 * 1024 && !value.contains('\0'),
                "provider field exceeds limit"
            );
            Ok((key.clone(), value))
        })
        .collect()
}

pub(crate) fn validate_fields(
    kind: ProviderKind,
    fields: &BTreeMap<String, String>,
    new_connection: bool,
) -> Result<()> {
    let allowed: &[&str] = match kind {
        ProviderKind::AmazonS3 => &["region"],
        ProviderKind::BackblazeB2 => &[],
        ProviderKind::CloudflareR2 => &["account_id"],
        ProviderKind::Wasabi => &["region", "endpoint"],
        ProviderKind::DigitalOceanSpaces => &["region"],
        ProviderKind::GenericS3 => &["region", "endpoint", "force_path_style"],
        ProviderKind::GoogleDrive => &["client_id", "client_secret", "folder"],
        ProviderKind::MicrosoftOneDrive => &[
            "client_id",
            "client_secret",
            "drive_id",
            "drive_type",
            "folder",
        ],
        ProviderKind::Dropbox | ProviderKind::Box => &["client_id", "client_secret", "folder"],
        ProviderKind::GoogleCloudStorage => &[],
        ProviderKind::AzureBlob => &[],
        ProviderKind::Sftp => &["host", "port", "host_keys", "remote_path"],
        ProviderKind::Webdav => &["url", "vendor", "remote_path"],
        ProviderKind::Local => bail!("local adapter is test-only"),
    };
    ensure!(fields.len() <= 64, "too many provider fields");
    for (key, value) in fields {
        // Old No Land profiles may carry these root/performance fields. They are
        // consumed by its adapter, not arbitrary rclone flags or local paths.
        ensure!(
            allowed.contains(&key.as_str())
                || [
                    "bucket",
                    "space_name",
                    "container",
                    "upload_concurrency",
                    "download_concurrency",
                    "performance_profile"
                ]
                .contains(&key.as_str()),
            "provider field is outside the approved schema"
        );
        ensure!(
            value.len() <= 512 * 1024 && !value.contains('\0'),
            "provider field exceeds limit"
        );
        ensure!(
            !value.contains(['\r', '\n']),
            "line breaks are not allowed in provider configuration"
        );
    }
    for (key, max) in [
        (
            "upload_concurrency",
            noland_rclone_adapter::ProviderCapabilities::for_provider(kind).max_upload_concurrency,
        ),
        (
            "download_concurrency",
            noland_rclone_adapter::ProviderCapabilities::for_provider(kind)
                .max_download_concurrency,
        ),
    ] {
        if let Some(value) = fields.get(key) {
            let value: usize = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid native transfer concurrency"))?;
            ensure!(
                value > 0 && value <= max,
                "native transfer concurrency exceeds provider capability"
            );
        }
    }
    if let Some(profile) = fields.get("performance_profile") {
        ensure!(
            matches!(
                profile.as_str(),
                "balanced" | "throughput" | "gameplay_safe"
            ),
            "native performance profile is invalid"
        );
    }
    let required: &[&str] = match kind {
        ProviderKind::CloudflareR2 => &["account_id"],
        ProviderKind::DigitalOceanSpaces => &["region"],
        ProviderKind::GenericS3 => &["endpoint"],
        ProviderKind::MicrosoftOneDrive => &["drive_id", "drive_type"],
        ProviderKind::Sftp => &["host", "host_keys"],
        ProviderKind::Webdav => &["url"],
        _ => &[],
    };
    for key in required {
        ensure!(
            fields
                .get(*key)
                .is_some_and(|value| !value.trim().is_empty()),
            "required provider configuration field is missing"
        );
    }
    if kind.is_oauth() && new_connection {
        ensure!(
            fields
                .get("client_id")
                .is_some_and(|value| !value.trim().is_empty()),
            "OAuth requires an explicitly configured registered client ID"
        );
        if kind == ProviderKind::Box {
            ensure!(
                fields
                    .get("client_secret")
                    .is_some_and(|value| !value.trim().is_empty()),
                "Box requires an explicitly configured confidential OAuth client secret"
            );
        }
    }
    if let Some(port) = fields.get("port") {
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid SFTP port"))?;
        ensure!(port != 0, "invalid SFTP port");
    }
    if let Some(drive_type) = fields.get("drive_type") {
        ensure!(
            ["personal", "business", "documentLibrary"].contains(&drive_type.as_str()),
            "invalid OneDrive drive type"
        );
    }
    for key in ["endpoint", "url"] {
        if let Some(value) = fields.get(key) {
            ensure!(
                value.starts_with("https://") && !value.contains('@'),
                "provider URL must use HTTPS without embedded credentials"
            );
        }
    }
    if let Some(account) = fields.get("account_id") {
        ensure!(
            !account.is_empty()
                && account.len() <= 128
                && account
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid Cloudflare account ID"
        );
    }
    Ok(())
}

pub(crate) fn validate_credentials(kind: ProviderKind, value: &Value) -> Result<()> {
    bounded_json(value, 1024 * 1024)?;
    let object = value
        .as_object()
        .context("credentials must use the No Land type/value shape")?;
    ensure!(
        object.len() == 2,
        "credentials must contain only type and value"
    );
    let credential_type = object
        .get("type")
        .and_then(Value::as_str)
        .context("credential type missing")?;
    let fields = object
        .get("value")
        .and_then(Value::as_object)
        .context("credential value missing")?;
    let allowed: &[&str] = match credential_type {
        "s3" => &["access_key_id", "secret_access_key", "session_token"],
        "backblaze_b2" => &["key_id", "application_key"],
        "o_auth2" => &["access_token", "refresh_token", "expires_at"],
        "username_password" => &["username", "password"],
        "ssh_key" => &["username", "private_key", "passphrase"],
        "service_account" => &["json"],
        _ => bail!("unsupported credential type; use the exact No Land serde shape"),
    };
    ensure!(
        fields.keys().all(|key| allowed.contains(&key.as_str())),
        "unknown credential field"
    );
    let compatible = match kind {
        ProviderKind::AmazonS3
        | ProviderKind::CloudflareR2
        | ProviderKind::Wasabi
        | ProviderKind::DigitalOceanSpaces
        | ProviderKind::GenericS3 => credential_type == "s3",
        ProviderKind::BackblazeB2 => credential_type == "backblaze_b2",
        ProviderKind::GoogleDrive
        | ProviderKind::MicrosoftOneDrive
        | ProviderKind::Dropbox
        | ProviderKind::Box => credential_type == "o_auth2",
        ProviderKind::GoogleCloudStorage => credential_type == "service_account",
        ProviderKind::AzureBlob | ProviderKind::Webdav => credential_type == "username_password",
        ProviderKind::Sftp => {
            credential_type == "username_password" || credential_type == "ssh_key"
        }
        ProviderKind::Local => false,
    };
    ensure!(compatible, "provider and credential type do not match");
    for key in allowed {
        if ["session_token", "refresh_token", "passphrase"].contains(key) {
            if let Some(value) = fields.get(*key).filter(|value| !value.is_null()) {
                ensure!(
                    value.is_string(),
                    "optional credential field must be a string"
                );
            }
        } else if *key == "expires_at" {
            ensure!(
                fields
                    .get(*key)
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value > 0),
                "OAuth expiry must be a valid Unix timestamp"
            );
        } else {
            let value = fields
                .get(*key)
                .and_then(Value::as_str)
                .context("required credential field missing")?;
            ensure!(
                !value.trim().is_empty(),
                "required credential field is empty"
            );
            ensure!(!value.contains('\0'), "credential contains an invalid NUL");
            if *key != "private_key" && *key != "json" {
                ensure!(
                    !value.contains(['\r', '\n']),
                    "credential contains an invalid line break"
                );
            }
            if *key == "json" {
                let mut document: Value = serde_json::from_str(value)
                    .map_err(|_| anyhow::anyhow!("service account JSON is invalid"))?;
                let valid = document.get("type").and_then(Value::as_str) == Some("service_account")
                    && document
                        .get("private_key")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && document
                        .get("client_email")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty());
                zeroize_json(&mut document);
                ensure!(valid, "service account JSON is missing required fields");
            }
        }
    }
    Ok(())
}

fn field(key: &str, label: &str, kind: &str, required: bool, credential: bool) -> Value {
    json!({"key":key,"label":label,"fieldType":kind,"type":kind,"required":required,"credential":credential})
}

pub fn provider_definitions() -> Value {
    Value::Array(ALL_PROVIDER_KINDS.iter().map(|kind| {
        let mut fields = Vec::new();
        let credential_type = match kind {
            ProviderKind::AmazonS3 | ProviderKind::CloudflareR2 | ProviderKind::Wasabi
                | ProviderKind::DigitalOceanSpaces | ProviderKind::GenericS3 => {
                fields.extend([
                    field("access_key_id", "Access key ID", "text", true, true),
                    field("secret_access_key", "Secret access key", "password", true, true),
                    field("session_token", "Session token", "password", false, true),
                ]); "s3"
            }
            ProviderKind::BackblazeB2 => {
                fields.extend([field("key_id", "Application key ID", "text", true, true),field("application_key", "Application key", "password", true, true)]);
                "backblaze_b2"
            }
            ProviderKind::GoogleDrive | ProviderKind::MicrosoftOneDrive | ProviderKind::Dropbox | ProviderKind::Box => {
                fields.extend([
                    field("client_id", "Registered OAuth client ID", "text", true, false),
                    field("client_secret", if *kind == ProviderKind::Box {
                        "Registered confidential OAuth client secret"
                    } else { "OAuth client secret (if required)" }, "password", *kind == ProviderKind::Box, false),
                ]); "o_auth2"
            }
            ProviderKind::GoogleCloudStorage => {
                fields.push(field("json", "Service account JSON", "password", true, true)); "service_account"
            }
            ProviderKind::AzureBlob => {
                fields.extend([field("username", "Storage account name", "text", true, true),field("password", "Storage account key", "password", true, true)]);
                "username_password"
            }
            ProviderKind::Sftp | ProviderKind::Webdav => {
                fields.extend([field("username", "Username", "text", true, true),field("password", "Password", "password", true, true)]);
                "username_password"
            }
            ProviderKind::Local => unreachable!("not in production provider list"),
        };
        if kind.uses_bucket_root() { fields.push(field("bucket", if *kind == ProviderKind::AzureBlob { "Container" } else { "Bucket" }, "text", true, false)); }
        fields.push(field("prefix", "Folder / prefix", "text", false, false));
        match kind {
            ProviderKind::AmazonS3 | ProviderKind::Wasabi | ProviderKind::DigitalOceanSpaces | ProviderKind::GenericS3 => {
                fields.push(field("region", "Region", "text", *kind == ProviderKind::DigitalOceanSpaces, false));
                if matches!(kind, ProviderKind::Wasabi | ProviderKind::GenericS3) { fields.push(field("endpoint", "HTTPS endpoint", "text", *kind == ProviderKind::GenericS3, false)); }
                if *kind == ProviderKind::GenericS3 { fields.push(field("force_path_style", "Force path style", "toggle", false, false)); }
            }
            ProviderKind::CloudflareR2 => fields.push(field("account_id", "Cloudflare account ID", "text", true, false)),
            // Concrete drive IDs/types are discovered in native Rust following
            // authorization and selected with a native chooser if necessary.
            ProviderKind::MicrosoftOneDrive => {},
            ProviderKind::Sftp => fields.extend([
                field("host", "Host", "text", true, false), field("port", "Port", "number", false, false),
                field("host_keys", "Trusted SSH host keys", "text", true, false),
                field("remote_path", "Remote path", "text", false, false),
            ]),
            ProviderKind::Webdav => fields.extend([field("url", "WebDAV HTTPS URL", "text", true, false),field("vendor", "Vendor", "text", false, false)]),
            _ => {}
        }
        json!({
            "id":kind.as_str(), "kind":kind.as_str(), "provider":kind.as_str(),
            "label":kind.label(), "isOauth":kind.is_oauth(), "oauth":kind.is_oauth(),
            "oauthConfigured":false, "credentialType":credential_type, "fields":fields,
            "nativeDriveDiscovery":*kind == ProviderKind::MicrosoftOneDrive,
            "oauthFlow":if *kind == ProviderKind::Box { "explicit_confidential_authorization_code" }
                else if kind.is_oauth() { "public_pkce_s256" } else { "none" },
            "credentialAlternatives":if *kind == ProviderKind::Sftp { json!(["username_password","ssh_key"]) } else { json!([credential_type]) },
            "category":if kind.is_oauth() {"cloud-drives"} else if kind.uses_bucket_root() {"object-storage"} else {"enterprise-and-self-hosted"},
        })
    }).collect())
}
