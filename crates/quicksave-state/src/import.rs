// SPDX-License-Identifier: GPL-3.0-only
//! Explicit runtime-only No Land import. Never calls its migrating vault getter.

use crate::{
    bounded_json, decode_key,
    provider::{fields_from_value, parse_kind, validate_credentials, validate_fields},
    validate_id, validate_text, zeroize_json, CredentialVault,
};
use anyhow::{bail, ensure, Context, Result};
use quicksave_platform::{FileStamp, RootIdentity, SafeRoot};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub const NOLAND_DOCUMENT_SERVICE: &str = "noland-connect.desktop-secrets.v2";
pub const NOLAND_DOCUMENT_ACCOUNT: &str = "vault";
pub const NOLAND_STATE_SERVICE: &str = "noland-connect.state-secrets.v1.desktop";
const NOLAND_LEGACY_SERVICE: &str = "noland-connect.state-secrets.v1";
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceReference {
    id: String,
    display_name: String,
    #[serde(default)]
    provider_label: String,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceProfileSecret {
    #[serde(default)]
    credentials: Value,
    #[serde(default)]
    provider_fields: BTreeMap<String, String>,
    #[serde(default)]
    repository_key_hex: String,
}

impl Drop for SourceProfileSecret {
    fn drop(&mut self) {
        zeroize_json(&mut self.credentials);
        for value in self.provider_fields.values_mut() {
            value.zeroize();
        }
        self.repository_key_hex.zeroize();
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceSecrets {
    #[serde(default)]
    profiles: BTreeMap<String, SourceProfileSecret>,
    #[serde(default)]
    repository_key_hex: String,
    // No oauthSessions, app passwords, SSH, Vast or network state projection.
}

impl Drop for SourceSecrets {
    fn drop(&mut self) {
        self.repository_key_hex.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceProjection {
    #[serde(default)]
    shared_storage_profiles: Vec<SourceReference>,
    #[serde(default)]
    shared_storage_credentials: SourceSecrets,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovedImportFile {
    path: String,
    kind: String,
    identity: RootIdentity,
    // FileStamp's wire format deliberately remains the platform's snake_case.
    stamp: FileStamp,
    parent_identity: RootIdentity,
}

fn approved_import_file(
    path: &Path,
    handoff: Option<&Value>,
) -> Result<Option<ApprovedImportFile>> {
    let Some(handoff) = handoff else {
        // Compatibility for trusted native standalone callers/tests. The gateway
        // always provides its server-held proof; presence never permits fallback.
        return Ok(None);
    };
    let entries = handoff
        .as_array()
        .context("native import path handoff must be an array")?;
    ensure!(
        entries.len() <= 4096,
        "native import path handoff exceeds limit"
    );
    let path = path.to_str().context("native import path must be UTF-8")?;
    let mut matching = entries
        .iter()
        .filter(|entry| entry.get("path").and_then(Value::as_str) == Some(path));
    let entry = matching
        .next()
        .context("native import handoff has no matching selected file")?;
    ensure!(
        matching.next().is_none(),
        "native import handoff has duplicate matching paths"
    );
    let approved: ApprovedImportFile = serde_json::from_value(entry.clone())
        .map_err(|_| anyhow::anyhow!("native import file handoff is invalid"))?;
    ensure!(
        approved.path == path && Path::new(&approved.path).is_absolute() && approved.kind == "file",
        "native import handoff does not approve this exact file"
    );
    ensure!(
        approved.identity.device == approved.stamp.device
            && approved.identity.file_id == approved.stamp.file_id,
        "native import handoff contains inconsistent file identities"
    );
    Ok(Some(approved))
}

fn read_projection(path: &Path, handoff: Option<&Value>) -> Result<SourceProjection> {
    ensure!(
        path.is_absolute(),
        "choose an absolute No Land state file path"
    );
    let parent = path.parent().context("No Land state path has no parent")?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("invalid state filename")?;
    // Select/validate the private proof before opening any new source path.
    let approved = approved_import_file(path, handoff)?;
    let root = SafeRoot::open(parent)?;
    if let Some(approved) = &approved {
        ensure!(
            root.identity()? == approved.parent_identity,
            "native-approved No Land state parent identity changed"
        );
    }
    let (mut file, stamp) = root.read_file(filename)?;
    if let Some(approved) = &approved {
        // This is before read_to_end, JSON parsing, and every source-vault access.
        // Never silently repin a different file at the gateway-approved name.
        ensure!(
            stamp == approved.stamp
                && stamp.device == approved.identity.device
                && stamp.file_id == approved.identity.file_id,
            "native-approved No Land state file identity or contents changed"
        );
    }
    ensure!(
        stamp.size <= MAX_SOURCE_BYTES as u64,
        "selected No Land state exceeds 8 MiB"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_SOURCE_BYTES,
        "selected No Land state exceeds 8 MiB"
    );
    // Detect changes during the read before interpreting any source JSON.
    root.verify_file(filename, &stamp)?;
    // Deserialize an allowlisted projection instead of retaining unrelated secrets.
    let projection: SourceProjection = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("selected No Land state has an invalid storage projection"))?;
    ensure!(
        projection.shared_storage_profiles.len() <= 256,
        "too many source storage profiles"
    );
    ensure!(
        projection.shared_storage_credentials.profiles.len() <= 256,
        "too many source profile credentials"
    );
    let mut ids = BTreeSet::new();
    for profile in &projection.shared_storage_profiles {
        validate_id(&profile.id)?;
        validate_text(&profile.display_name, 512, "source profile name")?;
        ensure!(ids.insert(&profile.id), "duplicate source profile ID");
    }
    Ok(projection)
}

#[derive(Default, Deserialize)]
struct SourceVaultDocument {
    entries: BTreeMap<String, Option<String>>,
}

impl Drop for SourceVaultDocument {
    fn drop(&mut self) {
        for value in self.entries.values_mut().flatten() {
            value.zeroize();
        }
    }
}

enum Lookup {
    Present(Zeroizing<String>),
    Deleted,
    Missing,
}

struct SourceReader<'a> {
    vault: &'a dyn CredentialVault,
    document: SourceVaultDocument,
}

impl<'a> SourceReader<'a> {
    fn open(vault: &'a dyn CredentialVault) -> Result<Self> {
        let document = match vault.read(NOLAND_DOCUMENT_SERVICE, NOLAND_DOCUMENT_ACCOUNT)? {
            Some(serialized) => {
                ensure!(
                    serialized.len() <= MAX_SOURCE_BYTES,
                    "source protected vault exceeds limit"
                );
                let document: SourceVaultDocument =
                    serde_json::from_str(&serialized).map_err(|_| {
                        anyhow::anyhow!(
                            "No Land protected vault is invalid; no legacy fallback attempted"
                        )
                    })?;
                ensure!(
                    document.entries.len() <= 100_000,
                    "source vault entry count exceeds limit"
                );
                document
            }
            None => SourceVaultDocument::default(),
        };
        Ok(Self { vault, document })
    }

    fn lookup_in(&self, service: &str, account: &str) -> Result<Lookup> {
        let key = serde_json::to_string(&(service, account))?;
        if let Some(value) = self.document.entries.get(&key) {
            return Ok(match value {
                Some(value) => Lookup::Present(Zeroizing::new(value.clone())),
                None => Lookup::Deleted,
            });
        }
        // Read-only legacy fallback ONLY for an absent key, never null/denied.
        Ok(match self.vault.read(service, account)? {
            Some(value) => Lookup::Present(value),
            None => Lookup::Missing,
        })
    }

    fn lookup(&self, account: &str) -> Result<Lookup> {
        match self.lookup_in(NOLAND_STATE_SERVICE, account)? {
            Lookup::Missing => self.lookup_in(NOLAND_LEGACY_SERVICE, account),
            other => Ok(other),
        }
    }
}

pub fn dynamic_profile_account(id: &str) -> String {
    format!(
        "shared-storage.profile.{}",
        hex::encode(Sha256::digest(id.as_bytes()))
    )
}

pub(crate) struct ImportedProfile {
    pub source_id: String,
    pub name: String,
    pub kind: String,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub credentials: Value,
    pub fields: BTreeMap<String, String>,
    pub key: Zeroizing<[u8; 32]>,
}

impl Drop for ImportedProfile {
    fn drop(&mut self) {
        zeroize_json(&mut self.credentials);
        for value in self.fields.values_mut() {
            value.zeroize();
        }
    }
}

/// Metadata-only preview: no source vault or provider accesses.
pub(crate) fn preview(input: &Value) -> Result<Value> {
    bounded_json(input, 128 * 1024)?;
    // The gateway must native-select/confirm first. In particular, an approval
    // scope query must not open an attacker-provided new local state file.
    Ok(
        json!({"requiresStateFile":false, "nativeSelectionRequired":true,
            "automaticSourceDiscovery":true,"manualFilePickerRequired":false,
            "nativeDiscoveryConsentRequired":true,"advancedManualFallback":true,
            "credentialReads":false, "profiles":[]}),
    )
}

pub(crate) fn prepare(input: &Value, vault: &dyn CredentialVault) -> Result<Vec<ImportedProfile>> {
    bounded_json(input, 128 * 1024)?;
    let path = input
        .get("stateFile")
        .and_then(Value::as_str)
        .context("native-selected No Land state file is required")?;
    let mut projection = read_projection(Path::new(path), input.get("_approvedPaths"))?;
    let selected: BTreeSet<String> = match input.get("profileIds") {
        Some(Value::Array(ids)) => {
            ensure!(
                !ids.is_empty() && ids.len() <= 256,
                "invalid source profile selection"
            );
            ids.iter()
                .map(|id| {
                    let id = id.as_str().context("source profile IDs must be strings")?;
                    validate_id(id)?;
                    Ok(id.to_owned())
                })
                .collect::<Result<_>>()?
        }
        None | Some(Value::Null) => projection
            .shared_storage_profiles
            .iter()
            .map(|profile| profile.id.clone())
            .collect(),
        _ => bail!("source profile selection must be an array"),
    };
    ensure!(
        !selected.is_empty(),
        "selected state contains no storage profiles"
    );
    ensure!(
        selected.iter().all(|id| projection
            .shared_storage_profiles
            .iter()
            .any(|profile| &profile.id == id)),
        "selected source profile was not found"
    );
    // Native consent has already occurred at the gateway before this method.
    let source = SourceReader::open(vault)?;
    let shared_key = match source.lookup("shared-storage.repository-key")? {
        Lookup::Present(value) => Some(value),
        Lookup::Deleted => None, // Never resurrect from the plaintext/legacy slot.
        Lookup::Missing
            if !projection
                .shared_storage_credentials
                .repository_key_hex
                .is_empty() =>
        {
            Some(Zeroizing::new(std::mem::take(
                &mut projection.shared_storage_credentials.repository_key_hex,
            )))
        }
        Lookup::Missing => None,
    };
    let mut imported = Vec::new();
    for reference in &projection.shared_storage_profiles {
        if !selected.contains(&reference.id) {
            continue;
        }
        let kind = match reference.provider.as_deref() {
            Some(provider) => parse_kind(provider)?,
            None => crate::provider::ALL_PROVIDER_KINDS
                .iter()
                .copied()
                .find(|kind| kind.label() == reference.provider_label)
                .context("source profile has no recognized storage provider kind")?,
        };
        let mut secret = match source.lookup(&dynamic_profile_account(&reference.id))? {
            Lookup::Present(value) => serde_json::from_str::<SourceProfileSecret>(&value)
                .map_err(|_| anyhow::anyhow!("selected source profile secret is invalid"))?,
            Lookup::Deleted => bail!("selected source profile is deleted in the source vault"),
            Lookup::Missing => projection
                .shared_storage_credentials
                .profiles
                .remove(&reference.id)
                .context("selected source profile credentials are unavailable")?,
        };
        validate_credentials(kind, &secret.credentials)?;
        // Normalize bounded scalar fields through the same schema as new profiles.
        let mut field_json = serde_json::to_value(&secret.provider_fields)?;
        let fields = fields_from_value(Some(&field_json));
        zeroize_json(&mut field_json);
        let fields = fields?;
        validate_fields(kind, &fields, false)?;
        let key_hex = shared_key
            .as_deref()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                (!secret.repository_key_hex.is_empty())
                    .then_some(secret.repository_key_hex.as_str())
            })
            .context("selected source profile has no repository key")?;
        let key = decode_key(key_hex)?;
        let bucket = reference
            .bucket
            .clone()
            .or_else(|| fields.get("bucket").cloned())
            .or_else(|| fields.get("space_name").cloned())
            .or_else(|| fields.get("container").cloned());
        if kind.uses_bucket_root() {
            ensure!(
                bucket
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty()),
                "source storage bucket/container is missing"
            );
        }
        let prefix = reference
            .prefix
            .clone()
            .or_else(|| fields.get("folder").cloned())
            .or_else(|| fields.get("remote_path").cloned());
        imported.push(ImportedProfile {
            source_id: reference.id.clone(),
            name: reference.display_name.clone(),
            kind: kind.as_str().into(),
            bucket,
            prefix,
            credentials: std::mem::take(&mut secret.credentials),
            fields,
            key,
        });
    }
    Ok(imported)
}
