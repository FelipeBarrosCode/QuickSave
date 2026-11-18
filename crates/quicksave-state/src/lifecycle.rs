// SPDX-License-Identifier: GPL-3.0-only
//! Native consent is a precondition; none of these requests is an IPC DTO.

use crate::{
    decode_key, parse_kind, validate_id, WorkspaceStore, QUICKSAVE_VAULT_SERVICE,
    REPOSITORY_KEY_ACCOUNT,
};
use anyhow::{ensure, Context, Result};
use quicksave_platform::{RootIdentity, SafeRoot};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

pub struct NativeOAuthProfile {
    pub provider_id: String,
    pub kind: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub credential_generation: u64,
}
impl Drop for NativeOAuthProfile {
    fn drop(&mut self) {
        self.client_id.zeroize();
        self.client_secret.zeroize();
    }
}

/// Exact external NEW-file destination from a native save dialog. No secret can
/// be serialized from the result, and an existing target is never overwritten.
pub struct NativeRecoveryExport {
    pub provider_id: Option<String>,
    pub destination: PathBuf,
    pub parent_identity: RootIdentity,
}

impl WorkspaceStore {
    /// Private CAS ticket field for native reauthorization of static providers.
    /// Never accept an expected generation supplied by JavaScript as authority.
    pub fn provider_credential_generation(&self, provider_id: &str) -> Result<u64> {
        validate_id(provider_id)?;
        self.transaction(|document| {
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .context("Provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "Provider is disconnected"
            );
            Ok(self.read_secret(provider)?.credential_generation)
        })
    }
    pub fn oauth_reauthorization_profile(&self, provider_id: &str) -> Result<NativeOAuthProfile> {
        validate_id(provider_id)?;
        self.transaction(|document| {
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .context("OAuth provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "Disconnected providers require an explicit new connection"
            );
            ensure!(
                parse_kind(&provider.kind)?.is_oauth(),
                "Provider does not use OAuth"
            );
            let secret = self.read_secret(provider)?;
            let client_id = secret
                .provider_fields
                .get("client_id")
                .filter(|id| !id.is_empty())
                .context("An explicitly configured registered OAuth client is required")?
                .clone();
            Ok(NativeOAuthProfile {
                provider_id: provider_id.into(),
                kind: provider.kind.clone(),
                client_id,
                client_secret: secret.provider_fields.get("client_secret").cloned(),
                credential_generation: secret.credential_generation,
            })
        })
    }

    /// Persist reauthorization privately, then require fresh live health. This
    /// does not switch routing/client/key/read-only scope, enable autosave, or
    /// claim that an opaque token proves the original provider-account identity.
    pub fn complete_oauth_reauthorization(
        &self,
        provider_id: &str,
        expected_generation: u64,
        credentials: &Value,
    ) -> Result<()> {
        let document = self.document()?;
        let provider = document
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .context("OAuth provider not found")?;
        ensure!(
            parse_kind(&provider.kind)?.is_oauth(),
            "Provider does not use OAuth"
        );
        self.complete_provider_reauthorization(provider_id, expected_generation, credentials)
            .map(|_| ())
    }

    /// Native-confirmed replacement for all fourteen provider credential types.
    /// Root/client/key/read-only fields cannot be edited here. Explicit sign-in
    /// changes an authority revision and revokes autosave: unlike a chained OAuth
    /// refresh, a new credential set cannot prove the original account identity.
    pub fn complete_provider_reauthorization(
        &self,
        provider_id: &str,
        expected_generation: u64,
        credentials: &Value,
    ) -> Result<u64> {
        validate_id(provider_id)?;
        crate::bounded_json(credentials, 1024 * 1024)?;
        self.transaction(|document| {
            let position = document
                .providers
                .iter()
                .position(|provider| provider.id == provider_id)
                .context("Provider not found")?;
            let provider = document.providers[position].clone();
            ensure!(
                provider.status != "disconnected",
                "Disconnected providers require an explicit new connection"
            );
            let kind = parse_kind(&provider.kind)?;
            crate::provider::validate_credentials(kind, credentials)?;
            if kind.is_oauth() {
                ensure!(
                    credentials["value"]["refresh_token"]
                        .as_str()
                        .is_some_and(|token| !token.is_empty()),
                    "Explicit OAuth reauthorization requires an actual offline refresh token"
                );
            }
            let mut secret = self.read_secret(&provider).map_err(|_| {
                anyhow::anyhow!("Native reauthorization profile is unavailable or changed")
            })?;
            ensure!(
                secret.credential_generation == expected_generation,
                "Provider credentials changed during native reauthorization"
            );
            crate::zeroize_json(&mut secret.credentials);
            secret.credentials = credentials.clone();
            secret.credential_generation = secret
                .credential_generation
                .checked_add(1)
                .context("Credential generation exhausted")?;
            secret.authority_revision = secret
                .authority_revision
                .checked_add(1)
                .context("Provider authority revision exhausted")?;
            let mut session = secret.session("native-reauthorization")?;
            crate::zeroize_json(&mut session);
            self.write_secret(&provider.credential_ref, &secret)
                .map_err(|_| {
                    anyhow::anyhow!("Native reauthorization persistence failed verification")
                })?;
            let changed = &mut document.providers[position];
            changed.status = "connecting".into();
            changed.error = None;
            changed.authority_revision = secret.authority_revision;
            for software in &mut document.software {
                if software.provider_id.as_deref() == Some(provider_id) {
                    self.revoke_bound("autosave", &json!({"softwareId":software.id}))?;
                    software.autosave = false;
                    software.autosave_grant = None;
                }
            }
            Ok(secret.credential_generation)
        })
    }

    /// Recovery key bytes go directly vault -> external private file, with
    /// durable create-new, privacy checks and read-back. Native confirmation
    /// approves the exact parent identity/destination before this method.
    pub fn export_recovery_key(&self, request: &NativeRecoveryExport) -> Result<Value> {
        let destination = &request.destination;
        ensure!(
            destination.is_absolute()
                && destination
                    .to_str()
                    .is_some_and(|text| text.len() <= quicksave_platform::MAX_PATH_BYTES
                        && !text.chars().any(char::is_control)),
            "Recovery export requires a bounded absolute native destination"
        );
        let parent_path = destination
            .parent()
            .context("Recovery destination has no parent")?;
        ensure!(
            !parent_path.components().any(|part| part
                .as_os_str()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(crate::NOLAND_APP_IDENTIFIER))),
            "Recovery export cannot write inside No Land application state"
        );
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .context("Recovery destination filename must be UTF-8")?;
        ensure!(
            name.len() <= 255
                && !name.chars().any(char::is_control)
                && !name.contains(['/', '\\', ':']),
            "Recovery destination filename is invalid"
        );
        let root = SafeRoot::open(parent_path)?;
        ensure!(
            root.identity()? == request.parent_identity,
            "Native recovery-export parent changed"
        );
        self.transaction(|document| {
            let account = match request.provider_id.as_deref() {
                Some(id) => {
                    validate_id(id)?;
                    let provider = document
                        .providers
                        .iter()
                        .find(|provider| provider.id == id)
                        .context("Recovery export provider not found")?;
                    if provider.status != "disconnected" {
                        self.read_secret(provider)?;
                    }
                    // A disconnected import retains its key in this deterministic
                    // QuickSave namespace, independently of deleted credentials.
                    let expected = if provider.origin == "noland" {
                        format!("repository.import.{id}")
                    } else {
                        REPOSITORY_KEY_ACCOUNT.into()
                    };
                    ensure!(
                        provider.repository_key_ref == expected,
                        "Recovery key reference is not bound to this provider"
                    );
                    expected
                }
                None => REPOSITORY_KEY_ACCOUNT.into(),
            };
            // Bound ancestor-ID checks, not a full home/disk scan. No key may be
            // published inside QuickSave state or any approved capture directory.
            let mut forbidden = BTreeSet::new();
            let data = SafeRoot::open(&self.inner.data_directory)?;
            let identity = data.identity()?;
            forbidden.insert((identity.device, identity.file_id));
            for software in &document.software {
                for source in &software.roots {
                    ensure!(
                        destination != Path::new(&source.path),
                        "Recovery key must not replace an approved capture source"
                    );
                    if source.directory {
                        forbidden.insert((source.identity.device, source.identity.file_id));
                    }
                }
            }
            for (index, ancestor) in parent_path.ancestors().enumerate() {
                ensure!(index <= 128, "Recovery destination has too many ancestors");
                let identity = SafeRoot::open(ancestor)?.identity()?;
                ensure!(
                    !forbidden.contains(&(identity.device, identity.file_id)),
                    "Recovery key must be external to QuickSave state and approved capture roots"
                );
            }
            let encoded = self
                .inner
                .vault
                .read(QUICKSAVE_VAULT_SERVICE, &account)?
                .context("The selected repository key is unavailable in the native vault")?;
            let key = decode_key(&encoded)?;
            root.write_new(name, |file| {
                quicksave_platform::verify_private_file(file)?;
                file.write_all(&key[..])?;
                Ok(())
            })?;
            let (mut file, stamp) = root.read_file(name)?;
            quicksave_platform::verify_private_file(&file)?;
            ensure!(stamp.size == 32, "Recovery export failed size verification");
            let mut verified = zeroize::Zeroizing::new([0u8; 32]);
            file.read_exact(&mut verified[..])?;
            root.verify_file(name, &stamp)?;
            ensure!(
                verified[..] == key[..],
                "Recovery export failed read-back verification"
            );
            ensure!(
                root.identity()? == request.parent_identity,
                "Recovery-export parent changed during publication"
            );
            Ok(json!({"written":true,"providerId":request.provider_id,
                "keyMaterialReturned":false,"format":"external_32_byte_repository_key",
                "keepExternalCopy":true}))
        })
    }
}
