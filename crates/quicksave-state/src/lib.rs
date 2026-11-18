// SPDX-License-Identifier: GPL-3.0-only
//! Native workspace settings and vault-bound authority. See README.md for the
//! cross-component API and explicit native-consent requirements.

mod discovery;
mod grant;
mod import;
mod lifecycle;
mod metadata_verification;
mod model;
mod provider;
mod state_file;
mod vault;

pub use discovery::{KnownDataDirs, NativeNolandSourceProof, NOLAND_APP_IDENTIFIER};
pub use import::{
    dynamic_profile_account, NOLAND_DOCUMENT_ACCOUNT, NOLAND_DOCUMENT_SERVICE, NOLAND_STATE_SERVICE,
};
pub use lifecycle::{NativeOAuthProfile, NativeRecoveryExport};
pub use metadata_verification::MetadataProjectionChanged;
pub use model::{
    AppTrackingBaseDirectory, AppTrackingIdentityPolicy, AppTrackingPolicyScope,
    AppTrackingSettings, NativeFileStampID, ProviderRecord, ScopeProviderId, StateAutoEnrollment,
    StateRoot, StateSoftware, WorkspaceDocument, WorkspaceSettings,
};
pub use vault::{
    CredentialVault, MemoryVault, NativeVault, DEVICE_KEY_ACCOUNT, QUICKSAVE_VAULT_SERVICE,
    REPOSITORY_KEY_ACCOUNT,
};

use anyhow::{bail, ensure, Context, Result};
use provider::{
    fields_from_value, parse_kind, validate_credentials, validate_fields, SecretProfile,
};
use quicksave_platform::FileStamp;
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

/// Native bridge input ONLY. Deliberately not Debug, Clone, or Serialize.
/// Its public fields satisfy the native Rust contract, not an IPC DTO.
pub struct ProviderAccess {
    pub provider_id: String,
    pub session: Value,
    pub repository_key: [u8; 32],
    pub read_only: bool,
}

impl ProviderAccess {
    /// Native-only performance metadata, not credentials. Consume before the
    /// source session is decoded; source RPC's performance_mode owns the original
    /// CPU/memory/provider-aware profile. No new per-object config is created.
    pub fn transfer_policy(&self) -> Value {
        self.session
            .get("native_transfer_policy")
            .cloned()
            .unwrap_or(Value::Null)
    }
}

impl Drop for ProviderAccess {
    fn drop(&mut self) {
        self.repository_key.zeroize();
        zeroize_json(&mut self.session);
    }
}

struct Inner {
    file: state_file::StateFile,
    operation: Mutex<()>,
    vault: Arc<dyn CredentialVault>,
    // Loaded only by explicit native operations or grant verification, not open
    // or pure dashboard/approval-scope queries.
    device_key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    verified_grants: Mutex<BTreeMap<String, (String, String)>>,
    noland_sources: Mutex<BTreeMap<String, Arc<NativeNolandSourceProof>>>,
    data_directory: PathBuf,
    data_root: quicksave_platform::SafeRoot,
    allow_native_discovery: bool,
}

#[derive(Clone)]
pub struct WorkspaceStore {
    inner: Arc<Inner>,
}

/// Request-scoped native metadata view. Do not retain between UI requests or
/// use instead of fresh publication guards. All MAC/nonce checks remain real;
/// only repeated whole-state reads are removed.
pub struct WorkspaceReadSnapshot {
    store: WorkspaceStore,
    document: WorkspaceDocument,
}
impl WorkspaceReadSnapshot {
    pub fn verify_grant(&self, kind: &str, scope: &Value, signature: &Value) -> Result<bool> {
        self.store.verify_bound(
            &self.document,
            &json!({"kind":kind,"scope":scope}),
            signature,
        )
    }
    pub fn verify_tracking_grant(&self, software_id: &str) -> Result<bool> {
        self.store
            .verify_tracking_in_document(&self.document, software_id)
    }
    /// Optional end-of-read validation, comparing decoded content rather than
    /// trusting an attacker-editable generation counter. Not a long-lived cache.
    pub fn is_current(&self) -> Result<bool> {
        Ok(self.store.document()? == self.document)
    }
}

impl WorkspaceStore {
    /// Creates/loads only private settings. No native vault reads on open.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_inner(data_dir, Arc::new(NativeVault), true)
    }

    pub fn open_with_vault(data_dir: &Path, vault: Arc<dyn CredentialVault>) -> Result<Self> {
        Self::open_inner(data_dir, vault, false)
    }

    fn open_inner(
        data_dir: &Path,
        vault: Arc<dyn CredentialVault>,
        allow_native_discovery: bool,
    ) -> Result<Self> {
        let store = Self {
            inner: Arc::new(Inner {
                file: state_file::StateFile::open(data_dir)?,
                operation: Mutex::new(()),
                vault,
                device_key: Mutex::new(None),
                verified_grants: Mutex::new(BTreeMap::new()),
                noland_sources: Mutex::new(BTreeMap::new()),
                data_directory: data_dir.to_path_buf(),
                data_root: quicksave_platform::SafeRoot::open(data_dir)?,
                allow_native_discovery,
            }),
        };
        // Initial publication is under the same OS lock as every later update.
        let _operation = store
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = store.inner.file.lock()?;
        match locked.read()? {
            Some(bytes) => {
                decode_document(&bytes)?;
            }
            None => {
                locked.replace(&encode_document(&WorkspaceDocument::default())?)?;
            }
        }
        drop(locked);
        drop(_operation);
        Ok(store)
    }

    /// Trusted native closure only. Reload under flock, preserve concurrent
    /// changes, validate, and skip durable replacement for identical updates.
    pub fn transaction<R>(
        &self,
        update: impl FnOnce(&mut WorkspaceDocument) -> Result<R>,
    ) -> Result<R> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock()?;
        let bytes = locked.read()?.context("workspace state disappeared")?;
        let mut document = decode_document(&bytes)?;
        let before = document.clone();
        let result = update(&mut document)?;
        ensure!(
            document.generation == before.generation,
            "transaction cannot replace the state generation"
        );
        document.validate()?;
        if document != before {
            metadata_verification::invalidate(self);
            document.generation = before
                .generation
                .checked_add(1)
                .context("state generation exhausted")?;
            locked.replace(&encode_document(&document)?)?;
        }
        Ok(result)
    }

    pub fn document(&self) -> Result<WorkspaceDocument> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock()?;
        decode_document(&locked.read()?.context("workspace state disappeared")?)
    }

    pub fn read_snapshot(&self) -> Result<WorkspaceReadSnapshot> {
        Ok(WorkspaceReadSnapshot {
            store: self.clone(),
            document: self.document()?,
        })
    }

    /// Pure non-secret DTO. Does not read the vault even for a forged grant.
    /// Existing authority is shown enabled after a native worker has verified
    /// the device key; an unverified startup flag is never treated as authority.
    pub fn sanitized(&self) -> Result<Value> {
        let document = self.document()?;
        let software = document
            .software
            .iter()
            .map(|software| {
                let tracking_verified = self
                    .cached_tracking_verify(&document, software)
                    .unwrap_or(false);
                let autosave_verified = tracking_verified
                    && (|| {
                        let provider = document
                            .providers
                            .iter()
                            .find(|provider| Some(&provider.id) == software.provider_id.as_ref())?;
                        let scope = grant::autosave_scope(software, provider).ok()?;
                        let stored = software.autosave_grant.as_ref()?;
                        self.cached_verify(&document, &scope, stored).ok()
                    })()
                    .unwrap_or(false);
                let mut value = software.sanitized(autosave_verified);
                if software.tracked && !tracking_verified {
                    value["tracked"] = json!(false);
                    value["status"] = json!("not_tracked");
                }
                value
            })
            .collect::<Vec<_>>();
        let needs_backup = software
            .iter()
            .filter(|value| value["tracked"] == true && value["dirty"] == true)
            .count();
        let autosave_enabled = software
            .iter()
            .filter(|value| value["autosave"] == true)
            .count();
        let connected = document
            .providers
            .iter()
            .filter(|provider| provider.status == "connected")
            .count();
        let app_tracking = document.settings.app_tracking.as_ref().map(|policy| {
            let scope = serde_json::to_value(&policy.policy_scope).unwrap_or(Value::Null);
            let verified = self
                .cached_verify(
                    &document,
                    &json!({"kind":"app_tracking_policy","scope":scope}),
                    &policy.policy_grant,
                )
                .unwrap_or(false);
            json!({"enabled":policy.policy_scope.enabled && verified,
                "policyVersion":policy.policy_scope.role_policy_version,
                "defaultProviderId":policy.policy_scope.provider_id,
                "verified":verified})
        });
        Ok(json!({
            "providers":document.providers.iter().map(ProviderRecord::sanitized).collect::<Vec<_>>(),
            "software":software, "activity":[], "settings":{
                "launchAtLogin":document.settings.launch_at_login,
                "keepLocalData":document.settings.keep_local_data,
                "appTracking":app_tracking,
            },
            "summary":{"needsBackup":needs_backup,"autosaveEnabled":autosave_enabled,"connectedProviders":connected},
        }))
    }

    pub fn provider_types(&self) -> Value {
        provider::provider_definitions()
    }

    /// Native restore plan/journal authority, NOT a repository/master key.
    /// Borrows bounded message bytes and hashes directly: no JSON normalization
    /// or whole-message copy. Device vault is accessed once, then cached in Rust.
    pub fn recovery_mac(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        self.native_document_mac(b"QuickSave/native-restore-recovery/v1\0", bytes, true)
    }

    /// Recovery/verification only: missing native device authority is an error.
    /// Never generate a replacement key while validating a retained journal.
    pub fn recovery_mac_existing(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        self.native_document_mac(b"QuickSave/native-restore-recovery/v1\0", bytes, false)
    }

    /// Separate purpose for the parent's durable native operation ledger.
    pub fn operation_mac(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        self.native_document_mac(b"QuickSave/native-operation-ledger/v1\0", bytes, true)
    }

    /// Read-only operation-ledger verification. Seal with operation_mac only
    /// after native consent; verification cannot manufacture missing authority.
    pub fn operation_mac_existing(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        self.native_document_mac(b"QuickSave/native-operation-ledger/v1\0", bytes, false)
    }

    fn native_document_mac(
        &self,
        domain: &[u8],
        bytes: &[u8],
        create_key: bool,
    ) -> Result<[u8; 32]> {
        use hmac::{Hmac, Mac};
        ensure!(
            bytes.len() <= 512 * 1024 * 1024,
            "native authority document exceeds 512 MiB"
        );
        // Native root identities bind a vault-shared device key to this exact
        // QuickSave workspace, without trusting a path or JSON generation.
        let identity = self.inner.data_root.identity()?;
        let key = self
            .device_key(create_key)?
            .context("native device authority key is unavailable")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[..])?;
        mac.update(domain);
        mac.update(&identity.device.to_le_bytes());
        mac.update(&identity.file_id[0].to_le_bytes());
        mac.update(&identity.file_id[1].to_le_bytes());
        mac.update(&(bytes.len() as u64).to_le_bytes());
        mac.update(bytes);
        ensure!(
            self.inner.data_root.identity()? == identity,
            "native workspace identity changed during authentication"
        );
        let mut result = [0u8; 32];
        result.copy_from_slice(&mac.finalize().into_bytes());
        Ok(result)
    }

    /// Native-only persistence of Tracker's exact {policyScope,policyGrant}.
    /// Parent obtains one-use native consent and issues the app_tracking_policy
    /// grant first. A bool/JSON object cannot create authority on its own.
    pub fn set_app_tracking_policy(&self, input: &Value) -> Result<()> {
        bounded_json(input, 640 * 1024)?;
        let policy: AppTrackingSettings = serde_json::from_value(input.clone())
            .map_err(|_| anyhow::anyhow!("invalid native app-tracking policy"))?;
        policy.validate()?;
        let scope = serde_json::to_value(&policy.policy_scope)?;
        self.transaction(|document| {
            ensure!(
                self.verify_bound(
                    document,
                    &json!({"kind":"app_tracking_policy","scope":scope}),
                    &policy.policy_grant
                )?,
                "app-tracking policy requires a valid native grant"
            );
            if let Some(old) = &document.settings.app_tracking {
                let old_scope = serde_json::to_value(&old.policy_scope)?;
                if old_scope != scope {
                    self.revoke_bound("app_tracking_policy", &old_scope)?;
                }
            }
            document.settings.app_tracking = Some(policy);
            Ok(())
        })
    }

    pub fn clear_app_tracking_policy(&self) -> Result<()> {
        self.transaction(|document| {
            if let Some(old) = &document.settings.app_tracking {
                self.revoke_bound(
                    "app_tracking_policy",
                    &serde_json::to_value(&old.policy_scope)?,
                )?;
            }
            document.settings.app_tracking = None;
            Ok(())
        })
    }

    /// Revalidates durable native authority at worker startup/use, never on a
    /// pure dashboard read. Returns no device key.
    pub fn app_tracking_policy(&self) -> Result<Option<Value>> {
        let document = self.document()?;
        let Some(policy) = document.settings.app_tracking.as_ref() else {
            return Ok(None);
        };
        let scope = serde_json::to_value(&policy.policy_scope)?;
        if !policy.policy_scope.enabled
            || !self.verify_bound(
                &document,
                &json!({"kind":"app_tracking_policy","scope":scope}),
                &policy.policy_grant,
            )?
        {
            return Ok(None);
        }
        Ok(Some(serde_json::to_value(policy)?))
    }

    /// Caller has native-approved this exact transient credential/profile input.
    /// This configures a profile; the bridge must perform real health checks.
    pub fn connect_provider(&self, input: &Value) -> Result<Value> {
        bounded_json(input, 2 * 1024 * 1024)?;
        let kind = parse_kind(required_str(input, "kind")?)?;
        let name = required_str(input, "name")?.to_owned();
        validate_text(&name, 512, "provider name")?;
        let fields = fields_from_value(input.get("fields"))?;
        validate_fields(kind, &fields, true)?;
        let credentials = input.get("credentials").context(
            "provider credentials are required; complete native authorization before saving a profile",
        )?;
        validate_credentials(kind, credentials)?;
        if kind.is_oauth() {
            ensure!(credentials["value"]["refresh_token"].as_str().is_some_and(|token| !token.trim().is_empty()),
                "Durable shared-storage OAuth requires an actual refresh token; authorize the registered client with offline access");
        }
        let bucket = optional_str(input, "bucket")?
            .or_else(|| fields.get("bucket").cloned())
            .or_else(|| fields.get("space_name").cloned())
            .or_else(|| fields.get("container").cloned());
        if kind.uses_bucket_root() {
            ensure!(
                bucket
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty()),
                "provider bucket/container is required"
            );
        }
        let prefix = optional_str(input, "prefix")?
            .or_else(|| fields.get("folder").cloned())
            .or_else(|| fields.get("remote_path").cloned())
            .or_else(|| (!kind.uses_bucket_root()).then(|| "QuickSave".into()));
        validate_provider_root(bucket.as_deref(), prefix.as_deref())?;
        let read_only = match input.get("readOnly") {
            None => false,
            Some(value) => value.as_bool().context("readOnly must be a boolean")?,
        };
        let id = uuid::Uuid::new_v4().to_string();
        let record = ProviderRecord {
            id: id.clone(),
            name,
            kind: kind.as_str().into(),
            status: "connecting".into(),
            origin: "quicksave".into(),
            read_only,
            bucket,
            prefix,
            public_scope: provider::public_scope(&fields)?,
            credential_ref: format!("provider.{id}"),
            repository_key_ref: REPOSITORY_KEY_ACCOUNT.into(),
            source_profile_id: None,
            authority_revision: 0,
            error: None,
        };
        let secret = SecretProfile {
            version: 1,
            credential_generation: 0,
            authority_revision: 0,
            provider_id: id.clone(),
            kind: record.kind.clone(),
            bucket: record.bucket.clone(),
            prefix: record.prefix.clone(),
            read_only,
            repository_key_ref: record.repository_key_ref.clone(),
            credentials: credentials.clone(),
            provider_fields: fields,
        };
        // Validate exact adapter/session shape locally, without provider I/O.
        let mut validation_session = secret.session("configure")?;
        zeroize_json(&mut validation_session);
        self.transaction(|document| {
            ensure!(
                document.providers.len() < model::MAX_PROVIDERS,
                "too many provider profiles"
            );
            self.repository_key(true)?;
            self.write_secret(&record.credential_ref, &secret)?;
            document.providers.push(record);
            Ok(())
        })?;
        self.sanitized()
    }

    /// Native-completed OAuth result only, never an IPC endpoint that accepts
    /// webview tokens. Browser/registration consent is owned by quicksave-oauth.
    pub fn connect_oauth(&self, input: &Value) -> Result<Value> {
        let kind = parse_kind(required_str(input, "kind")?)?;
        ensure!(
            kind.is_oauth(),
            "connect_oauth requires an OAuth storage provider"
        );
        self.connect_provider(input)
    }

    /// Native-only refresh of an existing OAuth profile, never an editable-field
    /// update or account-switch API. The caller's native OAuth flow must bind the
    /// refreshed tokens to the same provider account/client; opaque token strings
    /// cannot establish account ownership here.
    ///
    /// Accepts only the exact No Land `o_auth2` credential shape. Routing, client
    /// fields, key reference, read-only policy, health and authority grants remain
    /// unchanged. An omitted/null refresh token preserves the existing native
    /// refresh token; a nonempty replacement persists provider token rotation.
    /// Failures never publish settings or report a successful durable refresh.
    pub fn update_oauth_credentials(&self, provider_id: &str, credentials: &Value) -> Result<()> {
        self.update_oauth_credentials_inner(provider_id, None, credentials)
            .map(|_| ())
    }

    /// Native-only refresh handoff. Read the expected generation atomically with
    /// the original access using `oauth_credential_generation_for_access`.
    /// A stale worker cannot replace a newer rotation or resurrect a disconnect.
    /// Returns the new vault-only generation after checked durable read-back.
    pub fn update_oauth_credentials_cas(
        &self,
        provider_id: &str,
        expected_generation: u64,
        credentials: &Value,
    ) -> Result<u64> {
        self.update_oauth_credentials_inner(provider_id, Some(expected_generation), credentials)
    }

    /// Typed sink adapter. The temporary tagged credential is zeroized on both
    /// success and error; no token-bearing value needs to cross an IPC boundary.
    pub fn update_oauth_tokens_cas(
        &self,
        provider_id: &str,
        expected_generation: u64,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: i64,
    ) -> Result<u64> {
        let mut credentials = json!({"type":"o_auth2","value":{
            "access_token":access_token,"refresh_token":refresh_token,"expires_at":expires_at,
        }});
        let result =
            self.update_oauth_credentials_cas(provider_id, expected_generation, &credentials);
        zeroize_json(&mut credentials);
        result
    }

    fn update_oauth_credentials_inner(
        &self,
        provider_id: &str,
        expected_generation: Option<u64>,
        credentials: &Value,
    ) -> Result<u64> {
        validate_id(provider_id)?;
        // Reject malformed or expanded inputs before any credential-vault read.
        validate_credentials(
            noland_rclone_adapter::ProviderKind::GoogleDrive,
            credentials,
        )?;
        if let Some(token) = credentials["value"]
            .get("refresh_token")
            .filter(|value| !value.is_null())
        {
            let token = token
                .as_str()
                .context("OAuth refresh token must be a string")?;
            ensure!(
                !token.trim().is_empty() && !token.chars().any(char::is_control),
                "OAuth refresh token is empty or contains invalid characters"
            );
        }
        self.transaction(|document| {
            let provider = document.providers.iter().find(|provider| provider.id == provider_id)
                .context("OAuth provider not found")?;
            ensure!(provider.status != "disconnected", "OAuth provider is disconnected");
            let kind = parse_kind(&provider.kind)?;
            ensure!(kind.is_oauth(), "credential refresh requires an existing OAuth provider");
            let mut secret = self.read_secret(provider)
                .map_err(|_| anyhow::anyhow!("native OAuth profile is unavailable or its identity changed"))?;
            if let Some(expected) = expected_generation {
                ensure!(
                    secret.credential_generation == expected,
                    "native OAuth credentials changed during this operation; reattach fresh access or reauthorize"
                );
            }
            validate_credentials(kind, &secret.credentials)
                .map_err(|_| anyhow::anyhow!("existing native OAuth credentials are invalid"))?;
            let mut refreshed = credentials.clone();
            if refreshed["value"].get("refresh_token").is_none_or(Value::is_null) {
                refreshed["value"]["refresh_token"] = secret.credentials["value"]
                    .get("refresh_token").cloned().unwrap_or(Value::Null);
            }
            zeroize_json(&mut secret.credentials);
            secret.credentials = refreshed;
            secret.credential_generation = secret.credential_generation.checked_add(1)
                .context("native OAuth credential generation exhausted")?;
            let mut validation_session = secret.session("oauth-refresh")
                .map_err(|_| anyhow::anyhow!("native OAuth credential update is invalid"))?;
            zeroize_json(&mut validation_session);
            let encoded = Zeroizing::new(serde_json::to_string(&secret)
                .map_err(|_| anyhow::anyhow!("native OAuth credential encoding failed"))?);
            self.inner.vault.write(QUICKSAVE_VAULT_SERVICE, &provider.credential_ref, &encoded)
                .map_err(|_| anyhow::anyhow!("native OAuth credential persistence failed; retry the native flow or reconnect"))?;
            // Enforce read-back for injected backends too. A backend's Ok is not
            // evidence of an atomic/persistent replacement. Never compensate by
            // blindly restoring an old, potentially already-rotated token.
            let verified = self.inner.vault.read(QUICKSAVE_VAULT_SERVICE, &provider.credential_ref)
                .map_err(|_| anyhow::anyhow!("native OAuth credential persistence could not be verified"))?;
            ensure!(
                verified.as_deref().map(String::as_str) == Some(encoded.as_str()),
                "native OAuth credential persistence failed verification; retry the native flow or reconnect"
            );
            Ok(secret.credential_generation)
        })
    }

    /// Checks the complete operation-scoped session against the current vault
    /// before registering a refresh sink. No credentials/generation are IPC DTOs.
    pub fn oauth_credential_generation_for_access(&self, access: &ProviderAccess) -> Result<u64> {
        validate_id(&access.provider_id)?;
        let operation = access
            .session
            .get("operation_id")
            .and_then(Value::as_str)
            .context("native provider access has no operation binding")?;
        validate_id(operation)?;
        self.transaction(|document| {
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == access.provider_id)
                .context("OAuth provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "OAuth provider is disconnected"
            );
            ensure!(
                parse_kind(&provider.kind)?.is_oauth(),
                "native refresh sink requires OAuth"
            );
            let secret = self.read_secret(provider)?;
            let mut expected = secret.session(operation)?;
            let matches = expected == access.session && secret.read_only == access.read_only;
            zeroize_json(&mut expected);
            ensure!(
                matches,
                "native provider session is stale or its routing changed"
            );
            Ok(secret.credential_generation)
        })
    }

    /// Removes only this application's credential item, never any encryption key
    /// or cloud data. The app-wide master key survives all disconnections.
    pub fn disconnect_provider(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.transaction(|document| {
            let provider = document
                .providers
                .iter_mut()
                .find(|provider| provider.id == id)
                .context("provider not found")?;
            self.inner
                .vault
                .delete(QUICKSAVE_VAULT_SERVICE, &provider.credential_ref)?;
            provider.status = "disconnected".into();
            provider.error = None;
            for software in &mut document.software {
                if software.provider_id.as_deref() == Some(id) {
                    self.revoke_bound("autosave", &json!({"softwareId":software.id}))?;
                    software.autosave = false;
                    software.autosave_grant = None;
                }
            }
            Ok(())
        })
    }

    pub fn noland_import_preview(&self, input: &Value) -> Result<Value> {
        import::preview(input)
    }

    /// Only call after the parent gateway's native confirmation/file selection.
    /// No No Land item is modified, migrated, deleted, or used as write authority.
    pub fn import_noland(&self, input: &Value) -> Result<Value> {
        let native_input;
        let input = if let Some(source_id) = input.get("sourceId").and_then(Value::as_str) {
            let proof = self.noland_source_proof(source_id)?;
            if let Some(path) = input.get("stateFile") {
                ensure!(
                    path.as_str() == proof.state_file().to_str(),
                    "sourceId cannot authorize a different import path"
                );
            }
            if let Some(handoff) = input.get("_approvedPaths") {
                ensure!(
                    handoff == &json!([proof.approved_path_handoff()?]),
                    "discovered-source native ticket proof does not match the pinned source"
                );
            }
            native_input = {
                let mut input = input.clone();
                input["stateFile"] = json!(proof.state_file());
                input["_approvedPaths"] = json!([proof.approved_path_handoff()?]);
                input
            };
            &native_input
        } else {
            input
        };
        let mut imports = import::prepare(input, self.inner.vault.as_ref())?;
        self.transaction(|document| {
            ensure!(document.providers.len() + imports.len() <= model::MAX_PROVIDERS, "too many provider profiles");
            for import in &imports {
                ensure!(
                    !document.providers.iter().any(|provider|
                        provider.origin == "noland"
                            && provider.source_profile_id.as_deref() == Some(import.source_id.as_str())
                            && provider.status != "disconnected"
                    ),
                    "source profile already has a configured import; explicitly disconnect it before a fresh native-consented import"
                );
                validate_provider_root(import.bucket.as_deref(), import.prefix.as_deref())?;
            }
            for import in &mut imports {
                let id = uuid::Uuid::new_v4().to_string();
                let record = ProviderRecord {
                    id: id.clone(), name: import.name.clone(), kind: import.kind.clone(),
                    status: "connecting".into(), origin: "noland".into(), read_only: true,
                    bucket: import.bucket.clone(), prefix: import.prefix.clone(),
                    public_scope: provider::public_scope(&import.fields)?,
                    credential_ref: format!("provider.{id}"), repository_key_ref: format!("repository.import.{id}"),
                    source_profile_id: Some(import.source_id.clone()), authority_revision: 0, error: None,
                };
                let key_hex = Zeroizing::new(hex::encode(import.key.as_ref()));
                self.inner.vault.write(QUICKSAVE_VAULT_SERVICE, &record.repository_key_ref, &key_hex)?;
                ensure!(self.inner.vault.read(QUICKSAVE_VAULT_SERVICE, &record.repository_key_ref)?
                    .as_deref().map(String::as_str) == Some(key_hex.as_str()),
                    "Imported repository-key persistence failed verification");
                let secret = SecretProfile {
                    version: 1, credential_generation: 0, authority_revision: 0, provider_id: id, kind: record.kind.clone(),
                    bucket: record.bucket.clone(), prefix: record.prefix.clone(), read_only: true,
                    repository_key_ref: record.repository_key_ref.clone(),
                    credentials: std::mem::take(&mut import.credentials),
                    provider_fields: std::mem::take(&mut import.fields),
                };
                let mut validation_session = secret.session("import")?;
                zeroize_json(&mut validation_session);
                self.write_secret(&record.credential_ref, &secret)?;
                document.providers.push(record);
            }
            Ok(())
        })?;
        self.sanitized()
    }

    /// Native bridge only. Includes guarded No Land session JSON, never a UI DTO.
    pub fn provider_access(&self, id: &str, operation_id: &str) -> Result<ProviderAccess> {
        validate_id(id)?;
        validate_id(operation_id)?;
        // Keep state snapshot, routing validation, and vault read under one lock.
        self.transaction(|document| {
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == id)
                .context("provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "provider is disconnected"
            );
            let secret = self.read_secret(provider)?;
            let encoded = self
                .inner
                .vault
                .read(QUICKSAVE_VAULT_SERVICE, &provider.repository_key_ref)?
                .context("provider repository key is missing from the native vault")?;
            let repository_key = decode_key(&encoded)?;
            let session = secret.session(operation_id)?;
            Ok(ProviderAccess {
                provider_id: provider.id.clone(),
                session,
                repository_key: *repository_key,
                read_only: secret.read_only,
            })
        })
    }

    /// Separate native consent for exactly this profile/root. JSON is not a grant.
    pub fn grant_provider_write(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.transaction(|document| {
            let provider = document
                .providers
                .iter_mut()
                .find(|provider| provider.id == id)
                .context("provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "provider is disconnected"
            );
            let mut secret = self.read_secret(provider)?;
            secret.read_only = false;
            self.write_secret(&provider.credential_ref, &secret)?;
            provider.read_only = false;
            // A changed grant never silently reactivates prior autosave.
            for software in &mut document.software {
                if software.provider_id.as_deref() == Some(id) {
                    self.revoke_bound("autosave", &json!({"softwareId":software.id}))?;
                    software.autosave = false;
                    software.autosave_grant = None;
                }
            }
            Ok(())
        })
    }

    pub fn grant_provider_writes(&self, id: &str) -> Result<()> {
        self.grant_provider_write(id)
    }
    pub fn authorize_provider_writes(&self, id: &str) -> Result<()> {
        self.grant_provider_write(id)
    }

    pub fn provider_writable(&self, id: &str) -> Result<bool> {
        let document = self.document()?;
        let Some(provider) = document.providers.iter().find(|provider| provider.id == id) else {
            return Ok(false);
        };
        if provider.status != "connected" || provider.read_only {
            return Ok(false);
        }
        Ok(!self.read_secret(provider)?.read_only)
    }

    /// Trusted native health evidence only; never a user-supplied success flag.
    /// Raw provider error text is deliberately not retained or returned.
    pub fn record_provider_health(&self, id: &str, report: &Value) -> Result<()> {
        validate_id(id)?;
        bounded_json(report, 16 * 1024)?;
        if let Some(provider_id) = report.get("providerId").and_then(Value::as_str) {
            ensure!(
                provider_id == id,
                "health evidence belongs to a different provider"
            );
        }
        let listed = report.get("canList").and_then(Value::as_bool) == Some(true);
        let accessible = report.get("repositoryAccessible").and_then(Value::as_bool) == Some(true);
        let empty = report.get("repositoryEmpty").and_then(Value::as_bool) == Some(true);
        let can_read = report.get("canRead").and_then(Value::as_bool);
        let key_verified = report.get("keyVerified").and_then(Value::as_bool);
        let healthy = listed
            && accessible
            && report.get("error").is_none_or(Value::is_null)
            && if empty {
                // An actual readonly API list + absent repository head authenticates
                // a new empty root without inventing a successful decrypt/read.
                can_read == Some(false) && key_verified == Some(false)
            } else {
                can_read == Some(true) && key_verified == Some(true)
            };
        self.transaction(|document| {
            let provider = document
                .providers
                .iter_mut()
                .find(|provider| provider.id == id)
                .context("provider not found")?;
            ensure!(
                provider.status != "disconnected",
                "provider is disconnected"
            );
            // A modified prefix/ref/read-only flag cannot be legitimized by a
            // health report for some other native credential binding.
            let secret = self.read_secret(provider)?;
            let durable = !parse_kind(&provider.kind)?.is_oauth()
                || secret.credentials["value"]["refresh_token"]
                    .as_str()
                    .is_some_and(|token| !token.trim().is_empty());
            provider.status = if healthy && durable {
                "connected"
            } else {
                "error"
            }
            .into();
            provider.error = if healthy && durable {
                None
            } else {
                Some(
                    "Provider health verification failed; reconnect or retry the native check."
                        .into(),
                )
            };
            Ok(())
        })
    }

    pub fn software(&self) -> Result<Vec<Value>> {
        self.document()?
            .software
            .iter()
            .map(|software| Ok(serde_json::to_value(software)?))
            .collect()
    }

    pub fn software_record(&self, id: &str) -> Result<Value> {
        validate_id(id)?;
        let document = self.document()?;
        let software = document
            .software
            .iter()
            .find(|software| software.id == id)
            .context("software not found")?;
        Ok(serde_json::to_value(software)?)
    }

    /// Bounded typed merge patch. Omitted baseline/grant/generation fields survive
    /// coalesced updates. Native authority is never inferred from tracked=true.
    pub fn update_software(&self, patch: &Value) -> Result<Value> {
        bounded_json(patch, 3 * 1024 * 1024)?;
        let id = required_str(patch, "id")?.to_owned();
        validate_id(&id)?;
        let patch = patch
            .as_object()
            .context("software update must be an object")?;
        if let Some(reference) = patch.get("pendingWork").filter(|value| !value.is_null()) {
            // Reject malformed private locators before any merge revocation or
            // native source admission. This validates shape only, never grants.
            model::validate_pending_work_reference(reference, &id)?;
        }
        self.transaction(|document| {
            let position = document
                .software
                .iter()
                .position(|software| software.id == id);
            let previous = position.map(|position| document.software[position].clone());
            let initial = match &previous {
                Some(previous) => previous.clone(),
                None => {
                    ensure!(
                        document.software.len() < model::MAX_SOFTWARE,
                        "too many software records"
                    );
                    StateSoftware::new(
                        id.clone(),
                        patch
                            .get("name")
                            .and_then(Value::as_str)
                            .context("new software needs a name")?
                            .to_owned(),
                    )
                }
            };
            let mut merged = serde_json::to_value(&initial)?;
            let object = merged
                .as_object_mut()
                .context("invalid software document")?;
            for (key, value) in patch {
                object.insert(key.clone(), value.clone());
            }
            let mut candidate: StateSoftware = serde_json::from_value(merged).map_err(|_| {
                anyhow::anyhow!("software update contains unknown or invalid fields")
            })?;
            ensure!(candidate.id == id, "software identity changed");
            ensure!(
                candidate.unknown_generation >= initial.unknown_generation,
                "unknown generation cannot move backwards"
            );
            if candidate.unknown_generation != initial.unknown_generation {
                // A newer uncertainty partition invalidates CURRENT cleanliness,
                // never the historical baseline/version or signed root authority.
                candidate.dirty = true;
                candidate.reconciliation_required = true;
            }
            if candidate.status == "saved" && (candidate.dirty || candidate.reconciliation_required)
            {
                candidate.status = if candidate.reconciliation_required {
                    "checking"
                } else {
                    "needs_backup"
                }
                .into();
            }
            // Never copy an old/upload-only confirmation into CURRENT truth.
            // Nor can a supplied confirmedGeneration override Tracker's flags.
            // A nonzero uncertainty partition does not permanently ban a later
            // clean result from the actual native receipt/index verification.
            candidate.confirmed_generation = candidate.current_confirmation();
            let tracking_changed = initial.roots != candidate.roots
                || initial.app_id != candidate.app_id
                || initial.source_identity != candidate.source_identity
                || initial.auto_enrollment != candidate.auto_enrollment
                || initial.tracked != candidate.tracked;
            let provider_changed = initial.provider_id != candidate.provider_id;
            if initial.tracking_grant.is_some() && candidate.tracking_grant.is_none() {
                self.revoke_bound("tracking", &json!({"softwareId":id}))?;
            }
            if initial.autosave && (!candidate.autosave || candidate.autosave_grant.is_none()) {
                self.revoke_bound("autosave", &json!({"softwareId":id}))?;
            }
            if tracking_changed && !patch.contains_key("trackingGrant") {
                if previous.is_some() {
                    self.revoke_bound("tracking", &json!({"softwareId":id}))?;
                }
                candidate.tracking_grant = None;
            }
            if (tracking_changed || provider_changed) && !patch.contains_key("autosaveGrant") {
                if previous.is_some() {
                    self.revoke_bound("autosave", &json!({"softwareId":id}))?;
                }
                candidate.autosave = false;
                candidate.autosave_grant = None;
            }
            candidate.validate()?;
            if let Some(stored) = candidate
                .tracking_grant
                .as_ref()
                .filter(|value| !value.is_null())
            {
                let scope = grant::tracking_scope(&candidate)?;
                ensure!(
                    self.verify_bound(document, &scope, stored)?,
                    "tracking grant does not authorize these roots/app"
                );
            }
            if candidate.autosave {
                let provider = document
                    .providers
                    .iter()
                    .find(|provider| Some(&provider.id) == candidate.provider_id.as_ref())
                    .context("autosave provider not found")?;
                let scope = grant::autosave_scope(&candidate, provider)?;
                let stored = candidate
                    .autosave_grant
                    .as_ref()
                    .context("autosave requires a native authority grant")?;
                ensure!(
                    self.verify_bound(document, &scope, stored)?,
                    "autosave grant does not authorize this scope"
                );
                ensure!(
                    candidate.tracking_grant.is_some(),
                    "autosave requires signed tracking authority"
                );
            }
            let value = serde_json::to_value(&candidate)?;
            if let Some(position) = position {
                document.software[position] = candidate;
            } else {
                document.software.push(candidate);
            }
            Ok(value)
        })
    }

    pub fn set_software_provider(&self, software_id: &str, provider_id: &str) -> Result<()> {
        validate_id(provider_id)?;
        self.transaction(|document| {
            ensure!(
                document
                    .providers
                    .iter()
                    .any(|provider| provider.id == provider_id),
                "provider not found"
            );
            let software = document
                .software
                .iter_mut()
                .find(|software| software.id == software_id)
                .context("software not found")?;
            if software.provider_id.as_deref() != Some(provider_id) {
                self.revoke_bound("autosave", &json!({"softwareId":software_id}))?;
                software.provider_id = Some(provider_id.into());
                software.autosave = false;
                software.autosave_grant = None;
            }
            Ok(())
        })
    }

    /// Caller must have native-approved exactly the current roots/app/allowlist.
    pub fn seal_tracking_grant(&self, software_id: &str) -> Result<Value> {
        self.transaction(|document| {
            let software = document
                .software
                .iter()
                .find(|software| software.id == software_id)
                .context("software not found")?;
            let signature =
                self.issue_bound(document, "tracking", &grant::tracking_scope(software)?)?;
            let software = document
                .software
                .iter_mut()
                .find(|software| software.id == software_id)
                .context("software not found")?;
            software.tracking_grant = Some(signature.clone());
            Ok(signature)
        })
    }

    pub fn verify_tracking_grant(&self, software_id: &str) -> Result<bool> {
        let document = self.document()?;
        self.verify_tracking_in_document(&document, software_id)
    }

    fn verify_tracking_in_document(
        &self,
        document: &WorkspaceDocument,
        software_id: &str,
    ) -> Result<bool> {
        let software = document
            .software
            .iter()
            .find(|software| software.id == software_id)
            .context("software not found")?;
        let Some(signature) = &software.tracking_grant else {
            return Ok(false);
        };
        let Ok(scope) = grant::tracking_scope(software) else {
            return Ok(false);
        };
        if !self.verify_bound(document, &scope, signature)? {
            return Ok(false);
        }
        if let Some(enrollment) = &software.auto_enrollment {
            if !self.verify_bound(
                document,
                &json!({"kind":"app_tracking_policy","scope":enrollment.policy_scope}),
                &enrollment.policy_grant,
            )? || !self.verify_bound(
                document,
                &json!({"kind":"bundle_discovery","scope":enrollment.discovery_scope}),
                &enrollment.discovery_grant,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn cached_tracking_verify(
        &self,
        document: &WorkspaceDocument,
        software: &StateSoftware,
    ) -> Result<bool> {
        let Some(signature) = &software.tracking_grant else {
            return Ok(false);
        };
        let scope = grant::tracking_scope(software)?;
        if !self.cached_verify(document, &scope, signature)? {
            return Ok(false);
        }
        if let Some(enrollment) = &software.auto_enrollment {
            if !self.cached_verify(
                document,
                &json!({"kind":"app_tracking_policy","scope":enrollment.policy_scope}),
                &enrollment.policy_grant,
            )? || !self.cached_verify(
                document,
                &json!({"kind":"bundle_discovery","scope":enrollment.discovery_scope}),
                &enrollment.discovery_grant,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Native-approved opt-in. Disable never creates/loads a device key.
    pub fn set_autosave(&self, software_id: &str, provider_id: &str, enabled: bool) -> Result<()> {
        self.transaction(|document| {
            let software = document
                .software
                .iter()
                .find(|software| software.id == software_id)
                .context("software not found")?;
            if !enabled {
                self.revoke_bound("autosave", &json!({"softwareId":software_id}))?;
                let software = document
                    .software
                    .iter_mut()
                    .find(|software| software.id == software_id)
                    .context("software not found")?;
                software.autosave = false;
                software.autosave_grant = None;
                return Ok(());
            }
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .context("provider not found")?;
            let secret = self.read_secret(provider)?;
            ensure!(!secret.read_only, "provider has no native write grant");
            let tracking_scope = grant::tracking_scope(software)?;
            let tracking_signature = software
                .tracking_grant
                .as_ref()
                .context("tracking authority must be approved before autosave")?;
            ensure!(
                self.verify_bound(document, &tracking_scope, tracking_signature)?,
                "tracking authority is invalid"
            );
            let signature = self.issue_bound(
                document,
                "autosave",
                &grant::autosave_scope(software, provider)?,
            )?;
            let software = document
                .software
                .iter_mut()
                .find(|software| software.id == software_id)
                .context("software not found")?;
            software.autosave = true;
            software.autosave_grant = Some(signature);
            Ok(())
        })
    }

    pub fn verify_autosave_grant(&self, software_id: &str, provider_id: &str) -> Result<bool> {
        let document = self.document()?;
        let software = document
            .software
            .iter()
            .find(|software| software.id == software_id)
            .context("software not found")?;
        if !software.autosave {
            return Ok(false);
        }
        let Some(provider) = document
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
        else {
            return Ok(false);
        };
        if provider.status != "connected" || provider.read_only {
            return Ok(false);
        }
        let (Some(tracking_signature), Some(signature)) =
            (&software.tracking_grant, &software.autosave_grant)
        else {
            return Ok(false);
        };
        let Ok(tracking_scope) = grant::tracking_scope(software) else {
            return Ok(false);
        };
        if !self.verify_bound(&document, &tracking_scope, tracking_signature)? {
            return Ok(false);
        }
        let Ok(scope) = grant::autosave_scope(software, provider) else {
            return Ok(false);
        };
        if !self.verify_bound(&document, &scope, signature)? {
            return Ok(false);
        }
        let secret = self.read_secret(provider)?;
        Ok(!secret.read_only)
    }

    /// Native callers may sign tracking/baseline scopes. A top-level providerId
    /// automatically adds its current exact native routing binding to the MAC.
    pub fn grant_seal(&self, scope: &Value) -> Result<Value> {
        self.transaction(|document| {
            let (kind, scope) = normalize_scope(scope)?;
            self.issue_bound(document, &kind, scope)
        })
    }

    pub fn grant_verify(&self, scope: &Value, signature: &Value) -> Result<bool> {
        if let Some(result) = metadata_verification::verify(self, scope, signature) {
            return result;
        }
        let document = self.document()?;
        self.verify_bound(&document, scope, signature)
    }

    pub fn issue_grant(&self, kind: &str, scope: &Value) -> Result<Value> {
        self.grant_seal(&json!({"kind":kind,"scope":scope}))
    }

    pub fn verify_grant(&self, kind: &str, scope: &Value, signature: &Value) -> Result<bool> {
        self.grant_verify(&json!({"kind":kind,"scope":scope}), signature)
    }

    pub fn revoke_grant(&self, kind: &str, scope: &Value) -> Result<()> {
        self.transaction(|_| self.revoke_bound(kind, scope))
    }

    pub fn grant_revoke(&self, scope: &Value) -> Result<()> {
        let (kind, scope) = normalize_scope(scope)?;
        self.revoke_grant(&kind, scope)
    }

    pub fn mark_dirty(&self, id: &str) -> Result<u64> {
        self.transaction(|document| {
            let software = document
                .software
                .iter_mut()
                .find(|software| software.id == id)
                .context("software not found")?;
            software.dirty_generation = software
                .dirty_generation
                .checked_add(1)
                .context("dirty generation exhausted")?;
            software.dirty = true;
            software.confirmed_generation = None;
            software.status = "needs_backup".into();
            Ok(software.dirty_generation)
        })
    }

    pub fn mark_saved(
        &self,
        id: &str,
        captured_generation: u64,
        version: &str,
        saved_at: &str,
    ) -> Result<()> {
        validate_text(version, 1024, "confirmed version")?;
        chrono::DateTime::parse_from_rfc3339(saved_at).context("saved time must be RFC3339")?;
        self.transaction(|document| {
            let software = document
                .software
                .iter_mut()
                .find(|software| software.id == id)
                .context("software not found")?;
            ensure!(
                captured_generation <= software.dirty_generation,
                "saved generation is in the future"
            );
            ensure!(
                captured_generation >= software.last_confirmed_uploaded_generation,
                "stale confirmation cannot replace a newer baseline"
            );
            software.last_confirmed_uploaded_generation = captured_generation;
            software.last_confirmed_version = Some(version.into());
            software.last_saved_at = Some(saved_at.into());
            software.dirty = software.dirty_generation != captured_generation;
            software.status = if software.dirty {
                "needs_backup"
            } else if software.reconciliation_required {
                "checking"
            } else {
                "saved"
            }
            .into();
            software.confirmed_generation = software.current_confirmation();
            Ok(())
        })
    }

    fn verify_bound(
        &self,
        document: &WorkspaceDocument,
        scope: &Value,
        signature: &Value,
    ) -> Result<bool> {
        bounded_json(signature, 1024)?;
        // Malformed/missing grants must not cause key creation or vault reads.
        if signature.get("version").and_then(Value::as_u64) != Some(1)
            || signature.get("algorithm").and_then(Value::as_str) != Some("hmac-sha256")
            || signature
                .get("mac")
                .and_then(Value::as_str)
                .is_none_or(|value| value.len() != 64)
        {
            return Ok(false);
        }
        let (kind, scope) = match normalize_scope(scope) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let payload = match signature_payload(document, &kind, scope, signature) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let Some(key) = self.device_key(false)? else {
            return Ok(false);
        };
        if !grant::verify(&key, &payload, signature)? {
            return Ok(false);
        }
        let account = authority_account(&kind, scope)?;
        let Some(stored) = self.inner.vault.read(QUICKSAVE_VAULT_SERVICE, &account)? else {
            return Ok(false);
        };
        let authority: Value = serde_json::from_str(&stored)
            .map_err(|_| anyhow::anyhow!("native authority registry is invalid"))?;
        if authority.get("version").and_then(Value::as_u64) != Some(1)
            || authority.get("active").and_then(Value::as_bool) != Some(true)
            || authority.get("nonce") != signature.get("nonce")
        {
            return Ok(false);
        }
        self.remember_verified(&payload, signature)?;
        Ok(true)
    }

    fn issue_bound(
        &self,
        document: &WorkspaceDocument,
        kind: &str,
        scope: &Value,
    ) -> Result<Value> {
        let key = self
            .device_key(true)?
            .context("device authority key missing")?;
        let mut random = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(random.as_mut())
            .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        let nonce = hex::encode(random.as_ref());
        let account = authority_account(kind, scope)?;
        let payload = json!({"scope":bind_scope(document,scope)?,"kind":kind,"nonce":nonce});
        let mut signature = grant::seal(&key, &payload)?;
        signature["kind"] = json!(kind);
        signature["nonce"] = json!(nonce);
        signature["authorityRef"] = json!(account);
        let registry = Zeroizing::new(serde_json::to_string(
            &json!({"version":1,"active":true,"nonce":nonce}),
        )?);
        self.inner
            .vault
            .write(QUICKSAVE_VAULT_SERVICE, &account, &registry)?;
        // Rotating a scope's native nonce invalidates every previously issued
        // signature, including a state.json rollback to an earlier "enabled".
        self.inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
            .retain(|_, (existing_account, _)| existing_account != &account);
        self.remember_verified(&payload, &signature)?;
        Ok(signature)
    }

    fn revoke_bound(&self, kind: &str, scope: &Value) -> Result<()> {
        let account = authority_account(kind, scope)?;
        self.inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
            .retain(|_, (existing_account, _)| existing_account != &account);
        self.inner.vault.write(
            QUICKSAVE_VAULT_SERVICE,
            &account,
            r#"{"version":1,"active":false}"#,
        )
    }

    fn remember_verified(&self, payload: &Value, signature: &Value) -> Result<()> {
        let mac = signature
            .get("mac")
            .and_then(Value::as_str)
            .context("grant MAC missing")?;
        let fingerprint = hex::encode(Sha256::digest(grant::canonical(payload)?));
        let mut verified = self
            .inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?;
        if verified.len() >= 16_384 {
            verified.clear();
        }
        let account = signature
            .get("authorityRef")
            .and_then(Value::as_str)
            .context("grant authority reference missing")?;
        verified.insert(mac.into(), (account.into(), fingerprint));
        Ok(())
    }

    fn cached_verify(
        &self,
        document: &WorkspaceDocument,
        scope: &Value,
        signature: &Value,
    ) -> Result<bool> {
        let (kind, scope) = normalize_scope(scope)?;
        let payload = signature_payload(document, &kind, scope, signature)?;
        let Some(mac) = signature.get("mac").and_then(Value::as_str) else {
            return Ok(false);
        };
        let fingerprint = hex::encode(Sha256::digest(grant::canonical(&payload)?));
        Ok(self
            .inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
            .get(mac)
            .is_some_and(|(_, expected)| expected == &fingerprint))
    }

    fn device_key(&self, create: bool) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let mut cache = self
            .inner
            .device_key
            .lock()
            .map_err(|_| anyhow::anyhow!("device key cache poisoned"))?;
        if let Some(key) = cache.as_ref() {
            return Ok(Some(key.clone()));
        }
        let key = match self
            .inner
            .vault
            .read(QUICKSAVE_VAULT_SERVICE, DEVICE_KEY_ACCOUNT)?
        {
            Some(encoded) => decode_key(&encoded)?,
            None if create => {
                let mut key = Zeroizing::new([0u8; 32]);
                OsRng
                    .try_fill_bytes(key.as_mut())
                    .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
                let encoded = Zeroizing::new(hex::encode(key.as_ref()));
                self.inner
                    .vault
                    .write(QUICKSAVE_VAULT_SERVICE, DEVICE_KEY_ACCOUNT, &encoded)?;
                ensure!(
                    self.inner
                        .vault
                        .read(QUICKSAVE_VAULT_SERVICE, DEVICE_KEY_ACCOUNT)?
                        .as_deref()
                        .map(String::as_str)
                        == Some(encoded.as_str()),
                    "native device-key persistence failed verification"
                );
                key
            }
            None => return Ok(None),
        };
        *cache = Some(key.clone());
        Ok(Some(key))
    }

    fn repository_key(&self, create: bool) -> Result<Option<Zeroizing<[u8; 32]>>> {
        match self
            .inner
            .vault
            .read(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT)?
        {
            Some(encoded) => Ok(Some(decode_key(&encoded)?)),
            None if create => {
                let mut key = Zeroizing::new([0u8; 32]);
                OsRng
                    .try_fill_bytes(key.as_mut())
                    .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
                let encoded = Zeroizing::new(hex::encode(key.as_ref()));
                self.inner.vault.write(
                    QUICKSAVE_VAULT_SERVICE,
                    REPOSITORY_KEY_ACCOUNT,
                    &encoded,
                )?;
                ensure!(
                    self.inner
                        .vault
                        .read(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT)?
                        .as_deref()
                        .map(String::as_str)
                        == Some(encoded.as_str()),
                    "native repository-key persistence failed verification"
                );
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    fn write_secret(&self, account: &str, secret: &SecretProfile) -> Result<()> {
        let encoded = Zeroizing::new(
            serde_json::to_string(secret)
                .map_err(|_| anyhow::anyhow!("protected profile encoding failed"))?,
        );
        self.inner
            .vault
            .write(QUICKSAVE_VAULT_SERVICE, account, &encoded)?;
        ensure!(
            self.inner
                .vault
                .read(QUICKSAVE_VAULT_SERVICE, account)?
                .as_deref()
                .map(String::as_str)
                == Some(encoded.as_str()),
            "native provider credential persistence failed verification"
        );
        Ok(())
    }

    fn read_secret(&self, provider: &ProviderRecord) -> Result<SecretProfile> {
        let encoded = self
            .inner
            .vault
            .read(QUICKSAVE_VAULT_SERVICE, &provider.credential_ref)?
            .context("provider credentials are missing; reconnect explicitly")?;
        ensure!(
            encoded.len() <= vault::MAX_VAULT_VALUE_BYTES,
            "protected provider profile exceeds its size bound"
        );
        let secret: SecretProfile = serde_json::from_str(&encoded)
            .map_err(|_| anyhow::anyhow!("protected provider profile is invalid"))?;
        secret.verify_binding(provider)?;
        Ok(secret)
    }
}

fn normalize_scope(scope: &Value) -> Result<(String, &Value)> {
    bounded_json(scope, 2 * 1024 * 1024)?;
    if let (Some(kind), Some(inner)) = (
        scope.get("kind").and_then(Value::as_str),
        scope.get("scope"),
    ) {
        validate_id(kind)?;
        ensure!(kind.len() <= 64, "authority kind exceeds limit");
        return Ok((kind.into(), inner));
    }
    let kind = if scope.get("tracking").is_some()
        && scope.get("name").is_some()
        && scope.get("hash").is_some()
    {
        "baseline"
    } else if scope.get("tracking").is_some() && scope.get("providerId").is_some() {
        "autosave"
    } else if scope.get("softwareId").is_some() && scope.get("roots").is_some() {
        "tracking"
    } else {
        "native"
    };
    Ok((kind.into(), scope))
}

fn authority_account(kind: &str, scope: &Value) -> Result<String> {
    validate_id(kind)?;
    ensure!(kind.len() <= 64, "authority kind exceeds limit");
    bounded_json(scope, 2 * 1024 * 1024)?;
    let subject = scope.get("softwareId").and_then(Value::as_str).or_else(|| {
        scope
            .get("tracking")
            .and_then(|tracking| tracking.get("softwareId"))
            .and_then(Value::as_str)
    });
    let subject = match subject {
        Some(subject) => {
            validate_id(subject)?;
            subject.to_owned()
        }
        None => hex::encode(Sha256::digest(grant::canonical(scope)?)),
    };
    // One durable registry slot per software/purpose, not an unbounded entry per
    // file baseline, root revision or autosave toggle.
    Ok(format!(
        "authority.{}",
        hex::encode(Sha256::digest(serde_json::to_vec(&(kind, subject))?))
    ))
}

fn signature_payload(
    document: &WorkspaceDocument,
    kind: &str,
    scope: &Value,
    signature: &Value,
) -> Result<Value> {
    ensure!(
        signature.get("kind").and_then(Value::as_str) == Some(kind),
        "grant kind mismatch"
    );
    let nonce = signature
        .get("nonce")
        .and_then(Value::as_str)
        .context("grant nonce missing")?;
    ensure!(
        nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid grant nonce"
    );
    let account = authority_account(kind, scope)?;
    ensure!(
        signature.get("authorityRef").and_then(Value::as_str) == Some(account.as_str()),
        "grant authority slot mismatch"
    );
    Ok(json!({"scope":bind_scope(document,scope)?,"kind":kind,"nonce":nonce}))
}

fn bind_scope(document: &WorkspaceDocument, scope: &Value) -> Result<Value> {
    bounded_json(scope, 2 * 1024 * 1024)?;
    let provider = match scope.get("providerId").filter(|value| !value.is_null()) {
        Some(value) => {
            let id = value
                .as_str()
                .context("grant provider ID is not a string")?;
            let provider = document
                .providers
                .iter()
                .find(|provider| provider.id == id)
                .context("grant provider not found")?;
            Some(grant::provider_authority(provider))
        }
        None => None,
    };
    Ok(json!({"scope":scope,"providerAuthority":provider,"keepLocalData":true}))
}

fn decode_document(bytes: &[u8]) -> Result<WorkspaceDocument> {
    ensure!(
        bytes.len() <= state_file::MAX_STATE_BYTES,
        "state.json exceeds 8 MiB"
    );
    let document: WorkspaceDocument = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("workspace state.json has invalid or unknown fields"))?;
    document.validate()?;
    Ok(document)
}

fn encode_document(document: &WorkspaceDocument) -> Result<Vec<u8>> {
    document.validate()?;
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        limit: state_file::MAX_STATE_BYTES,
    };
    serde_json::to_writer_pretty(&mut writer, document)?;
    Ok(std::mem::take(&mut writer.bytes))
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl Drop for LimitedWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("JSON exceeds bounded document size"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn bounded_json(value: &Value, limit: usize) -> Result<()> {
    // Bound traversal depth/node count before recursive serde serialization.
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        ensure!(
            nodes <= 100_000 && depth <= 64,
            "JSON exceeds structural limits"
        );
        match value {
            Value::Array(values) => {
                ensure!(
                    pending.len() + values.len() <= 100_000,
                    "JSON exceeds node limit"
                );
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                ensure!(
                    pending.len() + values.len() <= 100_000,
                    "JSON exceeds node limit"
                );
                ensure!(
                    values.keys().all(|key| key.len() <= 32_768),
                    "JSON object key exceeds limit"
                );
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::String(value) => ensure!(value.len() <= limit, "JSON string exceeds limit"),
            _ => {}
        }
    }
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).context("JSON exceeds bounded document size")?;
    // JSON may contain credentials. Always clear the sizing buffer.
    writer.bytes.zeroize();
    Ok(())
}

pub(crate) fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "invalid logical identifier"
    );
    Ok(())
}

pub(crate) fn validate_text(value: &str, max: usize, label: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid {label}"
    );
    Ok(())
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context("required string field is missing")
}

fn optional_str(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => bail!("optional provider field must be a string"),
    }
}

pub(crate) fn validate_provider_root(bucket: Option<&str>, prefix: Option<&str>) -> Result<()> {
    if let Some(bucket) = bucket {
        validate_text(bucket, 1024, "bucket/container")?;
        ensure!(
            !bucket.contains(['/', '\\', ':']) && bucket != "." && bucket != "..",
            "invalid bucket/container"
        );
    }
    if let Some(prefix) = prefix {
        ensure!(
            prefix.len() <= 4096
                && !prefix.chars().any(char::is_control)
                && !prefix.contains(['\\', ':']),
            "invalid provider prefix"
        );
        ensure!(
            !prefix.split('/').any(|part| part == "." || part == ".."),
            "provider prefix contains dot traversal"
        );
    }
    Ok(())
}

pub(crate) fn decode_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        encoded.len() == 64,
        "repository/device key encoding has wrong length"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded, key.as_mut())
        .map_err(|_| anyhow::anyhow!("repository/device key encoding is invalid"))?;
    Ok(key)
}

pub(crate) fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json(value);
            }
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                zeroize_json(value);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
    *value = Value::Null;
}

#[cfg(all(test, unix))]
mod tests;
