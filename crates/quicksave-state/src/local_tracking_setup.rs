// SPDX-License-Identifier: GPL-3.0-only
//! Local tracking requires a signing key, not bulk cloud-credential import.
use crate::{
    decode_document,
    encrypted_vault::VaultContents,
    pending_legacy::{PendingLegacy, PENDING_LEGACY_ACCOUNT},
    secret_store::{LockedSecretAccess, ENCRYPTED_VAULT_ACCOUNT},
    vault::{ApprovedMigrationVault, SessionVaultGate, MAX_VAULT_ACCOUNTS},
    WorkspaceStore, DEVICE_KEY_ACCOUNT, QUICKSAVE_VAULT_SERVICE,
};
use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "local_tracking_setup_tests.rs"]
mod tests;

impl WorkspaceStore {
    fn verify_encrypted_storage_access(&self) -> Result<()> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock()?;
        let _access = LockedSecretAccess::new(
            &locked,
            self.inner.vault.as_ref(),
            self.encrypted_workspace_binding()?,
        )?;
        Ok(())
    }

    /// One active native item, no legacy inventory or cloud/session construction.
    /// Ordinary NativeVault makes this check noninteractive on macOS.
    pub fn encrypted_storage_readiness(&self) -> Result<Value> {
        let result = self.verify_encrypted_storage_access();
        Ok(match result {
            Ok(()) => json!({"ready":true}),
            Err(_) => json!({"ready":false,"issue":
                "Local encrypted storage is locked, missing or failed an integrity check. Authorize access or review recovery; no key was replaced."}),
        })
    }

    pub fn authorize_tracking_storage_scoped(
        &self,
        generation: u64,
        identity: &str,
    ) -> Result<Value> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock()?;
        let document = decode_document(&locked.read()?.context("workspace state disappeared")?)?;
        ensure!(
            generation == document.generation
                && identity == hex::encode(self.encrypted_workspace_binding()?),
            "approved local storage authorization scope changed"
        );
        let _access = LockedSecretAccess::new(
            &locked,
            self.inner.vault.as_ref(),
            self.encrypted_workspace_binding()?,
        )?;
        Ok(json!({"ready":true,"trackingStarted":false,"legacyCredentialImport":false}))
    }

    /// Private interactive backend cannot escape into background workers.
    /// Confirm that normal noninteractive access works before reporting ready.
    pub fn authorize_tracking_storage_with_native_authorization(
        directory: &Path,
        generation: u64,
        identity: &str,
    ) -> Result<Value> {
        let backing = Arc::new(SessionVaultGate::new(Arc::new(ApprovedMigrationVault)));
        let interactive = Self::open_inner(directory, backing, false)?;
        interactive.authorize_tracking_storage_scoped(generation, identity)?;
        let normal = Self::open(directory)?;
        ensure!(normal.encrypted_storage_readiness()?["ready"] == true,
            "Persistent local storage access was not granted. Choose Always Allow for QuickSave's single local vault item to permit background tracking.");
        Ok(json!({"ready":true,"trackingStarted":false,"legacyCredentialImport":false}))
    }

    /// Native-ticket entry point; only this one action can request the existing
    /// signing-key authorization. No cloud/provider/repository value is read.
    pub fn setup_local_tracking_with_native_authorization(
        directory: &Path,
        generation: u64,
        identity: &str,
    ) -> Result<Value> {
        let backing = Arc::new(SessionVaultGate::new(Arc::new(ApprovedMigrationVault)));
        let store = Self::open_inner(directory, backing, false)?;
        store.setup_local_tracking_scoped(generation, identity)
    }

    /// Injected/native implementation after explicit local-setup approval.
    pub fn setup_local_tracking_scoped(&self, generation: u64, identity: &str) -> Result<Value> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock()?;
        let mut document =
            decode_document(&locked.read()?.context("workspace state disappeared")?)?;
        ensure!(
            generation == document.generation
                && identity == hex::encode(self.encrypted_workspace_binding()?),
            "approved local tracking setup scope changed"
        );
        ensure!(
            document.encrypted_secrets.is_none(),
            "encrypted local storage already exists; do not reset its keys"
        );
        let next_generation = generation
            .checked_add(1)
            .context("state generation exhausted")?;
        let vault = self.inner.vault.as_ref();
        ensure!(
            vault
                .read(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)?
                .is_none(),
            "native encryption anchor already exists; explicit recovery is required"
        );
        let mut accounts = vault.accounts(QUICKSAVE_VAULT_SERVICE)?;
        accounts.sort();
        ensure!(
            accounts.len() <= MAX_VAULT_ACCOUNTS
                && accounts.windows(2).all(|pair| pair[0] < pair[1])
                && !accounts
                    .iter()
                    .any(|account| account == ENCRYPTED_VAULT_ACCOUNT
                        || account == PENDING_LEGACY_ACCOUNT),
            "legacy account inventory is invalid"
        );
        let mut contents = VaultContents {
            entries: BTreeMap::new(),
        };
        let has_existing_signer = accounts.iter().any(|account| account == DEVICE_KEY_ACCOUNT);
        let encoded = if has_existing_signer {
            let encoded = vault
                .read(QUICKSAVE_VAULT_SERVICE, DEVICE_KEY_ACCOUNT)?
                .context("existing local signing key is unavailable")?;
            crate::decode_key(&encoded)?;
            encoded
        } else {
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(key.as_mut())
                .map_err(|_| anyhow::anyhow!("local signing randomness unavailable"))?;
            Zeroizing::new(hex::encode(key.as_ref()))
        };
        // Revalidate ONLY the signing key and account metadata. Cloud secrets
        // are not fetched, probed for readability, or treated as absent.
        let mut observed = vault.accounts(QUICKSAVE_VAULT_SERVICE)?;
        observed.sort();
        ensure!(
            accounts == observed,
            "legacy account inventory changed during local setup"
        );
        if has_existing_signer {
            let verified = vault
                .read(QUICKSAVE_VAULT_SERVICE, DEVICE_KEY_ACCOUNT)?
                .context("local signing key disappeared")?;
            ensure!(
                verified.as_str() == encoded.as_str(),
                "local signing key changed"
            );
        }
        contents
            .entries
            .insert(DEVICE_KEY_ACCOUNT.into(), encoded.as_str().into());
        let remaining = accounts
            .iter()
            .filter(|account| account.as_str() != DEVICE_KEY_ACCOUNT)
            .cloned()
            .collect::<Vec<_>>();
        let deferred = remaining.len();
        if !remaining.is_empty() {
            PendingLegacy::new(accounts, remaining)?.install(&mut contents)?;
        }
        let access = LockedSecretAccess::initialize(
            &locked,
            vault,
            self.encrypted_workspace_binding()?,
            contents,
        )?;
        document.generation = next_generation;
        access.publish_metadata(&document)?;
        *self
            .inner
            .device_key
            .lock()
            .map_err(|_| anyhow::anyhow!("device cache poisoned"))? = None;
        self.inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
            .clear();
        crate::metadata_verification::invalidate(self);
        Ok(json!({"format":"encrypted_state","localTrackingSetup":true,
            "legacyCredentialsDeferred":deferred,"trackingStarted":false,
            "cloudOrUploadStarted":false,"oldCredentialValuesChanged":false}))
    }
}
