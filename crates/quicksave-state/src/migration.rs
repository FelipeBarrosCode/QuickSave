// SPDX-License-Identifier: GPL-3.0-only
//! Explicit native-approved migration. No startup migration, foreign namespace
//! inventory, legacy deletion, or missing-entry fallback is permitted.
use crate::{
    decode_document, encrypted_vault::VaultContents, secret_store::LockedSecretAccess,
    secret_store::ENCRYPTED_VAULT_ACCOUNT, vault::MAX_VAULT_ACCOUNTS, WorkspaceStore,
    QUICKSAVE_VAULT_SERVICE,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[path = "deferred_import.rs"]
mod deferred_import;
#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug)]
pub enum MigrationStage {
    LoadState,
    CheckNativeAnchor,
    Inventory,
    ReadLegacy,
    VerifyInventory,
    VerifyLegacy,
    PrepareEncrypted,
    WriteEncrypted,
    CommitAnchor,
    VerifyAnchor,
    PublishMetadata,
}
impl MigrationStage {
    pub(crate) fn attach(self, error: anyhow::Error) -> anyhow::Error {
        if error.downcast_ref::<Self>().is_some() {
            error
        } else {
            error.context(self)
        }
    }
}
impl std::fmt::Display for MigrationStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::LoadState => "opening local state",
            Self::CheckNativeAnchor => "checking the native encryption-key item",
            Self::Inventory => "listing old QuickSave credential items",
            Self::ReadLegacy => "reading old QuickSave credentials",
            Self::VerifyInventory => "rechecking the old credential inventory",
            Self::VerifyLegacy => "verifying old QuickSave credentials",
            Self::PrepareEncrypted => "preparing encrypted state",
            Self::WriteEncrypted => "writing encrypted state",
            Self::CommitAnchor => "saving the native encryption key",
            Self::VerifyAnchor => "verifying the native encryption key",
            Self::PublishMetadata => "publishing encrypted workspace metadata",
        })
    }
}
impl std::error::Error for MigrationStage {}

#[derive(Debug)]
enum MigrationCondition {
    AlreadyEncrypted,
    MissingEncryptedState,
    ScopeChanged,
    SourceChanged,
    Capacity,
}
impl std::fmt::Display for MigrationCondition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyEncrypted => "Encrypted storage already exists. Restart QuickSave instead of repeating migration; recovery may be needed if startup fails.",
            Self::MissingEncryptedState => "The native encryption-key item exists but its encrypted state is missing. Explicit recovery is required; no new key will be created.",
            Self::ScopeChanged => "The approved workspace changed. Obtain a new native approval.",
            Self::SourceChanged => "The old credential inventory or a required item changed or disappeared. Migration stopped before accepting a partial copy.",
            Self::Capacity => "The complete credential inventory cannot fit the bounded encrypted-state format. No items will be truncated.",
        })
    }
}
impl std::error::Error for MigrationCondition {}

/// A deliberately redacted diagnostic. Unknown backend errors are never
/// formatted: they may contain credential values, account names or file paths.
pub fn migration_error_message(error: &anyhow::Error) -> String {
    let stage = error
        .downcast_ref::<MigrationStage>()
        .map(ToString::to_string)
        .unwrap_or_else(|| "validating the migration request".into());
    let reason = if let Some(condition) = error.downcast_ref::<MigrationCondition>() {
        condition.to_string()
    } else if let Some(native) = error.downcast_ref::<crate::vault::NativeVaultFailure>() {
        if native.authorization_required() {
            format!("{native}. Existing items cannot be copied without macOS authorization.")
        } else {
            format!("{native}.")
        }
    } else if let Some(native) = error.downcast_ref::<std::io::Error>() {
        match native.kind() {
            std::io::ErrorKind::PermissionDenied => "Local storage access was denied.".into(),
            std::io::ErrorKind::NotFound => "Required local storage is missing.".into(),
            _ => "A native filesystem operation failed.".into(),
        }
    } else {
        "The required access, integrity check or storage operation did not succeed.".into()
    };
    format!("Migration stopped while {stage}: {reason}")
}

impl WorkspaceStore {
    /// Trusted native entry point ONLY after an explicit migration ticket was
    /// spent. The interactive backend is private and cannot escape into normal
    /// service/background operation. Root/generation are checked under the lock
    /// before any credential operation; no automatic migration or retry.
    pub fn migrate_with_native_authorization(
        data_dir: &std::path::Path,
        generation: u64,
        workspace_identity: &str,
    ) -> Result<Value> {
        let backing = std::sync::Arc::new(crate::vault::SessionVaultGate::new(
            std::sync::Arc::new(crate::vault::ApprovedMigrationVault),
        ));
        let store = Self::open_inner(data_dir, backing, false)?;
        store.migrate_to_encrypted_state_scoped(generation, workspace_identity)
    }

    /// Pure local format status, not proof that the native vault is unlocked.
    pub fn encrypted_vault_status(&self) -> Result<Value> {
        let document = self.document()?;
        let inventory_supported = self.inner.vault.account_inventory_supported();
        Ok(json!({
            "format":if document.encrypted_secrets.is_some() {"encrypted_state"} else {"legacy"},
            "secretsInPlaintext":false,
            "nativeAuthorizationVerified":false,
            "credentialSetupPending":document.credential_setup_pending,
            "migrationAutomatic":false,
            "legacyItemsDeleted":false,
            "legacyInventorySupported":inventory_supported,
            "legacyMigrationLimitation":if !inventory_supported && cfg!(windows) {
                Some("Bounded service-confined legacy Credential Manager inventory is not supported; no existing credentials will be guessed, discarded or scanned broadly.")
            } else if !inventory_supported {
                Some("This credential backend cannot provide a complete bounded legacy account inventory.")
            } else {None::<&str>},
        }))
    }

    /// Metadata-only native approval binding. Not an unlock or authority cache.
    pub fn encrypted_vault_migration_scope(&self) -> Result<Value> {
        let document = self.document()?;
        Ok(json!({
            "generation":document.generation,
            "workspaceIdentity":hex::encode(self.encrypted_workspace_binding()?),
            "format":if document.encrypted_secrets.is_some() {"encrypted_state"} else {"legacy"},
        }))
    }

    /// Recheck the native ticket's exact generation/root under the held OS lock.
    pub fn migrate_to_encrypted_state_scoped(
        &self,
        generation: u64,
        workspace_identity: &str,
    ) -> Result<Value> {
        ensure!(
            workspace_identity.len() == 64
                && workspace_identity
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid native encrypted-vault scope"
        );
        self.migrate_encrypted_inner(Some((generation, workspace_identity)))
    }

    /// Native Rust entry point. The service must spend its one-use native
    /// approval before calling this. Only QuickSave's own namespace is read.
    pub fn migrate_to_encrypted_state(&self) -> Result<Value> {
        self.migrate_encrypted_inner(None)
    }

    fn migrate_encrypted_inner(&self, expected: Option<(u64, &str)>) -> Result<Value> {
        let _operation = self
            .inner
            .operation
            .lock()
            .map_err(|_| anyhow::anyhow!("workspace state lock poisoned"))?;
        let locked = self.inner.file.lock().context(MigrationStage::LoadState)?;
        let bytes = locked
            .read()
            .context(MigrationStage::LoadState)?
            .context("workspace state disappeared")
            .context(MigrationStage::LoadState)?;
        let mut document = decode_document(&bytes).context(MigrationStage::LoadState)?;
        if let Some((generation, identity)) = expected {
            ensure!(
                generation == document.generation
                    && identity == hex::encode(self.encrypted_workspace_binding()?),
                MigrationCondition::ScopeChanged
            );
        }
        if document.encrypted_secrets.is_some() {
            // This hint may only deny an import, never authorize one. Completed
            // migrations do not needlessly touch the native item again.
            ensure!(
                document.credential_setup_pending,
                MigrationCondition::AlreadyEncrypted
            );
            return deferred_import::complete(self, &locked, document);
        }
        let generation = document
            .generation
            .checked_add(1)
            .context("state generation exhausted")?;
        let vault = self.inner.vault.as_ref();
        ensure!(
            vault
                .read(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
                .context(MigrationStage::CheckNativeAnchor)?
                .is_none(),
            MigrationCondition::MissingEncryptedState
        );
        let accounts = vault
            .accounts(QUICKSAVE_VAULT_SERVICE)
            .context(MigrationStage::Inventory)?;
        ensure!(
            accounts.len() <= MAX_VAULT_ACCOUNTS,
            MigrationCondition::Capacity
        );
        let mut contents = VaultContents {
            entries: BTreeMap::new(),
        };
        let mut total = 0usize;
        for account in &accounts {
            ensure!(
                !account.is_empty()
                    && account.len() <= 512
                    && !account.chars().any(char::is_control)
                    && account != ENCRYPTED_VAULT_ACCOUNT,
                MigrationCondition::SourceChanged
            );
            ensure!(
                account != crate::pending_legacy::PENDING_LEGACY_ACCOUNT,
                MigrationCondition::SourceChanged
            );
            let value = vault
                .read(QUICKSAVE_VAULT_SERVICE, account)
                .context(MigrationStage::ReadLegacy)?
                .ok_or(MigrationCondition::SourceChanged)
                .context(MigrationStage::ReadLegacy)?;
            total = total
                .checked_add(account.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(MigrationCondition::Capacity)
                .context(MigrationStage::ReadLegacy)?;
            ensure!(
                total <= crate::encrypted_vault::MAX_PLAINTEXT,
                MigrationCondition::Capacity
            );
            ensure!(
                !contents.entries.contains_key(account),
                MigrationCondition::SourceChanged
            );
            contents
                .entries
                .insert(account.clone(), value.as_str().to_owned());
        }
        // Cooperating QuickSave writers use this same OS lock. Revalidate the
        // complete native inventory and values before the migration commit.
        let mut final_accounts = vault
            .accounts(QUICKSAVE_VAULT_SERVICE)
            .context(MigrationStage::VerifyInventory)?;
        let mut initial_accounts = accounts.clone();
        initial_accounts.sort();
        final_accounts.sort();
        ensure!(
            initial_accounts == final_accounts,
            MigrationCondition::SourceChanged
        );
        for (account, expected) in &contents.entries {
            let observed = vault
                .read(QUICKSAVE_VAULT_SERVICE, account)
                .context(MigrationStage::VerifyLegacy)?
                .ok_or(MigrationCondition::SourceChanged)
                .context(MigrationStage::VerifyLegacy)?;
            ensure!(
                observed.as_str() == expected.as_str(),
                MigrationCondition::SourceChanged
            );
        }
        let count = contents.entries.len();
        let access = LockedSecretAccess::initialize(
            &locked,
            vault,
            self.encrypted_workspace_binding()?,
            contents,
        )
        .map_err(|error| MigrationStage::PrepareEncrypted.attach(error))?;
        document.generation = generation;
        access
            .publish_metadata(&document)
            .map_err(|error| MigrationStage::PublishMetadata.attach(error))?;
        *self
            .inner
            .device_key
            .lock()
            .map_err(|_| anyhow::anyhow!("device key cache poisoned"))? = None;
        self.inner
            .verified_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
            .clear();
        crate::metadata_verification::invalidate(self);
        Ok(json!({
            "format":"encrypted_state","migratedAccounts":count,
            "secretsInPlaintext":false,"legacyItemsDeleted":false,
            "activeNativeItemCount":1,"providerOrUploadStarted":false,
        }))
    }
}
