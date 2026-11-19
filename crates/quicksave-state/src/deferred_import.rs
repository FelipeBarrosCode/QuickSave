// SPDX-License-Identifier: GPL-3.0-only
//! Finish only the authenticated remaining inventory; never overwrite newer
//! local permissions, imported values, or deletion decisions.
use super::*;
use crate::{
    pending_legacy::{PendingLegacy, PENDING_LEGACY_ACCOUNT},
    state_file::LockedState,
    WorkspaceDocument,
};

pub(super) fn complete(
    store: &WorkspaceStore,
    locked: &LockedState<'_>,
    mut document: WorkspaceDocument,
) -> Result<Value> {
    let generation = document
        .generation
        .checked_add(1)
        .context("state generation exhausted")?;
    let access = LockedSecretAccess::new(
        locked,
        store.inner.vault.as_ref(),
        store.encrypted_workspace_binding()?,
    )
    .context(MigrationStage::CheckNativeAnchor)?;
    let encoded = access.read(QUICKSAVE_VAULT_SERVICE, PENDING_LEGACY_ACCOUNT)?;
    let manifest = match encoded {
        Some(encoded) => PendingLegacy::from_contents(&VaultContents {
            entries: BTreeMap::from([(PENDING_LEGACY_ACCOUNT.into(), encoded.as_str().into())]),
        })?
        .context("deferred inventory disappeared")?,
        None if document.credential_setup_pending => {
            // A prior secret commit may have completed before metadata
            // publication. Normalize from the authenticated slot, not old items.
            document.generation = generation;
            access.publish_metadata(&document)?;
            return Ok(json!({"format":"encrypted_state","migratedAccounts":0,
                "legacyItemsDeleted":false,"activeNativeItemCount":1}));
        }
        None => return Err(anyhow::Error::from(MigrationCondition::AlreadyEncrypted)),
    };
    let vault = store.inner.vault.as_ref();
    let inventory = || -> Result<Vec<String>> {
        let mut accounts = vault
            .accounts(QUICKSAVE_VAULT_SERVICE)
            .context(MigrationStage::Inventory)?;
        accounts.retain(|account| account != ENCRYPTED_VAULT_ACCOUNT);
        accounts.sort();
        ensure!(
            accounts.as_slice() == manifest.all_accounts(),
            MigrationCondition::SourceChanged
        );
        Ok(accounts)
    };
    let before = inventory()?;
    let mut contents = VaultContents {
        entries: BTreeMap::new(),
    };
    let mut total = 0usize;
    for account in manifest.remaining() {
        let value = vault
            .read(QUICKSAVE_VAULT_SERVICE, account)
            .context(MigrationStage::ReadLegacy)?
            .ok_or(MigrationCondition::SourceChanged)?;
        total = total
            .checked_add(account.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(MigrationCondition::Capacity)?;
        ensure!(
            total <= crate::encrypted_vault::MAX_PLAINTEXT,
            MigrationCondition::Capacity
        );
        contents
            .entries
            .insert(account.clone(), value.as_str().into());
    }
    ensure!(inventory()? == before, MigrationCondition::SourceChanged);
    for (account, value) in &contents.entries {
        let observed = vault
            .read(QUICKSAVE_VAULT_SERVICE, account)
            .context(MigrationStage::VerifyLegacy)?
            .ok_or(MigrationCondition::SourceChanged)?;
        ensure!(
            observed.as_str() == value.as_str(),
            MigrationCondition::SourceChanged
        );
    }
    access.complete_legacy_import(&contents.entries)?;
    document.generation = generation;
    access.publish_metadata(&document)?;
    store
        .inner
        .verified_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("authority cache poisoned"))?
        .clear();
    crate::metadata_verification::invalidate(store);
    Ok(
        json!({"format":"encrypted_state","migratedAccounts":contents.entries.len(),
        "legacyItemsDeleted":false,"activeNativeItemCount":1,"localTrackingPreserved":true}),
    )
}
