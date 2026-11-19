// SPDX-License-Identifier: GPL-3.0-only
//! A borrowed, non-reentrant state-lock context. The native item selects exactly
//! one encrypted slot; neither local generation nor a recovery fallback does.
use crate::{
    decode_document, encode_document,
    encrypted_vault::{EncryptedVault, VaultContents},
    migration::MigrationStage,
    pending_legacy::{LegacyCredentialDeferred, PendingLegacy, PENDING_LEGACY_ACCOUNT},
    state_file::LockedState,
    CredentialVault, WorkspaceDocument, QUICKSAVE_VAULT_SERVICE,
};
use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const ENCRYPTED_VAULT_ACCOUNT: &str = "QuickSaveEncryptedStateVault.v1";
const MAX_ANCHOR_BYTES: usize = 4096;

/// Request-scoped logical secret operations. Intentionally NOT Send + Sync:
/// a borrowed OS-lock context must not impersonate a process-global vault.
pub(crate) trait SecretAccess {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>>;
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
}

/// Explicit compatibility boundary, selected only for an unmigrated document.
/// This wrapper is never consulted by LockedSecretAccess for missing entries.
pub(crate) struct LegacySecretAccess<'a>(pub(crate) &'a dyn CredentialVault);

impl SecretAccess for LegacySecretAccess<'_> {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        self.0.read(service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            account != PENDING_LEGACY_ACCOUNT,
            "reserved migration account"
        );
        self.0.write(service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        ensure!(
            account != PENDING_LEGACY_ACCOUNT,
            "reserved migration account"
        );
        self.0.delete(service, account)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncryptedSecretsSlots {
    pub current: EncryptedVault,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<EncryptedVault>,
}

impl EncryptedSecretsSlots {
    pub(crate) fn validate(&self) -> Result<()> {
        self.current.validate()?;
        if let Some(candidate) = &self.candidate {
            candidate.validate()?;
            ensure!(
                self.current.revision.checked_add(1) == Some(candidate.revision),
                "encrypted vault candidate revision is not consecutive"
            );
        }
        Ok(())
    }

    fn selected(&self, anchor: &Anchor) -> Result<&EncryptedVault> {
        self.validate()?;
        for envelope in std::iter::once(&self.current).chain(self.candidate.iter()) {
            if envelope.revision == anchor.revision && envelope.digest()? == anchor.digest {
                return Ok(envelope);
            }
        }
        anyhow::bail!("encrypted state does not match the native vault anchor")
    }
}

// Never Debug: the one native item contains the KEK as well as the anchor.
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Anchor {
    version: u32,
    workspace_binding: [u8; 32],
    key: [u8; 32],
    revision: u64,
    digest: [u8; 32],
}

impl Drop for Anchor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn read_native_anchor(vault: &dyn CredentialVault, workspace_binding: &[u8; 32]) -> Result<Anchor> {
    let encoded = vault
        .read(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)?
        .context("native encrypted vault item is missing; explicit recovery is required")?;
    ensure!(
        encoded.len() <= MAX_ANCHOR_BYTES,
        "native vault anchor exceeds limit"
    );
    let anchor: Anchor = serde_json::from_str(&encoded)
        .map_err(|_| anyhow::anyhow!("native vault anchor is invalid"))?;
    ensure!(
        anchor.version == 1
            && anchor.revision > 0
            && &anchor.workspace_binding == workspace_binding,
        "native vault anchor belongs to another workspace or format"
    );
    Ok(anchor)
}

/// READ-ONLY, request-scoped metadata verification. No filesystem access and no
/// publication authority. Parent must retain its end-of-frame state/root check.
/// Retain ONE context per frame to reuse decryption; every read still fetches
/// the actual persistent native anchor before consulting the decrypted map.
pub(crate) struct SnapshotSecretAccess {
    slots: EncryptedSecretsSlots,
    vault: Arc<dyn CredentialVault>,
    workspace_binding: [u8; 32],
    current_digest: [u8; 32],
    candidate_digest: Option<[u8; 32]>,
    invalidated: Cell<bool>,
    // Neither this context, the anchor nor decrypted contents implement Debug.
    // VaultContents and Anchor zeroize their secrets on eviction/drop.
    cached: RefCell<Option<(Anchor, VaultContents)>>,
}

impl SnapshotSecretAccess {
    pub(crate) fn new(
        snapshot: &WorkspaceDocument,
        vault: Arc<dyn CredentialVault>,
        workspace_binding: [u8; 32],
    ) -> Result<Self> {
        let slots = snapshot
            .encrypted_secrets
            .as_ref()
            .context("metadata snapshot has no encrypted vault")?;
        slots.validate()?;
        Ok(Self {
            slots: slots.clone(),
            vault,
            workspace_binding,
            current_digest: slots.current.digest()?,
            candidate_digest: slots
                .candidate
                .as_ref()
                .map(EncryptedVault::digest)
                .transpose()?,
            invalidated: Cell::new(false),
            cached: RefCell::new(None),
        })
    }

    fn selected(&self, anchor: &Anchor) -> Result<&EncryptedVault> {
        if anchor.revision == self.slots.current.revision && anchor.digest == self.current_digest {
            return Ok(&self.slots.current);
        }
        if let Some(candidate) = &self.slots.candidate {
            if anchor.revision == candidate.revision && Some(anchor.digest) == self.candidate_digest
            {
                return Ok(candidate);
            }
        }
        Err(crate::MetadataProjectionChanged.into())
    }
}

impl SecretAccess for SnapshotSecretAccess {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "legacy vault fallback forbidden"
        );
        validate_account(account)?;
        // Never move this check behind the plaintext cache or accept missing /
        // denied native state as permission to reuse a previous successful read.
        let anchor = read_native_anchor(self.vault.as_ref(), &self.workspace_binding)?;
        if self.invalidated.get() {
            return Err(crate::MetadataProjectionChanged.into());
        }
        let mut cached = self.cached.borrow_mut();
        if let Some((previous, _)) = cached.as_ref() {
            if previous != &anchor {
                // Even when both envelopes appear in the frozen document, an
                // observed transition invalidates this frame rather than mixing
                // old and new authority across its individual verifications.
                *cached = None;
                self.invalidated.set(true);
                return Err(crate::MetadataProjectionChanged.into());
            }
        } else {
            let envelope = self.selected(&anchor).map_err(|error| {
                self.invalidated.set(true);
                error
            })?;
            let contents = envelope.open(
                &anchor.key,
                &self.workspace_binding,
                anchor.revision,
                &anchor.digest,
            )?;
            PendingLegacy::from_contents(&contents)?;
            *cached = Some((anchor, contents));
        }
        read_entry(
            &cached
                .as_ref()
                .context("metadata secret cache is unavailable")?
                .1,
            account,
        )
    }

    fn write(&self, _: &str, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("metadata snapshot secret access is read-only")
    }

    fn delete(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("metadata snapshot secret access is read-only")
    }
}

pub(crate) struct LockedSecretAccess<'a> {
    locked: &'a LockedState<'a>,
    vault: &'a dyn CredentialVault,
    workspace_binding: [u8; 32],
    persisted: RefCell<WorkspaceDocument>,
}

impl<'a> LockedSecretAccess<'a> {
    /// Never initializes, falls back to legacy entries, or acquires another lock.
    pub(crate) fn new(
        locked: &'a LockedState<'a>,
        vault: &'a dyn CredentialVault,
        workspace_binding: [u8; 32],
    ) -> Result<Self> {
        let document = decode_document(&locked.read()?.context("workspace state disappeared")?)?;
        ensure!(
            document.encrypted_secrets.is_some(),
            "encrypted vault requires explicit initialization or migration"
        );
        let access = Self {
            locked,
            vault,
            workspace_binding,
            persisted: RefCell::new(document),
        };
        // Authentication, not merely schema validation, is required on entry.
        let _ = access.load()?;
        Ok(access)
    }

    /// Explicit creation/migration only. Caller supplies the COMPLETE trusted
    /// inventory. No source item is modified or used as a missing-entry fallback.
    /// Failure after file publication deliberately leaves a fail-closed state.
    pub(crate) fn initialize(
        locked: &'a LockedState<'a>,
        vault: &'a dyn CredentialVault,
        workspace_binding: [u8; 32],
        contents: VaultContents,
    ) -> Result<Self> {
        PendingLegacy::from_contents(&contents)?;
        let mut document =
            decode_document(&locked.read()?.context("workspace state disappeared")?)?;
        ensure!(
            document.encrypted_secrets.is_none(),
            "encrypted vault is already present; initialization cannot reset it"
        );
        ensure!(
            vault
                .read(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
                .context(MigrationStage::CheckNativeAnchor)?
                .is_none(),
            "native encrypted vault item already exists; initialization cannot replace it"
        );
        let mut anchor = Anchor {
            version: 1,
            workspace_binding,
            key: [0; 32],
            revision: 1,
            digest: [0; 32],
        };
        OsRng
            .try_fill_bytes(&mut anchor.key)
            .map_err(|_| anyhow::anyhow!("secure vault randomness unavailable"))?;
        let envelope = EncryptedVault::seal(&anchor.key, &workspace_binding, 1, &contents)?;
        anchor.digest = envelope.digest()?;
        document.encrypted_secrets = Some(EncryptedSecretsSlots {
            current: envelope,
            candidate: None,
        });
        document.credential_setup_pending = PendingLegacy::from_contents(&contents)?.is_some();
        // Preflight complete file bounds before touching the native item.
        let bytes = encode_document(&document)?;
        locked
            .replace(&bytes)
            .context(MigrationStage::WriteEncrypted)?;
        ensure!(
            locked
                .read()
                .context(MigrationStage::WriteEncrypted)?
                .as_deref()
                == Some(bytes.as_slice()),
            MigrationStage::WriteEncrypted
        );
        let access = Self {
            locked,
            vault,
            workspace_binding,
            persisted: RefCell::new(document),
        };
        access
            .write_anchor(&anchor)
            .map_err(|error| MigrationStage::CommitAnchor.attach(error))?;
        let _ = access
            .load()
            .map_err(|error| MigrationStage::VerifyAnchor.attach(error))?;
        Ok(access)
    }

    fn read_anchor(&self) -> Result<Anchor> {
        read_native_anchor(self.vault, &self.workspace_binding)
    }

    fn write_anchor(&self, expected: &Anchor) -> Result<()> {
        let encoded = Zeroizing::new(
            serde_json::to_string(expected)
                .map_err(|_| anyhow::anyhow!("native vault anchor encoding failed"))?,
        );
        ensure!(
            encoded.len() <= MAX_ANCHOR_BYTES,
            "native vault anchor exceeds limit"
        );
        // Even an error may have changed the native item. Do not compensate by
        // restoring an older key/anchor, and attempt read-back on either outcome.
        let outcome = self
            .vault
            .write(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT, &encoded);
        let observed = self.read_anchor()?;
        ensure!(
            &observed == expected,
            "native vault anchor failed read-back verification"
        );
        outcome?;
        Ok(())
    }

    fn load(&self) -> Result<(Anchor, EncryptedVault, VaultContents)> {
        let document =
            decode_document(&self.locked.read()?.context("workspace state disappeared")?)?;
        let anchor = self.read_anchor()?;
        let envelope = document
            .encrypted_secrets
            .as_ref()
            .context("encrypted vault disappeared")?
            .selected(&anchor)?
            .clone();
        let contents = envelope.open(
            &anchor.key,
            &self.workspace_binding,
            anchor.revision,
            &anchor.digest,
        )?;
        PendingLegacy::from_contents(&contents)?;
        *self.persisted.borrow_mut() = document;
        Ok((anchor, envelope, contents))
    }

    fn replace_document(&self, document: WorkspaceDocument) -> Result<()> {
        let bytes = encode_document(&document)?;
        // Refresh the observed native file version before EVERY replacement,
        // but never overwrite an intervening edit simply because it was reread.
        let observed =
            decode_document(&self.locked.read()?.context("workspace state disappeared")?)?;
        ensure!(
            observed == *self.persisted.borrow(),
            "workspace changed during encrypted vault operation"
        );
        self.locked.replace(&bytes)?;
        ensure!(
            self.locked.read()?.as_deref() == Some(bytes.as_slice()),
            "encrypted workspace replacement failed read-back"
        );
        *self.persisted.borrow_mut() = document;
        Ok(())
    }

    fn mutate(&self, change: impl FnOnce(&mut VaultContents) -> Result<bool>) -> Result<()> {
        let (mut anchor, current, mut contents) = self.load()?;
        if !change(&mut contents)? {
            return Ok(());
        }
        let revision = anchor
            .revision
            .checked_add(1)
            .context("vault revision exhausted")?;
        let candidate =
            EncryptedVault::seal(&anchor.key, &self.workspace_binding, revision, &contents)?;
        let digest = candidate.digest()?;
        // Always derive metadata from the last PERSISTED state, never from an
        // outer transaction's edited document.
        let mut prepared = self.persisted.borrow().clone();
        prepared.encrypted_secrets = Some(EncryptedSecretsSlots {
            current,
            candidate: Some(candidate),
        });
        self.replace_document(prepared)?;
        anchor.revision = revision;
        anchor.digest = digest;
        self.write_anchor(&anchor)?;
        // Leave both slots durable. The next mutation or publish normalizes;
        // absence of cleanup can never undo the anchor-selected mutation.
        Ok(())
    }

    pub(crate) fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "legacy vault fallback forbidden"
        );
        validate_account(account)?;
        let (_, _, contents) = self.load()?;
        read_entry(&contents, account)
    }

    pub(crate) fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "writes outside QuickSave vault forbidden"
        );
        validate_account(account)?;
        ensure!(
            account != PENDING_LEGACY_ACCOUNT,
            "reserved migration account"
        );
        ensure!(
            value.len() <= crate::encrypted_vault::MAX_PLAINTEXT,
            "encrypted vault value exceeds limit"
        );
        self.mutate(|contents| {
            let removed_pending = remove_pending(contents, account)?;
            if contents
                .entries
                .get(account)
                .is_some_and(|old| old == value)
            {
                return Ok(removed_pending);
            }
            if let Some(mut previous) = contents.entries.insert(account.into(), value.into()) {
                previous.zeroize();
            }
            Ok(true)
        })
    }

    pub(crate) fn delete(&self, service: &str, account: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "deletes outside QuickSave vault forbidden"
        );
        validate_account(account)?;
        ensure!(
            account != PENDING_LEGACY_ACCOUNT,
            "reserved migration account"
        );
        self.mutate(|contents| {
            let removed_pending = remove_pending(contents, account)?;
            if let Some(mut previous) = contents.entries.remove(account) {
                previous.zeroize();
                return Ok(true);
            }
            Ok(removed_pending)
        })
    }

    /// Only the caller holding the state lock may supply the verified source
    /// values. Exact pending keys prevent resurrection after grant/revocation.
    pub(crate) fn complete_legacy_import(&self, entries: &BTreeMap<String, String>) -> Result<()> {
        self.mutate(|contents| {
            let manifest = PendingLegacy::from_contents(contents)?
                .context("no pending legacy import exists")?;
            ensure!(
                entries.keys().eq(manifest.remaining().iter()),
                "legacy import payload does not match pending accounts"
            );
            for (account, value) in entries {
                validate_account(account)?;
                ensure!(
                    !contents.entries.contains_key(account),
                    "legacy import would overwrite a current credential"
                );
                ensure!(
                    value.len() <= crate::encrypted_vault::MAX_PLAINTEXT,
                    "legacy import value exceeds limit"
                );
            }
            for (account, value) in entries {
                contents.entries.insert(account.clone(), value.clone());
            }
            if let Some(mut encoded) = contents.entries.remove(PENDING_LEGACY_ACCOUNT) {
                encoded.zeroize();
            }
            Ok(true)
        })
    }

    /// Parent owns metadata generation arithmetic. This method only merges the
    /// freshly authenticated committed slot into the supplied metadata candidate.
    pub(crate) fn publish_metadata(&self, document: &WorkspaceDocument) -> Result<()> {
        let (_, selected, contents) = self.load()?;
        let mut merged = document.clone();
        merged.encrypted_secrets = Some(EncryptedSecretsSlots {
            current: selected,
            candidate: None,
        });
        merged.credential_setup_pending = PendingLegacy::from_contents(&contents)?.is_some();
        self.replace_document(merged)
    }
}

fn read_entry(contents: &VaultContents, account: &str) -> Result<Option<Zeroizing<String>>> {
    let manifest = PendingLegacy::from_contents(contents)?;
    if !contents.entries.contains_key(account)
        && manifest.as_ref().is_some_and(|pending| {
            pending
                .remaining()
                .binary_search_by(|candidate| candidate.as_str().cmp(account))
                .is_ok()
        })
    {
        return Err(LegacyCredentialDeferred.into());
    }
    Ok(contents.entries.get(account).cloned().map(Zeroizing::new))
}

fn remove_pending(contents: &mut VaultContents, account: &str) -> Result<bool> {
    let Some(mut manifest) = PendingLegacy::from_contents(contents)? else {
        return Ok(false);
    };
    if !manifest.remove(account) {
        return Ok(false);
    }
    manifest.install(contents)?;
    Ok(true)
}

fn validate_account(account: &str) -> Result<()> {
    ensure!(
        !account.is_empty() && account.len() <= 512 && !account.chars().any(char::is_control),
        "invalid encrypted vault account"
    );
    Ok(())
}

impl SecretAccess for LockedSecretAccess<'_> {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        LockedSecretAccess::read(self, service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        LockedSecretAccess::write(self, service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        LockedSecretAccess::delete(self, service, account)
    }
}

#[cfg(all(test, unix))]
#[path = "secret_store_tests.rs"]
mod tests;
