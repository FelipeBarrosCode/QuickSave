// SPDX-License-Identifier: GPL-3.0-only
//! Isolated state and synthetic vault entries only; no OS vault or accounts.
use super::*;
use crate::{CredentialVault, MemoryVault};
use std::{path::Path, sync::Arc};

fn fixture() -> (tempfile::TempDir, MemoryVault, WorkspaceStore) {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let vault = MemoryVault::default();
    let store =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    (temp, vault, store)
}

fn restore_state(store: &WorkspaceStore, bytes: &[u8]) {
    let locked = store.inner.file.lock().unwrap();
    locked.read().unwrap();
    locked.replace(bytes).unwrap();
}

#[test]
fn migration_preserves_all_legacy_items_and_existing_grants_but_never_falls_back() {
    let (temp, vault, store) = fixture();
    vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "unreferenced-recovery-authority",
            "synthetic-retained-proof",
        )
        .unwrap();
    vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "provider.orphan",
            "synthetic-orphan-token",
        )
        .unwrap();
    let scope = json!({"softwareId":"fixture-app","purpose":"external-retained-work"});
    let signature = store.grant_seal(&scope).unwrap();
    assert!(store.grant_verify(&scope, &signature).unwrap());
    let old_state = std::fs::read(temp.path().join("workspace/state.json")).unwrap();
    let accounts = vault.accounts(QUICKSAVE_VAULT_SERVICE).unwrap();
    let original: BTreeMap<_, _> = accounts
        .iter()
        .map(|account| {
            (
                account.clone(),
                vault
                    .read(QUICKSAVE_VAULT_SERVICE, account)
                    .unwrap()
                    .unwrap(),
            )
        })
        .collect();
    let migration = store.migrate_to_encrypted_state().unwrap();
    assert_eq!(migration["migratedAccounts"], accounts.len());
    assert_eq!(migration["legacyItemsDeleted"], false);
    let encrypted_state =
        std::fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    assert!(encrypted_state.contains("\"encryptedSecrets\""));
    assert!(!encrypted_state.contains("synthetic-orphan-token"));
    assert!(!encrypted_state.contains("synthetic-retained-proof"));
    for (account, value) in &original {
        assert_eq!(
            vault
                .read(QUICKSAVE_VAULT_SERVICE, account)
                .unwrap()
                .unwrap()
                .as_str(),
            value.as_str()
        );
    }
    let checkpoint = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    assert!(store.grant_verify(&scope, &signature).unwrap());
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .clone();
    assert!(reads[checkpoint..]
        .iter()
        .all(|read| read[1] == ENCRYPTED_VAULT_ACCOUNT));
    // Old complete plaintext state must not resurrect retained native records.
    restore_state(&store, &old_state);
    let restored =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    assert!(!restored.grant_verify(&scope, &signature).unwrap_or(false));
    assert!(restored.migrate_to_encrypted_state().is_err());
}

#[test]
fn metadata_only_queries_and_updates_preserve_envelope_without_native_access() {
    let (_temp, vault, store) = fixture();
    store.migrate_to_encrypted_state().unwrap();
    let before = store.document().unwrap().encrypted_secrets.clone();
    let access = vault.access_log().unwrap();
    assert_eq!(
        store.encrypted_vault_status().unwrap()["format"],
        "encrypted_state"
    );
    store.sanitized().unwrap();
    store
        .transaction(|document| {
            document.settings.launch_at_login = true;
            Ok(())
        })
        .unwrap();
    assert_eq!(store.document().unwrap().encrypted_secrets, before);
    assert_eq!(vault.access_log().unwrap(), access);
}

#[test]
fn missing_anchor_after_migration_never_generates_replacement_keys() {
    let (_temp, vault, store) = fixture();
    let scope = json!({"softwareId":"fixture-app","purpose":"retained"});
    let signature = store.grant_seal(&scope).unwrap();
    store.migrate_to_encrypted_state().unwrap();
    vault
        .delete(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
        .unwrap();
    let before = vault.access_log().unwrap()["writes"].clone();
    assert!(store.grant_verify(&scope, &signature).is_err());
    assert!(store.grant_seal(&scope).is_err());
    assert_eq!(vault.access_log().unwrap()["writes"], before);
}

#[test]
fn migration_read_denial_does_not_publish_or_mutate_source_items() {
    let (_temp, vault, store) = fixture();
    vault
        .seed(QUICKSAVE_VAULT_SERVICE, "retained", "synthetic-secret")
        .unwrap();
    let before = store.document().unwrap();
    vault.deny_access(true).unwrap();
    assert!(store.migrate_to_encrypted_state().is_err());
    assert_eq!(store.document().unwrap(), before);
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    vault.deny_access(false).unwrap();
    assert_eq!(
        vault
            .read(QUICKSAVE_VAULT_SERVICE, "retained")
            .unwrap()
            .unwrap()
            .as_str(),
        "synthetic-secret"
    );
}

#[test]
fn unsupported_inventory_is_not_treated_as_an_empty_vault() {
    struct NoInventory(MemoryVault);
    impl CredentialVault for NoInventory {
        fn read(&self, service: &str, account: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
            self.0.read(service, account)
        }
        fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
            self.0.write(service, account, value)
        }
        fn delete(&self, service: &str, account: &str) -> Result<()> {
            self.0.delete(service, account)
        }
    }
    let base = std::env::temp_dir().canonicalize().unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let backing = MemoryVault::default();
    let store = WorkspaceStore::open_with_vault(
        &temp.path().join(Path::new("workspace")),
        Arc::new(NoInventory(backing.clone())),
    )
    .unwrap();
    assert!(store.migrate_to_encrypted_state().is_err());
    assert!(store.document().unwrap().encrypted_secrets.is_none());
    assert_eq!(backing.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn independent_encrypted_handles_preserve_concurrent_grant_updates() {
    let (temp, vault, store) = fixture();
    store.migrate_to_encrypted_state().unwrap();
    let path = temp.path().join("workspace");
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4).map(|index| {
        let path = path.clone();
        let vault = vault.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let store = WorkspaceStore::open_with_vault(&path,Arc::new(vault)).unwrap();
            barrier.wait();
            let scope = json!({"softwareId":format!("parallel-{index}"),"purpose":"retained-operation"});
            let signature = store.grant_seal(&scope).unwrap();
            (scope,signature)
        })
    }).collect();
    for worker in workers {
        let (scope, signature) = worker.join().unwrap();
        assert!(store.grant_verify(&scope, &signature).unwrap());
    }
    let accounts = vault.accounts(QUICKSAVE_VAULT_SERVICE).unwrap();
    assert_eq!(accounts, vec![ENCRYPTED_VAULT_ACCOUNT.to_owned()]);
}

#[test]
fn native_scope_changes_are_rejected_before_any_credential_read() {
    let (_temp, vault, store) = fixture();
    let scope = store.encrypted_vault_migration_scope().unwrap();
    let before = vault.access_log().unwrap();
    store
        .transaction(|document| {
            document.settings.launch_at_login = true;
            Ok(())
        })
        .unwrap();
    assert!(store
        .migrate_to_encrypted_state_scoped(
            scope["generation"].as_u64().unwrap(),
            scope["workspaceIdentity"].as_str().unwrap()
        )
        .is_err());
    assert_eq!(vault.access_log().unwrap(), before);
}

#[cfg(unix)]
#[test]
fn encrypted_metadata_frame_keeps_one_state_snapshot_and_fresh_native_authority_reads() {
    let (temp, vault, store) = fixture();
    let scope = json!({"softwareId":"synthetic-metadata","roots":[]});
    let signature = store.issue_grant("tracking", &scope).unwrap();
    store.migrate_to_encrypted_state().unwrap();
    let state = temp.path().join("workspace/state.json");
    let held = temp.path().join("workspace/held-test-state.json");
    let before = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    store
        .with_metadata_verification_snapshot(|| {
            std::fs::rename(&state, &held)?;
            let result = (|| {
                for _ in 0..4096 {
                    assert!(store.verify_grant("tracking", &scope, &signature)?);
                }
                let worker_store = store.clone();
                let worker_scope = scope.clone();
                let worker_signature = signature.clone();
                assert!(std::thread::spawn(move || worker_store
                    .verify_grant("tracking", &worker_scope, &worker_signature)
                    .is_err())
                .join()
                .unwrap());
                Ok(())
            })();
            std::fs::rename(&held, &state)?;
            result
        })
        .unwrap();
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(reads.len() - before, 2 * 4096);
    assert!(reads[before..]
        .iter()
        .all(|read| read[1] == ENCRYPTED_VAULT_ACCOUNT));
}

#[test]
fn migration_diagnostics_identify_legacy_authorization_without_account_or_secret_text() {
    struct DeniedLegacy(MemoryVault);
    impl CredentialVault for DeniedLegacy {
        fn read(&self, service: &str, account: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
            if account == "synthetic-private-account" {
                return Err(crate::vault::NativeVaultFailure {
                    os_status: Some(-25308),
                }
                .into());
            }
            self.0.read(service, account)
        }
        fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
            self.0.write(service, account, value)
        }
        fn delete(&self, service: &str, account: &str) -> Result<()> {
            self.0.delete(service, account)
        }
        fn accounts(&self, service: &str) -> Result<Vec<String>> {
            self.0.accounts(service)
        }
    }
    let base = std::env::temp_dir().canonicalize().unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let backing = MemoryVault::default();
    backing
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "synthetic-private-account",
            "synthetic-secret-value",
        )
        .unwrap();
    let store = WorkspaceStore::open_with_vault(
        &temp.path().join("workspace"),
        Arc::new(DeniedLegacy(backing.clone())),
    )
    .unwrap();
    let error = store.migrate_to_encrypted_state().unwrap_err();
    let message = migration_error_message(&error);
    assert!(message.contains("reading old QuickSave credentials"));
    assert!(message.contains("-25308"));
    assert!(message.contains("authorization"));
    for forbidden in [
        "synthetic-private-account",
        "synthetic-secret-value",
        "Windows",
        "connection",
    ] {
        assert!(!message.contains(forbidden));
    }
    assert!(store.document().unwrap().encrypted_secrets.is_none());
    assert_eq!(backing.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn migration_diagnostics_never_format_unknown_backend_error_bodies_or_paths() {
    let error =
        anyhow::anyhow!("synthetic-secret-in-backend-body").context(MigrationStage::Inventory);
    let message = migration_error_message(&error);
    assert!(message.contains("listing old QuickSave credential items"));
    assert!(!message.contains("synthetic-secret"));
    let error = anyhow::Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "/synthetic/private/secret",
    ))
    .context(MigrationStage::WriteEncrypted);
    let message = migration_error_message(&error);
    assert!(message.contains("writing encrypted state"));
    assert!(message.contains("Local storage access was denied"));
    assert!(!message.contains("/synthetic"));
}

#[test]
fn repeating_completed_migration_reports_restart_without_more_vault_access() {
    let (_temp, vault, store) = fixture();
    store.migrate_to_encrypted_state().unwrap();
    let before = vault.access_log().unwrap();
    let error = store.migrate_to_encrypted_state().unwrap_err();
    let message = migration_error_message(&error);
    assert!(message.contains("Restart QuickSave"));
    assert!(!message.contains("Windows"));
    assert_eq!(vault.access_log().unwrap(), before);
}

#[test]
fn interactive_entry_rejects_stale_scope_before_the_native_vault_backend() {
    let (temp, _vault, store) = fixture();
    let scope = store.encrypted_vault_migration_scope().unwrap();
    store
        .transaction(|document| {
            document.settings.launch_at_login = true;
            Ok(())
        })
        .unwrap();
    let error = WorkspaceStore::migrate_with_native_authorization(
        &temp.path().join("workspace"),
        scope["generation"].as_u64().unwrap(),
        scope["workspaceIdentity"].as_str().unwrap(),
    )
    .unwrap_err();
    assert!(migration_error_message(&error).contains("approved workspace changed"));
    assert!(error
        .downcast_ref::<crate::vault::NativeVaultFailure>()
        .is_none());
}
