// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic vault and temporary config only; never OS credentials.
use super::*;
use crate::{CredentialVault, MemoryVault, REPOSITORY_KEY_ACCOUNT};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct SignerOnlyVault {
    backing: MemoryVault,
    defer_cloud: AtomicBool,
    cloud_reads: AtomicUsize,
}
impl CredentialVault for SignerOnlyVault {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        if account != DEVICE_KEY_ACCOUNT && account != ENCRYPTED_VAULT_ACCOUNT {
            self.cloud_reads.fetch_add(1, Ordering::SeqCst);
            ensure!(
                !self.defer_cloud.load(Ordering::SeqCst),
                "synthetic cloud credential is locked"
            );
        }
        self.backing.read(service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        self.backing.write(service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.backing.delete(service, account)
    }
    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        self.backing.accounts(service)
    }
    fn account_inventory_supported(&self) -> bool {
        true
    }
}

fn fixture() -> (tempfile::TempDir, Arc<SignerOnlyVault>, WorkspaceStore) {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let temp = tempfile::tempdir_in(base).unwrap();
    let vault = Arc::new(SignerOnlyVault {
        backing: MemoryVault::default(),
        defer_cloud: AtomicBool::new(true),
        cloud_reads: AtomicUsize::new(0),
    });
    let store =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), vault.clone()).unwrap();
    (temp, vault, store)
}
fn setup(store: &WorkspaceStore) -> Value {
    let scope = store.encrypted_vault_migration_scope().unwrap();
    store
        .setup_local_tracking_scoped(
            scope["generation"].as_u64().unwrap(),
            scope["workspaceIdentity"].as_str().unwrap(),
        )
        .unwrap()
}

#[test]
fn local_tracking_never_reads_cloud_values_and_full_import_preserves_new_permissions() {
    let (temp, vault, store) = fixture();
    vault
        .backing
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            DEVICE_KEY_ACCOUNT,
            &"11".repeat(32),
        )
        .unwrap();
    vault
        .backing
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            REPOSITORY_KEY_ACCOUNT,
            &"22".repeat(32),
        )
        .unwrap();
    vault
        .backing
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "provider.orphan",
            "synthetic-cloud-secret",
        )
        .unwrap();
    let scope = json!({"softwareId":"local-fixture","roots":[]});
    let old = store.issue_grant("tracking", &scope).unwrap();
    let result = setup(&store);
    assert_eq!(result["localTrackingSetup"], true);
    assert_eq!(result["trackingStarted"], false);
    assert_eq!(vault.cloud_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.encrypted_vault_status().unwrap()["credentialSetupPending"],
        true
    );
    let current = store.issue_grant("tracking", &scope).unwrap();
    assert!(store.verify_grant("tracking", &scope, &current).unwrap());
    assert!(!store.verify_grant("tracking", &scope, &old).unwrap());
    let before = vault.backing.access_log().unwrap()["writes"].clone();
    assert!(store.connect_provider(&json!({
        "kind":"backblaze_b2","name":"Not connected","bucket":"synthetic-bucket","prefix":"backups",
        "credentials":{"type":"backblaze_b2","value":{"key_id":"synthetic-id","application_key":"synthetic-token"}},
    })).is_err());
    assert_eq!(vault.cloud_reads.load(Ordering::SeqCst), 0);
    assert_eq!(vault.backing.access_log().unwrap()["writes"], before);
    assert!(store.document().unwrap().providers.is_empty());
    let bytes = std::fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    assert!(!bytes.contains("synthetic-cloud-secret"));
    assert!(!bytes.contains(&"11".repeat(32)));
    vault.defer_cloud.store(false, Ordering::SeqCst);
    store.migrate_to_encrypted_state().unwrap();
    assert_eq!(
        store.encrypted_vault_status().unwrap()["credentialSetupPending"],
        false
    );
    assert!(store.verify_grant("tracking", &scope, &current).unwrap());
    assert!(!store.verify_grant("tracking", &scope, &old).unwrap());
    assert_eq!(
        vault
            .backing
            .read(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT)
            .unwrap()
            .unwrap()
            .as_str(),
        "22".repeat(32)
    );
}

#[test]
fn fresh_local_setup_uses_one_native_item_and_readiness_does_not_start_tracking() {
    let (temp, vault, store) = fixture();
    let result = setup(&store);
    assert_eq!(result["legacyCredentialsDeferred"], 0);
    assert_eq!(
        vault.backing.accounts(QUICKSAVE_VAULT_SERVICE).unwrap(),
        vec![ENCRYPTED_VAULT_ACCOUNT.to_owned()]
    );
    assert_eq!(store.encrypted_storage_readiness().unwrap()["ready"], true);
    let scope = store.encrypted_vault_migration_scope().unwrap();
    assert_eq!(
        store
            .authorize_tracking_storage_scoped(
                scope["generation"].as_u64().unwrap(),
                scope["workspaceIdentity"].as_str().unwrap()
            )
            .unwrap()["trackingStarted"],
        false
    );
    assert!(store.document().unwrap().software.is_empty());
    let reopened =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), vault.clone()).unwrap();
    assert_eq!(
        reopened.encrypted_storage_readiness().unwrap()["ready"],
        true
    );
    assert_eq!(vault.cloud_reads.load(Ordering::SeqCst), 0);
}

#[test]
fn denied_signer_or_changed_scope_never_resets_old_keys() {
    let (_temp, vault, store) = fixture();
    vault
        .backing
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            DEVICE_KEY_ACCOUNT,
            "invalid-synthetic-key",
        )
        .unwrap();
    let scope = store.encrypted_vault_migration_scope().unwrap();
    assert!(store
        .setup_local_tracking_scoped(
            scope["generation"].as_u64().unwrap(),
            scope["workspaceIdentity"].as_str().unwrap()
        )
        .is_err());
    assert_eq!(vault.backing.access_log().unwrap()["writes"], json!([]));
    assert!(store.document().unwrap().encrypted_secrets.is_none());
    store
        .transaction(|document| {
            document.settings.launch_at_login = true;
            Ok(())
        })
        .unwrap();
    assert!(store
        .setup_local_tracking_scoped(
            scope["generation"].as_u64().unwrap(),
            scope["workspaceIdentity"].as_str().unwrap()
        )
        .is_err());
    assert_eq!(vault.backing.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn denial_latch_is_vault_free_and_cannot_change_approved_scope() {
    let (_temp, vault, store) = fixture();
    setup(&store);
    store
        .update_software(&json!({"id":"paused-local","name":"Synthetic local app"}))
        .unwrap();
    let before = store.software_record("paused-local").unwrap();
    let accesses = vault.backing.access_log().unwrap();
    store
        .pause_tracking_authorization(&json!({
            "id":"paused-local","authorizationPending":true,"dirtyGeneration":2,
            "unknownGeneration":1,"roots":[{"path":"/unapproved"}],"autosave":true,
            "trackingGrant":{"forged":true},"providerId":"unapproved-provider",
        }))
        .unwrap();
    assert_eq!(vault.backing.access_log().unwrap(), accesses);
    let after = store.software_record("paused-local").unwrap();
    for field in [
        "roots",
        "trackingGrant",
        "autosave",
        "providerId",
        "baseline",
        "bundleIndexSource",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    assert_eq!(after["authorizationPending"], true);
    assert!(after["confirmedGeneration"].is_null());
    assert_eq!(after["status"], "needs_authorization");
    assert!(!store.verify_tracking_grant("paused-local").unwrap());
    assert_eq!(vault.backing.access_log().unwrap(), accesses);
}
