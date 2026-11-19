// SPDX-License-Identifier: GPL-3.0-only
//! Only isolated filesystem state and an injected synthetic vault.
use super::*;
use quicksave_state::MemoryVault;

#[tokio::test]
async fn isolated_host_and_service_share_the_migrated_anchor_without_exposing_ciphertext() {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let temporary = tempfile::tempdir_in(base).unwrap();
    let data = temporary.path().join("data");
    let home = temporary.path().join("home");
    quicksave_platform::ensure_private_directory(&home).unwrap();
    let vault = Arc::new(MemoryVault::default());
    let store = WorkspaceStore::open_with_vault(&data, vault.clone()).unwrap();
    store.migrate_to_encrypted_state().unwrap();
    let mac = store.operation_mac(b"isolated original work").unwrap();
    let service = WorkspaceService::open_isolated_with_vault(&data, &home, vault.clone())
        .await
        .unwrap();
    let dashboard = service.query("dashboard", json!({})).await.unwrap();
    assert!(dashboard["software"].as_array().unwrap().is_empty());
    assert!(dashboard.get("encryptedSecrets").is_none());
    let raw = StoreAdapter(store.clone(), None).snapshot().unwrap();
    assert!(raw.get("encryptedSecrets").is_none());
    assert_eq!(
        store
            .operation_mac_existing(b"isolated original work")
            .unwrap(),
        mac
    );
    service.shutdown().await.unwrap();
    let reopened = WorkspaceStore::open_with_vault(&data, vault.clone()).unwrap();
    assert_eq!(
        reopened
            .operation_mac_existing(b"isolated original work")
            .unwrap(),
        mac
    );
}
