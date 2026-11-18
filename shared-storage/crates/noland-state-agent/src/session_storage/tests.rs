use super::*;
use crate::index_test_support::{root, session, write_catalog, TestProvider};
use crate::AgentConfig;

#[tokio::test]
async fn native_session_rechecks_after_metadata_io_before_visibility_marker_and_latest() {
    use std::sync::atomic::AtomicUsize;
    let approved = Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
    let base = if approved.is_dir() {
        approved.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let root = base.join(format!("qs-native-publish-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let mut config = AgentConfig::isolated(root.join("agent"));
    config.native_host = true;
    config.converge_complete_backups = false;
    {
        use std::os::unix::fs::DirBuilderExt;
        for directory in [&config.paths.state_root, &config.paths.run_root] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .unwrap();
        }
    }
    let agent = StateAgent::boot(config).unwrap();
    let provider = TestProvider::new(root.join("cloud"));
    let master = MasterKey::generate();
    let mut session = session(&provider.inner.root);
    let operation = Uuid::new_v4();
    session.operation_id = operation.to_string();
    let now = chrono::Utc::now();
    agent
        .db
        .upsert_operation(&noland_state_core::OperationRecord {
            operation_id: operation,
            kind: "backup".into(),
            app_id: None,
            state: "COMMITTING".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: serde_json::json!({}),
        })
        .unwrap();
    let catalog = CatalogDocument::empty();
    let key = format!("catalog/commits/{}.enc", catalog.catalog_commit_id);
    let marker = format!("catalog/commits/{}.COMMITTED", catalog.catalog_commit_id);
    let written = provider.inner.root.join(&key);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    agent
        .native_set_publication_guard(
            operation,
            Arc::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                if written.exists() {
                    return Err(StateError::Conflict(
                        "synthetic grant revoked during metadata I/O".into(),
                    ));
                }
                Ok(())
            }),
        )
        .unwrap();
    let storage = SessionStorage::new(provider.clone(), &agent, &session, &master);
    let bytes = seal_metadata(&derive_keys(&master).catalog, b"catalog", &catalog)
        .unwrap()
        .envelope;
    let batch = MetadataBatch::with_committed(
        vec![MetadataWrite::new(RemoteKey::new(&key), bytes)],
        MetadataWrite::new(RemoteKey::new(&marker), b"COMMITTED".to_vec()),
    );
    assert!(storage.put_metadata_batch(&batch).await.is_err());
    assert!(provider.inner.root.join(key).exists());
    assert!(!provider.inner.root.join(marker).exists());
    assert!(storage
        .put_small_versioned(
            bytes::Bytes::from(catalog.catalog_commit_id.to_string()),
            &RemoteKey::new("catalog/LATEST")
        )
        .await
        .is_err());
    assert!(!provider.inner.root.join("catalog/LATEST").exists());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(storage);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn immutable_catalog_reuse_rebuilds_corruption_and_observes_external_changes_and_removal() {
    let root = root("catalog-cache");
    let agent = StateAgent::boot(AgentConfig::isolated(root.join("agent"))).unwrap();
    let provider = TestProvider::new(root.join("cloud"));
    let master = MasterKey::generate();
    let session = session(&provider.inner.root);
    let catalog = CatalogDocument::empty();
    write_catalog(&provider, &master, &catalog).await;
    let storage = SessionStorage::new(provider.clone(), &agent, &session, &master);
    let key = format!("catalog/commits/{}.enc", catalog.catalog_commit_id);
    for _ in 0..2 {
        let loaded = noland_storage::load_catalog(&storage, &master)
            .await
            .unwrap();
        assert_eq!(loaded.catalog_commit_id, catalog.catalog_commit_id);
    }
    assert_eq!(
        provider.reads(&key),
        1,
        "only immutable ciphertext is reused"
    );
    assert_eq!(
        provider.reads("catalog/LATEST"),
        2,
        "mutable pointer always fresh"
    );
    let binding = crate::storage_scope::binding(storage.storage_identity(), &master).unwrap();
    let mut corrupt = agent.db.cached_metadata(&binding, &key).unwrap().unwrap();
    corrupt.payload[0] ^= 1;
    agent
        .db
        .cache_authenticated_metadata(&binding, &key, &corrupt.payload, &corrupt.receipt)
        .unwrap();
    noland_storage::load_catalog(&storage, &master)
        .await
        .unwrap();
    assert_eq!(
        provider.reads(&key),
        2,
        "bad local receipt rebuilds from remote"
    );
    let external = CatalogDocument::empty();
    write_catalog(&provider, &master, &external).await;
    assert_eq!(
        noland_storage::load_catalog(&storage, &master)
            .await
            .unwrap()
            .catalog_commit_id,
        external.catalog_commit_id
    );
    let removed = format!("catalog/commits/{}.enc", external.catalog_commit_id);
    // Simulate an external loss of our fixture object. Production deletion
    // deliberately cannot remove immutable catalog history through this API.
    std::fs::remove_file(provider.inner.root.join(&removed)).unwrap();
    assert!(
        noland_storage::load_catalog(&storage, &master)
            .await
            .is_err(),
        "cached bytes cannot conceal removed committed data"
    );
    crate::cloud_catalog::invalidate(&agent, storage.storage_identity(), &master);
    assert!(agent.db.cached_metadata(&binding, &key).unwrap().is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn catalog_cache_never_crosses_account_endpoint_or_key_and_never_caches_mutable_reads() {
    let root = root("catalog-scope");
    let agent = StateAgent::boot(AgentConfig::isolated(root.join("agent"))).unwrap();
    let provider = TestProvider::new(root.join("cloud"));
    let master = MasterKey::generate();
    let mut session = session(&provider.inner.root);
    session.provider = "sftp".into();
    session.backend_type = "sftp".into();
    session.config_ini =
        "[fixture]\ntype = sftp\nhost = one.test\nuser = alice\npass = first\n".into();
    let catalog = CatalogDocument::empty();
    write_catalog(&provider, &master, &catalog).await;
    let key = RemoteKey::new(format!("catalog/commits/{}.enc", catalog.catalog_commit_id));
    let storage = SessionStorage::new(provider.clone(), &agent, &session, &master);
    storage
        .read_small(&key, MAX_SMALL_READ_BYTES)
        .await
        .unwrap();
    assert_eq!(provider.reads(key.as_str()), 1);
    for config in [
        session.config_ini.replace("alice", "bob"),
        session.config_ini.replace("one.test", "two.test"),
    ] {
        let mut changed = session.clone();
        changed.config_ini = config;
        let storage = SessionStorage::new(provider.clone(), &agent, &changed, &master);
        storage
            .read_small(&key, MAX_SMALL_READ_BYTES)
            .await
            .unwrap();
        assert_eq!(storage.metadata_metrics()["immutable_hits"], 0);
    }
    session.config_ini = session.config_ini.replace("first", "rotated");
    let rotated = SessionStorage::new(provider.clone(), &agent, &session, &master);
    rotated
        .read_small(&key, MAX_SMALL_READ_BYTES)
        .await
        .unwrap();
    assert_eq!(
        rotated.metadata_metrics()["immutable_hits"],
        1,
        "credential rotation is not namespace rotation"
    );
    let wrong_key = MasterKey::generate();
    let wrong = SessionStorage::new(provider.clone(), &agent, &session, &wrong_key);
    assert!(wrong.read_small(&key, MAX_SMALL_READ_BYTES).await.is_err());
    for _ in 0..2 {
        rotated
            .read_small(&RemoteKey::new("catalog/LATEST"), 1024)
            .await
            .unwrap();
    }
    assert_eq!(provider.reads("catalog/LATEST"), 2);
    assert!(
        rotated.read_small(&key, 1).await.is_err(),
        "cache obeys the caller's read bound"
    );
    provider.controls.fail_stats.store(true, Ordering::Relaxed);
    assert!(rotated
        .read_small(&key, MAX_SMALL_READ_BYTES)
        .await
        .is_err());
    provider.controls.fail_stats.store(false, Ordering::Relaxed);
    assert!(rotated.read_small(&key, MAX_SMALL_READ_BYTES).await.is_ok());
    std::fs::remove_dir_all(root).unwrap();
}
