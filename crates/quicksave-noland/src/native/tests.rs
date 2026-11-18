// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use noland_state_core::{BackupMode, BackupPerformanceMode, OperationRecord, RestoreMode};
use noland_storage::LocalStorage;

fn fixture_restore_control(
    plan: &noland_restore::RestorePlan,
    destination: &Path,
) -> Result<Arc<noland_restore::NativeRestoreControl>> {
    let identity = SafeRoot::open(destination)?.identity()?;
    let controller = restore_control::NativeRestoreController::new(Arc::new(|bytes| {
        Ok(*blake3::keyed_hash(&[0x39;32], bytes).as_bytes())
    }));
    let preview = controller.preview(plan.restore_id, &plan.manifest, destination,
        noland_restore::NativeObjectId { device:identity.device,file_id:identity.file_id },
        noland_restore::NativeConflictMode::CreateOnly)?;
    // Fixture-owned consent and device key, never an incoming JSON flag.
    controller.approve(preview, Arc::new(|| Ok(())))
}

#[tokio::test]
async fn native_boot_retains_untrusted_credential_artifacts_without_wiping_hardlinks() -> Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let Fixture {
        _temp,
        root,
        engine,
        ..
    } = Fixture::new().await?;
    let run = engine.agent.config.paths.run_root.clone();
    drop(engine);
    let session = run.join("storage").join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&session)?;
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700))?;
    let outside = root.join("outside-credential-cleanup-sentinel");
    std::fs::write(
        &outside,
        b"synthetic outside data must survive native startup",
    )?;
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))?;
    let artifact = session.join("rclone.conf");
    std::fs::hard_link(&outside, &artifact)?;
    let reopened = NativeEngine::open(&root.join("quicksave-data"), &root.join("home"))?;
    assert!(artifact.exists());
    assert_eq!(
        std::fs::read(&outside)?,
        b"synthetic outside data must survive native startup"
    );
    drop(reopened);
    drop(_temp);
    Ok(())
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    engine: NativeEngine,
    source: PathBuf,
    cloud: PathBuf,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let approved =
            Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
        let temp = if approved.is_dir() {
            tempfile::tempdir_in(approved)?
        } else {
            tempfile::tempdir()?
        };
        // macOS's temp-dir spelling may contain /var -> /private. Resolve only
        // this test-owned fixture, never source/provider state.
        let root = std::fs::canonicalize(temp.path())?;
        let source = root.join("approved");
        let cloud = root.join("fixture-provider");
        let home = root.join("home");
        std::fs::create_dir(&source)?;
        std::fs::create_dir(&cloud)?;
        std::fs::create_dir(&home)?;
        std::fs::write(source.join("first.sav"), b"first exact stable revision")?;
        std::fs::write(source.join("second.sav"), b"second exact stable revision")?;
        let engine = NativeEngine::open(&root.join("quicksave-data"), &home)?;
        engine
            .register(
                &json!({"id":"fixture","appId":"quicksave:fixture","name":"Fixture",
            "roots":[{"id":"saves","path":source}]}),
            )
            .await?;
        Ok(Self {
            _temp: temp,
            root,
            engine,
            source,
            cloud,
        })
    }

    fn access(&self, read_only: bool) -> ProviderAccess {
        ProviderAccess {
            provider_id: "synthetic-local".into(),
            session: json!({"operation_id":Uuid::new_v4(),"provider":"local","backend_type":"local",
                "remote_name":"fixture","root":self.cloud,"config_ini":"[fixture]\ntype = local\n",
                "expires_at_unix":0,"upload_concurrency":null}),
            repository_key: [0x71; 32],
            read_only,
        }
    }

    async fn source_backup(&self, file_keys: Option<Vec<NativeFileKey>>) -> Result<BundleManifest> {
        let selected = self.native_selection(file_keys)?;
        self.source_backup_selection(selected, Arc::new(|| Ok(())))
            .await
    }

    fn capture_input(&self, ids: Option<Vec<String>>) -> Result<Value> {
        let app = AppId("quicksave:fixture".into());
        let files = self.engine.local_files(&app)?;
        let root = SafeRoot::open(&self.source)?;
        let selected = ids
            .as_ref()
            .map(|ids| ids.iter().cloned().collect::<BTreeSet<_>>());
        let mut expected = Vec::new();
        for file in files.iter().filter(|file| {
            selected
                .as_ref()
                .is_none_or(|ids| ids.contains(file["id"].as_str().unwrap()))
        }) {
            let relative = file["path"].as_str().unwrap();
            let (mut opened, stamp) = root.read_file(relative)?;
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0u8; 128 * 1024];
            loop {
                let count = std::io::Read::read(&mut opened, &mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            root.verify_file(relative, &stamp)?;
            expected.push(json!({"id":file["id"],"size":stamp.size,
                "fileHash":hasher.finalize().to_hex().to_string()}));
        }
        let snapshot = blake3::hash(&serde_json::to_vec(&expected)?)
            .to_hex()
            .to_string();
        let mut input = json!({"softwareId":"fixture","captureSource":{"snapshotIdentity":snapshot,"expectedFiles":expected}});
        if let Some(ids) = ids {
            input["fileIds"] = json!(ids);
        }
        Ok(input)
    }

    fn native_selection(&self, keys: Option<Vec<NativeFileKey>>) -> Result<NativeSelection> {
        let app = AppId("quicksave:fixture".into());
        let files = self.engine.local_files(&app)?;
        let ids = keys.map(|keys| {
            keys.iter()
                .map(|key| native_file_id(&key.logical_root, &key.relative_path))
                .collect()
        });
        let input = self.capture_input(ids)?;
        let keys = selection_keys(&input, &files)?.unwrap_or_else(|| {
            files
                .iter()
                .map(|file| NativeFileKey {
                    logical_root: file["rootId"].as_str().unwrap().into(),
                    relative_path: file["path"].as_str().unwrap().into(),
                })
                .collect()
        });
        let (snapshot, expected) = expected_capture_evidence(&input, &keys, &files)?;
        Ok(NativeSelection {
            version: 1,
            file_keys: Some(keys),
            roots_fingerprint: self.engine.agent.native_binding_fingerprint(&app)?,
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(snapshot),
            expected_files: Some(expected),
            capture_scope: None,
            coverage: NativeCoverage::LegacyExactSelection,
            software_instance_id: None,
        })
    }

    async fn source_backup_selection(
        &self,
        selected: NativeSelection,
        guard: noland_state_agent::native_host::NativePublicationGuard,
    ) -> Result<BundleManifest> {
        let app = AppId("quicksave:fixture".into());
        let id = Uuid::new_v4();
        self.engine.agent.native_set_publication_guard(id, guard)?;
        let now = chrono::Utc::now();
        self.engine.agent.db.upsert_operation(&OperationRecord {
            operation_id: id,
            kind: "backup".into(),
            app_id: Some(app.clone()),
            state: "QUEUED".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: json!({"native_selection":selected,"mode":"complete_application",
                "performance_mode":"automatic","regenerable_caches":"include"}),
        })?;
        let provider = LocalStorage::new(self.cloud.clone());
        let master = MasterKey::from_bytes([0x71; 32]);
        Ok(noland_state_agent::backup::run_backup(
            &self.engine.agent,
            &app,
            BackupMode::CompleteApplication,
            BackupPerformanceMode::Automatic,
            &provider,
            &master,
            Some(id),
        )
        .await?)
    }
}

#[test]
fn required_rclone_version_is_not_inferred_from_any_version_output() {
    assert!(parse_rclone_version("rclone v1.53.3\n").is_err());
    assert!(parse_rclone_version("rclone v1.75.9\n").is_err());
    assert_eq!(
        parse_rclone_version("rclone v1.76.0\n- os/type: darwin").unwrap(),
        "1.76.0"
    );
    assert!(parse_rclone_version("fake rclone 9.0.0").is_err());
    assert!(parse_rclone_version("rclone v1.76.invalid").is_err());
}

#[test]
fn exact_file_selection_rejects_empty_unknown_duplicate_and_directory_ids() {
    let first = file_item("$HOME", "save/first.sav", false, 20).unwrap();
    let directory = file_item("$HOME", "save/folder", true, 0).unwrap();
    let files = vec![first.clone(), directory.clone()];
    assert!(selection_keys(&json!({}), &files).unwrap().is_none());
    for ids in [
        json!([]),
        json!(["unknown"]),
        json!([first["id"], first["id"]]),
        json!([directory["id"]]),
    ] {
        assert!(selection_keys(&json!({"fileIds":ids}), &files).is_err());
    }
    let keys = selection_keys(&json!({"fileIds":[first["id"]]}), &files)
        .unwrap()
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].relative_path, "save/first.sav");
}

#[tokio::test]
async fn native_boot_is_private_local_and_never_starts_a_socket_or_discovery() -> Result<()> {
    let fixture = Fixture::new().await?;
    assert!(!fixture.engine.agent.config.converge_complete_backups);
    assert!(fixture.engine.agent.config.native_host);
    assert!(!fixture.engine.agent.config.paths.rpc_socket.exists());
    assert!(fixture.engine.agent.roots.lock().home.is_none());
    assert!(fixture.engine.agent.db.open_sessions()?.is_empty());
    assert_eq!(
        fixture
            .engine
            .software_files(&json!({"softwareId":"fixture"}))
            .await?["files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(fixture
        .engine
        .register(&json!({"id":"internal","name":"Internal",
        "roots":[{"path":fixture.root.join("quicksave-data")}]}))
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn individual_approved_file_never_registers_its_sibling() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .engine
        .register(&json!({"id":"one-file","name":"One file",
        "roots":[{"id":"one","path":fixture.source.join("first.sav")}]}))
        .await?;
    let files = fixture
        .engine
        .software_files(&json!({"softwareId":"one-file"}))
        .await?;
    let files = files["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], "first.sav");
    Ok(())
}

#[tokio::test]
async fn manual_parent_allowlist_never_enumerates_siblings_and_matches_tracker_ids() -> Result<()> {
    let fixture = Fixture::new().await?;
    let unapproved = fixture.source.join("unapproved-symlink");
    std::os::unix::fs::symlink(fixture.root.join("outside-do-not-read"), &unapproved)?;
    let identity = SourcePath::new(&fixture.source)?.metadata()?;
    fixture
        .engine
        .register(&json!({"id":"manual","name":"Manual leaf",
        "roots":[{"id":"stable-parent-root","path":fixture.source,"role":"manual",
            "identity":{"device":identity.dev(),"fileId":[identity.ino(),0]},
            "allowedFiles":["first.sav"]}]}))
        .await?;
    let listing = fixture
        .engine
        .software_files(&json!({"softwareId":"manual"}))
        .await?;
    let files = listing["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], "first.sav");
    assert_eq!(
        files[0]["id"],
        quicksave_tracking::file_id("stable-parent-root", "first.sav")
    );
    assert!(selection_keys(
        &json!({"fileIds":[quicksave_tracking::file_id("stable-parent-root","second.sav")]}),
        files
    )
    .is_err());
    // Extending native-confirmed leaf authority preserves the stable root/file
    // identities; no third sibling becomes visible.
    fixture
        .engine
        .register(&json!({"id":"manual","name":"Manual leaves",
        "roots":[{"id":"stable-parent-root","path":fixture.source,"role":"manual",
            "identity":{"device":identity.dev(),"fileId":[identity.ino(),0]},
            "allowedFiles":["first.sav","second.sav"]}]}))
        .await?;
    let listing = fixture
        .engine
        .software_files(&json!({"softwareId":"manual"}))
        .await?;
    assert_eq!(listing["files"].as_array().unwrap().len(), 2);
    assert!(listing["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["id"] == quicksave_tracking::file_id("stable-parent-root", "first.sav")));
    Ok(())
}

#[tokio::test]
async fn symlink_and_replaced_approved_root_fail_closed() -> Result<()> {
    let fixture = Fixture::new().await?;
    let outside = fixture.root.join("unapproved-secret");
    std::fs::write(&outside, b"must not capture")?;
    std::os::unix::fs::symlink(&outside, fixture.source.join("link"))?;
    assert!(fixture
        .engine
        .software_files(&json!({"softwareId":"fixture"}))
        .await
        .is_err());
    std::fs::remove_file(fixture.source.join("link"))?;
    std::fs::rename(&fixture.source, fixture.root.join("original-approved"))?;
    std::fs::create_dir(&fixture.source)?;
    std::fs::write(fixture.source.join("first.sav"), b"borrowed replacement")?;
    assert!(fixture
        .engine
        .software_files(&json!({"softwareId":"fixture"}))
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn real_source_full_subset_additive_history_and_files_only_roundtrip() -> Result<()> {
    let fixture = Fixture::new().await?;
    let full = fixture.source_backup(None).await?;
    assert_eq!(full.files.len(), 2);
    let selected = NativeFileKey {
        logical_root: full.files[0].logical_root.clone(),
        relative_path: full.files[0].relative_path.clone(),
    };
    std::fs::write(
        fixture.source.join(&selected.relative_path),
        b"changed selected revision",
    )?;
    let subset = fixture.source_backup(Some(vec![selected.clone()])).await?;
    assert_eq!(subset.files.len(), 1);
    assert_eq!(subset.files[0].relative_path, selected.relative_path);
    let provider = LocalStorage::new(fixture.cloud.clone());
    let master = MasterKey::from_bytes([0x71; 32]);
    let catalog = noland_storage::load_catalog(&provider, &master).await?;
    assert_eq!(catalog.apps.len(), 1);
    assert_eq!(
        catalog.apps[0].bundles.len(),
        2,
        "QuickSave must not converge or retire the prior version"
    );
    let read = noland_storage::read_committed_manifest(
        &provider,
        &master,
        &full.app.app_id,
        full.bundle_id,
    )
    .await?;
    assert_eq!(
        read.files.len(),
        2,
        "existing No Land bundle remains authenticated and readable"
    );
    let envelope = std::fs::read(
        fixture
            .cloud
            .join(noland_state_core::bundle_dir(
                &full.app.app_id,
                full.bundle_id,
            ))
            .join("manifest.enc"),
    )?;
    assert_eq!(&envelope[..4], b"NLNE");
    let destination = fixture.root.join("download");
    std::fs::create_dir(&destination)?;
    let mut plan = noland_restore::prepare_restore(
        &provider,
        &master,
        &fixture.engine.agent.config.paths,
        &full.app.app_id,
        full.bundle_id,
        RestoreMode::CompleteApplication,
    )
    .await?;
    // Fresh root mapping ignores an imported Linux absolute hint entirely.
    for file in &mut plan.manifest.files {
        file.source_path_hint = Some("/home/gamer/private/not-authority".into());
    }
    let target_identity = SourcePath::new(&destination)?.metadata()?;
    plan.manifest.environment["quicksave_native_download"] = json!({"no_overwrite":true,"files_only":true,"destination":destination,
            "identity":[target_identity.dev(),target_identity.ino()]});
    let roots =
        noland_state_agent::native_host::native_restore_roots(&destination, &plan.manifest)?;
    let index =
        noland_storage::read_pack_index(&provider, &master, &full.app.app_id, full.bundle_id)
            .await?;
    let control = fixture_restore_control(&plan, &destination)?;
    let restored = noland_restore::restore_pipelined(
        &provider,
        &master,
        plan.into_shared().with_native_control(control),
        &index,
        &roots,
        None,
        None,
        noland_restore::PipelineOptions::default(),
        |_| Ok(()),
    )
    .await?;
    assert_eq!(restored.io.unfinished_files, 0);
    assert_eq!(restored.io.unfinished_bytes, 0);
    assert!(restored.io.peak_unfinished_files > 0);
    for file in &read.files {
        let root = roots.resolve(&file.logical_root_parsed().unwrap()).unwrap();
        let bytes = std::fs::read(root.join(&file.relative_path))?;
        assert_eq!(
            format!("blake3:{}", blake3::hash(&bytes).to_hex()),
            file.file_hash
        );
    }
    assert_eq!(
        std::fs::read(fixture.source.join(&selected.relative_path))?,
        b"changed selected revision"
    );
    Ok(())
}

#[test]
fn source_legacy_json_envelopes_are_opened_by_the_actual_metadata_decoder() -> Result<()> {
    let key = [0x31; 32];
    let expected =
        json!({"legacy":true,"files":[{"logical_root":"$HOME","relative_path":"saves/slot.sav"}]});
    let bytes = serde_json::to_vec_pretty(&expected)?;
    let envelope = noland_crypto::wrap_envelope(&key, b"legacy-fixture", &bytes)?;
    assert_eq!(&envelope[..4], b"NLNE");
    let actual: Value = noland_storage::open_metadata(&key, b"legacy-fixture", envelope)?;
    assert_eq!(actual, expected);
    assert!(noland_storage::open_metadata::<Value>(
        &[0x32; 32],
        b"legacy-fixture",
        noland_crypto::wrap_envelope(&key, b"legacy-fixture", &bytes)?
    )
    .is_err());
    Ok(())
}

#[test]
fn activity_projection_never_serializes_private_details_errors_or_secret_values() {
    // Public source error projection is also used for unexpected raw provider
    // messages, including signed URLs and credentials echoed by subprocesses.
    let error = public_source_error(StateError::Storage(
        "SECRET-token https://private.invalid/key".into(),
    ));
    assert!(!error.to_string().contains("SECRET"));
    assert!(!error.to_string().contains("private.invalid"));
}

#[tokio::test]
async fn actual_source_queued_cancel_and_retry_keep_the_signed_exact_subset() -> Result<()> {
    use noland_state_agent::operation_manager::{CancelOutcome, OperationLane};
    let fixture = Fixture::new().await?;
    let private = PrivateAccess::from_access(&fixture.access(false))?;
    let app = AppId("quicksave:fixture".into());
    let files = fixture.engine.local_files(&app)?;
    let native = fixture.native_selection(selection_keys(
        &json!({"fileIds":[files[0]["id"]]}),
        &files,
    )?)?;
    let blocker = Uuid::new_v4();
    let (started, waiting) = tokio::sync::oneshot::channel();
    assert!(fixture.engine.agent.operations.spawn_cancellable_on_lane(
        blocker,
        OperationLane::Transfer,
        async move {
            let _ = started.send(());
            std::future::pending::<()>().await;
        },
        || {},
        |_| {}
    ));
    waiting.await?;
    let id = Uuid::new_v4();
    fixture
        .engine
        .rpc_private(
            "StartBackup",
            &private,
            json!({
                "app_id":app.as_str(),"client_operation_id":id,"native_selection":native,
                "mode":"custom",
            }),
        )
        .await?;
    fixture.engine.cancel(&id.to_string()).await?;
    wait_stopped(&fixture.engine, id).await?;
    assert_eq!(
        fixture.engine.status(&id.to_string()).await?["state"],
        "cancelled"
    );
    let original = fixture.engine.agent.db.get_operation(id)?.unwrap();
    let mut changed = original.detail_json["native_selection"].clone();
    changed["file_keys"][0]["relative_path"] = json!("unapproved-new-selection");
    assert!(fixture
        .engine
        .rpc_private(
            "RetryOperation",
            &private,
            json!({
                "operation_id":id,"native_selection":changed,
            })
        )
        .await
        .is_err());
    assert_eq!(
        fixture.engine.agent.db.get_operation(id)?.unwrap().state,
        "CANCELLED"
    );
    std::fs::write(
        fixture.source.join("new-after-cancellation.sav"),
        b"not in original exact request",
    )?;
    fixture
        .engine
        .rpc_private("RetryOperation", &private, json!({"operation_id":id}))
        .await?;
    let retried = fixture.engine.agent.db.get_operation(id)?.unwrap();
    assert_eq!(
        retried.detail_json["native_selection"],
        original.detail_json["native_selection"]
    );
    assert_eq!(
        retried.detail_json["submission_binding"],
        original.detail_json["submission_binding"]
    );
    fixture.engine.cancel(&id.to_string()).await?;
    wait_stopped(&fixture.engine, id).await?;
    assert_eq!(
        fixture.engine.agent.operations.cancel(blocker),
        CancelOutcome::Requested
    );
    wait_stopped(&fixture.engine, blocker).await?;
    assert!(
        std::fs::read_dir(&fixture.cloud)?.next().is_none(),
        "queued journal/cancellation fixture must never touch a provider"
    );
    Ok(())
}

async fn wait_stopped(engine: &NativeEngine, id: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while engine.agent.operations.is_running(id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("source operation owner did not drain")?;
    Ok(())
}

#[tokio::test]
async fn real_source_dependency_deletion_uses_exact_plan_and_separate_ack() -> Result<()> {
    let fixture = Fixture::new().await?;
    let full = fixture.source_backup(None).await?;
    let key = NativeFileKey {
        logical_root: full.files[0].logical_root.clone(),
        relative_path: full.files[0].relative_path.clone(),
    };
    fixture.source_backup(Some(vec![key])).await?;
    let provider = LocalStorage::new(fixture.cloud.clone());
    let master = MasterKey::from_bytes([0x71; 32]);
    let plan_id = Uuid::new_v4();
    let guard = noland_storage::RepositoryGuard::acquire(
        &provider,
        &master,
        plan_id,
        "synthetic-test-owner",
    )
    .await?;
    let plan = noland_storage::prepare_full_deletion_selected(
        &provider,
        &master,
        &[(full.app.app_id.clone(), full.bundle_id)],
        plan_id,
        "synthetic-test-owner",
    )
    .await?;
    guard.release().await?;
    let dependencies = (plan.targets.len() - plan.requested_count) as u64;
    assert!(
        dependencies > 0,
        "subset bundle depends on the original full bundle's shared packs"
    );
    for input in [
        json!({}),
        json!({"acknowledgeDependencies":false}),
        json!({"acknowledgeDependencies":"true"}),
    ] {
        assert!(require_dependency_ack(dependencies, &input).is_err());
    }
    assert_eq!(
        noland_storage::load_catalog(&provider, &master).await?.apps[0]
            .bundles
            .len(),
        2
    );
    require_dependency_ack(dependencies, &json!({"acknowledgeDependencies":true}))?;
    let guard = noland_storage::RepositoryGuard::acquire(
        &provider,
        &master,
        plan.operation_id,
        "synthetic-test-owner",
    )
    .await?;
    noland_storage::execute_full_deletion(&provider, &master, &plan).await?;
    guard.release().await?;
    assert!(noland_storage::load_catalog(&provider, &master)
        .await?
        .apps
        .is_empty());
    assert!(fixture.source.join("first.sav").exists());
    assert!(fixture.source.join("second.sav").exists());
    Ok(())
}

#[tokio::test]
async fn oauth_source_refresh_is_explicitly_gated_without_a_durable_native_handoff() -> Result<()> {
    let fixture = Fixture::new().await?;
    for provider in ["google_drive", "microsoft_onedrive", "box", "dropbox"] {
        let mut access = fixture.access(false);
        access.session["provider"] = json!(provider);
        access.session["config_ini"] = json!(
            "[fixture]\ntype = box\ntoken = {\"refresh_token\":\"synthetic-private-refresh\"}\n"
        );
        let error = match PrivateAccess::from_access(&access) {
            Ok(_) => bail!("OAuth engine session was accepted without a durable refresh handoff"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("gated"));
        assert!(!error.to_string().contains("synthetic-private-refresh"));
    }
    Ok(())
}

#[tokio::test]
async fn native_restore_boundary_swap_and_create_new_collision_cannot_clobber_files() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let target = fixture.root.join("fresh-target");
    std::fs::create_dir(&target)?;
    let identity = SourcePath::new(&target)?.metadata()?;
    let expected = (identity.dev(), identity.ino());
    let partial = target.join("owned-partial");
    let source = SourcePath::new_beneath(&partial, &target, expected)?;
    let mut output = source.open_partial_private(true)?;
    output.write_all(b"authenticated fixture payload")?;
    output.sync_all()?;
    std::fs::write(target.join("existing.sav"), b"must keep original")?;
    let existing = SourcePath::new_beneath(&target.join("existing.sav"), &target, expected)?;
    assert!(source.publish_new_to(&existing).is_err());
    assert_eq!(
        std::fs::read(target.join("existing.sav"))?,
        b"must keep original"
    );
    std::fs::rename(&target, fixture.root.join("original-target"))?;
    std::fs::create_dir(&target)?;
    assert!(SourcePath::new_beneath(&target.join("outside-partial"), &target, expected).is_err());
    assert!(std::fs::read_dir(&target)?.next().is_none());
    std::fs::remove_dir(&target)?;
    std::os::unix::fs::symlink(&fixture.source, &target)?;
    assert!(SourcePath::new_beneath(&target.join("first.sav"), &target, expected).is_err());
    assert_eq!(
        std::fs::read(fixture.source.join("first.sav"))?,
        b"first exact stable revision"
    );
    Ok(())
}

#[tokio::test]
async fn gateway_destination_proof_cannot_be_repinned_to_a_replacement_directory() -> Result<()> {
    let fixture = Fixture::new().await?;
    let destination = fixture.root.join("native-picked-target");
    std::fs::create_dir(&destination)?;
    let expected = SafeRoot::open(&destination)?.identity()?;
    let selection = json!({"destination":destination,"_approvedPaths":[{
        "path":destination,"kind":"directory","identity":expected,
    }]});
    assert_eq!(
        approved_destination_identity(&selection, &destination, &expected)?,
        (expected.device, expected.file_id[0])
    );
    std::fs::rename(&destination, fixture.root.join("old-native-picked-target"))?;
    std::fs::create_dir(&destination)?;
    let replacement = SafeRoot::open(&destination)?.identity()?;
    assert!(approved_destination_identity(&selection, &destination, &replacement).is_err());
    assert!(approved_destination_identity(
        &json!({"_approvedPaths":[]}),
        &destination,
        &replacement
    )
    .is_err());
    assert!(std::fs::read_dir(&destination)?.next().is_none());
    Ok(())
}

#[tokio::test]
async fn native_boot_never_replays_forged_legacy_restore_paths_or_deletes_replacements(
) -> Result<()> {
    let Fixture {
        _temp,
        root,
        engine,
        source: _,
        cloud: _,
    } = Fixture::new().await?;
    let id = Uuid::new_v4();
    let workspace = engine.agent.config.paths.restore_dir(&id.to_string());
    std::fs::create_dir_all(&workspace)?;
    let sentinel = root.join("external-synthetic-sentinel");
    std::fs::write(&sentinel, b"original synthetic data")?;
    let journal = json!({"version":3,"restore_id":id,"state":"active",
        "allowed_roots":[root],"rollback_mappings":[],"prior_symlinks":[],
        "created_paths":[sentinel],"created_directories":[],"partial_paths":[],"tombstone_guards":[]});
    std::fs::write(
        workspace.join("restore-transaction.json"),
        serde_json::to_vec(&journal)?,
    )?;
    // The journal has no authority and no corresponding restore operation.
    // A later replacement at the same pathname is equally unowned by it.
    std::fs::remove_file(&sentinel)?;
    std::fs::write(&sentinel, b"foreign replacement must survive native boot")?;
    drop(engine);
    let reopened = NativeEngine::open(&root.join("quicksave-data"), &root.join("home"))?;
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"foreign replacement must survive native boot"
    );
    assert!(workspace.join("restore-transaction.json").exists());
    assert!(reopened.agent.db.get_operation(id)?.is_none());
    drop(reopened);
    drop(_temp);
    Ok(())
}

#[tokio::test]
async fn native_interrupted_restore_is_marked_without_rollback_and_cannot_retry() -> Result<()> {
    let Fixture {
        _temp,
        root,
        engine,
        source: _,
        cloud: _,
    } = Fixture::new().await?;
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    engine.agent.db.upsert_operation(&OperationRecord {
        operation_id: id,
        kind: "restore".into(),
        app_id: None,
        state: "APPLYING".into(),
        created_at: now,
        updated_at: now,
        last_error: None,
        detail_json: json!({}),
    })?;
    drop(engine);
    let reopened = NativeEngine::open(&root.join("quicksave-data"), &root.join("home"))?;
    let operation = reopened.agent.db.get_operation(id)?.unwrap();
    assert_eq!(operation.state, "INTERRUPTED");
    assert_eq!(
        operation.detail_json["native_restore_cleanup_required"],
        true
    );
    assert_eq!(operation.detail_json["resume"]["retry_available"], false);
    assert_eq!(reopened.status(&id.to_string()).await?["canRetry"], false);
    assert!(reopened.rpc_private("RetryOperation",&PrivateAccess::from_access(&ProviderAccess {
        provider_id:"synthetic".into(),session:json!({"operation_id":Uuid::new_v4(),"provider":"local",
            "backend_type":"local","remote_name":"fixture","root":root.join("unused-provider"),
            "config_ini":"[fixture]\ntype = local\n","expires_at_unix":0,"upload_concurrency":null}),
        repository_key:[0x71;32],read_only:false,
    })?,json!({"operation_id":id})).await.is_err());
    drop(reopened);
    drop(_temp);
    Ok(())
}

#[tokio::test]
async fn mismatched_tracker_hash_stops_actual_source_before_manifest_or_catalog_commit(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut selection = fixture.native_selection(None)?;
    selection.expected_files.as_mut().unwrap()[0].file_hash = format!("blake3:{}", "0".repeat(64));
    assert!(fixture
        .source_backup_selection(selection, Arc::new(|| Ok(())))
        .await
        .is_err());
    let entries = SafeRoot::open(&fixture.cloud)?.entries()?;
    assert!(!entries
        .iter()
        .any(|entry| entry.relative_path.ends_with("/COMMITTED")));
    assert!(!fixture.cloud.join("catalog/LATEST").exists());
    Ok(())
}

#[tokio::test]
async fn post_capture_publication_guard_blocks_revoked_authority_and_rechecks_catalog() -> Result<()>
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = Fixture::new().await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let source = fixture.source.clone();
    let cloud = fixture.cloud.clone();
    let selection = fixture.native_selection(None)?;
    let guard = Arc::new(move || {
        let invocation = observed.fetch_add(1, Ordering::SeqCst);
        // This callback runs after capture/immutable pack upload, not only at
        // submission or in an after-the-fact UI monitor.
        if !cloud.join("packs").exists() || !source.join("first.sav").exists() {
            return Err(StateError::Conflict(
                "synthetic capture was not completed".into(),
            ));
        }
        if invocation > 0 {
            return Err(StateError::Conflict(
                "synthetic grant revoked before catalog".into(),
            ));
        }
        Ok(())
    });
    assert!(fixture
        .source_backup_selection(selection, guard)
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!fixture.cloud.join("catalog/LATEST").exists());
    Ok(())
}

#[tokio::test]
async fn native_failure_retains_new_outputs_and_does_not_unlink_foreign_replacement() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let manifest = fixture.source_backup(None).await?;
    let provider = LocalStorage::new(fixture.cloud.clone());
    let master = MasterKey::from_bytes([0x71; 32]);
    let mut plan = noland_restore::prepare_restore(
        &provider,
        &master,
        &fixture.engine.agent.config.paths,
        &manifest.app.app_id,
        manifest.bundle_id,
        RestoreMode::CompleteApplication,
    )
    .await?;
    let destination = fixture.root.join("native-failure-target");
    std::fs::create_dir(&destination)?;
    let identity = SourcePath::new(&destination)?.metadata()?;
    plan.manifest.environment["quicksave_native_download"] = json!({"no_overwrite":true,"files_only":true,
        "destination":destination,"identity":[identity.dev(),identity.ino()]});
    let roots =
        noland_state_agent::native_host::native_restore_roots(&destination, &plan.manifest)?;
    let index = noland_storage::read_pack_index(
        &provider,
        &master,
        &manifest.app.app_id,
        manifest.bundle_id,
    )
    .await?;
    noland_restore::download_and_verify(&provider, &master, &plan, &index).await?;
    let control = fixture_restore_control(&plan, &destination)?;
    let mut transaction = noland_restore::RestoreTransaction::new_native(&plan, &roots, control)?;
    transaction.publish_to(noland_restore::RestoreTarget::Complete)?;
    let file = &manifest.files[0];
    let target = roots
        .resolve(&file.logical_root_parsed().unwrap())
        .unwrap()
        .join(&file.relative_path);
    std::fs::remove_file(&target)?;
    std::fs::write(&target, b"foreign replacement after native publication")?;
    assert!(transaction.abort().is_err());
    drop(transaction);
    assert_eq!(
        std::fs::read(&target)?,
        b"foreign replacement after native publication"
    );
    assert!(plan.staging.join("restore-native.v1.json").exists());
    Ok(())
}

#[tokio::test]
async fn native_database_rejects_existing_sidecar_symlinks_before_sqlite_io() -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let Fixture {
            _temp,
            root,
            engine,
            source: _,
            cloud: _,
        } = Fixture::new().await?;
        assert_eq!(engine.agent.db.integrity_check()?, "ok");
        let database = engine.agent.config.paths.db_path.clone();
        drop(engine); // Start from a real, cleanly closed, valid native database.
        let sentinel = root.join("outside-sqlite-sentinel");
        std::fs::write(&sentinel, b"SQLite must never open this as a sidecar")?;
        let before = std::fs::metadata(&sentinel)?;
        let mut sidecar = database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar)?;
        } // Only fixture-owned closed DB files.
        std::os::unix::fs::symlink(&sentinel, &sidecar)?;
        assert!(
            NativeEngine::open(&root.join("quicksave-data"), &root.join("home")).is_err(),
            "unsafe existing SQLite sidecar {suffix} was accepted"
        );
        assert_eq!(
            std::fs::read(&sentinel)?,
            b"SQLite must never open this as a sidecar"
        );
        assert!(noland_snapshot::same_file_identity(
            &before,
            &std::fs::metadata(&sentinel)?
        ));
        assert!(std::fs::symlink_metadata(&sidecar)?
            .file_type()
            .is_symlink());
        drop(_temp);
    }
    Ok(())
}

#[tokio::test]
async fn native_database_rejects_hardlinked_or_insecure_main_without_repair() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for hardlink in [false, true] {
        let Fixture {
            _temp,
            root,
            engine,
            source: _,
            cloud: _,
        } = Fixture::new().await?;
        let database = engine.agent.config.paths.db_path.clone();
        drop(engine);
        if hardlink {
            std::fs::hard_link(&database, root.join("outside-db-hardlink"))?;
        } else {
            std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))?;
        }
        let before = std::fs::read(&database)?;
        assert!(NativeEngine::open(&root.join("quicksave-data"), &root.join("home")).is_err());
        assert_eq!(std::fs::read(&database)?, before);
        if !hardlink {
            assert_eq!(std::fs::metadata(&database)?.mode() & 0o7777, 0o644);
        }
        drop(_temp);
    }
    Ok(())
}

/// Actual rclone process + API22 operations, never a fake executable or cloud.
/// Install rclone >=1.76 separately, then run the parent-serialized ignored suite.
#[tokio::test]
#[ignore = "requires separately installed rclone >=1.76; uses only an isolated synthetic local provider"]
async fn installed_rclone_full_subset_download_frozen_dependency_ack_delete() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.engine.preflight().await?;
    let empty = fixture.engine.probe(&fixture.access(false)).await?;
    assert_eq!(empty["canList"], true);
    assert_eq!(empty["canRead"], false);
    assert_eq!(empty["keyVerified"], false);
    let first = fixture
        .engine
        .upload_guarded(
            fixture.access(false),
            fixture.capture_input(None)?,
            Arc::new(|| Ok(())),
        )
        .await?;
    wait(&fixture.engine, first["operationId"].as_str().unwrap()).await?;
    let catalog = fixture.engine.catalog(&fixture.access(false)).await?;
    let first_bundle = catalog["bundles"][0].clone();
    let files = fixture
        .engine
        .files(
            &fixture.access(false),
            &json!({"appId":first_bundle["appId"],"bundleId":first_bundle["id"]}),
        )
        .await?;
    let file_id = files["files"][0]["id"].clone();
    let second = fixture
        .engine
        .upload_guarded(
            fixture.access(false),
            fixture.capture_input(Some(vec![file_id.as_str().unwrap().to_owned()]))?,
            Arc::new(|| Ok(())),
        )
        .await?;
    wait(&fixture.engine, second["operationId"].as_str().unwrap()).await?;
    let catalog = fixture.engine.catalog(&fixture.access(false)).await?;
    assert_eq!(catalog["bundles"].as_array().unwrap().len(), 2);
    let verified = fixture.engine.health(&fixture.access(false)).await?;
    assert_eq!(verified["canRead"], true);
    assert_eq!(verified["keyVerified"], true);
    let destination = fixture.root.join("download");
    std::fs::create_dir(&destination)?;
    let download = fixture
        .engine
        .download(
            fixture.access(true),
            json!({
        "appId":first_bundle["appId"],"bundleId":first_bundle["id"],"destination":destination,
        "fileIds":[file_id]}),
        )
        .await?;
    wait(&fixture.engine, download["operationId"].as_str().unwrap()).await?;
    assert_eq!(
        SafeRoot::open(&destination)?
            .entries()?
            .iter()
            .filter(|e| !e.is_directory)
            .count(),
        1
    );
    let preview = fixture
        .engine
        .preview_delete(
            &fixture.access(false),
            json!({
        "appId":first_bundle["appId"],"bundleId":first_bundle["id"]}),
        )
        .await?;
    assert!(preview["dependentBundles"].as_u64().unwrap() >= 1);
    assert!(fixture
        .engine
        .delete(
            fixture.access(false),
            json!({
        "previewId":preview["previewId"],"acknowledgeDependencies":false})
        )
        .await
        .is_err());
    let deleted = fixture
        .engine
        .delete(
            fixture.access(false),
            json!({
        "previewId":preview["previewId"],"acknowledgeDependencies":true}),
        )
        .await?;
    wait(&fixture.engine, deleted["operationId"].as_str().unwrap()).await?;
    assert!(
        fixture.engine.catalog(&fixture.access(false)).await?["bundles"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(fixture.source.join("first.sav").exists());
    assert!(fixture.source.join("second.sav").exists());
    Ok(())
}

async fn wait(engine: &NativeEngine, id: &str) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let value = engine.status(id).await?;
            match value["state"].as_str() {
                Some("completed") => return Ok(value),
                Some("failed" | "cancelled" | "interrupted") => bail!(
                    "source fixture operation did not complete: {}",
                    value["state"]
                ),
                _ => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .context("synthetic source fixture operation timed out")?
}
