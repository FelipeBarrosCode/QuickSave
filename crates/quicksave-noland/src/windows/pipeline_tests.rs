// SPDX-License-Identifier: GPL-3.0-only
//! Actual Windows handles + real No Land CAS/pack fixture. No rclone, provider
//! account, credential vault or live application state is used.
use super::*;

#[tokio::test]
async fn windows_small_files_share_a_lease_and_real_deduplicated_nlpk_pack() {
    small_file_capture_fixture(false).await;
}

#[tokio::test]
async fn windows_metadata_only_plan_gets_real_hashes_from_the_single_cas_capture_pass() {
    small_file_capture_fixture(true).await;
}

async fn small_file_capture_fixture(metadata_only: bool) {
    let fixture = super::super::tests::Fixture::new();
    let source_path = fixture.root.join("software");
    let source = SafeRoot::open(&source_path).unwrap();
    let payload = vec![b's'; 4096];
    let app = AppId("quicksave:fixture".into());
    let logical = logical_token(app.as_str(), "installation");
    let mut files = Vec::new();
    for index in 0..16 {
        let relative = format!("file-{index:02}.dat");
        source
            .write_new(&relative, |file| {
                file.write_all(&payload)?;
                Ok(())
            })
            .unwrap();
        let (_, stamp) = source.read_file(&relative).unwrap();
        files.push(ExpectedFile {
            id: file_id(&logical, &relative),
            root: logical.clone(),
            relative,
            size: payload.len() as u64,
            stamp,
            hash: if metadata_only {
                String::new()
            } else {
                noland_cas::blake3_hex(&payload)
            },
        });
    }
    let operation = Uuid::new_v4();
    let master = MasterKey::from_bytes([17; 32]);
    let plan = Arc::new(FrozenPlan {
        version: 1,
        api: 22,
        operation,
        instance: Uuid::new_v4(),
        provider: "fixture".into(),
        storage: "fixture".into(),
        created_at: chrono::Utc::now(),
        work: Work::Upload {
            software: "fixture".into(),
            software_instance_id: "quicksave:fixture@native-fixture".into(),
            app: app.clone(),
            name: "Fixture".into(),
            source_identity: AppIdentity::new(app, "Fixture"),
            roots: vec![RootSpec {
                id: "installation".into(),
                logical: logical.clone(),
                path: source_path,
                identity: source.identity().unwrap(),
                allowed_files: None,
                role: NativeRootRole::Installation,
            }],
            snapshot: "fixture-snapshot".into(),
            files,
            metadata: Vec::new(),
            complete_approved_scope: false,
            coverage: NativeCoverage::SelectedNodes,
            capture_scope: metadata_only.then(|| CaptureScope {
                version: 1,
                work_id: "work-fixture".into(),
                metadata_identity: "fixture-snapshot".into(),
                node_count: 16,
                full_scope: None,
            }),
            capture_origin: None,
            full_snapshot: None,
            reuse_epoch: None,
            bundle: Uuid::new_v4(),
            commit: Uuid::new_v4(),
        },
    });
    plan.validate().unwrap();
    let root = SafeRoot::open(&fixture.root).unwrap();
    for name in ["receipts", "cas"] {
        root.create_dir(name).unwrap();
    }
    let directory_path = fixture.root.join("receipts");
    let directory = Arc::new(
        ReceiptDirectory::with_authority(
            &directory_path,
            Arc::new(|bytes| Ok(*blake3::keyed_hash(&[29; 32], bytes).as_bytes())),
        )
        .unwrap(),
    );
    let cas = LocalCas::new(fixture.root.join("cas")).unwrap();
    let (send, mut receive) = mpsc::channel(4);
    let failed = Arc::new(AtomicBool::new(false));
    let capture = Arc::new(Capture {
        plan,
        master: master.clone(),
        directory: Arc::clone(&directory),
        roots: BTreeMap::from([(logical, Arc::new(source))]),
        cas,
        inherited: Arc::new(BTreeMap::new()),
        previous: BTreeMap::new(),
        file_batches: Mutex::new(BTreeMap::new()),
        send,
        stop: Arc::new(AtomicBool::new(false)),
        failed: Arc::clone(&failed),
        check: Arc::new(|| Ok(())), // Synthetic native authority; no real vault.
    });
    let producer = OwnedWorker::start("quicksave-win-small-fixture", move || capture.batch(0, 16))
        .unwrap()
        .stop_on_drop(failed);
    let mut waves = Vec::new();
    let mut files = 0;
    while let Some(event) = receive.recv().await {
        match event {
            Event::Wave(wave) => waves.push(wave),
            Event::File(file) => {
                assert_eq!(file.file.size, payload.len() as u64);
                assert_eq!(file.file.file_hash, noland_cas::blake3_hex(&payload));
                assert!(file.file.uid.is_none() && file.file.gid.is_none());
                files += 1;
            }
            Event::Failure(_) => panic!("native fixture capture failed"),
        }
    }
    producer.finish().await.unwrap();
    assert_eq!(files, 16);
    assert_eq!(
        waves.len(),
        1,
        "small files must not cause one pack/remote transfer per file"
    );
    let wave = waves.pop().unwrap();
    assert_eq!(
        wave.sources.len(),
        1,
        "actual leased CAS deduplicates identical payloads"
    );
    let db = StateDb::open_native(&directory_path.join("fixture.db")).unwrap();
    let check: Check = Arc::new(|| Ok(()));
    let receipt = prepare_wave(
        wave,
        BTreeSet::from([noland_cas::blake3_hex(&payload)]),
        &directory,
        &directory_path,
        &master,
        operation,
        &db,
        &check,
    )
    .unwrap();
    assert_eq!(receipt.packs.len(), 1);
    assert_eq!(receipt.packs[0].entries.len(), 1);
    assert_eq!(
        noland_pack::extract_chunk(
            &receipt.packs[0].path,
            &receipt.packs[0].entries[0],
            &master
        )
        .unwrap(),
        payload
    );
    drop(db);
}

#[test]
fn native_retry_receipts_require_device_authority_not_just_the_repository_key() {
    let fixture = super::super::tests::Fixture::new();
    let root = SafeRoot::open(&fixture.root).unwrap();
    root.create_dir("receipts").unwrap();
    let path = fixture.root.join("receipts");
    let directory = ReceiptDirectory::with_authority(
        &path,
        Arc::new(|bytes| Ok(*blake3::keyed_hash(&[29; 32], bytes).as_bytes())),
    )
    .unwrap();
    let foreign = ReceiptDirectory::with_authority(
        &path,
        Arc::new(|bytes| Ok(*blake3::keyed_hash(&[30; 32], bytes).as_bytes())),
    )
    .unwrap();
    let master = MasterKey::from_bytes([17; 32]);
    let operation = Uuid::new_v4();
    let document = json!({"actualHash":noland_cas::blake3_hex(b"real fixture")});
    write_document(&directory, "valid.enc", &master, operation, &document).unwrap();
    assert_eq!(
        read_document::<Value>(&directory, "valid.enc", &master, operation).unwrap(),
        Some(document.clone())
    );
    assert!(read_document::<Value>(&foreign, "valid.enc", &master, operation).is_err());
    write_document(&foreign, "forged.enc", &master, operation, &document).unwrap();
    assert!(read_document::<Value>(&directory, "forged.enc", &master, operation).is_err());
    let (file, _) = directory.read_file("valid.enc").unwrap();
    let mut bytes = Vec::new();
    file.take(4096).read_to_end(&mut bytes).unwrap();
    directory
        .write_new("copied.enc", |file| {
            file.write_all(&bytes)?;
            Ok(())
        })
        .unwrap();
    assert!(
        read_document::<Value>(&directory, "copied.enc", &master, operation).is_err(),
        "device authentication must bind the exact operation/receipt name"
    );
    assert!(read_document::<Value>(&directory, "valid.enc", &master, Uuid::new_v4()).is_err());
}
