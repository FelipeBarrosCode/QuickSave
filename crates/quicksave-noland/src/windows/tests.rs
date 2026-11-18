// SPDX-License-Identifier: GPL-3.0-only
//! Native Windows filesystem fixtures only. No account, default vault, installed
//! tool discovery, live No Land state or network is accessed by these tests.
use super::*;

pub(super) struct Fixture {
    pub(super) root: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!("quicksave-win-engine-{}", Uuid::new_v4()));
        ensure_private_directory(&root)
            .expect("native NTFS/ReFS, protected-DACL and real flush privileges are required");
        let handle = SafeRoot::open(&root).unwrap();
        for child in ["data", "home", "software"] {
            handle.create_dir(child).unwrap();
        }
        Self { root }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this test's generated directory; never a production app root.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn native_windows_engine_journals_open_without_credentials_and_joins_shutdown() {
    let fixture = Fixture::new();
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    assert!(engine.recent().await.unwrap().is_empty());
    assert!(
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).is_err(),
        "a second native owner must fail nonblocking rather than share SQLite admission"
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn native_windows_file_pages_use_actual_cached_metadata_not_poll_time_tree_scans() {
    let fixture = Fixture::new();
    let source_path = fixture.root.join("software");
    let source = SafeRoot::open(&source_path).unwrap();
    source
        .write_new("one.dat", |file| {
            file.write_all(b"one")?;
            Ok(())
        })
        .unwrap();
    let identity = source.identity().unwrap();
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    let software = json!({
        "id":"fixture","appId":"quicksave:fixture","name":"Fixture",
        "roots":[{"id":"save","path":source_path,"role":"save","identity":identity}],
    });
    engine.register(&software).await.unwrap();
    let before = engine
        .software_files(&json!({"softwareId":"fixture"}))
        .await
        .unwrap();
    source
        .write_new("later.dat", |file| {
            file.write_all(b"later")?;
            Ok(())
        })
        .unwrap();
    let after = engine
        .software_files(&json!({"softwareId":"fixture"}))
        .await
        .unwrap();
    assert_eq!(
        before["files"], after["files"],
        "a UI page must not silently rescan/widen source authority"
    );
    assert_eq!(
        after["contentState"],
        "metadata_index_not_capture_authority"
    );
    engine.shutdown().await.unwrap();
}

#[test]
fn root_role_and_full_source_identity_are_frozen_not_synthetic_unix_metadata() {
    assert!(matches!(
        NativeRootRole::parse("installation")
            .unwrap()
            .classification(),
        (
            noland_state_core::PersistenceClass::ReconstructableApp,
            noland_state_core::SemanticRole::AppContent
        )
    ));
    assert!(NativeRootRole::parse("unknown-wildcard").is_err());
    let app = AppIdentity::new(AppId::steam(123), "Fixture");
    let decoded: AppIdentity = serde_json::from_value(serde_json::to_value(&app).unwrap()).unwrap();
    assert_eq!(decoded.app_id, app.app_id);
}

#[tokio::test]
async fn canonical_steam_identity_does_not_collapse_distinct_native_installations() {
    let fixture = Fixture::new();
    let source = SafeRoot::open(&fixture.root.join("software")).unwrap();
    source.create_dir("first").unwrap();
    source.create_dir("second").unwrap();
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    for (id, leaf) in [("first", "first"), ("second", "second")] {
        let path = fixture.root.join("software").join(leaf);
        let identity = SafeRoot::open(&path).unwrap().identity().unwrap();
        engine
            .register(&json!({
                "id":id,"appId":format!("steam:480@{id}"),"name":"Native fixture",
                "sourceIdentity":AppIdentity::new(AppId::steam(480), "Native fixture"),
                "roots":[{"id":format!("save-{id}"),"path":path,"role":"save","identity":identity}],
            }))
            .await
            .unwrap();
    }
    let first = engine.binding(&json!({"softwareId":"first"})).unwrap();
    let second = engine.binding(&json!({"softwareId":"second"})).unwrap();
    assert_eq!(first.app, AppId::steam(480));
    assert_eq!(second.app, first.app);
    assert_ne!(first.instance, second.instance);
    assert_ne!(first.roots[0].spec.logical, second.roots[0].spec.logical);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn metadata_only_capture_freezes_native_stamps_without_predicting_content_hashes() {
    struct Controller {
        nodes: Vec<capture::FrozenCaptureNode>,
    }
    impl capture::NativeCaptureController for Controller {
        fn node_page(
            &self,
            _: &CaptureScope,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<capture::FrozenCaptureNode>> {
            Ok(self.nodes[offset..(offset + limit).min(self.nodes.len())].to_vec())
        }
        fn accept(&self, _: Arc<capture::PreparedCaptureReceipt>) -> Result<()> {
            bail!("metadata freezing must not invent a completed source receipt")
        }
        fn verify_publication(&self) -> Result<()> {
            bail!("no source receipt was captured")
        }
    }
    let fixture = Fixture::new();
    let path = fixture.root.join("software");
    let root = SafeRoot::open(&path).unwrap();
    root.write_new("payload.dat", |file| {
        file.write_all(b"payload")?;
        Ok(())
    })
    .unwrap();
    let engine =
        NativeEngine::open(&fixture.root.join("data"), &fixture.root.join("home")).unwrap();
    engine
        .register(&json!({
            "id":"fixture","appId":"quicksave:fixture@native","name":"Native fixture",
            "sourceIdentity":AppIdentity::new(AppId("quicksave:fixture".into()), "Native fixture"),
            "roots":[{"id":"save","path":path,"role":"save","identity":root.identity().unwrap()}],
        }))
        .await
        .unwrap();
    let binding = engine.binding(&json!({"softwareId":"fixture"})).unwrap();
    let logical = binding.roots[0].spec.logical.clone();
    let (_, stamp) = root.read_file("payload.dat").unwrap();
    let scope = CaptureScope {
        version: 1,
        work_id: "work-fixture".into(),
        metadata_identity: "metadata-fixture".into(),
        node_count: 1,
        full_scope: None,
    };
    let controller = Controller {
        nodes: vec![capture::FrozenCaptureNode {
            id: file_id(&logical, "payload.dat"),
            root_id: "save".into(),
            logical_root: logical,
            path: "payload.dat".into(),
            kind: "file".into(),
            size: 7,
            stamp: stamp.clone(),
            link_target_hash: None,
        }],
    };
    let (files, metadata, _) = capture::freeze(&binding, &scope, &controller, "fixture").unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].stamp, stamp);
    assert!(files[0].hash.is_empty());
    assert!(metadata.is_empty());
    root.write_new("later.dat", |file| {
        file.write_all(b"not selected")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        capture::freeze(&binding, &scope, &controller, "fixture")
            .unwrap()
            .0
            .len(),
        1
    );
    let mut stale = controller;
    stale.nodes[0].stamp.file_id[1] ^= 1 << 63;
    assert!(capture::freeze(&binding, &scope, &stale, "fixture").is_err());
    engine.shutdown().await.unwrap();
}
