// SPDX-License-Identifier: GPL-3.0-only
//! Windows-only synthetic files, ACLs and callbacks. Never starts a helper,
//! browser, account request or native credential vault.
use super::*;
use crate::{register_native_private_credential_sink, NativePrivateCredentialSink};
use noland_rclone_adapter::{session_from_input, AdapterCredential, AdapterInput, TokenMode};
use std::{collections::BTreeMap, fs, sync::atomic::AtomicUsize};

struct Fixture {
    root: PathBuf,
    session: EphemeralRcloneSession,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "quicksave-windows-handoff-{}",
            uuid::Uuid::new_v4()
        ));
        crate::native_fs::create_private_directory(&root).unwrap();
        let session = session_from_input(
            &AdapterInput {
                provider: ProviderKind::GoogleDrive,
                remote_name: "synthetic_windows_drive".into(),
                credentials: AdapterCredential::OAuth2 {
                    access_token: "SYNTHETIC-OLD".into(),
                    refresh_token: Some("SYNTHETIC-OLD-REFRESH".into()),
                    expires_at: 2_000_000_000,
                },
                fields: BTreeMap::from([("client_id".into(), "synthetic-owned-client".into())]),
                bucket: None,
                prefix: Some("synthetic-root".into()),
            },
            uuid::Uuid::new_v4().to_string(),
            TokenMode::Operation,
        )
        .unwrap();
        Self { root, session }
    }
    fn sink(&self, fail: bool) -> (crate::NativeCredentialSinkRegistration, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let sink: NativePrivateCredentialSink = Arc::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            if fail {
                Err(StateError::Conflict("synthetic persistence failure".into()))
            } else {
                Ok(())
            }
        });
        (
            register_native_private_credential_sink(&self.session, sink).unwrap(),
            calls,
        )
    }
    fn replace_as_rclone(&self, config: &Path) {
        let text = self.session.config_ini.lines().map(|line| {
            if line.trim_start().starts_with("token =") {
                format!("token = {}", serde_json::json!({
                    "access_token":"SYNTHETIC-ROTATED","token_type":"Bearer",
                    "refresh_token":"SYNTHETIC-ROTATED-REFRESH","expiry":"2035-01-01T00:00:00Z",
                }))
            } else { line.to_owned() }
        }).collect::<Vec<_>>().join("\n") + "\n";
        let temporary =
            config.with_file_name(format!("rclone-fixture-{}.tmp", uuid::Uuid::new_v4()));
        // Ordinary file creation must inherit only the current user, not the
        // process token's broader default ACL, just like rclone's config writer.
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let file = noland_snapshot::SourcePath::new(&temporary)
            .unwrap()
            .open_regular()
            .unwrap();
        crate::native_fs::verify_private_file(&file).unwrap();
        assert!(noland_snapshot::native_metadata::verify_private_file(&file).is_err());
        drop(file);
        fs::rename(temporary, config).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn windows_real_native_ids_user_only_replacements_and_checked_finalization() {
    let fixture = Fixture::new();
    let (registration, calls) = fixture.sink(false);
    let (config, guard) =
        write_guarded_ephemeral_session(&fixture.root.join("run"), &fixture.session).unwrap();
    {
        let file = noland_snapshot::SourcePath::new(&config)
            .unwrap()
            .open_regular()
            .unwrap();
        assert_eq!(
            crate::native_fs::identity(&file).unwrap(),
            noland_snapshot::WindowsMetadata::from_file(&file)
                .unwrap()
                .identity
        );
    }
    fixture.replace_as_rclone(&config);
    guard.finish().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!config.parent().unwrap().exists());
    registration.checkpoint().unwrap();
}

#[test]
fn windows_failed_handoff_survives_startup_then_checked_recovery() {
    let fixture = Fixture::new();
    let (registration, _) = fixture.sink(true);
    let run = fixture.root.join("run");
    let (config, guard) = write_guarded_ephemeral_session(&run, &fixture.session).unwrap();
    let execution = config
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    fixture.replace_as_rclone(&config);
    assert!(guard.finish().is_err());
    drop(registration);
    shred_all_ephemeral_sessions(&run).unwrap();
    assert!(config.exists());
    assert_eq!(retained_credential_sessions(&run).unwrap().len(), 1);
    let (_registration, calls) = fixture.sink(false);
    finish_retained_credential_session(&run, &execution, &fixture.session).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!config.parent().unwrap().exists());
}

#[test]
fn windows_case_alias_does_not_make_a_live_session_a_retained_artifact() {
    let fixture = Fixture::new();
    let (_registration, _) = fixture.sink(false);
    let run = fixture.root.join("run");
    let (config, guard) = write_guarded_ephemeral_session(&run, &fixture.session).unwrap();
    let alias = PathBuf::from(run.to_str().unwrap().to_uppercase());
    assert!(retained_credential_sessions(&alias).unwrap().is_empty());
    assert!(shred_ephemeral_session(
        &alias,
        config
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
    )
    .is_err());
    guard.finish().unwrap();
}

#[test]
fn windows_cleanup_never_truncates_an_external_hard_link() {
    let fixture = Fixture::new();
    let local = EphemeralRcloneSession {
        operation_id: uuid::Uuid::new_v4().to_string(),
        provider: "local".into(),
        backend_type: "local".into(),
        remote_name: "synthetic_local".into(),
        root: fixture
            .root
            .join("synthetic-cloud")
            .to_str()
            .unwrap()
            .to_owned(),
        config_ini: "[synthetic_local]\ntype = local\n".into(),
        expires_at_unix: 0,
        upload_concurrency: None,
    };
    let (config, guard) =
        write_guarded_ephemeral_session(&fixture.root.join("run"), &local).unwrap();
    let outside = fixture.root.join("outside-sentinel");
    fs::write(&outside, b"synthetic unrelated bytes").unwrap();
    fs::remove_file(&config).unwrap();
    fs::hard_link(&outside, &config).unwrap();
    drop(guard);
    assert_eq!(fs::read(outside).unwrap(), b"synthetic unrelated bytes");
}

#[test]
fn windows_immutable_batch_staging_unlinks_readonly_leases_without_mutating_the_pack() {
    use std::io::Write;
    let fixture = Fixture::new();
    let pack = fixture.root.join("synthetic-sealed.pack");
    {
        let mut file = noland_snapshot::SourcePath::new(&pack)
            .unwrap()
            .open_partial_private(true)
            .unwrap();
        file.write_all(b"synthetic sealed ciphertext").unwrap();
        file.sync_all().unwrap();
    }
    let mut permissions = fs::metadata(&pack).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&pack, permissions).unwrap();
    let mut stage = StagingTree::create_under(&fixture.root, "readonly-batch").unwrap();
    stage
        .link_or_copy(&pack, &RemoteKey::new("packs/synthetic/fixture.pack"))
        .unwrap();
    let staged = stage.root.clone();
    assert_eq!(stage.files, 1);
    drop(stage);
    assert!(!staged.exists());
    assert_eq!(fs::read(&pack).unwrap(), b"synthetic sealed ciphertext");
    assert!(fs::metadata(&pack).unwrap().permissions().readonly());
    // Only test-fixture teardown changes its synthetic file's flag.
    let mut permissions = fs::metadata(&pack).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&pack, permissions).unwrap();
}
