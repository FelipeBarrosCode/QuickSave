// SPDX-License-Identifier: GPL-3.0-only
// Network-free synthetic providers/configs only. No installed helper or keychain.
use super::*;
use crate::{
    native_session_token_fingerprint, register_native_private_credential_sink,
    NativeCredentialSinkRegistration, NativePrivateCredentialSink,
};
use noland_rclone_adapter::{session_from_input, AdapterCredential, AdapterInput, TokenMode};
use std::{
    collections::BTreeMap,
    fs,
    sync::{atomic::AtomicUsize, Mutex},
};

struct Fixture {
    root: PathBuf,
    session: EphemeralRcloneSession,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let approved = base.join("opencode");
        let base = if approved.is_dir() { approved } else { base };
        let root = base.join(format!(
            "quicksave-private-refresh-{}",
            uuid::Uuid::new_v4()
        ));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let session = session_from_input(
            &AdapterInput {
                provider: ProviderKind::GoogleDrive,
                remote_name: "synthetic_drive".into(),
                credentials: AdapterCredential::OAuth2 {
                    access_token: "SYNTHETIC-OLD-ACCESS".into(),
                    refresh_token: Some("SYNTHETIC-OLD-REFRESH".into()),
                    expires_at: 2_000_000_000,
                },
                fields: BTreeMap::from([(
                    "client_id".into(),
                    "synthetic-registered-client".into(),
                )]),
                bucket: None,
                prefix: Some("synthetic-approved-root".into()),
            },
            uuid::Uuid::new_v4().to_string(),
            TokenMode::Operation,
        )
        .unwrap();
        Self { root, session }
    }
    fn register(&self, fail: bool) -> (NativeCredentialSinkRegistration, Arc<AtomicUsize>) {
        let revision = Mutex::new(native_session_token_fingerprint(&self.session).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let sink: NativePrivateCredentialSink = Arc::new(move |rotation| {
            seen.fetch_add(1, Ordering::SeqCst);
            if fail {
                return Err(StateError::Storage(
                    "SYNTHETIC-PRIVATE-VAULT-FAILURE".into(),
                ));
            }
            let mut prior = revision.lock().unwrap();
            if rotation.token_fingerprint == *prior {
                return Ok(());
            }
            if rotation.expected_token_fingerprint != *prior {
                return Err(StateError::Conflict("synthetic stale rotation".into()));
            }
            *prior = rotation.token_fingerprint;
            Ok(())
        });
        (
            register_native_private_credential_sink(&self.session, sink).unwrap(),
            calls,
        )
    }
    fn rotated(&self, label: &str) -> String {
        self.session.config_ini.lines().map(|line| {
            if line.trim_start().starts_with("token =") {
                format!("token = {}", serde_json::json!({
                    "access_token":format!("SYNTHETIC-{label}-ACCESS"),"token_type":"Bearer",
                    "refresh_token":format!("SYNTHETIC-{label}-REFRESH"),"expiry":"2035-01-01T00:00:00Z",
                }))
            } else { line.to_owned() }
        }).collect::<Vec<_>>().join("\n") + "\n"
    }
    fn rotate(&self, path: &Path, label: &str) {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let temporary = path.with_file_name(format!("fixture-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap();
        file.write_all(self.rotated(label).as_bytes()).unwrap();
        file.sync_all().unwrap();
        fs::rename(&temporary, path).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn command_rotation_is_checked_before_health_success_and_cleanup() {
    let fixture = Fixture::new();
    let (_registration, calls) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let rotated = fixture.root.join("synthetic-reply.ini");
    fs::write(&rotated, fixture.rotated("COMMAND")).unwrap();
    let script = fixture.root.join("fake-read-only-provider");
    fs::write(
        &script,
        format!("set -eu\n/bin/cp {rotated:?} \"$2\"\nexit 0\n"),
    )
    .unwrap();
    let mut storage = RcloneStorage::try_from_session(&fixture.session, &config)
        .unwrap()
        .for_deletion();
    storage.control_executable = Some(script);
    let health = storage.health_check().await.unwrap();
    assert!(health.ok);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    guard.finish().unwrap();
    assert!(!config.parent().unwrap().exists());
}

#[tokio::test]
async fn callback_failure_is_sticky_and_never_a_successful_health_or_cleanup() {
    let fixture = Fixture::new();
    let (_registration, calls) = fixture.register(true);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    fixture.rotate(&config, "FAILED");
    let storage = RcloneStorage::try_from_session(&fixture.session, &config).unwrap();
    // Admission sees the rotation before it could launch any executable.
    assert!(storage.begin_native_attempt().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let error = guard.finish().err().unwrap();
    assert!(!format!("{error:?}").contains("SYNTHETIC-PRIVATE"));
    assert!(config.is_file());
}

#[tokio::test]
async fn parallel_attempts_remain_parallel_but_stale_rotation_cannot_replace_newer() {
    let fixture = Fixture::new();
    let (_registration, calls) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let storage = RcloneStorage::try_from_session(&fixture.session, &config).unwrap();
    let first = storage.begin_native_attempt().await.unwrap();
    // A long first transfer must not serialize the next independent batch.
    let second = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        storage.begin_native_attempt(),
    )
    .await
    .unwrap()
    .unwrap();
    fixture.rotate(&config, "FIRST");
    RcloneStorage::finish_native_attempt(first).unwrap();
    fixture.rotate(&config, "STALE-PARALLEL");
    assert!(RcloneStorage::finish_native_attempt(second).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(guard.finish().is_err());
    assert!(config.is_file());
}

#[tokio::test]
async fn nested_reads_and_retry_materialize_latest_committed_token_without_vault_polling() {
    let fixture = Fixture::new();
    let (_registration, calls) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let (nested, nested_guard) =
        write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    fixture.rotate(&config, "LATEST");
    guard.finish().unwrap();
    let storage = RcloneStorage::try_from_session(&fixture.session, &nested).unwrap();
    let attempt = storage.begin_native_attempt().await.unwrap();
    assert!(fs::read_to_string(&nested)
        .unwrap()
        .contains("SYNTHETIC-LATEST-REFRESH"));
    RcloneStorage::finish_native_attempt(attempt).unwrap();
    nested_guard.finish().unwrap();
    let (retry, retry_guard) =
        write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    assert!(fs::read_to_string(&retry)
        .unwrap()
        .contains("SYNTHETIC-LATEST-REFRESH"));
    retry_guard.finish().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn visibility_marker_uses_already_committed_access_only_and_restores_same_config() {
    let fixture = Fixture::new();
    let (_registration, calls) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    fixture.rotate(&config, "BEFORE-COMMITTED");
    let storage = RcloneStorage::try_from_session(&fixture.session, &config).unwrap();
    let publication = storage.begin_native_attempt_mode(true).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!fs::read_to_string(&config)
        .unwrap()
        .contains("refresh_token"));
    assert!(storage.begin_native_attempt().await.is_err());
    RcloneStorage::finish_native_attempt(publication).unwrap();
    assert!(fs::read_to_string(&config)
        .unwrap()
        .contains("SYNTHETIC-BEFORE-COMMITTED-REFRESH"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    guard.finish().unwrap();
}

#[test]
fn parser_rejects_extra_remotes_duplicate_keys_client_backend_and_routing_tamper() {
    for mutation in [
        "extra_remote",
        "duplicate",
        "client",
        "backend",
        "routing",
        "oversized",
    ] {
        let fixture = Fixture::new();
        let (_registration, calls) = fixture.register(false);
        let (config, guard) =
            write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
        let mut ini = fixture.rotated("REJECTED");
        match mutation {
            "extra_remote" => ini.push_str("\n[other]\ntype = local\n"),
            "duplicate" => ini.push_str("\nclient_id = second\n"),
            "client" => ini = ini.replace("synthetic-registered-client", "unapproved-client"),
            "backend" => ini = ini.replace("type = drive", "type = local"),
            "routing" => ini.push_str("\nroot_folder_id = unapproved\n"),
            "oversized" => ini.push_str(&"x".repeat(2 * 1024 * 1024)),
            _ => unreachable!(),
        }
        fs::write(&config, ini).unwrap();
        assert!(guard.finish().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(config.is_file());
    }
}

#[test]
fn startup_retains_unpersisted_rotation_then_checked_native_recovery_can_finish() {
    let fixture = Fixture::new();
    let (registration, _) = fixture.register(true);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let execution = config
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    fixture.rotate(&config, "CRASH-RETAINED");
    assert!(guard.finish().is_err());
    drop(registration);
    shred_all_ephemeral_sessions(&fixture.root).unwrap();
    assert!(config.is_file());
    let retained = retained_credential_sessions(&fixture.root).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].execution_id, execution);
    let (_registration, calls) = fixture.register(false);
    finish_retained_credential_session(&fixture.root, &execution, &fixture.session).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!config.parent().unwrap().exists());
}

#[test]
fn oauth_never_runs_without_registered_sink_or_with_a_different_root_binding() {
    let fixture = Fixture::new();
    assert!(write_guarded_ephemeral_session(&fixture.root, &fixture.session).is_err());
    let (_registration, _) = fixture.register(false);
    let mut changed = fixture.session.clone();
    changed.root = "not-approved".into();
    assert!(write_guarded_ephemeral_session(&fixture.root, &changed).is_err());
}

#[test]
fn sftp_and_webdav_session_scope_handles_random_obscure_ivs_but_guard_forbids_config_rewrites() {
    for kind in [ProviderKind::Sftp, ProviderKind::Webdav] {
        let fixture = Fixture::new();
        let fields = if kind == ProviderKind::Sftp {
            BTreeMap::from([
                ("host".into(), "synthetic.invalid".into()),
                ("host_keys".into(), "ssh-ed25519 SYNTHETIC-ONLY".into()),
            ])
        } else {
            BTreeMap::from([("url".into(), "https://synthetic.invalid".into())])
        };
        let input = AdapterInput {
            provider: kind,
            remote_name: "synthetic_static".into(),
            credentials: AdapterCredential::UsernamePassword {
                username: "synthetic-user".into(),
                password: "synthetic-password".into(),
            },
            fields,
            bucket: None,
            prefix: Some("synthetic-root".into()),
        };
        let first = session_from_input(&input, "first-static", TokenMode::Operation).unwrap();
        let second = session_from_input(&input, "second-static", TokenMode::Operation).unwrap();
        assert_ne!(first.config_ini, second.config_ini); // random public obscure IVs
        assert!(crate::native_sessions_have_same_scope(&first, &second).unwrap());
        let mut changed = second.clone();
        changed.config_ini = changed
            .config_ini
            .replace("synthetic-user", "different-user");
        assert!(!crate::native_sessions_have_same_scope(&first, &changed).unwrap());
        let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &first).unwrap();
        fs::write(&config, &second.config_ini).unwrap();
        assert!(guard.finish().is_err()); // token-only mutation rule is unchanged
    }
}

#[tokio::test]
async fn bounded_progress_framing_handles_crlf_eof_and_cancellation_without_losing_prefix() {
    use tokio::io::AsyncWriteExt;
    let mut lines = BoundedProgressLines::new(&b"one\r\ntwo\nlast"[..]);
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("one"));
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("two"));
    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("last"));
    assert!(lines.next_line().await.unwrap().is_none());
    let oversized = vec![b'x'; 256 * 1024 + 1];
    assert!(BoundedProgressLines::new(oversized.as_slice())
        .next_line()
        .await
        .is_err());
    let (mut writer, reader) = tokio::io::duplex(1024);
    let mut lines = BoundedProgressLines::new(reader);
    writer.write_all(b"first-").await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(5), lines.next_line())
            .await
            .is_err()
    );
    writer.write_all(b"second\n").await.unwrap();
    assert_eq!(
        lines.next_line().await.unwrap().as_deref(),
        Some("first-second")
    );
}

#[tokio::test]
async fn unfinished_children_stay_live_even_after_an_outer_guard_is_consumed_early() {
    let fixture = Fixture::new();
    let (_registration, _) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let storage = RcloneStorage::try_from_session(&fixture.session, &config).unwrap();
    let attempt = storage.begin_native_attempt().await.unwrap();
    assert!(guard.finish().is_err());
    assert!(retained_credential_sessions(&fixture.root)
        .unwrap()
        .is_empty());
    assert!(shred_ephemeral_session(
        &fixture.root,
        config
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
    )
    .is_err());
    assert!(RcloneStorage::finish_native_attempt(attempt).is_err());
    assert_eq!(
        retained_credential_sessions(&fixture.root).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn finalized_guard_seals_future_subprocess_admission_without_poisoning_a_healthy_lifecycle() {
    let fixture = Fixture::new();
    let (registration, _) = fixture.register(false);
    let (config, guard) = write_guarded_ephemeral_session(&fixture.root, &fixture.session).unwrap();
    let storage = RcloneStorage::try_from_session(&fixture.session, &config).unwrap();
    guard.finish().unwrap();
    registration.checkpoint().unwrap();
    assert!(storage.begin_native_attempt().await.is_err());
    assert!(!config.parent().unwrap().exists());
    registration.checkpoint().unwrap();
}
