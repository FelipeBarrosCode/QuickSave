// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic isolated files and injected vaults only. Never instantiate a
//! production vault/account or load a real No Land state file in these tests.

use super::*;
use noland_rclone_adapter::{EphemeralRcloneSession, ProviderKind};
use std::{fs, path::PathBuf, thread};
use tempfile::TempDir;

fn temporary() -> TempDir {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let approved = base.join("opencode");
    tempfile::Builder::new()
        .prefix("quicksave-state-")
        .tempdir_in(if approved.is_dir() { approved } else { base })
        .unwrap()
}

fn fixture() -> (TempDir, MemoryVault, WorkspaceStore) {
    let temp = temporary();
    let vault = MemoryVault::default();
    let store =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    (temp, vault, store)
}

fn b2_input(name: &str) -> Value {
    json!({
        "kind":"backblaze_b2","name":name,"bucket":"synthetic-bucket","prefix":"backups",
        "credentials":{"type":"backblaze_b2","value":{"key_id":"synthetic-key-id","application_key":"synthetic-provider-secret"}},
    })
}

fn connected(store: &WorkspaceStore) -> String {
    let result = store
        .connect_provider(&b2_input("Synthetic storage"))
        .unwrap();
    let id = result["providers"].as_array().unwrap().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        result["providers"].as_array().unwrap().last().unwrap()["status"],
        "connecting"
    );
    store.record_provider_health(&id, &json!({"canList":true,"canRead":true,"repositoryAccessible":true,"repositoryEmpty":false,"keyVerified":true})).unwrap();
    id
}

fn oauth_credentials(access: &str, refresh: Option<&str>) -> Value {
    json!({
        "type":"o_auth2","value":{
            "access_token":access,"refresh_token":refresh,"expires_at":1900000000,
        },
    })
}

fn connected_oauth(store: &WorkspaceStore, kind: ProviderKind) -> String {
    let mut fields =
        json!({"client_id":"synthetic-client","client_secret":"PRIVATE-CLIENT-SECRET"});
    if kind == ProviderKind::MicrosoftOneDrive {
        fields["drive_id"] = json!("synthetic-drive");
        fields["drive_type"] = json!("personal");
    }
    let result = store
        .connect_provider(&json!({
            "kind":kind.as_str(),"name":kind.label(),"prefix":"approved-cloud-root","fields":fields,
            "credentials":oauth_credentials("PRIVATE-OLD-ACCESS",Some("PRIVATE-OLD-REFRESH")),
        }))
        .unwrap();
    let id = result["providers"].as_array().unwrap().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    store
        .record_provider_health(
            &id,
            &json!({
                "providerId":id,"canList":true,"repositoryAccessible":true,"repositoryEmpty":true,
                "canRead":false,"keyVerified":false,
            }),
        )
        .unwrap();
    id
}

fn roots(path: &str) -> Value {
    json!([{
        "id":"root-1","path":path,"role":"manual",
        "identity":{"device":17,"fileId":[42,0]},"allowedFiles":["save.dat"],
    }])
}

fn tracked(store: &WorkspaceStore, provider: &str) {
    store.update_software(&json!({
        "id":"software-1","appId":"test.application","name":"Synthetic application","tracked":true,
        "roots":roots("/synthetic/approved"),"providerId":provider,
        "dirtyGeneration":1,
    })).unwrap();
    store.seal_tracking_grant("software-1").unwrap();
}

#[cfg(unix)]
#[test]
fn unix_manual_leaves_keep_exact_native_names_in_the_tracking_grant() {
    let (_temporary, _vault, store) = fixture();
    let mut approved = roots("/synthetic/approved");
    approved[0]["allowedFiles"] = json!(["a:b", "a\\b"]);
    store
        .update_software(&json!({
            "id":"native-names","appId":"test.native.names","name":"Synthetic native names",
            "tracked":true,"roots":approved,"dirtyGeneration":1,
        }))
        .unwrap();
    store.seal_tracking_grant("native-names").unwrap();
    assert!(store.verify_tracking_grant("native-names").unwrap());
    let record = store.software_record("native-names").unwrap();
    assert_eq!(record["roots"][0]["allowedFiles"], json!(["a:b", "a\\b"]));
    let mut changed = record["roots"].clone();
    changed[0]["allowedFiles"] = json!(["a:b", "ab"]);
    store
        .update_software(&json!({"id":"native-names","roots":changed}))
        .unwrap();
    assert!(!store.verify_tracking_grant("native-names").unwrap());
}

/// Exact trackingresume::frame_scope / write_frame schema, not an authentic
/// frame or grant. No signing API, private work file or native vault is used.
fn pending_work_reference(software: &str, bytes: u64) -> Value {
    let name = "work-11111111-1111-4111-8111-111111111111.json";
    let hash = "01".repeat(32);
    let scope = json!({
        "version":1,"softwareId":software,
        "workId":"22222222-2222-4222-8222-222222222222",
        "generation":u64::MAX,"originToken":"33333333-3333-4333-8333-333333333333",
        "appId":null,"providerId":null,
        "trackingScopeHash":"02".repeat(32),"trackingGrantHash":"03".repeat(32),
        "sourceIdentityHash":"04".repeat(32),"autosaveScopeHash":"05".repeat(32),
        "authorizationHash":"06".repeat(32),"automatic":false,"unknownGeneration":u64::MAX,
        "metadataIdentity":"07".repeat(32),"fullScopeProofHash":"08".repeat(32),
        "baselineReferenceHash":"09".repeat(32),"selectedIdsHash":"0a".repeat(32),
        "deletedIdsHash":"0b".repeat(32),"originalReferenceHash":"0c".repeat(32),
        "captureReceiptHash":"0d".repeat(32),"frameHash":hash,"name":name,"bytes":bytes,
        "stage":"metadata_frozen",
    });
    let account = authority_account("tracking_frozen_work", &scope).unwrap();
    json!({
        "version":1,"name":name,"hash":hash,"bytes":bytes,"scope":scope,
        "grant":{"version":1,"algorithm":"hmac-sha256","kind":"tracking_frozen_work",
            "nonce":"ce".repeat(32),"mac":"be".repeat(32),"authorityRef":account},
    })
}

fn source_file(temp: &TempDir, secret: Option<Value>) -> PathBuf {
    let path = temp.path().join("selected-noland-state.json");
    fs::write(&path, serde_json::to_vec(&json!({
        "sharedStorageProfiles":[{
            "id":"source-profile","displayName":"Imported storage","providerLabel":"Backblaze B2",
            "provider":"backblaze_b2","bucket":"synthetic-bucket","prefix":"old-repository",
        }],
        "sharedStorageCredentials":{
            "repositoryKeyHex":"",
            "profiles":secret.map(|value| json!({"source-profile":value})).unwrap_or_else(||json!({})),
            "oauthSessions":{"unrelated":{"credentials":{"type":"o_auth2","value":{"access_token":"DO-NOT-COPY-OAUTH-SESSION"}}}},
        },
        "credentials":{"vastApiKey":"DO-NOT-COPY-VAST","appPassword":"DO-NOT-COPY-APP-PASSWORD"},
        "ssh":{"sshPassword":"DO-NOT-COPY-SSH","privateKeyPath":"/unrelated/forbidden"},
        "wireguard":{"privateKey":"DO-NOT-COPY-WIREGUARD"},
    })).unwrap()).unwrap();
    path
}

fn source_secret(key: &str) -> Value {
    json!({
        "credentials":{"type":"backblaze_b2","value":{"key_id":"import-key-id","application_key":"import-secret"}},
        "providerFields":{},"repositoryKeyHex":key,
    })
}

fn source_document(vault: &MemoryVault, entries: Vec<(&str, Option<String>)>) {
    let entries: BTreeMap<String, Option<String>> = entries
        .into_iter()
        .map(|(account, value)| {
            (
                serde_json::to_string(&(NOLAND_STATE_SERVICE, account)).unwrap(),
                value,
            )
        })
        .collect();
    vault
        .seed(
            NOLAND_DOCUMENT_SERVICE,
            NOLAND_DOCUMENT_ACCOUNT,
            &serde_json::to_string(&json!({"entries":entries})).unwrap(),
        )
        .unwrap();
}

fn import_file_handoff(path: &std::path::Path) -> Value {
    let parent = quicksave_platform::SafeRoot::open(path.parent().unwrap()).unwrap();
    let (_file, stamp) = parent
        .read_file(path.file_name().unwrap().to_str().unwrap())
        .unwrap();
    json!({
        "path":path,"kind":"file",
        "identity":{"device":stamp.device,"fileId":stamp.file_id},
        "stamp":stamp,"parentIdentity":parent.identity().unwrap(),
    })
}

#[test]
fn open_queries_and_import_preview_never_read_vault_or_selected_file() {
    let (_temp, vault, store) = fixture();
    vault.deny_access(true).unwrap();
    assert!(store.sanitized().unwrap()["providers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(store.provider_types().as_array().unwrap().len(), 14);
    assert!(store.software().unwrap().is_empty());
    let preview = store
        .noland_import_preview(&json!({"stateFile":"/does-not-exist/state.json"}))
        .unwrap();
    assert_eq!(preview["nativeSelectionRequired"], true);
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn writes_private_atomic_state_and_coalesces_identical_updates() {
    use std::os::unix::fs::MetadataExt;
    let (temp, _vault, store) = fixture();
    let path = temp.path().join("workspace/state.json");
    let initial = fs::metadata(&path).unwrap();
    assert_eq!(initial.mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(temp.path().join("workspace")).unwrap().mode() & 0o777,
        0o700
    );
    let patch = json!({"id":"untracked","name":"Discovered application","status":"not_tracked","dirty":false});
    store.update_software(&patch).unwrap();
    let after = fs::metadata(&path).unwrap();
    assert_ne!(
        initial.ino(),
        after.ino(),
        "replacement must use a new staged inode"
    );
    let generation = store.document().unwrap().generation;
    store.update_software(&patch).unwrap();
    assert_eq!(store.document().unwrap().generation, generation);
    assert_eq!(
        fs::metadata(&path).unwrap().ino(),
        after.ino(),
        "identical changes must coalesce"
    );
}

#[test]
fn transactions_preserve_parallel_updates_across_independent_handles() {
    let (temp, vault, store) = fixture();
    store
        .update_software(&json!({"id":"counter","name":"Counter"}))
        .unwrap();
    let mut workers = Vec::new();
    for _ in 0..4 {
        let store = WorkspaceStore::open_with_vault(
            &temp.path().join("workspace"),
            Arc::new(vault.clone()),
        )
        .unwrap();
        workers.push(thread::spawn(move || {
            for _ in 0..8 {
                store.mark_dirty("counter").unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        store.software_record("counter").unwrap()["dirtyGeneration"],
        32
    );
}

#[test]
fn failed_transaction_preserves_previous_durable_document() {
    let (temp, _vault, store) = fixture();
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let result: Result<()> = store.transaction(|document| {
        document.settings.keep_local_data = false;
        bail!("synthetic rejected update");
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert!(store
        .transaction(|document| {
            document.settings.keep_local_data = false;
            Ok(())
        })
        .is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
}

#[test]
fn rejects_state_symlink_hardlink_and_replaced_directory() {
    use std::os::unix::fs::symlink;
    let (temp, vault, store) = fixture();
    let path = temp.path().join("workspace/state.json");
    let outside = temp.path().join("outside.json");
    fs::rename(&path, &outside).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.sanitized().is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    assert!(store.sanitized().is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&outside, &path).unwrap();
    fs::rename(temp.path().join("workspace"), temp.path().join("moved")).unwrap();
    let replacement =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault)).unwrap();
    assert!(store.sanitized().is_err());
    assert!(replacement.sanitized().is_ok());
}

#[test]
fn rejects_replaced_lock_inode() {
    let (temp, _vault, store) = fixture();
    let lock = store.inner.file.lock().unwrap();
    let path = temp.path().join("workspace/state.lock");
    fs::rename(&path, temp.path().join("old-lock")).unwrap();
    fs::write(&path, b"").unwrap();
    assert!(lock.read().is_err());
}

#[test]
fn rejects_unlocked_state_content_mutation_instead_of_overwriting_unknown_work() {
    let (temp, _vault, store) = fixture();
    let locked = store.inner.file.lock().unwrap();
    let before = locked.read().unwrap().unwrap();
    let path = temp.path().join("workspace/state.json");
    let mut changed: Value = serde_json::from_slice(&before).unwrap();
    changed["settings"]["launchAtLogin"] = json!(true);
    let changed = serde_json::to_vec(&changed).unwrap();
    fs::write(&path, &changed).unwrap();
    assert!(locked.replace(&before).is_err());
    assert_eq!(fs::read(path).unwrap(), changed);
}

#[test]
fn state_process_worker() {
    let Some(path) = std::env::var_os("QUICKSAVE_SYNTHETIC_STATE_WORKER") else {
        return;
    };
    let path = PathBuf::from(path);
    // Only the explicitly spawned synthetic test directory can be opened.
    let temporary_base = std::env::temp_dir().canonicalize().unwrap();
    assert!(path.starts_with(temporary_base));
    assert_eq!(path.file_name().unwrap(), "workspace");
    assert!(path
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("quicksave-state-"));
    let store = WorkspaceStore::open_with_vault(&path, Arc::new(MemoryVault::default())).unwrap();
    for _ in 0..8 {
        store.mark_dirty("process-counter").unwrap();
    }
}

#[test]
fn flock_serializes_separate_process_generations() {
    use std::process::{Command, Stdio};
    let (temp, _vault, store) = fixture();
    store
        .update_software(&json!({"id":"process-counter","name":"Synthetic process counter"}))
        .unwrap();
    let mut children = Vec::new();
    for _ in 0..3 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::state_process_worker", "--test-threads=1"])
                .env(
                    "QUICKSAVE_SYNTHETIC_STATE_WORKER",
                    temp.path().join("workspace"),
                )
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(
            child.wait().unwrap().success(),
            "synthetic lock worker failed"
        );
    }
    assert_eq!(
        store.software_record("process-counter").unwrap()["dirtyGeneration"],
        24
    );
}

#[test]
fn rejects_oversize_corrupt_unknown_and_nonprivate_state() {
    use std::os::unix::fs::PermissionsExt;
    let (temp, _vault, store) = fixture();
    let path = temp.path().join("workspace/state.json");
    let before = fs::read(&path).unwrap();
    fs::write(&path, vec![b' '; state_file::MAX_STATE_BYTES + 1]).unwrap();
    assert!(store.sanitized().is_err());
    fs::write(&path, br#"{"password":"never-settings"}"#).unwrap();
    assert!(store.sanitized().is_err());
    fs::write(&path, &before).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.sanitized().is_err());
}

#[test]
fn new_profiles_require_real_health_and_keep_secrets_out_of_state_and_dto() {
    let (temp, _vault, store) = fixture();
    let dashboard = store.connect_provider(&b2_input("Synthetic")).unwrap();
    let id = dashboard["providers"][0]["id"].as_str().unwrap();
    assert_eq!(dashboard["providers"][0]["status"], "connecting");
    assert_eq!(dashboard["summary"]["connectedProviders"], 0);
    let state = fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    for secret in [
        "synthetic-key-id",
        "synthetic-provider-secret",
        "config_ini",
        "repositoryKeyHex",
    ] {
        assert!(!state.contains(secret));
        assert!(!dashboard.to_string().contains(secret));
    }
    store
        .record_provider_health(id, &json!({"authenticated":true}))
        .unwrap();
    assert_eq!(
        store.sanitized().unwrap()["providers"][0]["status"],
        "error"
    );
    assert!(!store.provider_writable(id).unwrap());
    store.record_provider_health(id, &json!({"canList":true,"canRead":true,"repositoryAccessible":true,"repositoryEmpty":false,"keyVerified":true})).unwrap();
    assert!(store.provider_writable(id).unwrap());
}

#[test]
fn actual_empty_repository_probe_connects_without_fabricating_can_read_or_authentication() {
    let (_temp, _vault, store) = fixture();
    let result = store
        .connect_provider(&b2_input("New empty repository"))
        .unwrap();
    let id = result["providers"][0]["id"].as_str().unwrap();
    let probe = json!({
        "providerId":id,"canList":true,"canRead":false,"repositoryAccessible":true,
        "repositoryEmpty":true,"keyVerified":false,
        "observedAt":"2026-11-17T12:00:00Z",
        "evidence":"actual read-only list and absent repository head",
    });
    assert!(probe.get("authenticated").is_none());
    store.record_provider_health(id, &probe).unwrap();
    assert_eq!(
        store.sanitized().unwrap()["providers"][0]["status"],
        "connected"
    );
    assert!(store.provider_writable(id).unwrap());
    let mut incomplete_nonempty = probe;
    incomplete_nonempty["repositoryEmpty"] = json!(false);
    incomplete_nonempty["canRead"] = json!(true);
    incomplete_nonempty["error"] = json!("SYNTHETIC-SECRET-IN-RAW-PROVIDER-ERROR");
    store
        .record_provider_health(id, &incomplete_nonempty)
        .unwrap();
    let dashboard = store.sanitized().unwrap();
    assert_eq!(dashboard["providers"][0]["status"], "error");
    assert!(!dashboard.to_string().contains("SYNTHETIC-SECRET"));
}

#[test]
fn native_repository_key_is_shared_and_survives_every_disconnect_and_restart() {
    let (temp, vault, store) = fixture();
    let first = connected(&store);
    let access = store.provider_access(&first, "first-operation").unwrap();
    let key = Zeroizing::new(access.repository_key);
    store.disconnect_provider(&first).unwrap();
    assert!(store.provider_access(&first, "disconnected").is_err());
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault)).unwrap();
    let second = connected(&restarted);
    let access = restarted
        .provider_access(&second, "next-operation")
        .unwrap();
    assert_eq!(&access.repository_key, key.as_ref());
}

#[test]
fn session_is_exact_shared_adapter_wire_shape_and_operation_scoped() {
    let (_temp, _vault, store) = fixture();
    let id = connected(&store);
    let access = store.provider_access(&id, "native-operation").unwrap();
    let session: EphemeralRcloneSession = serde_json::from_value(access.session.clone()).unwrap();
    assert_eq!(session.operation_id, "native-operation");
    assert_eq!(session.backend_type, "b2");
    assert_eq!(session.root, "synthetic-bucket/backups");
    assert!(session.config_ini.contains("synthetic-provider-secret"));
    assert!(!access.read_only);
    assert!(store.provider_access(&id, "bad\noperation").is_err());
}

#[test]
fn every_production_provider_uses_real_adapter_and_exact_credential_shape() {
    let (_temp, _vault, store) = fixture();
    for kind in provider::ALL_PROVIDER_KINDS {
        let (credentials, fields) = match kind {
            ProviderKind::AmazonS3
            | ProviderKind::Wasabi
            | ProviderKind::GenericS3
            | ProviderKind::DigitalOceanSpaces
            | ProviderKind::CloudflareR2 => (
                json!({"type":"s3","value":{"access_key_id":"test-access","secret_access_key":"test-secret","session_token":null}}),
                match kind {
                    ProviderKind::GenericS3 => json!({"endpoint":"https://storage.invalid"}),
                    ProviderKind::DigitalOceanSpaces => json!({"region":"nyc3"}),
                    ProviderKind::CloudflareR2 => json!({"account_id":"synthetic"}),
                    _ => json!({}),
                },
            ),
            ProviderKind::BackblazeB2 => (b2_input("unused")["credentials"].clone(), json!({})),
            ProviderKind::GoogleDrive
            | ProviderKind::MicrosoftOneDrive
            | ProviderKind::Dropbox
            | ProviderKind::Box => (
                json!({"type":"o_auth2","value":{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_at":1900000000}}),
                if kind == ProviderKind::MicrosoftOneDrive {
                    json!({"client_id":"registered-client","drive_id":"synthetic-drive","drive_type":"personal"})
                } else if kind == ProviderKind::Box {
                    json!({"client_id":"registered-client","client_secret":"synthetic-user-owned-confidential-client-secret"})
                } else {
                    json!({"client_id":"registered-client"})
                },
            ),
            ProviderKind::GoogleCloudStorage => (
                json!({"type":"service_account","value":{"json":json!({"type":"service_account","private_key":"SYNTHETIC-KEY","client_email":"synthetic@example.invalid"}).to_string()}}),
                json!({}),
            ),
            ProviderKind::AzureBlob | ProviderKind::Sftp | ProviderKind::Webdav => (
                json!({"type":"username_password","value":{"username":"synthetic-user","password":"synthetic-password"}}),
                match kind {
                    ProviderKind::Sftp => {
                        json!({"host":"sftp.invalid","host_keys":"ssh-ed25519 SYNTHETIC-ONLY"})
                    }
                    ProviderKind::Webdav => json!({"url":"https://webdav.invalid"}),
                    _ => json!({}),
                },
            ),
            ProviderKind::Local => unreachable!(),
        };
        let result = store.connect_provider(&json!({
            "kind":kind.as_str(),"name":kind.label(),"bucket":kind.uses_bucket_root().then_some("test-bucket"),
            "prefix":"test-prefix","fields":fields,"credentials":credentials,
        })).unwrap();
        let id = result["providers"].as_array().unwrap().last().unwrap()["id"]
            .as_str()
            .unwrap();
        let access = store.provider_access(id, "test-operation").unwrap();
        let session: EphemeralRcloneSession =
            serde_json::from_value(access.session.clone()).unwrap();
        assert_eq!(session.provider, kind.as_str());
        assert_eq!(session.backend_type, kind.backend_type());
    }
}

#[test]
fn rejects_local_remote_unknown_fields_missing_clients_and_unpinned_sftp() {
    let (_temp, _vault, store) = fixture();
    assert!(store
        .connect_provider(&json!({"kind":"local","name":"No local provider"}))
        .is_err());
    let mut input = b2_input("Bad field");
    input["fields"] = json!({"config":"/arbitrary/global/rclone.conf"});
    assert!(store.connect_provider(&input).is_err());
    let oauth = json!({"kind":"google_drive","name":"No client","credentials":{"type":"o_auth2","value":{"access_token":"synthetic","refresh_token":null,"expires_at":1900000000}}});
    assert!(store.connect_provider(&oauth).is_err());
    assert!(store
        .connect_oauth(&json!({"kind":"google_drive"}))
        .is_err());
    let sftp = json!({"kind":"sftp","name":"No host trust","fields":{"host":"example.invalid"},"credentials":{"type":"username_password","value":{"username":"user","password":"password"}}});
    assert!(store.connect_provider(&sftp).is_err());
    let mut injected = b2_input("Bad prefix");
    injected["prefix"] = json!("../different-root");
    assert!(store.connect_provider(&injected).is_err());
}

#[test]
fn editable_provider_routing_and_read_only_flags_cannot_override_native_binding() {
    let (_temp, _vault, store) = fixture();
    let id = connected(&store);
    store
        .transaction(|document| {
            document.providers[0].prefix = Some("attacker-root".into());
            Ok(())
        })
        .unwrap();
    assert!(store.provider_access(&id, "tampered").is_err());
    assert!(store
        .record_provider_health(
            &id,
            &json!({"canList":true,"canRead":true,"repositoryAccessible":true,"repositoryEmpty":false,"keyVerified":true})
        )
        .is_err());
}

#[test]
fn failed_vault_writes_never_publish_configured_profiles() {
    let (temp, vault, store) = fixture();
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    vault.fail_writes(true).unwrap();
    assert!(store.connect_provider(&b2_input("Rejected")).is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert!(store.sanitized().unwrap()["providers"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn noland_v2_import_is_read_only_source_unchanged_storage_only_and_new_namespace() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let source_before = fs::read(&path).unwrap();
    let account = dynamic_profile_account("source-profile");
    source_document(
        &vault,
        vec![
            (&account, Some(source_secret(&"bb".repeat(32)).to_string())),
            ("shared-storage.repository-key", Some("aa".repeat(32))),
            ("credentials.vast-api-key", Some("DO-NOT-COPY-VAST".into())),
            ("ssh.password", Some("DO-NOT-COPY-SSH".into())),
        ],
    );
    let source_vault_before = vault
        .read(NOLAND_DOCUMENT_SERVICE, NOLAND_DOCUMENT_ACCOUNT)
        .unwrap()
        .unwrap();
    let result = store.import_noland(&json!({"stateFile":path})).unwrap();
    let id = result["providers"][0]["id"].as_str().unwrap();
    assert_eq!(result["providers"][0]["origin"], "noland");
    assert_eq!(result["providers"][0]["status"], "connecting");
    assert_eq!(result["providers"][0]["readOnly"], true);
    let access = store.provider_access(id, "read-imported").unwrap();
    assert!(access.read_only);
    assert_eq!(
        access.repository_key, [0xaa; 32],
        "global No Land key has source precedence"
    );
    assert_eq!(fs::read(&path).unwrap(), source_before);
    assert_eq!(
        vault
            .read(NOLAND_DOCUMENT_SERVICE, NOLAND_DOCUMENT_ACCOUNT)
            .unwrap()
            .unwrap()
            .as_str(),
        source_vault_before.as_str()
    );
    let log = vault.access_log().unwrap();
    for write in log["writes"].as_array().unwrap() {
        assert_eq!(write[0], QUICKSAVE_VAULT_SERVICE);
    }
    let state = fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    for secret in [
        "DO-NOT-COPY",
        "import-secret",
        &"aa".repeat(32),
        &"bb".repeat(32),
    ] {
        assert!(!state.contains(secret));
    }
    for provider in store.document().unwrap().providers {
        let secret = vault
            .read(QUICKSAVE_VAULT_SERVICE, &provider.credential_ref)
            .unwrap()
            .unwrap();
        assert!(!secret.contains("DO-NOT-COPY"));
    }
}

#[test]
fn imported_write_authority_requires_separate_vault_grant_not_json_false() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let account = dynamic_profile_account("source-profile");
    source_document(
        &vault,
        vec![(&account, Some(source_secret(&"cc".repeat(32)).to_string()))],
    );
    let result = store.import_noland(&json!({"stateFile":path})).unwrap();
    let id = result["providers"][0]["id"].as_str().unwrap().to_owned();
    store
        .transaction(|document| {
            document.providers[0].read_only = false;
            Ok(())
        })
        .unwrap();
    assert!(store.provider_access(&id, "forged-write").is_err());
    assert!(
        store.grant_provider_writes(&id).is_err(),
        "tampered state must first be restored to the valid vault binding"
    );
    store
        .transaction(|document| {
            document.providers[0].read_only = true;
            Ok(())
        })
        .unwrap();
    store.authorize_provider_writes(&id).unwrap();
    let access = store.provider_access(&id, "native-granted-write").unwrap();
    assert!(!access.read_only);
    assert_eq!(access.repository_key, [0xcc; 32]);
}

#[test]
fn tombstoned_profile_never_falls_back_to_raw_legacy_or_plaintext() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, Some(source_secret(&"dd".repeat(32))));
    let account = dynamic_profile_account("source-profile");
    source_document(&vault, vec![(&account, None)]);
    vault
        .seed(
            NOLAND_STATE_SERVICE,
            &account,
            &source_secret(&"ee".repeat(32)).to_string(),
        )
        .unwrap();
    assert!(store.import_noland(&json!({"stateFile":path})).is_err());
    let log = vault.access_log().unwrap();
    assert!(!log["reads"]
        .as_array()
        .unwrap()
        .iter()
        .any(|read| read[0] == NOLAND_STATE_SERVICE && read[1] == account));
    assert_eq!(log["writes"], json!([]));
}

#[test]
fn tombstoned_global_key_does_not_resurrect_plaintext_or_legacy_key() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let mut selected: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    selected["sharedStorageCredentials"]["repositoryKeyHex"] = json!("ff".repeat(32));
    fs::write(&path, serde_json::to_vec(&selected).unwrap()).unwrap();
    let account = dynamic_profile_account("source-profile");
    source_document(
        &vault,
        vec![
            (&account, Some(source_secret("").to_string())),
            ("shared-storage.repository-key", None),
        ],
    );
    vault
        .seed(
            NOLAND_STATE_SERVICE,
            "shared-storage.repository-key",
            &"ff".repeat(32),
        )
        .unwrap();
    assert!(store.import_noland(&json!({"stateFile":path})).is_err());
    let log = vault.access_log().unwrap();
    assert!(!log["reads"]
        .as_array()
        .unwrap()
        .iter()
        .any(|read| read[0] == NOLAND_STATE_SERVICE && read[1] == "shared-storage.repository-key"));
}

#[test]
fn absent_v2_entries_allow_only_read_only_legacy_lookup() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let account = dynamic_profile_account("source-profile");
    vault
        .seed(
            NOLAND_STATE_SERVICE,
            &account,
            &source_secret(&"ab".repeat(32)).to_string(),
        )
        .unwrap();
    let result = store.import_noland(&json!({"stateFile":path})).unwrap();
    assert_eq!(result["providers"][0]["readOnly"], true);
    assert!(vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry[0] == QUICKSAVE_VAULT_SERVICE));
}

#[test]
fn source_vault_denial_or_corruption_does_not_attempt_legacy_fallback() {
    for denied in [true, false] {
        let (temp, vault, store) = fixture();
        let path = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
        if denied {
            vault.deny_access(true).unwrap();
        } else {
            vault
                .seed(
                    NOLAND_DOCUMENT_SERVICE,
                    NOLAND_DOCUMENT_ACCOUNT,
                    "invalid-vault-document",
                )
                .unwrap();
        }
        assert!(store.import_noland(&json!({"stateFile":path})).is_err());
        vault.deny_access(false).unwrap();
        let log = vault.access_log().unwrap();
        assert!(log["reads"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry[0] == NOLAND_DOCUMENT_SERVICE));
        assert_eq!(log["writes"], json!([]));
    }
}

#[test]
fn selected_source_symlink_is_rejected_before_any_vault_read() {
    use std::os::unix::fs::symlink;
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
    let alias = temp.path().join("source-alias.json");
    symlink(path, &alias).unwrap();
    assert!(store.import_noland(&json!({"stateFile":alias})).is_err());
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
}

#[test]
fn pure_desktop_provider_aliases_map_to_portable_session_types() {
    assert_eq!(
        provider::parse_kind("digital_ocean_spaces").unwrap(),
        ProviderKind::DigitalOceanSpaces
    );
    assert_eq!(
        provider::parse_kind("microsoft_one_drive").unwrap(),
        ProviderKind::MicrosoftOneDrive
    );
}

#[test]
fn manual_tracking_is_signed_and_binds_paths_ids_app_and_file_allowlist() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    assert!(store.verify_tracking_grant("software-1").unwrap());
    assert_eq!(
        store.software_record("software-1").unwrap()["autosave"],
        false
    );
    let before = store.software_record("software-1").unwrap();
    let mutations = [
        ("path", json!("/synthetic/not-approved")),
        ("identity", json!({"device":17,"fileId":[999,0]})),
        ("allowedFiles", json!(["save.dat", "neighbor.secret"])),
    ];
    for (field, value) in mutations {
        store
            .transaction(|document| {
                let root = &mut document.software[0].roots[0];
                match field {
                    "path" => root.path = value.as_str().unwrap().into(),
                    "identity" => root.identity = serde_json::from_value(value).unwrap(),
                    "allowedFiles" => {
                        root.allowed_files = Some(serde_json::from_value(value).unwrap())
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap();
        assert!(!store.verify_tracking_grant("software-1").unwrap());
        store
            .transaction(|document| {
                document.software[0] = serde_json::from_value(before.clone()).unwrap();
                Ok(())
            })
            .unwrap();
        assert!(store.verify_tracking_grant("software-1").unwrap());
    }
    store
        .transaction(|document| {
            document.software[0].app_id = Some("other.application".into());
            Ok(())
        })
        .unwrap();
    assert!(!store.verify_tracking_grant("software-1").unwrap());
}

#[test]
fn grant_revocation_and_reissue_survive_restart_and_prevent_json_rollback() {
    let (temp, vault, store) = fixture();
    let scope = json!({"version":1,"softwareId":"software-1","appId":"test.app","roots":roots("/synthetic/approved")});
    let first = store.issue_grant("tracking", &scope).unwrap();
    assert!(store.verify_grant("tracking", &scope, &first).unwrap());
    store.revoke_grant("tracking", &scope).unwrap();
    assert!(!store.verify_grant("tracking", &scope, &first).unwrap());
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault)).unwrap();
    assert!(!restarted.verify_grant("tracking", &scope, &first).unwrap());
    let second = restarted.issue_grant("tracking", &scope).unwrap();
    assert!(restarted.verify_grant("tracking", &scope, &second).unwrap());
    assert!(!restarted.verify_grant("tracking", &scope, &first).unwrap());
    assert!(
        !restarted.verify_grant("baseline", &scope, &second).unwrap(),
        "grant kinds are domain separated"
    );
}

#[test]
fn autosave_grants_bind_provider_root_and_preserve_events_during_upload() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    store.set_autosave("software-1", &provider, true).unwrap();
    assert!(store
        .verify_autosave_grant("software-1", &provider)
        .unwrap());
    let captured = store.mark_dirty("software-1").unwrap();
    store.mark_dirty("software-1").unwrap();
    store
        .mark_saved("software-1", captured, "version-1", "2026-11-17T12:00:00Z")
        .unwrap();
    let record = store.software_record("software-1").unwrap();
    assert_eq!(record["dirty"], true);
    assert_eq!(record["status"], "needs_backup");
    assert_eq!(record["confirmedGeneration"], Value::Null);
    assert_eq!(record["lastConfirmedUploadedGeneration"], captured);
    let current = record["dirtyGeneration"].as_u64().unwrap();
    store
        .mark_saved("software-1", current, "version-2", "2026-11-17T12:01:00Z")
        .unwrap();
    let record = store.software_record("software-1").unwrap();
    assert_eq!(record["dirty"], false);
    assert_eq!(record["reconciliationRequired"], true);
    assert_eq!(record["confirmedGeneration"], Value::Null);
    assert_eq!(record["status"], "checking");
    // State-only projection fixture. A source-backed upload additionally needs
    // Tracker's actual native receipt/index verification; flags cannot do it.
    let record = store
        .update_software(&json!({
            "id":"software-1","status":"saved","reconciliationRequired":false,
        }))
        .unwrap();
    assert_eq!(record["confirmedGeneration"], current);
    store.mark_dirty("software-1").unwrap();
    let record = store.software_record("software-1").unwrap();
    assert_eq!(record["unknownGeneration"], 0);
    assert_eq!(record["confirmedGeneration"], Value::Null);
    assert_eq!(record["lastConfirmedUploadedGeneration"], current);
    store
        .transaction(|document| {
            document.providers[0].prefix = Some("different-root".into());
            Ok(())
        })
        .unwrap();
    assert!(!store
        .verify_autosave_grant("software-1", &provider)
        .unwrap());
}

#[test]
fn current_confirmation_requires_saved_clean_reconciled_matching_nonzero_generations() {
    for unknown in [0, 1, u64::MAX] {
        for status in [
            "saved",
            "checking",
            "uploading",
            "error",
            "needs_backup",
            "not_tracked",
        ] {
            for tracked in [false, true] {
                for dirty in [false, true] {
                    for reconciliation in [false, true] {
                        let mut record =
                            StateSoftware::new("synthetic-current".into(), "Synthetic".into());
                        record.tracked = tracked;
                        record.status = status.into();
                        record.dirty = dirty;
                        record.reconciliation_required = reconciliation;
                        record.unknown_generation = unknown;
                        record.dirty_generation = 7;
                        record.last_confirmed_uploaded_generation = 7;
                        let expected = if tracked && status == "saved" && !dirty && !reconciliation
                        {
                            Some(7)
                        } else {
                            None
                        };
                        assert_eq!(record.current_confirmation(), expected);
                        record.dirty_generation = 8;
                        assert_eq!(record.current_confirmation(), None);
                        record.dirty_generation = 0;
                        record.last_confirmed_uploaded_generation = 0;
                        assert_eq!(record.current_confirmation(), None);
                    }
                }
            }
        }
    }
}

#[test]
fn software_merge_clears_stale_current_confirmation_without_touching_version_history() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    let baseline = json!({"name":"historical-baseline","hash":"01".repeat(32),"grant":{}});
    let historical_receipt = json!({
        "scope":{"generation":7,"unknownGeneration":0},"grant":{},
    });
    store
        .update_software(&json!({
            "id":"software-1","dirtyGeneration":7,"lastConfirmedUploadedGeneration":7,
            "lastConfirmedVersion":"historical-version","lastSavedAt":"2026-11-17T12:00:00Z",
            "baseline":baseline,"baselineFullScope":true,"captureReceipt":historical_receipt,
        }))
        .unwrap();
    for patch in [
        json!({"status":"checking"}),
        json!({"status":"uploading"}),
        json!({"status":"error"}),
        json!({"status":"saved","dirty":true}),
        json!({"status":"saved","reconciliationRequired":true}),
        json!({"status":"saved","dirtyGeneration":8}),
    ] {
        // This exercises the persistence projection, not acceptance of the
        // synthetic baseline/receipt as real native source publication proof.
        let clean = store
            .update_software(&json!({
                "id":"software-1","dirtyGeneration":7,"dirty":false,
                "status":"saved","reconciliationRequired":false,
            }))
            .unwrap();
        assert_eq!(clean["confirmedGeneration"], 7);
        let mut update = patch;
        update["id"] = json!("software-1");
        update["confirmedGeneration"] = json!(u64::MAX);
        let after = store.update_software(&update).unwrap();
        assert_eq!(after["confirmedGeneration"], Value::Null);
        for field in [
            "lastConfirmedUploadedGeneration",
            "lastConfirmedVersion",
            "lastSavedAt",
            "baseline",
            "baselineFullScope",
            "captureReceipt",
            "trackingGrant",
            "roots",
        ] {
            assert_eq!(
                after[field], clean[field],
                "current-state projection changed {field}"
            );
        }
        assert!(store.verify_tracking_grant("software-1").unwrap());
        assert!(
            !store
                .verify_grant(
                    "tracking_capture_receipt",
                    &historical_receipt["scope"],
                    &historical_receipt["grant"],
                )
                .unwrap(),
            "settings flags must not manufacture source receipt authority"
        );
    }
}

#[test]
fn unknown_generation_is_strict_default_zero_and_roundtrips_the_full_unsigned_range() {
    let mut legacy = serde_json::to_value(StateSoftware::new(
        "synthetic-unknown".into(),
        "Synthetic".into(),
    ))
    .unwrap();
    legacy.as_object_mut().unwrap().remove("unknownGeneration");
    let parsed: StateSoftware = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(parsed.unknown_generation, 0);
    for counter in [0, 1, u64::MAX] {
        legacy["unknownGeneration"] = json!(counter);
        let parsed: StateSoftware = serde_json::from_value(legacy.clone()).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.unknown_generation, counter);
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["unknownGeneration"],
            counter
        );
    }
    for invalid in [Value::Null, json!(-1), json!(1.5), json!("1")] {
        legacy["unknownGeneration"] = invalid;
        assert!(serde_json::from_value::<StateSoftware>(legacy.clone()).is_err());
    }
}

#[test]
fn unknown_dirty_persistence_preserves_history_grants_and_missing_roots_without_claiming_saved() {
    let (temp, vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider); // Synthetic signed roots deliberately do not exist.
    store.set_autosave("software-1", &provider, true).unwrap();
    // Metadata fixtures only; no claim that these identify a materialized index.
    store.update_software(&json!({
        "id":"software-1","baseline":{"name":"synthetic-old-baseline","hash":"01".repeat(32),"grant":{}},
        "baselineFullScope":true,"previousBundleManifest":{"version":1,"history":"retained"},
        "bundleIndexSource":{"revisionId":"synthetic-old-index"},
        "captureReceipt":{"nativeReceiptId":"synthetic-old-receipt"},
    })).unwrap();
    store
        .mark_saved(
            "software-1",
            1,
            "historical-version",
            "2026-11-17T12:00:00Z",
        )
        .unwrap();
    let before = store
        .update_software(&json!({
            "id":"software-1","status":"saved","reconciliationRequired":false,
        }))
        .unwrap();
    assert_eq!(before["confirmedGeneration"], 1);
    let writes = vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .len();
    let after = store
        .update_software(&json!({
            "id":"software-1","unknownGeneration":1,"dirtyGeneration":2,
            "dirty":true,"status":"checking",
        }))
        .unwrap();
    assert_eq!(after["unknownGeneration"], 1);
    assert_eq!(after["confirmedGeneration"], Value::Null);
    assert_eq!(after["dirty"], true);
    assert_eq!(after["reconciliationRequired"], true);
    assert_ne!(after["status"], "saved");
    for field in [
        "roots",
        "trackingGrant",
        "autosaveGrant",
        "providerId",
        "appId",
        "baseline",
        "baselineFullScope",
        "previousBundleManifest",
        "bundleIndexSource",
        "captureReceipt",
        "lastSavedAt",
        "lastConfirmedUploadedGeneration",
        "lastConfirmedVersion",
    ] {
        assert_eq!(
            after[field], before[field],
            "unknown transition changed {field}"
        );
    }
    assert!(store.verify_tracking_grant("software-1").unwrap());
    assert!(store
        .verify_autosave_grant("software-1", &provider)
        .unwrap());
    assert_eq!(
        vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len(),
        writes
    );
    store
        .update_software(&json!({"id":"software-1","name":"Updated metadata"}))
        .unwrap();
    assert_eq!(
        store.software_record("software-1").unwrap()["unknownGeneration"],
        1
    );
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault)).unwrap();
    assert_eq!(
        restarted.software_record("software-1").unwrap()["unknownGeneration"],
        1
    );
    let bytes = fs::read(temp.path().join("workspace/state.json")).unwrap();
    assert!(restarted
        .update_software(&json!({"id":"software-1","unknownGeneration":0}))
        .is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        bytes
    );
    restarted
        .mark_saved("software-1", 1, "late-old-version", "2026-11-17T12:01:00Z")
        .unwrap();
    let late = restarted.software_record("software-1").unwrap();
    assert_eq!(late["confirmedGeneration"], Value::Null);
    assert_eq!(late["dirty"], true);
    assert_ne!(late["status"], "saved");
    assert_eq!(late["baseline"], before["baseline"]);
    assert_eq!(
        restarted.sanitized().unwrap()["software"][0]["unknownGeneration"],
        1
    );
    // Tracker's later verified source receipt/index can return a clean current
    // result in the SAME uncertainty partition. These are schema-only fixture
    // bytes, deliberately not a replacement for native SourceCaptureReceipt.
    let capture_receipt = json!({
        "scope":{"generation":2,"unknownGeneration":1},"grant":{},
    });
    let clean = restarted
        .update_software(&json!({
            "id":"software-1","unknownGeneration":1,"dirtyGeneration":2,
            "lastConfirmedUploadedGeneration":2,"dirty":false,"status":"saved",
            "reconciliationRequired":false,"captureReceipt":capture_receipt,
        }))
        .unwrap();
    assert_eq!(clean["unknownGeneration"], 1);
    assert_eq!(clean["confirmedGeneration"], 2);
    assert_eq!(clean["baseline"], before["baseline"]);
    assert_eq!(clean["trackingGrant"], before["trackingGrant"]);
    assert_eq!(
        clean["captureReceipt"]["scope"]["unknownGeneration"],
        clean["unknownGeneration"]
    );
    assert!(
        !restarted
            .verify_grant(
                "tracking_capture_receipt",
                &capture_receipt["scope"],
                &capture_receipt["grant"],
            )
            .unwrap(),
        "a settings merge cannot replace the native source receipt verifier"
    );
    restarted.mark_dirty("software-1").unwrap();
    let dirty = restarted.software_record("software-1").unwrap();
    assert_eq!(dirty["unknownGeneration"], 1);
    assert_eq!(dirty["confirmedGeneration"], Value::Null);
    assert_eq!(dirty["lastConfirmedUploadedGeneration"], 2);
    assert_eq!(dirty["baseline"], before["baseline"]);
}

#[test]
fn autosave_disable_cannot_be_reenabled_by_restoring_old_settings() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    store.set_autosave("software-1", &provider, true).unwrap();
    let old = store.document().unwrap().software[0].clone();
    store.set_autosave("software-1", &provider, false).unwrap();
    store
        .transaction(|document| {
            document.software[0] = old;
            Ok(())
        })
        .unwrap();
    assert!(!store
        .verify_autosave_grant("software-1", &provider)
        .unwrap());
}

#[test]
fn status_merge_patches_preserve_tracking_baseline_and_generations() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    store.update_software(&json!({"id":"software-1","baseline":{"name":"baseline-1","hash":"synthetic-hash","grant":null}})).unwrap();
    store
        .update_software(&json!({"id":"software-1","status":"checking","fileCount":9}))
        .unwrap();
    let record = store.software_record("software-1").unwrap();
    assert_eq!(record["dirtyGeneration"], 1);
    assert_eq!(record["roots"], roots("/synthetic/approved"));
    assert_eq!(record["baseline"]["name"], "baseline-1");
    assert!(store.verify_tracking_grant("software-1").unwrap());
}

#[test]
fn forged_grants_do_not_create_device_keys_and_unknown_secret_settings_are_rejected() {
    let (_temp, vault, store) = fixture();
    assert!(!store
        .grant_verify(&json!({"softwareId":"fake"}), &json!({"approved":true}))
        .unwrap());
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    assert!(store
        .update_software(&json!({"id":"bad","name":"Bad","repositoryKey":"plaintext"}))
        .is_err());
    assert!(store
        .update_software(&json!({"id":"bad","name":"Bad","baseline":{"password":"plaintext"}}))
        .is_err());
    assert!(store
        .update_software(&json!({"id":"bad","name":"Bad","roots":roots("relative/path")}))
        .is_err());
}

#[test]
fn canonical_json_grants_ignore_map_order_but_not_array_or_scope_changes() {
    let (_temp, _vault, store) = fixture();
    let first: Value = serde_json::from_str(
        r#"{"softwareId":"test","purpose":"test","values":[1,2],"nested":{"z":2,"a":1}}"#,
    )
    .unwrap();
    let reordered: Value = serde_json::from_str(
        r#"{"nested":{"a":1,"z":2},"values":[1,2],"purpose":"test","softwareId":"test"}"#,
    )
    .unwrap();
    let signature = store.grant_seal(&first).unwrap();
    assert!(store.grant_verify(&reordered, &signature).unwrap());
    let mut different = reordered;
    different["values"] = json!([2, 1]);
    assert!(!store.grant_verify(&different, &signature).unwrap());
}

#[test]
fn native_document_macs_are_device_root_and_purpose_bound_without_state_or_repeat_vault_io() {
    let (temp, vault, store) = fixture();
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let recovery = store.recovery_mac(b"synthetic native journal").unwrap();
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        store.recovery_mac(b"synthetic native journal").unwrap(),
        recovery
    );
    assert_ne!(
        store.operation_mac(b"synthetic native journal").unwrap(),
        recovery
    );
    assert_ne!(
        store.recovery_mac(b"different native journal").unwrap(),
        recovery
    );
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        reads
    );
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    assert_eq!(
        restarted.recovery_mac(b"synthetic native journal").unwrap(),
        recovery
    );
    let other =
        WorkspaceStore::open_with_vault(&temp.path().join("other-workspace"), Arc::new(vault))
            .unwrap();
    assert_ne!(
        other.recovery_mac(b"synthetic native journal").unwrap(),
        recovery
    );
}

#[test]
fn existing_only_document_macs_never_create_missing_authority_and_match_the_original_domains() {
    let (temp, vault, store) = fixture();
    assert!(store
        .recovery_mac_existing(b"retained recovery journal")
        .is_err());
    assert!(store
        .operation_mac_existing(b"retained operation journal")
        .is_err());
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    let recovery = store.recovery_mac(b"retained recovery journal").unwrap();
    let operation = store.operation_mac(b"retained operation journal").unwrap();
    assert_eq!(
        store
            .recovery_mac_existing(b"retained recovery journal")
            .unwrap(),
        recovery
    );
    assert_eq!(
        store
            .operation_mac_existing(b"retained operation journal")
            .unwrap(),
        operation
    );
    assert_ne!(recovery, operation);
    let reopened =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    let writes = vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        reopened
            .recovery_mac_existing(b"retained recovery journal")
            .unwrap(),
        recovery
    );
    assert_eq!(
        reopened
            .operation_mac_existing(b"retained operation journal")
            .unwrap(),
        operation
    );
    assert_eq!(
        vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len(),
        writes
    );
    // A fresh process/store with a lost native vault must not replace its device
    // key while inspecting the same private journals.
    let lost = MemoryVault::default();
    let reopened =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(lost.clone()))
            .unwrap();
    assert!(reopened
        .recovery_mac_existing(b"retained recovery journal")
        .is_err());
    assert!(reopened
        .operation_mac_existing(b"retained operation journal")
        .is_err());
    assert_eq!(lost.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn request_scoped_snapshot_verifies_real_macs_without_reopening_state_for_each_record() {
    let (temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    let snapshot = store.read_snapshot().unwrap();
    let state = temp.path().join("workspace/state.json");
    let held = temp.path().join("workspace/temporarily-held-state.json");
    fs::rename(&state, &held).unwrap();
    assert!(snapshot.verify_tracking_grant("software-1").unwrap());
    assert!(store.document().is_err()); // The ordinary fresh reader really opens it.
    fs::rename(&held, &state).unwrap();
    assert!(snapshot.is_current().unwrap());
    store
        .update_software(&json!({"id":"software-1","name":"Renamed metadata"}))
        .unwrap();
    assert!(!snapshot.is_current().unwrap());
}

#[test]
fn metadata_frame_reuses_one_document_for_4096_trait_verifications_but_not_threads_or_other_stores()
{
    let (temp, vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    let document = store.document().unwrap();
    let software = &document.software[0];
    let scope = grant::tracking_scope(software).unwrap();
    let signature = software.tracking_grant.as_ref().unwrap();
    let separate =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    let publication_scope = json!({"providerId":provider,"operationId":"fresh-publication"});
    let publication = store
        .issue_grant("native_upload", &publication_scope)
        .unwrap();
    let state = temp.path().join("workspace/state.json");
    let held = temp.path().join("workspace/held-metadata-state.json");
    let before_reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    store
        .with_metadata_verification_snapshot(|| {
            fs::rename(&state, &held)?;
            for _ in 0..4096 {
                assert!(store.clone().verify_grant("tracking", &scope, signature)?);
            }
            assert!(store.document().is_err());
            assert!(store.provider_access(&provider, "fresh-provider").is_err());
            assert!(store
                .update_software(&json!({"id":"software-1","name":"must stay fresh"}))
                .is_err());
            assert!(store
                .verify_grant("native_upload", &publication_scope, &publication)
                .is_err());
            assert!(separate
                .verify_grant("tracking", &scope, signature)
                .is_err());
            let worker_store = store.clone();
            let worker_scope = scope.clone();
            let worker_signature = signature.clone();
            assert!(thread::spawn(move || worker_store
                .verify_grant("tracking", &worker_scope, &worker_signature)
                .is_err())
            .join()
            .unwrap());
            fs::rename(&held, &state)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len()
            - before_reads,
        4096
    );
}

#[test]
fn metadata_frame_keeps_real_revocation_checks_and_discards_changed_results_without_replay() {
    let (_temp, vault, store) = fixture();
    let scope = json!({"softwareId":"synthetic-metadata","roots":[]});
    let signature = store.issue_grant("tracking", &scope).unwrap();
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    store
        .with_metadata_verification_snapshot(|| {
            assert!(store.verify_grant("tracking", &scope, &signature)?);
            store.revoke_grant("tracking", &scope)?;
            assert!(!store.verify_grant("tracking", &scope, &signature)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len()
            - reads,
        2
    );
    let mut calls = 0;
    let result = store.with_metadata_verification_snapshot(|| {
        calls += 1;
        store.update_software(&json!({"id":"fresh-write","name":"Actual fresh mutation"}))?;
        assert!(store.software_record("fresh-write").is_ok());
        Ok("must not be returned after a state change")
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert!(store
        .with_metadata_verification_snapshot(|| Ok("fresh request"))
        .is_ok());
}

#[test]
fn metadata_frame_restores_outer_frame_and_unwinds_without_leaking_a_snapshot() {
    let (temp, _vault, store) = fixture();
    let scope = json!({"softwareId":"synthetic-nesting","roots":[]});
    let signature = store.issue_grant("tracking", &scope).unwrap();
    let state = temp.path().join("workspace/state.json");
    let held = temp.path().join("workspace/held-nested-state.json");
    store
        .with_metadata_verification_snapshot(|| {
            let inner: Result<()> = store.with_metadata_verification_snapshot(|| {
                bail!("synthetic nested projection failed")
            });
            assert!(inner.is_err());
            fs::rename(&state, &held)?;
            assert!(store.verify_grant("tracking", &scope, &signature)?);
            fs::rename(&held, &state)?;
            Ok(())
        })
        .unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<()> = store.with_metadata_verification_snapshot(|| {
            fs::rename(&state, &held)?;
            panic!("synthetic projection panic");
        });
    }));
    assert!(panicked.is_err());
    assert!(store.verify_grant("tracking", &scope, &signature).is_err());
    fs::rename(&held, &state).unwrap();
}

#[test]
fn explicit_provider_reauthorization_changes_authority_and_revokes_old_write_scopes_not_keys() {
    let (_temp, _vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    store.set_autosave("software-1", &provider, true).unwrap();
    let scope = json!({"providerId":provider,"operationId":"synthetic-before-reauthorization"});
    let grant = store.issue_grant("native_upload", &scope).unwrap();
    let access = store
        .provider_access(&provider, "before-reauthorization")
        .unwrap();
    let generation = store.provider_credential_generation(&provider).unwrap();
    let credentials = json!({"type":"backblaze_b2","value":{
        "key_id":"synthetic-replacement-id","application_key":"SYNTHETIC-REPLACEMENT-SECRET"}});
    assert_eq!(
        store
            .complete_provider_reauthorization(&provider, generation, &credentials)
            .unwrap(),
        generation + 1
    );
    assert!(!store.verify_grant("native_upload", &scope, &grant).unwrap());
    assert!(!store
        .verify_autosave_grant("software-1", &provider)
        .unwrap());
    assert_eq!(store.document().unwrap().providers[0].status, "connecting");
    assert_eq!(store.document().unwrap().providers[0].authority_revision, 1);
    let after = store
        .provider_access(&provider, "after-reauthorization")
        .unwrap();
    assert_eq!(access.repository_key, after.repository_key);
    assert!(after
        .session
        .to_string()
        .contains("SYNTHETIC-REPLACEMENT-SECRET"));
    assert!(!store
        .sanitized()
        .unwrap()
        .to_string()
        .contains("SYNTHETIC-REPLACEMENT-SECRET"));
    assert!(store
        .complete_provider_reauthorization(&provider, generation, &credentials)
        .is_err());
}

#[test]
fn enrollment_coverage_binding_is_exact_and_preserves_unresolved_array_order() {
    let policy = json!({
        "version":1,"policyId":"synthetic-policy","rolePolicyVersion":1,
        "source":"verified_native_discovery","enabled":true,
        "baseDirectories":[{"id":"base","path":"/synthetic/base","identity":{"device":1,"fileId":[2,0]},
            "allowedRoles":["save"],"ownershipRules":["native_installation_handle"]}],
        "appIdentityPolicy":{"allowedAppIds":["synthetic.app"],"allowNewVerifiedApps":false,
            "allowedEvidenceKinds":["native_installation_handle"],"allowNativeInstallationOnly":true},
        "excludedPaths":[], "providerId":null,
    });
    let discovery = json!({"version":1,"source":"verified_native_discovery",
        "policyHash":blake3::hash(&serde_json::to_vec(&policy).unwrap()).to_hex().to_string(),
        "candidatesHash":"01".repeat(32)});
    let mut enrollment: StateAutoEnrollment = serde_json::from_value(json!({
        "policyScope":policy,"policyGrant":{},"discoveryScope":discovery,"discoveryGrant":{},
        "appEvidenceHash":"02".repeat(32),"candidateHash":"03".repeat(32),
        "identityEvidence":[],"unresolvedRoots":["first-root","second-root"],
        "unresolvedReasons":["first-reason","second-reason"],"rootsComplete":false,
    }))
    .unwrap();
    let coverage = json!({"rootsComplete":false,"unresolvedRoots":enrollment.unresolved_roots,
        "unresolvedReasons":enrollment.unresolved_reasons});
    let expected = blake3::hash(&serde_json::to_vec(&coverage).unwrap())
        .to_hex()
        .to_string();
    let first = enrollment.binding().unwrap();
    assert_eq!(first["coverageHash"], expected);
    enrollment
        .unresolved_roots
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_ne!(
        enrollment.binding().unwrap()["coverageHash"],
        first["coverageHash"]
    );
    let mut settings = json!({"policyScope":policy,"policyGrant":{}});
    let round_trip: AppTrackingSettings = serde_json::from_value(settings.clone()).unwrap();
    assert_eq!(serde_json::to_value(round_trip).unwrap(), settings);
    settings["policyScope"]
        .as_object_mut()
        .unwrap()
        .remove("providerId");
    let round_trip: AppTrackingSettings = serde_json::from_value(settings.clone()).unwrap();
    assert_eq!(serde_json::to_value(round_trip).unwrap(), settings);
}

#[test]
fn strict_tracker_schema_roundtrips_native_fields_and_binds_the_entire_source_identity() {
    let (_temp, _vault, store) = fixture();
    let identity = json!({
        "app_id":"synthetic.source.app","source_kind":"native_installation",
        "installation":{"device":17,"file_id":[41,0],"evidence":["first","second"]},
    });
    let record = store
        .update_software(&json!({
            "id":"pending-native","appId":"synthetic.source.app","name":"Synthetic native record",
            "tracked":false,"roots":roots("/synthetic/approved-native"),
            "sourceIdentity":identity,
        }))
        .unwrap();
    let signature = store.seal_tracking_grant("pending-native").unwrap();
    // Approved-but-unindexed records remain loadable/verifiable without being
    // advertised as a materialized tracked application.
    assert!(!record["tracked"].as_bool().unwrap());
    assert!(store.verify_tracking_grant("pending-native").unwrap());
    let persisted = store.software_record("pending-native").unwrap();
    let parsed: StateSoftware = serde_json::from_value(persisted.clone()).unwrap();
    assert_eq!(
        grant::tracking_scope(&parsed).unwrap()["sourceIdentity"],
        identity
    );

    // Exact metadata schema round-trip, not a claim that these fixture paths
    // identify a real bundle or authorize any source content operation.
    let mut full = persisted.clone();
    for (field, value) in [
        (
            "bundleIndexSource",
            json!({"revisionId":"fixture-revision","roots":[{"rootId":"root-1"}]}),
        ),
        (
            "bundleIndexRef",
            json!("/synthetic/private-index/fixture.json"),
        ),
        ("bundleIndexHash", json!("01".repeat(32))),
        (
            "previousBundleManifest",
            json!({"version":1,"source":"synthetic-fixture"}),
        ),
        (
            "captureReceipt",
            json!({"version":1,"nativeReceiptId":"fixture-receipt"}),
        ),
        ("baselineFullScope", json!(true)),
        ("appRunning", json!(false)),
    ] {
        full[field] = value;
    }
    let parsed: StateSoftware = serde_json::from_value(full.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), full);
    full["unrecognizedTrackerField"] = json!(true);
    assert!(serde_json::from_value::<StateSoftware>(full).is_err());

    let mut changed = identity;
    changed["installation"]["file_id"] = json!([99, 0]);
    assert!(store
        .update_software(&json!({
            "id":"pending-native","sourceIdentity":changed,"trackingGrant":signature,
        }))
        .is_err());
    assert_eq!(store.software_record("pending-native").unwrap(), persisted);
    assert!(store.verify_tracking_grant("pending-native").unwrap());
}

#[test]
fn canonical_product_and_installation_ids_roundtrip_with_real_native_root_proofs_and_mac_binding() {
    const SOFTWARE: &str = "fixture-software";
    const INSTANCE: &str = "steam:480@fixture-installation";
    const CANONICAL: &str = "steam:480";
    let (temp, vault, store) = fixture();
    let installation = temp.path().join("fixture-installation");
    let source = installation.join("save-root");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("slot.dat"), b"isolated synthetic save").unwrap();
    let native_root = quicksave_platform::SafeRoot::open(&source).unwrap();
    let root_identity = native_root.identity().unwrap();
    let installation_root = quicksave_platform::SafeRoot::open(&installation).unwrap();
    let root_stamp = installation_root
        .metadata_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.relative_path == "save-root")
        .unwrap()
        .stamp;
    assert_eq!(root_identity.device, root_stamp.device);
    assert_eq!(root_identity.file_id, root_stamp.file_id);
    let native_root_proof = json!({
        "id":"fixture-save-root","path":source,"role":"save",
        "identity":root_identity,"stamp":root_stamp,"allowedFiles":null,
    });
    // The real No Land AppIdentity wire shape, with canonical product identity.
    // Native root proof and the injected vault are actual isolated test handles;
    // no claim is made that this fixture performs native app enrollment.
    let identity = json!({
        "app_id":CANONICAL,"display_name":"Synthetic Steam fixture",
        "canonical_executable":null,"desktop_entry_id":null,"steam_app_id":480,
        "launcher":"steam","aliases":["first synthetic alias","second synthetic alias"],
        "identity_confidence":0.75,"icon_path":null,
    });
    store
        .update_software(&json!({
            "id":SOFTWARE,"appId":INSTANCE,"sourceIdentity":identity,
            "name":"Synthetic Steam fixture","tracked":true,"dirtyGeneration":1,
            "roots":[native_root_proof],
        }))
        .unwrap();
    let signature = store.seal_tracking_grant(SOFTWARE).unwrap();
    let persisted = store.software_record(SOFTWARE).unwrap();
    assert_eq!(persisted["id"], SOFTWARE);
    assert_eq!(persisted["appId"], INSTANCE);
    assert_eq!(persisted["sourceIdentity"], identity);
    assert_eq!(persisted["sourceIdentity"]["app_id"], CANONICAL);
    assert_eq!(persisted["roots"][0], native_root_proof);
    let parsed: StateSoftware = serde_json::from_value(persisted.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), persisted);
    let scope = grant::tracking_scope(&parsed).unwrap();
    assert_eq!(scope["softwareId"], SOFTWARE);
    assert_eq!(scope["appId"], INSTANCE);
    assert_eq!(scope["sourceIdentity"], identity);
    assert_eq!(scope["roots"][0]["identity"], native_root_proof["identity"]);
    let writes = vault.access_log().unwrap()["writes"].clone();
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    assert_eq!(restarted.software_record(SOFTWARE).unwrap(), persisted);
    assert!(restarted.verify_tracking_grant(SOFTWARE).unwrap());
    assert!(restarted
        .verify_grant("tracking", &scope, &signature)
        .unwrap());
    let bytes = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let mut changed_canonical = identity.clone();
    changed_canonical["app_id"] = json!("steam:481");
    let mut changed_evidence = identity.clone();
    changed_evidence["aliases"]
        .as_array_mut()
        .unwrap()
        .reverse();
    for mut patch in [
        json!({"appId":"steam:480@different-installation"}),
        json!({"sourceIdentity":changed_canonical}),
        json!({"sourceIdentity":changed_evidence}),
    ] {
        patch["id"] = json!(SOFTWARE);
        patch["trackingGrant"] = signature.clone();
        // Keep this failure test from independently revoking unused autosave.
        patch["autosaveGrant"] = Value::Null;
        let mut changed = persisted.clone();
        for (key, value) in patch.as_object().unwrap() {
            changed[key] = value.clone();
        }
        let changed: StateSoftware = serde_json::from_value(changed).unwrap();
        changed.validate().unwrap(); // Distinct IDs are valid schema, not authority.
        let changed_scope = grant::tracking_scope(&changed).unwrap();
        assert!(!restarted
            .verify_grant("tracking", &changed_scope, &signature)
            .unwrap());
        assert!(restarted.update_software(&patch).is_err());
        assert_eq!(restarted.software_record(SOFTWARE).unwrap(), persisted);
        assert_eq!(
            fs::read(temp.path().join("workspace/state.json")).unwrap(),
            bytes
        );
        assert!(restarted.verify_tracking_grant(SOFTWARE).unwrap());
    }
    assert_eq!(native_root.identity().unwrap(), root_identity);
    assert_eq!(vault.access_log().unwrap()["writes"], writes);
}

#[test]
fn distinct_source_identity_bounds_and_filename_safe_identifier_rules_remain_strict() {
    let mut record = StateSoftware::new("fixture-software".into(), "Synthetic fixture".into());
    record.app_id = Some("steam:480@fixture-installation".into());
    record.source_identity = Some(json!({"app_id":"steam:480"}));
    record.validate().unwrap();
    for canonical in [
        Value::Null,
        json!(480),
        json!(""),
        json!("steam:480\n"),
        json!("s".repeat(513)),
    ] {
        let mut invalid = record.clone();
        invalid.source_identity.as_mut().unwrap()["app_id"] = canonical;
        assert!(invalid.validate().is_err());
    }
    for instance in [
        "".to_owned(),
        "steam:480@installation\n".to_owned(),
        "s".repeat(1025),
    ] {
        let mut invalid = record.clone();
        invalid.app_id = Some(instance);
        assert!(invalid.validate().is_err());
    }
    let mut excessive = record.clone();
    excessive.source_identity.as_mut().unwrap()["aliases"] = json!(["s".repeat(16 * 1024)]);
    assert!(excessive.validate().is_err());
    let mut secret = record.clone();
    secret.source_identity.as_mut().unwrap()["credentials"] = json!({"value":"synthetic-secret"});
    assert!(secret.validate().is_err());
    record.app_id = Some("i".repeat(1024));
    record.source_identity.as_mut().unwrap()["app_id"] = json!("c".repeat(512));
    record.validate().unwrap();
    assert!(validate_id("fixture.provider_1-name").is_ok());
    assert!(validate_id("fixture-software").is_ok());
    assert!(validate_id("steam:480").is_err());
    assert!(validate_id("steam:480@fixture-installation").is_err());
}

#[test]
fn pending_work_roundtrips_losslessly_without_vault_io_and_never_reaches_sanitized_dtos() {
    let (temp, vault, store) = fixture();
    vault.deny_access(true).unwrap();
    let reference = pending_work_reference("retained-work", 128 * 1024 * 1024);
    let history = json!({
        "id":"retained-work","name":"Synthetic retained work",
        "dirtyGeneration":u64::MAX,"unknownGeneration":u64::MAX,
        "lastConfirmedUploadedGeneration":7,"lastConfirmedVersion":"historical-version",
        "lastSavedAt":"2026-11-17T12:00:00Z",
        "baseline":{"name":"historical-baseline.json","hash":"11".repeat(32),"grant":{}},
        "baselineFullScope":true,"previousBundleManifest":{"version":1,"history":"retained"},
        "captureReceipt":{"scope":{"privateScope":"unchanged"},"grant":{}},
        "pendingWork":reference,
    });
    let before = store.update_software(&history).unwrap();
    assert_eq!(before["pendingWork"], reference);
    let typed: StateSoftware = serde_json::from_value(before.clone()).unwrap();
    typed.validate().unwrap();
    assert_eq!(serde_json::to_value(typed).unwrap(), before);
    store
        .update_software(&json!({"id":"retained-work","name":"Updated metadata"}))
        .unwrap();
    let restarted =
        WorkspaceStore::open_with_vault(&temp.path().join("workspace"), Arc::new(vault.clone()))
            .unwrap();
    let retained = restarted.software_record("retained-work").unwrap();
    assert_eq!(retained["pendingWork"], reference);
    assert_eq!(retained["pendingWork"]["scope"]["generation"], u64::MAX);
    assert_eq!(
        retained["pendingWork"]["scope"]["unknownGeneration"],
        u64::MAX
    );
    assert_eq!(retained["pendingWork"]["scope"]["appId"], Value::Null);
    assert!(retained["pendingWork"]["scope"].get("appId").is_some());
    assert_eq!(restarted.software().unwrap()[0]["pendingWork"], reference);
    for field in [
        "baseline",
        "baselineFullScope",
        "previousBundleManifest",
        "captureReceipt",
        "lastConfirmedUploadedGeneration",
        "lastConfirmedVersion",
        "lastSavedAt",
    ] {
        assert_eq!(
            retained[field], before[field],
            "pending work changed history {field}"
        );
    }
    let dto = restarted.sanitized().unwrap();
    let projected = &dto["software"][0];
    for private in [
        "pendingWork",
        "trackingGrant",
        "autosaveGrant",
        "captureReceipt",
        "baseline",
    ] {
        assert!(
            projected.get(private).is_none(),
            "private field escaped: {private}"
        );
    }
    let serialized = serde_json::to_string(&dto).unwrap();
    for private in [
        reference["name"].as_str().unwrap(),
        reference["grant"]["mac"].as_str().unwrap(),
        reference["grant"]["nonce"].as_str().unwrap(),
        reference["grant"]["authorityRef"].as_str().unwrap(),
    ] {
        assert!(!serialized.contains(private));
    }
    let cleared = restarted
        .update_software(&json!({
            "id":"retained-work","pendingWork":null,
        }))
        .unwrap();
    assert!(cleared.get("pendingWork").is_none());
    for field in [
        "baseline",
        "baselineFullScope",
        "captureReceipt",
        "previousBundleManifest",
    ] {
        assert_eq!(cleared[field], before[field]);
    }
    let legacy: StateSoftware = serde_json::from_value(cleared.clone()).unwrap();
    assert!(legacy.pending_work.is_none());
    let mut explicit_none = cleared;
    explicit_none["pendingWork"] = Value::Null;
    let legacy: StateSoftware = serde_json::from_value(explicit_none).unwrap();
    assert!(legacy.pending_work.is_none());
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn pending_work_requires_the_exact_compact_native_reference_not_frame_json_or_paths() {
    let (temp, vault, store) = fixture();
    vault.deny_access(true).unwrap();
    let reference = pending_work_reference("strict-work", 4096);
    store
        .update_software(&json!({
            "id":"strict-work","name":"Synthetic strict work","pendingWork":reference,
        }))
        .unwrap();
    let path = temp.path().join("workspace/state.json");
    let before = fs::read(&path).unwrap();
    let mut invalid = vec![
        json!(false),
        json!([]),
        json!("private-frame.json"),
        json!({}),
    ];
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/scope/version", json!(2)),
        ("/scope/softwareId", json!("different-software")),
        ("/scope/name", json!("work-different.json")),
        ("/scope/frameHash", json!("ff".repeat(32))),
        ("/scope/bytes", json!(4097)),
        ("/scope/stage", json!("source_job_started")),
        ("/scope/generation", json!("7")),
        ("/scope/generation", json!(-1)),
        ("/scope/unknownGeneration", json!(1.5)),
        ("/scope/automatic", json!(1)),
        ("/scope/appId", json!({"frame":"not-an-ID"})),
        ("/scope/appId", json!("/Users/synthetic/private-source")),
        ("/scope/appId", json!(r"C:\synthetic\private-source")),
        ("/scope/providerId", json!(["provider"])),
        (
            "/scope/metadataIdentity",
            json!({"nodes":[{"data":"not-a-reference"}]}),
        ),
        ("/scope/authorizationHash", json!("s".repeat(250 * 1024))),
        ("/grant/version", json!(2)),
        ("/grant/kind", json!("tracking")),
        ("/grant/algorithm", json!("plaintext")),
        ("/grant/nonce", json!({"value":"ce".repeat(32)})),
        ("/grant/nonce", json!("not-a-raw-64-hex-nonce")),
        ("/grant/mac", json!("gg".repeat(32))),
        ("/grant/authorityRef", json!("authority.not-a-native-slot")),
    ] {
        let mut changed = reference.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        invalid.push(changed);
    }
    for name in [
        "/Users/synthetic/work-private.json",
        r"C:\synthetic\work-private.json",
        r"\\server\private\work-file.json",
        "../work-parent.json",
        "work-nested/child.json",
        r"work-nested\child.json",
        "work-name:alternate-stream.json",
        "work-newline\n.json",
    ] {
        let mut changed = reference.clone();
        changed["name"] = json!(name);
        changed["scope"]["name"] = json!(name);
        invalid.push(changed);
    }
    for bytes in [0, 128 * 1024 * 1024 + 1, u64::MAX] {
        let mut changed = reference.clone();
        changed["bytes"] = json!(bytes);
        changed["scope"]["bytes"] = json!(bytes);
        invalid.push(changed);
    }
    for object in ["", "/scope", "/grant"] {
        let keys: Vec<String> = reference
            .pointer(object)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut changed = reference.clone();
            changed
                .pointer_mut(object)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            invalid.push(changed);
        }
        let mut changed = reference.clone();
        changed
            .pointer_mut(object)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "displayHint".into(),
                json!("Non-secret unknown fields still fail"),
            );
        invalid.push(changed);
        let mut changed = reference.clone();
        changed
            .pointer_mut(object)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "content".into(),
                json!({"nodes":[{"bytes":"INLINE-FRAME-CONTENT"}]}),
            );
        invalid.push(changed);
        let mut changed = reference.clone();
        changed
            .pointer_mut(object)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("accessToken".into(), json!("PRIVATE-SYNTHETIC-CONTENT"));
        invalid.push(changed);
    }
    for malformed in invalid {
        let mut record = store.software_record("strict-work").unwrap();
        record["pendingWork"] = malformed.clone();
        let parsed: StateSoftware = serde_json::from_value(record).unwrap();
        assert!(parsed.validate().is_err());
        assert!(store
            .update_software(&json!({
                "id":"strict-work","pendingWork":malformed,
            }))
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    assert!(store
        .update_software(&json!({
            "id":"strict-work","unrecognizedPrivateReference":reference,
        }))
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn pending_work_state_shape_never_authenticates_a_plaintext_pointer_or_creates_missing_keys() {
    let (temp, vault, store) = fixture();
    let mut reference = pending_work_reference("untrusted-frame", 4096);
    // Both actual frame stages are valid schema; neither grants native work.
    reference["scope"]["stage"] = json!("source_receipt_accepted");
    reference["scope"]["appId"] = json!("steam:480@synthetic-installation");
    reference["scope"]["providerId"] = json!("synthetic-provider");
    store
        .update_software(&json!({
            "id":"untrusted-frame","name":"Untrusted frame fixture","pendingWork":reference,
        }))
        .unwrap();
    assert_eq!(store.sanitized().unwrap()["software"][0]["tracked"], false);
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    assert!(!store
        .verify_grant(
            "tracking_frozen_work",
            &reference["scope"],
            &reference["grant"],
        )
        .unwrap());
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert_eq!(
        store.software_record("untrusted-frame").unwrap()["pendingWork"],
        reference
    );
}

#[test]
fn malformed_pending_work_in_state_fails_on_load_without_touching_a_frame_or_vault() {
    let (temp, vault, store) = fixture();
    let reference = pending_work_reference("invalid-on-load", 4096);
    store
        .update_software(&json!({
            "id":"invalid-on-load","name":"Synthetic load fixture","pendingWork":reference,
        }))
        .unwrap();
    let path = temp.path().join("workspace/state.json");
    let mut stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    stored["software"][0]["pendingWork"]["name"] = json!("/synthetic/private-frame.json");
    stored["software"][0]["pendingWork"]["scope"]["name"] = json!("/synthetic/private-frame.json");
    let malformed = serde_json::to_vec(&stored).unwrap();
    fs::write(&path, &malformed).unwrap(); // Malicious synthetic settings, not live state.
    vault.deny_access(true).unwrap();
    assert!(store.document().is_err());
    assert!(WorkspaceStore::open_with_vault(
        &temp.path().join("workspace"),
        Arc::new(vault.clone()),
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), malformed);
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn pending_work_retains_tracker_aggregate_count_and_frame_byte_limits() {
    let mut document = WorkspaceDocument::default();
    for index in 0..64 {
        let id = format!("pending-{index}");
        let mut record = StateSoftware::new(id.clone(), "Synthetic pending work".into());
        record.pending_work = Some(pending_work_reference(&id, 2 * 1024 * 1024));
        document.software.push(record);
    }
    document.validate().unwrap(); // Exactly 64 current references / 128 MiB.
    let mut extra = StateSoftware::new("pending-extra".into(), "Synthetic extra work".into());
    extra.pending_work = Some(pending_work_reference("pending-extra", 1));
    document.software.push(extra);
    assert!(document.validate().is_err());
    let _ = document.software.pop();
    let reference = document.software[0].pending_work.as_mut().unwrap();
    reference["bytes"] = json!(2 * 1024 * 1024 + 1);
    reference["scope"]["bytes"] = reference["bytes"].clone();
    assert!(document.validate().is_err());
}

#[test]
fn sanitization_with_existing_grants_remains_vault_free() {
    let (_temp, vault, store) = fixture();
    let provider = connected(&store);
    tracked(&store, &provider);
    store.set_autosave("software-1", &provider, true).unwrap();
    assert!(store.verify_tracking_grant("software-1").unwrap());
    let before = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    vault.deny_access(true).unwrap();
    assert_eq!(store.sanitized().unwrap()["software"][0]["autosave"], true);
    vault.deny_access(false).unwrap();
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        before
    );
}

#[test]
fn provider_access_drop_zeroizes_session_and_key_via_shared_helper() {
    let mut value = json!({"config_ini":"secret","nested":["token"]});
    zeroize_json(&mut value);
    assert_eq!(value, Value::Null);
    // ProviderAccess has an unconditional Drop implementation calling this same
    // helper and Zeroize on its fixed key; it cannot derive Debug/Serialize.
}

#[test]
fn oauth_generation_cas_rejects_parallel_old_refresh_and_disconnect_resurrection() {
    let (temp, vault, store) = fixture();
    let id = connected_oauth(&store, ProviderKind::GoogleDrive);
    let first = store.provider_access(&id, "parallel-first").unwrap();
    let second = store.provider_access(&id, "parallel-second").unwrap();
    let first_generation = store
        .oauth_credential_generation_for_access(&first)
        .unwrap();
    let second_generation = store
        .oauth_credential_generation_for_access(&second)
        .unwrap();
    assert_eq!(first_generation, second_generation);
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let next = store
        .update_oauth_tokens_cas(
            &id,
            first_generation,
            "SYNTHETIC-FIRST",
            Some("SYNTHETIC-FIRST-ROTATED"),
            2_000_000_000,
        )
        .unwrap();
    assert_eq!(next, first_generation + 1);
    assert!(store
        .update_oauth_tokens_cas(
            &id,
            second_generation,
            "SYNTHETIC-STALE",
            Some("SYNTHETIC-STALE-ROTATED"),
            2_000_000_001
        )
        .is_err());
    assert!(store
        .oauth_credential_generation_for_access(&second)
        .is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert!(store
        .provider_access(&id, "fresh")
        .unwrap()
        .session
        .to_string()
        .contains("SYNTHETIC-FIRST-ROTATED"));
    store.disconnect_provider(&id).unwrap();
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    assert!(store
        .update_oauth_tokens_cas(
            &id,
            next,
            "SYNTHETIC-RESURRECT",
            Some("SYNTHETIC-RESURRECT-REFRESH"),
            2_000_000_002
        )
        .is_err());
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        reads
    );
    assert_eq!(
        store.sanitized().unwrap()["providers"][0]["status"],
        "disconnected"
    );
}

#[test]
fn automatic_noland_discovery_is_metadata_only_opaque_and_store_bound() {
    let (temp, vault, store) = fixture();
    let base = temp.path().join("known-data");
    let directory = base.join(NOLAND_APP_IDENTIFIER);
    fs::create_dir_all(&directory).unwrap();
    // Deliberately invalid JSON: discovery must not parse or read its contents.
    let path = directory.join("state.json");
    fs::write(&path, b"SYNTHETIC-PRIVATE-NOT-JSON").unwrap();
    vault.deny_access(true).unwrap();
    let found = store
        .discover_noland_sources_in(&KnownDataDirs { bases: vec![base] })
        .unwrap();
    assert_eq!(found["hasData"], true);
    assert_eq!(found["requiresChoice"], false);
    let id = found["selectedSourceId"].as_str().unwrap();
    assert_ne!(id, path.to_str().unwrap());
    assert!(!found.to_string().contains(temp.path().to_str().unwrap()));
    let proof = store.noland_source_proof(id).unwrap();
    assert_eq!(proof.state_file(), path);
    let scope = store.noland_import_source_scope(id).unwrap();
    assert_eq!(scope["_approvedPaths"][0]["kind"], "file");
    assert!(store.import_noland(&json!({"sourceId":id})).is_err());
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    fs::write(&path, b"SYNTHETIC-REPLACEMENT").unwrap();
    assert!(proof.approved_path_handoff().is_err());
    assert!(store.noland_source_proof(id).is_err());
}

#[test]
fn automatic_noland_discovery_none_multiple_symlinks_and_unsafe_modes_never_fake_import_success() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (temp, vault, store) = fixture();
    let first = temp.path().join("known-local");
    let second = temp.path().join("known-roaming");
    let dirs = KnownDataDirs {
        bases: vec![first.clone(), second.clone()],
    };
    let none = store.discover_noland_sources_in(&dirs).unwrap();
    assert_eq!(none["hasData"], false);
    assert!(none["error"].as_str().is_some());
    for base in [&first, &second] {
        fs::create_dir_all(base.join(NOLAND_APP_IDENTIFIER)).unwrap();
        fs::write(base.join(NOLAND_APP_IDENTIFIER).join("state.json"), b"{}").unwrap();
    }
    let multiple = store.discover_noland_sources_in(&dirs).unwrap();
    assert_eq!(multiple["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(multiple["requiresChoice"], true);
    assert!(multiple["selectedSourceId"].is_null());
    let target = first.join(NOLAND_APP_IDENTIFIER).join("state.json");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
    let second_path = second.join(NOLAND_APP_IDENTIFIER).join("state.json");
    fs::remove_file(&second_path).unwrap();
    symlink(&target, &second_path).unwrap();
    let rejected = store.discover_noland_sources_in(&dirs).unwrap();
    assert_eq!(rejected["hasData"], false);
    assert_eq!(rejected["rejectedCandidates"], 2);
    assert!(store.import_noland(&json!({"sourceId":target})).is_err());
    assert!(store.sanitized().unwrap()["providers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
}

#[test]
fn discovered_noland_source_import_remains_read_only_and_source_is_unchanged() {
    let (temp, vault, store) = fixture();
    let original = source_file(&temp, Some(source_secret(&"73".repeat(32))));
    let base = temp.path().join("known-data");
    let directory = base.join(NOLAND_APP_IDENTIFIER);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("state.json");
    fs::copy(original, &path).unwrap();
    let before = fs::read(&path).unwrap();
    let found = store
        .discover_noland_sources_in(&KnownDataDirs { bases: vec![base] })
        .unwrap();
    let id = found["selectedSourceId"].as_str().unwrap();
    let scope = store.noland_import_source_scope(id).unwrap();
    let imported = store.import_noland(&scope).unwrap();
    assert_eq!(imported["providers"][0]["readOnly"], true);
    assert_eq!(imported["providers"][0]["status"], "connecting");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry[0] == QUICKSAVE_VAULT_SERVICE));
}

#[test]
fn recovery_export_is_private_external_create_new_and_never_returns_key_material() {
    let (temp, _vault, store) = fixture();
    let id = connected(&store);
    let external = temp.path().join("external-native-selection");
    fs::create_dir(&external).unwrap();
    let root = quicksave_platform::SafeRoot::open(&external).unwrap();
    let request = NativeRecoveryExport {
        provider_id: Some(id.clone()),
        destination: external.join("recovery.key"),
        parent_identity: root.identity().unwrap(),
    };
    let expected = Zeroizing::new(
        store
            .provider_access(&id, "export-check")
            .unwrap()
            .repository_key,
    );
    let receipt = store.export_recovery_key(&request).unwrap();
    assert_eq!(receipt["keyMaterialReturned"], false);
    assert_eq!(fs::read(&request.destination).unwrap(), expected[..]);
    quicksave_platform::verify_private_file(&fs::File::open(&request.destination).unwrap())
        .unwrap();
    assert!(!receipt.to_string().contains(&hex::encode(&expected[..])));
    assert!(store.export_recovery_key(&request).is_err());
    let data = quicksave_platform::SafeRoot::open(&temp.path().join("workspace")).unwrap();
    assert!(store
        .export_recovery_key(&NativeRecoveryExport {
            provider_id: None,
            destination: temp.path().join("workspace/forbidden.key"),
            parent_identity: data.identity().unwrap(),
        })
        .is_err());
    let source = temp.path().join("approved-capture-directory");
    fs::create_dir(&source).unwrap();
    let source_root = quicksave_platform::SafeRoot::open(&source).unwrap();
    store
        .update_software(&json!({
            "id":"capture-export-boundary","name":"Synthetic capture",
            "roots":[{"id":"source","path":source,"identity":source_root.identity().unwrap(),
                "allowedFiles":["approved.dat"]}],
        }))
        .unwrap();
    assert!(store
        .export_recovery_key(&NativeRecoveryExport {
            provider_id: Some(id),
            destination: source.join("unlisted-but-not-external.key"),
            parent_identity: source_root.identity().unwrap(),
        })
        .is_err());
    let noland = temp.path().join(NOLAND_APP_IDENTIFIER);
    fs::create_dir(&noland).unwrap();
    let noland_root = quicksave_platform::SafeRoot::open(&noland).unwrap();
    assert!(store
        .export_recovery_key(&NativeRecoveryExport {
            provider_id: None,
            destination: noland.join("forbidden.key"),
            parent_identity: noland_root.identity().unwrap(),
        })
        .is_err());
    assert!(!noland.join("forbidden.key").exists());
}

#[test]
fn typed_app_tracking_policy_requires_native_grant_and_revocation_survives_plaintext_rollback() {
    let (_temp, _vault, store) = fixture();
    let scope = json!({
        "version":1,"policyId":"synthetic-policy","rolePolicyVersion":1,
        "source":"verified_native_discovery","enabled":true,
        "baseDirectories":[{"id":"synthetic-base","path":"/synthetic/approved-base",
            "identity":{"device":1,"fileId":[2,0]},"allowedRoles":["installation","save"],
            "ownershipRules":["native_installation_handle"]}],
        "appIdentityPolicy":{"allowedAppIds":["synthetic.app"],"allowNewVerifiedApps":false,
            "allowedEvidenceKinds":["native_installation_handle"],"allowNativeInstallationOnly":true},
        "excludedPaths":[],
    });
    assert!(store
        .set_app_tracking_policy(&json!({"policyScope":scope,"policyGrant":{}}))
        .is_err());
    let grant = store.issue_grant("app_tracking_policy", &scope).unwrap();
    let policy = json!({"policyScope":scope,"policyGrant":grant});
    store.set_app_tracking_policy(&policy).unwrap();
    assert!(store.app_tracking_policy().unwrap().is_some());
    assert_eq!(
        store.sanitized().unwrap()["settings"]["appTracking"]["enabled"],
        true
    );
    let prior = store.document().unwrap().settings.app_tracking;
    store.clear_app_tracking_policy().unwrap();
    store
        .transaction(|document| {
            document.settings.app_tracking = prior;
            Ok(())
        })
        .unwrap();
    assert!(store.app_tracking_policy().unwrap().is_none());
    assert_eq!(
        store.sanitized().unwrap()["settings"]["appTracking"]["enabled"],
        false
    );
}

#[test]
fn oauth_refresh_rotation_preserves_native_binding_key_grants_and_exact_state_bytes() {
    for kind in [
        ProviderKind::GoogleDrive,
        ProviderKind::MicrosoftOneDrive,
        ProviderKind::Dropbox,
        ProviderKind::Box,
    ] {
        let (temp, vault, store) = fixture();
        let id = connected_oauth(&store, kind);
        tracked(&store, &id);
        store.set_autosave("software-1", &id, true).unwrap();
        assert!(store.verify_autosave_grant("software-1", &id).unwrap());
        let before_document = store.document().unwrap();
        let before_bytes = fs::read(temp.path().join("workspace/state.json")).unwrap();
        let before_dashboard = store.sanitized().unwrap();
        let before_key = Zeroizing::new(
            store
                .provider_access(&id, "before-refresh")
                .unwrap()
                .repository_key,
        );
        let before_secret = store.read_secret(&before_document.providers[0]).unwrap();
        let refreshed =
            oauth_credentials("PRIVATE-ROTATED-ACCESS", Some("PRIVATE-ROTATED-REFRESH"));
        store.update_oauth_credentials(&id, &refreshed).unwrap();
        assert_eq!(store.document().unwrap(), before_document);
        assert_eq!(
            fs::read(temp.path().join("workspace/state.json")).unwrap(),
            before_bytes
        );
        assert_eq!(store.sanitized().unwrap(), before_dashboard);
        assert!(store.verify_tracking_grant("software-1").unwrap());
        assert!(store.verify_autosave_grant("software-1", &id).unwrap());
        let after_secret = store.read_secret(&before_document.providers[0]).unwrap();
        assert_eq!(after_secret.provider_fields, before_secret.provider_fields);
        assert_eq!(
            after_secret.repository_key_ref,
            before_secret.repository_key_ref
        );
        assert_eq!(after_secret.read_only, before_secret.read_only);
        assert_eq!(after_secret.credentials, refreshed);
        let after_access = store.provider_access(&id, "after-refresh").unwrap();
        assert_eq!(&after_access.repository_key[..], &before_key[..]);
        let config = after_access.session["config_ini"].as_str().unwrap();
        assert!(config.contains("PRIVATE-ROTATED-ACCESS"));
        assert!(config.contains("PRIVATE-ROTATED-REFRESH"));
        assert!(!config.contains("PRIVATE-OLD-ACCESS"));
        assert!(!config.contains("PRIVATE-OLD-REFRESH"));
        for output in [
            String::from_utf8(before_bytes).unwrap(),
            store.sanitized().unwrap().to_string(),
        ] {
            for forbidden in [
                "PRIVATE-ROTATED-ACCESS",
                "PRIVATE-ROTATED-REFRESH",
                "PRIVATE-CLIENT-SECRET",
                "PRIVATE-OLD-ACCESS",
                "PRIVATE-OLD-REFRESH",
            ] {
                assert!(
                    !output.contains(forbidden),
                    "native token escaped into settings/DTO"
                );
            }
        }
        assert!(vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry[0] == QUICKSAVE_VAULT_SERVICE));
    }
}

#[test]
fn oauth_refresh_missing_token_preserves_previous_rotation_and_rejects_empty_token() {
    let (_temp, _vault, store) = fixture();
    let id = connected_oauth(&store, ProviderKind::GoogleDrive);
    store
        .update_oauth_credentials(
            &id,
            &oauth_credentials("PRIVATE-NEW-ACCESS", Some("PRIVATE-ROTATED-REFRESH")),
        )
        .unwrap();
    let mut omitted = oauth_credentials("PRIVATE-OMITTED-ACCESS", None);
    omitted["value"]
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    store.update_oauth_credentials(&id, &omitted).unwrap();
    let null = oauth_credentials("PRIVATE-NULL-ACCESS", None);
    store.update_oauth_credentials(&id, &null).unwrap();
    let record = store.document().unwrap().providers.remove(0);
    let secret = store.read_secret(&record).unwrap();
    assert_eq!(
        secret.credentials["value"]["refresh_token"],
        "PRIVATE-ROTATED-REFRESH"
    );
    assert_eq!(
        secret.credentials["value"]["access_token"],
        "PRIVATE-NULL-ACCESS"
    );
    assert!(store
        .update_oauth_credentials(&id, &oauth_credentials("PRIVATE-REJECTED-ACCESS", Some("")))
        .is_err());
    let access = store
        .provider_access(&id, "after-rejected-refresh")
        .unwrap();
    assert!(!access
        .session
        .to_string()
        .contains("PRIVATE-REJECTED-ACCESS"));
}

#[test]
fn oauth_refresh_imported_profile_never_updates_source_or_grants_cloud_writes() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state["sharedStorageProfiles"][0]["provider"] = json!("google_drive");
    state["sharedStorageProfiles"][0]["providerLabel"] = json!("Google Drive");
    state["sharedStorageProfiles"][0]["bucket"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let account = dynamic_profile_account("source-profile");
    source_document(&vault, vec![(&account, Some(json!({
        "credentials":oauth_credentials("PRIVATE-SOURCE-ACCESS",Some("PRIVATE-SOURCE-REFRESH")),
        "providerFields":{"client_id":"source-client","client_secret":"PRIVATE-SOURCE-CLIENT-SECRET"},
        "repositoryKeyHex":"ca".repeat(32),
    }).to_string()))]);
    let before_source_file = fs::read(&path).unwrap();
    let before_source_vault = vault
        .read(NOLAND_DOCUMENT_SERVICE, NOLAND_DOCUMENT_ACCOUNT)
        .unwrap()
        .unwrap();
    let dashboard = store.import_noland(&json!({"stateFile":path})).unwrap();
    let id = dashboard["providers"][0]["id"].as_str().unwrap();
    tracked(&store, id);
    let before_document = store.document().unwrap();
    let before_bytes = fs::read(temp.path().join("workspace/state.json")).unwrap();
    store
        .update_oauth_credentials(
            id,
            &oauth_credentials(
                "PRIVATE-IMPORT-NEW-ACCESS",
                Some("PRIVATE-IMPORT-ROTATED-REFRESH"),
            ),
        )
        .unwrap();
    assert_eq!(store.document().unwrap(), before_document);
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before_bytes
    );
    assert!(store.verify_tracking_grant("software-1").unwrap());
    let access = store
        .provider_access(id, "imported-refreshed-read")
        .unwrap();
    assert!(access.read_only);
    assert_eq!(access.repository_key, [0xca; 32]);
    assert!(access
        .session
        .to_string()
        .contains("PRIVATE-IMPORT-ROTATED-REFRESH"));
    assert_eq!(fs::read(path).unwrap(), before_source_file);
    assert_eq!(
        vault
            .read(NOLAND_DOCUMENT_SERVICE, NOLAND_DOCUMENT_ACCOUNT)
            .unwrap()
            .unwrap()
            .as_str(),
        before_source_vault.as_str()
    );
    assert!(vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry[0] == QUICKSAVE_VAULT_SERVICE));
    assert_eq!(store.sanitized().unwrap()["providers"][0]["readOnly"], true);
}

#[test]
fn oauth_refresh_rejects_expanded_wrong_type_unknown_or_disconnected_input_before_vault_reads() {
    let (_temp, vault, store) = fixture();
    let valid = oauth_credentials(
        "PRIVATE-INVALID-INPUT-ACCESS",
        Some("PRIVATE-INVALID-INPUT-REFRESH"),
    );
    assert!(store
        .update_oauth_credentials("unknown-provider", &valid)
        .is_err());
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    let static_id = connected(&store);
    let before_static = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    assert!(store.update_oauth_credentials(&static_id, &valid).is_err());
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        before_static
    );
    let id = connected_oauth(&store, ProviderKind::GoogleDrive);
    let mut invalid = vec![
        b2_input("wrong credential type")["credentials"].clone(),
        json!({"type":"oauth2","value":valid["value"]}),
    ];
    let mut expanded = valid.clone();
    expanded["providerId"] = json!("other-provider");
    invalid.push(expanded);
    let mut fields = valid.clone();
    fields["value"]["prefix"] = json!("not-approved");
    invalid.push(fields);
    let mut bad_expiry = valid.clone();
    bad_expiry["value"]["expires_at"] = json!(0);
    invalid.push(bad_expiry);
    let before = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    for input in invalid {
        let error = store.update_oauth_credentials(&id, &input).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-INVALID-INPUT"));
    }
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        before
    );
    store.disconnect_provider(&id).unwrap();
    let before = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    assert!(store.update_oauth_credentials(&id, &valid).is_err());
    assert_eq!(
        vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        before
    );
    assert!(store.provider_access(&id, "disconnected-refresh").is_err());
}

#[test]
fn oauth_refresh_rejects_changed_routing_policy_key_or_protected_provider_identity() {
    let (temp, vault, store) = fixture();
    let id = connected_oauth(&store, ProviderKind::GoogleDrive);
    let original = store.document().unwrap().providers[0].clone();
    let refreshed = oauth_credentials(
        "PRIVATE-IDENTITY-REJECTED-ACCESS",
        Some("PRIVATE-IDENTITY-REJECTED-REFRESH"),
    );
    for change in ["root", "kind", "key", "readonly"] {
        store
            .transaction(|document| {
                document.providers[0] = original.clone();
                let provider = &mut document.providers[0];
                match change {
                    "root" => provider.prefix = Some("unapproved-root".into()),
                    "kind" => provider.kind = "dropbox".into(),
                    "key" => provider.repository_key_ref = format!("repository.import.{}", id),
                    "readonly" => provider.read_only = true,
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap();
        let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
        let writes = vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len();
        let error = store.update_oauth_credentials(&id, &refreshed).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-IDENTITY"));
        assert_eq!(
            fs::read(temp.path().join("workspace/state.json")).unwrap(),
            before
        );
        assert_eq!(
            vault.access_log().unwrap()["writes"]
                .as_array()
                .unwrap()
                .len(),
            writes
        );
    }
    store
        .transaction(|document| {
            document.providers[0] = original.clone();
            Ok(())
        })
        .unwrap();
    let protected = vault
        .read(QUICKSAVE_VAULT_SERVICE, &original.credential_ref)
        .unwrap()
        .unwrap();
    let mut changed: Value = serde_json::from_str(&protected).unwrap();
    changed["providerId"] = json!("another-native-profile");
    vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            &original.credential_ref,
            &changed.to_string(),
        )
        .unwrap();
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let writes = vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .len();
    assert!(store.update_oauth_credentials(&id, &refreshed).is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert_eq!(
        vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len(),
        writes
    );
}

#[derive(Clone, Default)]
struct RefreshFaultVault {
    memory: MemoryVault,
    mode: Arc<std::sync::atomic::AtomicU8>,
}

impl CredentialVault for RefreshFaultVault {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        self.memory.read(service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        if mode != 0 && account.starts_with("provider.") {
            match mode {
                1 => bail!("PRIVATE-BACKEND-ERROR: token write refused"),
                2 | 3 => {
                    self.memory
                        .write(service, account, "{PRIVATE-PARTIAL-PROFILE")?;
                    if mode == 2 {
                        bail!("PRIVATE-BACKEND-ERROR: partial write then failure");
                    }
                    return Ok(());
                }
                4 => return Ok(()), // Claimed success without persistence.
                _ => unreachable!(),
            }
        }
        self.memory.write(service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.memory.delete(service, account)
    }
}

#[test]
fn oauth_refresh_nonatomic_and_silent_vault_failures_never_publish_or_report_success() {
    for mode in [1, 2, 3, 4] {
        let temp = temporary();
        let vault = RefreshFaultVault::default();
        let store = WorkspaceStore::open_with_vault(
            &temp.path().join("workspace"),
            Arc::new(vault.clone()),
        )
        .unwrap();
        let id = connected_oauth(&store, ProviderKind::GoogleDrive);
        let before_document = store.document().unwrap();
        let before_bytes = fs::read(temp.path().join("workspace/state.json")).unwrap();
        let before_dashboard = store.sanitized().unwrap();
        vault.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
        let error = store
            .update_oauth_credentials(
                &id,
                &oauth_credentials("PRIVATE-FAILED-ACCESS", Some("PRIVATE-FAILED-REFRESH")),
            )
            .unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-"));
        assert_eq!(store.document().unwrap(), before_document);
        assert_eq!(
            fs::read(temp.path().join("workspace/state.json")).unwrap(),
            before_bytes
        );
        assert_eq!(store.sanitized().unwrap(), before_dashboard);
        if mode == 1 || mode == 4 {
            let access = store
                .provider_access(&id, "old-credentials-after-rejected-refresh")
                .unwrap();
            assert!(access.session.to_string().contains("PRIVATE-OLD-ACCESS"));
            assert!(!access.session.to_string().contains("PRIVATE-FAILED-ACCESS"));
        } else {
            assert!(store
                .provider_access(&id, "corrupt-profile-fails-closed")
                .is_err());
        }
        assert!(!store.sanitized().unwrap().to_string().contains("PRIVATE-"));
    }
}

#[test]
fn provider_definition_field_types_match_native_ui_normalization_contract() {
    let (_temp, _vault, store) = fixture();
    let definitions = store.provider_types();
    assert_eq!(definitions.as_array().unwrap().len(), 14);
    for definition in definitions.as_array().unwrap() {
        assert!(definition["kind"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(definition["label"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(definition["isOauth"].is_boolean());
        assert!(definition["credentialType"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        let fields = definition["fields"].as_array().unwrap();
        assert!(fields.len() <= 40);
        let mut names = std::collections::BTreeSet::new();
        for field in fields {
            assert!(names.insert(field["key"].as_str().unwrap()));
            assert!(field["label"]
                .as_str()
                .is_some_and(|value| !value.is_empty()));
            assert!(field["required"].is_boolean());
            assert!(field["credential"].is_boolean());
            assert!(["text", "password", "select", "number", "toggle"]
                .contains(&field["fieldType"].as_str().unwrap()));
        }
        if definition["isOauth"] == true {
            assert_eq!(definition["credentialType"], "o_auth2");
            assert!(fields
                .iter()
                .any(|field| field["key"] == "client_id" && field["fieldType"] == "text"));
            assert!(fields
                .iter()
                .any(|field| field["key"] == "client_secret" && field["fieldType"] == "password"));
        }
    }
}

#[test]
fn import_handoff_matches_native_ids_and_platform_snake_case_stamp() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
    let handoff = import_file_handoff(&path);
    assert!(handoff["identity"]["fileId"].is_array());
    assert!(handoff["parentIdentity"]["fileId"].is_array());
    assert!(handoff["stamp"]["file_id"].is_array());
    assert!(handoff["stamp"].get("fileId").is_none());
    let result = store
        .import_noland(&json!({
            "stateFile":path,"_approvedPaths":[handoff],
        }))
        .unwrap();
    assert_eq!(result["providers"][0]["origin"], "noland");
    assert_eq!(result["providers"][0]["readOnly"], true);
    assert!(!vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn import_rejects_replaced_approved_file_before_read_parse_or_any_vault_operation() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
    let handoff = import_file_handoff(&path);
    let before_workspace = fs::read(temp.path().join("workspace/state.json")).unwrap();
    // Keep the old inode alive under another name so the replacement cannot
    // happen to reuse its ID. The new bytes must never reach the JSON parser.
    fs::rename(&path, temp.path().join("old-approved-state.json")).unwrap();
    let replacement = b"NOT-JSON: UNAPPROVED REPLACEMENT MUST NOT BE READ OR PARSED";
    fs::write(&path, replacement).unwrap();
    let error = store
        .import_noland(&json!({
            "stateFile":path,"_approvedPaths":[handoff],
        }))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("native-approved No Land state file identity or contents changed"));
    assert!(!error.to_string().contains("invalid storage projection"));
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before_workspace
    );
    assert_eq!(fs::read(path).unwrap(), replacement);
}

#[test]
fn import_rejects_replaced_parent_even_when_file_id_and_full_stamp_are_unchanged() {
    let (temp, vault, store) = fixture();
    let source = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
    let first_parent = temp.path().join("approved-source");
    let replacement_parent = temp.path().join("replacement-source");
    fs::create_dir(&first_parent).unwrap();
    fs::create_dir(&replacement_parent).unwrap();
    let path = first_parent.join("state.json");
    fs::rename(source, &path).unwrap();
    // Establish both links before approval; changing only directory names later
    // does not change the regular file's native ID, mtime, length, or ctime.
    fs::hard_link(&path, replacement_parent.join("state.json")).unwrap();
    let handoff = import_file_handoff(&path);
    let expected: quicksave_platform::FileStamp =
        serde_json::from_value(handoff["stamp"].clone()).unwrap();
    fs::rename(&first_parent, temp.path().join("retired-source")).unwrap();
    fs::rename(&replacement_parent, &first_parent).unwrap();
    let new_parent = quicksave_platform::SafeRoot::open(&first_parent).unwrap();
    let (_file, observed) = new_parent.read_file("state.json").unwrap();
    assert_eq!(
        observed, expected,
        "this test isolates the parent-ID handoff, not file replacement"
    );
    let error = store
        .import_noland(&json!({
            "stateFile":path,"_approvedPaths":[handoff],
        }))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("native-approved No Land state parent identity changed"));
    assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
    assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
}

#[test]
fn import_present_handoff_never_falls_back_for_missing_malformed_or_ambiguous_proofs() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, Some(source_secret(&"ab".repeat(32))));
    let handoff = import_file_handoff(&path);
    let mut other_path = handoff.clone();
    other_path["path"] = json!(temp.path().join("another-source.json"));
    let mut wrong_kind = handoff.clone();
    wrong_kind["kind"] = json!("directory");
    let mut missing_stamp = handoff.clone();
    missing_stamp.as_object_mut().unwrap().remove("stamp");
    let mut wrong_stamp = handoff.clone();
    wrong_stamp["stamp"]["size"] = json!(handoff["stamp"]["size"].as_u64().unwrap() + 1);
    let mut wrong_identity = handoff.clone();
    wrong_identity["identity"]["fileId"] = json!([0, 0]);
    for proof in [
        Value::Null,
        json!({}),
        json!([]),
        json!([other_path]),
        json!([wrong_kind]),
        json!([missing_stamp]),
        json!([wrong_stamp]),
        json!([wrong_identity]),
        json!([handoff.clone(), handoff]),
    ] {
        assert!(store
            .import_noland(&json!({"stateFile":path,"_approvedPaths":proof}))
            .is_err());
        assert_eq!(vault.access_log().unwrap()["reads"], json!([]));
        assert_eq!(vault.access_log().unwrap()["writes"], json!([]));
    }
    assert!(store.document().unwrap().providers.is_empty());
}

#[test]
fn manual_provider_public_scope_names_destinations_without_copying_credentials() {
    let (temp, _vault, store) = fixture();
    let cases = [
        (
            "generic_s3",
            json!({"endpoint":"https://storage.example.invalid","region":"custom-region"}),
            json!({"type":"s3","value":{"access_key_id":"PRIVATE-SCOPE-ACCESS-KEY","secret_access_key":"PRIVATE-SCOPE-SECRET","session_token":null}}),
            json!({"endpoint":"https://storage.example.invalid","region":"custom-region"}),
        ),
        (
            "sftp",
            json!({"host":"sftp.example.invalid","port":"2222","host_keys":"ssh-ed25519 SYNTHETIC-PUBLIC-HOST-KEY","remote_path":"/srv/approved"}),
            json!({"type":"username_password","value":{"username":"PRIVATE-SCOPE-USERNAME","password":"PRIVATE-SCOPE-PASSWORD"}}),
            json!({"host":"sftp.example.invalid","port":"2222","host_keys":"ssh-ed25519 SYNTHETIC-PUBLIC-HOST-KEY","remote_path":"/srv/approved"}),
        ),
        (
            "webdav",
            json!({"url":"https://webdav.example.invalid/approved","vendor":"nextcloud","remote_path":"approved-folder"}),
            json!({"type":"username_password","value":{"username":"PRIVATE-SCOPE-USERNAME","password":"PRIVATE-SCOPE-PASSWORD"}}),
            json!({"url":"https://webdav.example.invalid/approved","remote_path":"approved-folder"}),
        ),
        (
            "microsoft_onedrive",
            json!({"client_id":"PRIVATE-SCOPE-CLIENT-ID","client_secret":"PRIVATE-SCOPE-CLIENT-SECRET","drive_id":"public-drive-id","drive_type":"personal","folder":"approved-folder"}),
            oauth_credentials(
                "PRIVATE-SCOPE-OAUTH-ACCESS",
                Some("PRIVATE-SCOPE-OAUTH-REFRESH"),
            ),
            json!({"drive_id":"public-drive-id","drive_type":"personal","folder":"approved-folder"}),
        ),
    ];
    for (kind, fields, credentials, expected) in cases {
        let result = store
            .connect_provider(&json!({
                "kind":kind,"name":kind,"fields":fields,"credentials":credentials,
                "bucket":if kind == "generic_s3" {Some("public-approved-bucket")}else{None},
            }))
            .unwrap();
        let record = store.document().unwrap().providers.pop().unwrap();
        assert_eq!(
            serde_json::to_value(&record.public_scope).unwrap(),
            expected
        );
        assert!(
            result["providers"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .get("publicScope")
                .is_none(),
            "normal UI DTO should stay compact"
        );
        store
            .provider_access(&record.id, "verify-public-scope-binding")
            .unwrap();
    }
    let bytes = fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    assert!(bytes.contains("https://storage.example.invalid"));
    assert!(bytes.contains("sftp.example.invalid"));
    assert!(bytes.contains("https://webdav.example.invalid/approved"));
    assert!(!bytes.contains("PRIVATE-SCOPE-"));
    assert!(!bytes.contains("client_secret"));
    assert!(!bytes.contains("access_token"));
    assert!(!bytes.contains("password"));
}

#[test]
fn imported_custom_endpoint_is_publicly_bound_without_storage_or_app_secrets() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let mut selected: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    selected["sharedStorageProfiles"][0]["provider"] = json!("generic_s3");
    selected["sharedStorageProfiles"][0]["providerLabel"] = json!("Generic S3");
    fs::write(&path, serde_json::to_vec(&selected).unwrap()).unwrap();
    let account = dynamic_profile_account("source-profile");
    source_document(&vault, vec![(&account, Some(json!({
        "credentials":{"type":"s3","value":{"access_key_id":"PRIVATE-IMPORTED-SCOPE-KEY","secret_access_key":"PRIVATE-IMPORTED-SCOPE-SECRET","session_token":null}},
        "providerFields":{"endpoint":"https://imported-storage.example.invalid","region":"imported-region"},
        "repositoryKeyHex":"de".repeat(32),
    }).to_string()))]);
    let handoff = import_file_handoff(&path);
    let result = store
        .import_noland(&json!({"stateFile":path,"_approvedPaths":[handoff]}))
        .unwrap();
    let id = result["providers"][0]["id"].as_str().unwrap();
    let record = store.document().unwrap().providers.remove(0);
    assert_eq!(
        serde_json::to_value(&record.public_scope).unwrap(),
        json!({
            "endpoint":"https://imported-storage.example.invalid","region":"imported-region",
        })
    );
    assert!(record.read_only);
    let state = fs::read_to_string(temp.path().join("workspace/state.json")).unwrap();
    assert!(state.contains("https://imported-storage.example.invalid"));
    assert!(!state.contains("PRIVATE-IMPORTED-SCOPE"));
    assert!(!state.contains("DO-NOT-COPY"));
    assert!(!state.contains(&"de".repeat(32)));
    store
        .provider_access(id, "before-public-display-tamper")
        .unwrap();
    store
        .transaction(|document| {
            document.providers[0].public_scope.insert(
                "endpoint".into(),
                "https://misleading-display.example.invalid".into(),
            );
            Ok(())
        })
        .unwrap();
    assert!(store
        .provider_access(id, "after-public-display-tamper")
        .is_err());
    assert!(
        store.grant_provider_writes(id).is_err(),
        "a misleading consent display must not acquire native write authority"
    );
    assert!(store.record_provider_health(id, &json!({
        "canList":true,"repositoryAccessible":true,"repositoryEmpty":true,"canRead":false,"keyVerified":false,
    })).is_err());
}

#[test]
fn public_destination_scope_is_part_of_persistent_autosave_authority() {
    let (_temp, _vault, store) = fixture();
    let result = store.connect_provider(&json!({
        "kind":"generic_s3","name":"Custom approved storage","bucket":"approved-bucket","prefix":"approved-prefix",
        "fields":{"endpoint":"https://approved-endpoint.example.invalid"},
        "credentials":{"type":"s3","value":{"access_key_id":"synthetic-access","secret_access_key":"synthetic-secret","session_token":null}},
    })).unwrap();
    let id = result["providers"][0]["id"].as_str().unwrap();
    store.record_provider_health(id, &json!({
        "canList":true,"repositoryAccessible":true,"repositoryEmpty":true,"canRead":false,"keyVerified":false,
    })).unwrap();
    tracked(&store, id);
    store.set_autosave("software-1", id, true).unwrap();
    assert!(store.verify_autosave_grant("software-1", id).unwrap());
    store
        .transaction(|document| {
            document.providers[0].public_scope.insert(
                "endpoint".into(),
                "https://different-display.example.invalid".into(),
            );
            Ok(())
        })
        .unwrap();
    assert!(!store.verify_autosave_grant("software-1", id).unwrap());
    assert!(store.provider_access(id, "public-scope-tampered").is_err());
}

#[test]
fn legacy_public_scope_defaults_never_trigger_preconsent_vault_migration() {
    for with_endpoint in [false, true] {
        let (temp, vault, store) = fixture();
        let result = if with_endpoint {
            store.connect_provider(&json!({
                "kind":"generic_s3","name":"Old custom storage","bucket":"old-bucket",
                "fields":{"endpoint":"https://legacy-endpoint.example.invalid"},
                "credentials":{"type":"s3","value":{"access_key_id":"synthetic-key","secret_access_key":"synthetic-secret","session_token":null}},
            })).unwrap()
        } else {
            store
                .connect_provider(&b2_input("Old no-destination-fields profile"))
                .unwrap()
        };
        let id = result["providers"][0]["id"].as_str().unwrap();
        let path = temp.path().join("workspace/state.json");
        let mut old: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        old["providers"][0]
            .as_object_mut()
            .unwrap()
            .remove("publicScope");
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let before = vault.access_log().unwrap();
        let reopened = WorkspaceStore::open_with_vault(
            &temp.path().join("workspace"),
            Arc::new(vault.clone()),
        )
        .unwrap();
        assert!(reopened.document().unwrap().providers[0]
            .public_scope
            .is_empty());
        reopened.sanitized().unwrap();
        assert_eq!(
            vault.access_log().unwrap(),
            before,
            "open/queries cannot hydrate public destinations from the vault before consent"
        );
        let access = reopened.provider_access(id, "legacy-profile-explicit-native-use");
        if with_endpoint {
            assert!(
                access.is_err(),
                "a missing custom endpoint display requires native-consented reconnect"
            );
        } else {
            assert!(access.is_ok(), "profiles without relevant private destination fields retain empty-scope compatibility");
        }
        assert_eq!(fs::read(&path).unwrap(), serde_json::to_vec(&old).unwrap());
    }
}

#[test]
fn public_scope_projection_excludes_secret_fields_and_bounds_destination_values() {
    let fields: BTreeMap<String, String> = [
        ("endpoint", "https://storage.example.invalid"),
        ("host", "sftp.example.invalid"),
        ("port", "22"),
        ("folder", "approved-folder"),
        ("client_id", "PRIVATE-PROJECTION-CLIENT-ID"),
        ("client_secret", "PRIVATE-PROJECTION-CLIENT-SECRET"),
        ("access_token", "PRIVATE-PROJECTION-TOKEN"),
        ("password", "PRIVATE-PROJECTION-PASSWORD"),
        ("credentials", "PRIVATE-PROJECTION-CREDENTIALS"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let projection = provider::public_scope(&fields).unwrap();
    assert_eq!(projection.len(), 4);
    assert!(!serde_json::to_string(&projection)
        .unwrap()
        .contains("PRIVATE-PROJECTION"));
    for (key, value) in [
        ("client_secret", "secret".to_owned()),
        ("host", "control\ncharacters".to_owned()),
        ("host", "x".repeat(16 * 1024 + 1)),
        (
            "url",
            "https://storage.example.invalid?token=PRIVATE".to_owned(),
        ),
        (
            "endpoint",
            "https://username:PRIVATE@storage.example.invalid".to_owned(),
        ),
    ] {
        assert!(provider::validate_public_scope(&BTreeMap::from([(key.into(), value)])).is_err());
    }
}

#[test]
fn disconnected_noland_profile_reimports_as_fresh_readonly_identity_without_old_grants() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let account = dynamic_profile_account("source-profile");
    source_document(
        &vault,
        vec![
            (&account, Some(source_secret(&"bb".repeat(32)).to_string())),
            ("shared-storage.repository-key", Some("aa".repeat(32))),
        ],
    );
    let input = json!({
        "stateFile":path,"profileIds":["source-profile"],"_approvedPaths":[import_file_handoff(&path)],
    });
    store.import_noland(&input).unwrap();
    let first_id = store.document().unwrap().providers[0].id.clone();
    store.grant_provider_writes(&first_id).unwrap();
    store
        .record_provider_health(
            &first_id,
            &json!({
                "canList":true,"repositoryAccessible":true,"repositoryEmpty":true,
                "canRead":false,"keyVerified":false,
            }),
        )
        .unwrap();
    tracked(&store, &first_id);
    store.set_autosave("software-1", &first_id, true).unwrap();
    store
        .mark_saved(
            "software-1",
            1,
            "retained-old-version",
            "2026-11-17T12:00:00Z",
        )
        .unwrap();
    let old = store.document().unwrap();
    let old_record = old.providers[0].clone();
    let old_software = old.software[0].clone();
    let old_grant = old_software.autosave_grant.clone().unwrap();
    let old_scope = grant::autosave_scope(&old_software, &old_record).unwrap();
    let old_key = vault
        .read(QUICKSAVE_VAULT_SERVICE, &old_record.repository_key_ref)
        .unwrap()
        .unwrap();
    assert!(store
        .verify_grant("autosave", &old_scope, &old_grant)
        .unwrap());
    store.disconnect_provider(&first_id).unwrap();
    assert!(!store
        .verify_grant("autosave", &old_scope, &old_grant)
        .unwrap());
    assert!(vault
        .read(QUICKSAVE_VAULT_SERVICE, &old_record.credential_ref)
        .unwrap()
        .is_none());

    store.import_noland(&input).unwrap();
    let after = store.document().unwrap();
    assert_eq!(after.providers.len(), 2);
    assert_eq!(after.providers[0].id, first_id);
    assert_eq!(after.providers[0].status, "disconnected");
    assert_eq!(
        after.providers[0].repository_key_ref,
        old_record.repository_key_ref
    );
    let fresh = &after.providers[1];
    assert_ne!(fresh.id, first_id);
    assert_ne!(fresh.credential_ref, old_record.credential_ref);
    assert_ne!(fresh.repository_key_ref, old_record.repository_key_ref);
    assert_eq!(fresh.source_profile_id.as_deref(), Some("source-profile"));
    assert_eq!(fresh.status, "connecting");
    assert!(fresh.read_only);
    assert!(
        store
            .provider_access(&fresh.id, "fresh-import-read")
            .unwrap()
            .read_only
    );
    assert!(store
        .provider_access(&first_id, "old-import-cannot-reconnect")
        .is_err());
    assert_eq!(
        vault
            .read(QUICKSAVE_VAULT_SERVICE, &old_record.repository_key_ref)
            .unwrap()
            .unwrap()
            .as_str(),
        old_key.as_str()
    );
    assert_eq!(
        after.software[0].provider_id.as_deref(),
        Some(first_id.as_str())
    );
    assert_eq!(
        after.software[0].tracking_grant,
        old_software.tracking_grant
    );
    assert_eq!(
        after.software[0].last_confirmed_version.as_deref(),
        Some("retained-old-version")
    );
    assert!(!after.software[0].autosave);
    assert!(after.software[0].autosave_grant.is_none());
    assert!(!store
        .verify_autosave_grant("software-1", &fresh.id)
        .unwrap());
    assert!(!store
        .verify_grant("autosave", &old_scope, &old_grant)
        .unwrap());

    // One disconnected historical record is not enough: every matching previous
    // import must be disconnected before another fresh identity can be created.
    let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
    let writes = vault.access_log().unwrap()["writes"]
        .as_array()
        .unwrap()
        .len();
    assert!(store.import_noland(&input).is_err());
    assert_eq!(
        fs::read(temp.path().join("workspace/state.json")).unwrap(),
        before
    );
    assert_eq!(
        vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len(),
        writes
    );
    store.disconnect_provider(&fresh.id).unwrap();
    store.import_noland(&input).unwrap();
    let third = store.document().unwrap();
    assert_eq!(third.providers.len(), 3);
    assert!(third.providers[..2]
        .iter()
        .all(|provider| provider.status == "disconnected"));
    assert_ne!(third.providers[2].id, first_id);
    assert_ne!(third.providers[2].id, fresh.id);
    assert!(third.providers[2].read_only);
    assert_eq!(
        third.software[0].provider_id.as_deref(),
        Some(first_id.as_str())
    );
    assert!(!third.software[0].autosave);
    assert_eq!(
        vault
            .read(QUICKSAVE_VAULT_SERVICE, &old_record.repository_key_ref)
            .unwrap()
            .unwrap()
            .as_str(),
        old_key.as_str()
    );
    assert!(vault
        .read(QUICKSAVE_VAULT_SERVICE, &fresh.repository_key_ref)
        .unwrap()
        .is_some());
}

#[test]
fn connecting_connected_and_error_noland_profiles_reject_duplicate_import_without_replacement() {
    for status in ["connecting", "connected", "error"] {
        let (temp, vault, store) = fixture();
        let path = source_file(&temp, None);
        let account = dynamic_profile_account("source-profile");
        source_document(
            &vault,
            vec![(&account, Some(source_secret(&"ab".repeat(32)).to_string()))],
        );
        let input = json!({"stateFile":path,"_approvedPaths":[import_file_handoff(&path)]});
        store.import_noland(&input).unwrap();
        let id = store.document().unwrap().providers[0].id.clone();
        if status != "connecting" {
            let healthy = status == "connected";
            store
                .record_provider_health(
                    &id,
                    &json!({
                        "canList":healthy,"repositoryAccessible":healthy,"repositoryEmpty":true,
                        "canRead":false,"keyVerified":false,
                    }),
                )
                .unwrap();
        }
        let record = store.document().unwrap().providers.remove(0);
        assert_eq!(record.status, status);
        let credentials = vault
            .read(QUICKSAVE_VAULT_SERVICE, &record.credential_ref)
            .unwrap()
            .unwrap();
        let before = fs::read(temp.path().join("workspace/state.json")).unwrap();
        let writes = vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len();
        let error = store.import_noland(&input).unwrap_err();
        assert!(error.to_string().contains("explicitly disconnect"));
        assert_eq!(store.document().unwrap().providers.len(), 1);
        assert_eq!(
            fs::read(temp.path().join("workspace/state.json")).unwrap(),
            before
        );
        assert_eq!(
            vault.access_log().unwrap()["writes"]
                .as_array()
                .unwrap()
                .len(),
            writes
        );
        assert_eq!(
            vault
                .read(QUICKSAVE_VAULT_SERVICE, &record.credential_ref)
                .unwrap()
                .unwrap()
                .as_str(),
            credentials.as_str()
        );
    }
}

#[test]
fn imported_error_profile_health_retry_uses_only_retained_quicksave_credentials() {
    let (temp, vault, store) = fixture();
    let path = source_file(&temp, None);
    let account = dynamic_profile_account("source-profile");
    source_document(
        &vault,
        vec![(&account, Some(source_secret(&"ab".repeat(32)).to_string()))],
    );
    store.import_noland(&json!({"stateFile":path})).unwrap();
    let id = store.document().unwrap().providers[0].id.clone();
    store
        .record_provider_health(&id, &json!({"canList":false,"repositoryAccessible":false}))
        .unwrap();
    assert_eq!(store.document().unwrap().providers[0].status, "error");
    let reads = vault.access_log().unwrap()["reads"]
        .as_array()
        .unwrap()
        .len();
    store
        .provider_access(&id, "retry-owned-provider-health")
        .unwrap();
    store.record_provider_health(&id, &json!({
        "canList":true,"repositoryAccessible":true,"repositoryEmpty":true,"canRead":false,"keyVerified":false,
    })).unwrap();
    assert_eq!(store.document().unwrap().providers[0].status, "connected");
    let log = vault.access_log().unwrap();
    assert!(log["reads"].as_array().unwrap()[reads..]
        .iter()
        .all(|entry| entry[0] == QUICKSAVE_VAULT_SERVICE));
    assert_eq!(store.document().unwrap().providers[0].id, id);
    assert!(store.document().unwrap().providers[0].read_only);
}
