// SPDX-License-Identifier: GPL-3.0-only
//! Native-only bridge between operation-bound rclone refresh and vault CAS.
//! The parent NativeEngine retains the registration with its PrivateAccess,
//! calls checkpoint at its existing COMMITTED/LATEST authorization barrier, and
//! calls each ephemeral guard's finish before reporting success (also on errors).

use anyhow::{ensure, Context, Result};
use noland_rclone_adapter::{EphemeralRcloneSession, ProviderKind};
use noland_state_core::StateError;
use noland_storage::{
    native_session_token_fingerprint, NativeCredentialSinkRegistration, NativePrivateCredentialSink,
};
use quicksave_state::{ProviderAccess, WorkspaceStore};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Parent can retain one holder for OAuth handoff AND original source tuning.
/// Static providers still receive their approved policy without a credential
/// callback; no vault/config IO is performed per chunk or progress tick.
pub struct NativeProviderLifecycle {
    credentials: Option<NativeCredentialSinkRegistration>,
    _transfer: Option<noland_storage::NativeTransferPolicyRegistration>,
}
impl NativeProviderLifecycle {
    pub fn checkpoint(&self) -> Result<()> {
        if let Some(credentials) = &self.credentials {
            credentials
                .checkpoint()
                .map_err(|_| anyhow::anyhow!("native credential publication checkpoint failed"))?;
        }
        Ok(())
    }
    pub fn invalidate(&self) -> Result<()> {
        if let Some(credentials) = &self.credentials {
            credentials
                .invalidate()
                .map_err(|_| anyhow::anyhow!("native credential binding invalidation failed"))?;
        }
        if let Some(policy) = &self._transfer {
            policy
                .invalidate()
                .map_err(|_| anyhow::anyhow!("native transfer policy invalidation failed"))?;
        }
        Ok(())
    }
}

pub fn register_native_provider_lifecycle(
    store: WorkspaceStore,
    access: &ProviderAccess,
    operation_id: &str,
) -> Result<NativeProviderLifecycle> {
    let credentials = register_provider_access_for_operation(store, access, operation_id)?;
    let policy = access.transfer_policy();
    let _transfer = if policy.is_null()
        || policy
            .as_object()
            .is_some_and(|object| object.values().all(serde_json::Value::is_null))
    {
        None
    } else {
        let mut session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
            .map_err(|_| anyhow::anyhow!("native provider session is invalid"))?;
        session.operation_id = operation_id.to_owned();
        let kind =
            ProviderKind::parse(&session.provider).context("native provider kind is invalid")?;
        let tuning = policy
            .get("performanceProfile")
            .filter(|value| !value.is_null())
            .map(|value| {
                let workload = match value.as_str() {
                    Some("balanced") => noland_storage::TransferWorkload::Balanced,
                    Some("throughput") => noland_storage::TransferWorkload::Throughput,
                    Some("gameplay_safe") => noland_storage::TransferWorkload::GameplaySafe,
                    _ => anyhow::bail!("native performance profile is invalid"),
                };
                Ok(noland_storage::TransferTuning::automatic(
                    kind,
                    workload.for_active_transfer(),
                ))
            })
            .transpose()?;
        let ceiling = |field: &str| -> Result<Option<usize>> {
            policy
                .get(field)
                .filter(|value| !value.is_null())
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| usize::try_from(value).ok())
                        .context("invalid native transfer ceiling")
                })
                .transpose()
        };
        Some(
            noland_storage::register_native_transfer_policy(
                &session,
                noland_storage::NativeTransferPolicy {
                    tuning,
                    upload_ceiling: ceiling("uploadConcurrency")?,
                    download_ceiling: ceiling("downloadConcurrency")?,
                },
            )
            .map_err(|_| anyhow::anyhow!("native transfer policy registration failed"))?,
        )
    };
    Ok(NativeProviderLifecycle {
        credentials,
        _transfer,
    })
}

/// No registration is necessary for static providers. OAuth requires matching the
/// *original* access to the current vault before installing any sink, so a stale
/// worker cannot begin with an obsolete refresh token and then overwrite a newer
/// rotation. Neither the registration nor callback is a serializable UI object.
pub fn register_provider_access(
    store: WorkspaceStore,
    access: &ProviderAccess,
) -> Result<Option<NativeCredentialSinkRegistration>> {
    let operation_id = access
        .session
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .context("native provider operation binding is missing")?;
    register_provider_access_for_operation(store, access, operation_id)
}

pub fn register_provider_access_for_operation(
    store: WorkspaceStore,
    access: &ProviderAccess,
    operation_id: &str,
) -> Result<Option<NativeCredentialSinkRegistration>> {
    register_access(store, access, operation_id, false)
}

fn register_access(
    store: WorkspaceStore,
    access: &ProviderAccess,
    operation_id: &str,
    recovery: bool,
) -> Result<Option<NativeCredentialSinkRegistration>> {
    ensure!(
        !operation_id.is_empty()
            && operation_id.len() <= 255
            && operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !matches!(operation_id, "." | ".."),
        "native operation binding is invalid"
    );
    let mut session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
        .map_err(|_| anyhow::anyhow!("native provider session is invalid"))?;
    let kind = ProviderKind::parse(&session.provider).context("native provider kind is invalid")?;
    if !kind.is_oauth() {
        return Ok(None);
    }
    let generation = Mutex::new((
        store.oauth_credential_generation_for_access(access)?,
        native_session_token_fingerprint(&session)
            .map_err(|_| anyhow::anyhow!("invalid native OAuth token revision"))?,
    ));
    let authority_revision = access
        .session
        .get("native_authority_revision")
        .and_then(serde_json::Value::as_u64)
        .context("native provider authority revision is missing")?;
    let recovery_scope_document = serde_json::to_vec(&serde_json::json!({
        "kind":"native_provider_credential_recovery_v1",
        "providerId":access.provider_id,
        "authorityRevision":authority_revision,
    }))?;
    let recovery_scope = if recovery {
        store.operation_mac_existing(&recovery_scope_document)?
    } else {
        store.operation_mac(&recovery_scope_document)?
    };
    session.operation_id = operation_id.to_owned();
    let provider_id = access.provider_id.clone();
    let operation_id = session.operation_id.clone();
    let provider = session.provider.clone();
    let remote = session.remote_name.clone();
    let root = session.root.clone();
    let sink: NativePrivateCredentialSink = Arc::new(move |rotation| {
        let rejected = || {
            StateError::Conflict(
            "native-vault credential rotation could not be committed; reattach fresh access or reauthorize".into(),
        )
        };
        if rotation.operation_id != operation_id
            || rotation.provider != provider
            || rotation.remote_name != remote
            || rotation.root != root
        {
            return Err(rejected());
        }
        let mut expected = generation.lock().map_err(|_| rejected())?;
        if rotation.expected_token_fingerprint != expected.1 {
            if rotation.token_fingerprint == expected.1 {
                return Ok(());
            }
            return Err(rejected());
        }
        let next = store
            .update_oauth_tokens_cas(
                &provider_id,
                expected.0,
                &rotation.access_token,
                rotation.refresh_token.as_deref(),
                rotation.expires_at_unix,
            )
            .map_err(|_| rejected())?;
        *expected = (next, rotation.token_fingerprint);
        Ok(())
    });
    let registration = if recovery {
        noland_storage::register_native_private_credential_sink_for_recovery_with_scope(
            &session,
            sink,
            recovery_scope,
        )
    } else {
        noland_storage::register_native_private_credential_sink_with_scope(
            &session,
            sink,
            recovery_scope,
        )
    };
    Ok(Some(registration.map_err(|_| {
        anyhow::anyhow!("native credential sink registration failed")
    })?))
}

/// One native factory result for the parent's NativeEngine authority callback.
/// Neither access/session/master material nor registrations are IPC DTOs.
pub struct NativeProviderContext {
    pub access: ProviderAccess,
    pub lifecycle: NativeProviderLifecycle,
}

/// At initial attachment or checked recovery after the old worker has stopped,
/// finish this provider's retained handoffs, refresh its native vault access, and
/// bind the actual operation ID. Ordinary retries retain their existing context.
/// This recovers crash/write-failure rotations rather
/// than silently starting with a known-obsolete refresh token. No provider HTTP
/// or source No Land state/vault is accessed; only this app's private run files.
pub fn prepare_native_provider_context(
    store: WorkspaceStore,
    original: &ProviderAccess,
    operation_id: &str,
    run_root: &Path,
) -> Result<NativeProviderContext> {
    let original_session: EphemeralRcloneSession = serde_json::from_value(original.session.clone())
        .map_err(|_| anyhow::anyhow!("native provider session is invalid"))?;
    let kind = ProviderKind::parse(&original_session.provider)
        .context("native provider kind is invalid")?;
    if kind == ProviderKind::Local {
        // Native-only local fixtures have no account/authentication to invent.
        // The explicit test runtime separately enforces its pinned sandbox.
        let mut access = ProviderAccess {
            provider_id: original.provider_id.clone(),
            session: original.session.clone(),
            repository_key: original.repository_key,
            read_only: original.read_only,
        };
        access.session["operation_id"] = serde_json::json!(operation_id);
        let lifecycle = register_native_provider_lifecycle(store, &access, operation_id)?;
        return Ok(NativeProviderContext { access, lifecycle });
    }
    let check_scope = |fresh: &ProviderAccess| -> Result<EphemeralRcloneSession> {
        let session: EphemeralRcloneSession = serde_json::from_value(fresh.session.clone())
            .map_err(|_| anyhow::anyhow!("native provider session is invalid"))?;
        ensure!(
            fresh.provider_id == original.provider_id
                && fresh.repository_key == original.repository_key
                && fresh.read_only == original.read_only
                && fresh.transfer_policy() == original.transfer_policy()
                && fresh.session.get("native_authority_revision")
                    == original.session.get("native_authority_revision")
                && noland_storage::native_sessions_have_same_scope(&original_session, &session)
                    .map_err(|_| anyhow::anyhow!("native provider scope validation failed"))?,
            "provider account/root/client/native authority changed; prepare a new approved request"
        );
        Ok(session)
    };
    let mut access = store.provider_access(&original.provider_id, operation_id)?;
    let session = check_scope(&access)?;
    if kind.is_oauth() {
        for retained in noland_storage::retained_credential_sessions(run_root).map_err(|_| {
            anyhow::anyhow!("retained native credential inventory requires recovery")
        })? {
            if retained.provider != session.provider
                || retained.remote_name != session.remote_name
                || retained.root != session.root
            {
                continue;
            }
            let recovery = register_access(store.clone(), &access, &retained.operation_id, true)?;
            let mut expected = check_scope(&access)?;
            expected.operation_id = retained.operation_id.clone();
            noland_storage::finish_retained_credential_session(run_root, &retained.execution_id, &expected)
                .map_err(|_| anyhow::anyhow!("retained OAuth handoff could not be verified; native reauthorization is required"))?;
            drop(recovery);
            access = store.provider_access(&original.provider_id, operation_id)?;
            check_scope(&access)?;
        }
    }
    let lifecycle = register_native_provider_lifecycle(store, &access, operation_id)?;
    Ok(NativeProviderContext { access, lifecycle })
}

/// A digest from a trusted build/package resource manifest, NOT from JavaScript,
/// settings, an environment variable, or a colocated writable checksum file.
pub struct TrustedRcloneResource {
    pub path: PathBuf,
    pub blake3: [u8; 32],
}

/// Resolve a verified app resource first, then a known installed tool. Does not
/// execute, download, chmod, provision, search PATH or inspect provider accounts.
/// Parent still performs exact-executable version/flag preflight and installs
/// noland_storage's native executable pin before any operation.
pub fn resolve_rclone(resources: &[TrustedRcloneResource]) -> Result<PathBuf> {
    ensure!(resources.len() <= 8, "too many bundled helper candidates");
    for resource in resources {
        if !resource.path.exists() {
            continue;
        }
        noland_storage::pin_native_rclone_resource(&resource.path, resource.blake3).map_err(
            |_| {
                anyhow::anyhow!("native rclone resource digest/format/identity verification failed")
            },
        )?;
        return Ok(resource.path.clone());
    }
    #[cfg(unix)]
    for candidate in [
        "/opt/homebrew/bin/rclone",
        "/usr/local/bin/rclone",
        "/usr/bin/rclone",
        "/bin/rclone",
    ] {
        if !Path::new(candidate).exists() {
            continue;
        }
        let path = std::fs::canonicalize(candidate)?;
        let file = noland_snapshot::SourcePath::new(&path)?.open_regular()?;
        verify_executable(&file.metadata()?)?;
        return Ok(path);
    }
    anyhow::bail!("No verified bundled or supported installed rclone helper was found; no automatic download is performed")
}

#[cfg(unix)]
fn verify_executable(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(
        metadata.is_file()
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() }),
        "rclone executable is not trusted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quicksave_state::{MemoryVault, QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT};
    use serde_json::json;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, MemoryVault, WorkspaceStore, String) {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let approved = base.join("opencode");
        let temp = tempfile::Builder::new()
            .prefix("quicksave-vault-handoff-")
            .tempdir_in(if approved.is_dir() { approved } else { base })
            .unwrap();
        let vault = MemoryVault::default();
        let store =
            WorkspaceStore::open_with_vault(&temp.path().join("state"), Arc::new(vault.clone()))
                .unwrap();
        let result = store
            .connect_provider(&json!({
                "kind":"google_drive","name":"Synthetic OAuth","prefix":"synthetic-approved-root",
                "fields":{"client_id":"synthetic-user-owned-client"},
                "credentials":{"type":"o_auth2","value":{"access_token":"SYNTHETIC-ORIGINAL-ACCESS",
                    "refresh_token":"SYNTHETIC-ORIGINAL-REFRESH","expires_at":2_000_000_000}},
            }))
            .unwrap();
        (
            temp,
            vault,
            store,
            result["providers"][0]["id"].as_str().unwrap().to_owned(),
        )
    }
    fn session(access: &ProviderAccess) -> EphemeralRcloneSession {
        serde_json::from_value(access.session.clone()).unwrap()
    }
    fn rotate(path: &Path, original: &EphemeralRcloneSession, name: &str) {
        let config = original
            .config_ini
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("token =") {
                    format!(
                        "token = {}",
                        json!({"access_token":format!("SYNTHETIC-{name}-ACCESS"),
                    "refresh_token":format!("SYNTHETIC-{name}-REFRESH"),
                    "token_type":"Bearer","expiry":"2035-01-01T00:00:00Z"})
                    )
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(path, config).unwrap();
    }

    #[test]
    fn injected_vault_failure_retains_then_native_context_recovers_before_using_rotated_tokens() {
        let (temp, vault, store, id) = fixture();
        let run = temp.path().join("run");
        let original = store.provider_access(&id, "original-access").unwrap();
        let context =
            prepare_native_provider_context(store.clone(), &original, "first-operation", &run)
                .unwrap();
        let first = session(&context.access);
        let (config, guard) =
            noland_storage::write_guarded_ephemeral_session(&run, &first).unwrap();
        let state_before = fs::read(temp.path().join("state/state.json")).unwrap();
        vault.fail_writes(true).unwrap();
        rotate(&config, &first, "RECOVERED");
        assert!(guard.finish().is_err());
        assert!(context.lifecycle.checkpoint().is_err());
        assert!(config.is_file());
        assert_eq!(
            fs::read(temp.path().join("state/state.json")).unwrap(),
            state_before
        );
        vault.fail_writes(false).unwrap();
        let recovered =
            prepare_native_provider_context(store.clone(), &original, "recovered-operation", &run)
                .unwrap();
        assert!(session(&recovered.access)
            .config_ini
            .contains("SYNTHETIC-RECOVERED-REFRESH"));
        assert!(!config.parent().unwrap().exists());
        assert_eq!(recovered.access.repository_key, original.repository_key);
        let reads = vault.access_log().unwrap()["reads"]
            .as_array()
            .unwrap()
            .len();
        for _ in 0..8 {
            recovered.lifecycle.checkpoint().unwrap();
        }
        assert_eq!(
            vault.access_log().unwrap()["reads"]
                .as_array()
                .unwrap()
                .len(),
            reads
        );
        assert!(!store
            .sanitized()
            .unwrap()
            .to_string()
            .contains("SYNTHETIC-RECOVERED"));
        assert_eq!(
            fs::read(temp.path().join("state/state.json")).unwrap(),
            state_before
        );
    }

    #[test]
    fn live_sessions_are_not_startup_artifacts_and_old_parallel_cas_cannot_replace_new_vault_rotation(
    ) {
        let (temp, _vault, store, id) = fixture();
        let run = temp.path().join("run");
        let original = store.provider_access(&id, "parallel-access").unwrap();
        let first =
            prepare_native_provider_context(store.clone(), &original, "parallel-first", &run)
                .unwrap();
        let first_session = session(&first.access);
        let (first_config, first_guard) =
            noland_storage::write_guarded_ephemeral_session(&run, &first_session).unwrap();
        assert!(noland_storage::retained_credential_sessions(&run)
            .unwrap()
            .is_empty());
        let second =
            prepare_native_provider_context(store.clone(), &original, "parallel-second", &run)
                .unwrap();
        let second_session = session(&second.access);
        let (second_config, second_guard) =
            noland_storage::write_guarded_ephemeral_session(&run, &second_session).unwrap();
        rotate(&first_config, &first_session, "NEWEST-COMMITTED");
        first_guard.finish().unwrap();
        rotate(&second_config, &second_session, "STALE-PARALLEL");
        assert!(second_guard.finish().is_err());
        assert!(second.lifecycle.checkpoint().is_err());
        let fresh = store.provider_access(&id, "current").unwrap();
        assert!(session(&fresh)
            .config_ini
            .contains("SYNTHETIC-NEWEST-COMMITTED-REFRESH"));
        assert!(!session(&fresh)
            .config_ini
            .contains("SYNTHETIC-STALE-PARALLEL"));
        // A competing stale artifact is not silently adopted as the latest token.
        assert!(prepare_native_provider_context(store, &fresh, "must-reauthorize", &run).is_err());
        assert!(second_config.is_file());
    }

    #[test]
    fn disconnect_cannot_be_resurrected_by_a_late_guard_or_native_recovery() {
        use quicksave_state::CredentialVault;
        let (temp, vault, store, id) = fixture();
        let run = temp.path().join("run");
        let original = store.provider_access(&id, "disconnect-access").unwrap();
        let context =
            prepare_native_provider_context(store.clone(), &original, "disconnect-operation", &run)
                .unwrap();
        let session = session(&context.access);
        let (config, guard) =
            noland_storage::write_guarded_ephemeral_session(&run, &session).unwrap();
        store.disconnect_provider(&id).unwrap();
        rotate(&config, &session, "LATE-DISCONNECTED");
        assert!(guard.finish().is_err());
        assert!(prepare_native_provider_context(
            store.clone(),
            &original,
            "cannot-resurrect",
            &run
        )
        .is_err());
        assert_eq!(
            store.sanitized().unwrap()["providers"][0]["status"],
            "disconnected"
        );
        assert!(vault
            .read(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT)
            .unwrap()
            .is_some());
        assert!(config.is_file());
    }

    #[test]
    fn explicit_reauthorization_cannot_adopt_an_old_handoff_even_when_original_token_text_matches()
    {
        let (temp, vault, store, id) = fixture();
        let run = temp.path().join("run");
        let original = store
            .provider_access(&id, "reauthorization-access")
            .unwrap();
        let context =
            prepare_native_provider_context(store.clone(), &original, "old-authority", &run)
                .unwrap();
        let session = session(&context.access);
        let (config, guard) =
            noland_storage::write_guarded_ephemeral_session(&run, &session).unwrap();
        vault.fail_writes(true).unwrap();
        rotate(&config, &session, "OLD-AUTHORITY");
        assert!(guard.finish().is_err());
        drop(context);
        vault.fail_writes(false).unwrap();
        let generation = store.provider_credential_generation(&id).unwrap();
        store
            .complete_provider_reauthorization(
                &id,
                generation,
                &json!({
                    "type":"o_auth2","value":{"access_token":"SYNTHETIC-ORIGINAL-ACCESS",
                        "refresh_token":"SYNTHETIC-ORIGINAL-REFRESH","expires_at":2_000_000_000},
                }),
            )
            .unwrap();
        let fresh = store.provider_access(&id, "new-authority-access").unwrap();
        assert!(
            prepare_native_provider_context(store.clone(), &fresh, "new-authority", &run).is_err()
        );
        assert_eq!(
            store.provider_credential_generation(&id).unwrap(),
            generation + 1
        );
        assert_eq!(store.document().unwrap().providers[0].authority_revision, 1);
        assert!(fresh.session["config_ini"]
            .as_str()
            .unwrap()
            .contains("SYNTHETIC-ORIGINAL-REFRESH"));
        assert!(config.is_file());
    }
}
