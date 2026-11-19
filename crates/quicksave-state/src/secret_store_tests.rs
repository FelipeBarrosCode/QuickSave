// SPDX-License-Identifier: GPL-3.0-only
//! Isolated state files and synthetic native items only.
use super::*;
use crate::{state_file::StateFile, MemoryVault};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
};

const BINDING: [u8; 32] = [81; 32];

struct Fixture {
    _temporary: tempfile::TempDir,
    path: std::path::PathBuf,
    file: StateFile,
    vault: MemoryVault,
}

impl Fixture {
    fn pending() -> Self {
        let fixture = Self::uninitialized();
        let mut contents = VaultContents {
            entries: BTreeMap::from([("device.synthetic".into(), "device-key".into())]),
        };
        PendingLegacy::new(
            vec![
                "device.synthetic".into(),
                "authority.synthetic".into(),
                "provider.synthetic".into(),
                crate::REPOSITORY_KEY_ACCOUNT.into(),
            ],
            vec![
                "authority.synthetic".into(),
                "provider.synthetic".into(),
                crate::REPOSITORY_KEY_ACCOUNT.into(),
            ],
        )
        .unwrap()
        .install(&mut contents)
        .unwrap();
        {
            let locked = fixture.file.lock().unwrap();
            LockedSecretAccess::initialize(&locked, &fixture.vault, BINDING, contents).unwrap();
        }
        fixture
    }

    fn new() -> Self {
        let fixture = Self::uninitialized();
        {
            let locked = fixture.file.lock().unwrap();
            LockedSecretAccess::initialize(
                &locked,
                &fixture.vault,
                BINDING,
                VaultContents {
                    entries: BTreeMap::from([
                        ("authority.synthetic".into(), "active-old-nonce".into()),
                        (
                            "provider.synthetic".into(),
                            "synthetic-private-token".into(),
                        ),
                    ]),
                },
            )
            .unwrap();
        }
        fixture
    }

    fn uninitialized() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-secret-protocol-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let path = temporary.path().join("private");
        let file = StateFile::open(&path).unwrap();
        let vault = MemoryVault::default();
        {
            let locked = file.lock().unwrap();
            assert!(locked.read().unwrap().is_none());
            locked
                .replace(&encode_document(&WorkspaceDocument::default()).unwrap())
                .unwrap();
        }
        Self {
            _temporary: temporary,
            path,
            file,
            vault,
        }
    }
}

#[test]
fn secret_commit_preserves_persisted_metadata_and_survives_outer_failure() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let before = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let mut outer = before.clone();
    outer.settings.launch_at_login = true;
    access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    let persisted = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    assert_eq!(persisted.settings, before.settings);
    assert_eq!(persisted.generation, before.generation);
    // A validation failure at final metadata publication cannot undo revocation.
    outer.settings.keep_local_data = false;
    assert!(access.publish_metadata(&outer).is_err());
    drop(access);
    let restarted = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    assert_eq!(
        restarted
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("inactive")
    );
    assert!(
        !decode_document(&locked.read().unwrap().unwrap())
            .unwrap()
            .settings
            .launch_at_login
    );
}

#[test]
fn prepared_before_anchor_failure_selects_old_slot_and_recovers() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    fixture.vault.fail_writes(true).unwrap();
    assert!(access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .is_err());
    fixture.vault.fail_writes(false).unwrap();
    let restarted = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    assert_eq!(
        restarted
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("active-old-nonce")
    );
    restarted
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    let mut outer = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    outer.generation += 1;
    outer.settings.launch_at_login = true;
    restarted.publish_metadata(&outer).unwrap();
    let persisted = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    assert!(persisted.encrypted_secrets.unwrap().candidate.is_none());
    assert!(persisted.settings.launch_at_login);
    assert_eq!(persisted.generation, outer.generation);
}

struct AmbiguousVault {
    backing: MemoryVault,
    fail_after_write: AtomicBool,
    deny_read_after_write: AtomicBool,
    deny_reads: AtomicBool,
}

impl CredentialVault for AmbiguousVault {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        ensure!(
            !self.deny_reads.load(Ordering::SeqCst),
            "synthetic read denied"
        );
        self.backing.read(service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        self.backing.write(service, account, value)?;
        if self.deny_read_after_write.load(Ordering::SeqCst) {
            self.deny_reads.store(true, Ordering::SeqCst);
        }
        ensure!(
            !self.fail_after_write.load(Ordering::SeqCst),
            "synthetic ambiguous write failure"
        );
        Ok(())
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.backing.delete(service, account)
    }
}

#[test]
fn ambiguous_anchor_write_and_readback_denial_never_restore_old_authority() {
    for deny_readback in [false, true] {
        let fixture = Fixture::new();
        let vault = AmbiguousVault {
            backing: fixture.vault.clone(),
            fail_after_write: AtomicBool::new(!deny_readback),
            deny_read_after_write: AtomicBool::new(deny_readback),
            deny_reads: AtomicBool::new(false),
        };
        let locked = fixture.file.lock().unwrap();
        let access = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
        assert!(access
            .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
            .is_err());
        vault.deny_reads.store(false, Ordering::SeqCst);
        let restarted = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
        assert_eq!(
            restarted
                .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("inactive")
        );
    }
}

#[test]
fn rollback_wrong_workspace_missing_anchor_and_reinitialization_fail_closed() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let old = locked.read().unwrap().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    access
        .delete(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_none());
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, [82; 32]).is_err());
    // Historical complete state cannot reintroduce a deleted provider token.
    locked.read().unwrap();
    locked.replace(&old).unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, BINDING).is_err());
    fixture
        .vault
        .delete(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
        .unwrap();
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, BINDING).is_err());
    assert!(LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::new()
        },
    )
    .is_err());
}

#[test]
fn migration_keeps_legacy_items_and_never_uses_them_as_fallback() {
    let fixture = Fixture::uninitialized();
    fixture
        .vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "legacy-unimported",
            "old-source-value",
        )
        .unwrap();
    fixture
        .vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "provider.synthetic",
            "original-provider-token",
        )
        .unwrap();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::from([(
                "provider.synthetic".into(),
                "original-provider-token".into(),
            )]),
        },
    )
    .unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "legacy-unimported")
        .unwrap()
        .is_none());
    assert!(access
        .read("noland-connect.desktop-secrets.v2", "vault")
        .is_err());
    access
        .write(QUICKSAVE_VAULT_SERVICE, "new-account", "new-secret")
        .unwrap();
    assert_eq!(
        fixture
            .vault
            .read(QUICKSAVE_VAULT_SERVICE, "legacy-unimported")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("old-source-value")
    );
    access
        .delete(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_none());
    assert_eq!(
        fixture
            .vault
            .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("original-provider-token")
    );
    let bytes = locked.read().unwrap().unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("new-secret"));
    let log = fixture.vault.access_log().unwrap();
    for entry in log["writes"].as_array().unwrap() {
        assert_eq!(entry[1], ENCRYPTED_VAULT_ACCOUNT);
    }
}

#[test]
fn failed_initial_anchor_creation_leaves_fail_closed_state_not_an_empty_reset() {
    let fixture = Fixture::uninitialized();
    let locked = fixture.file.lock().unwrap();
    fixture.vault.fail_writes(true).unwrap();
    assert!(LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::new()
        },
    )
    .is_err());
    fixture.vault.fail_writes(false).unwrap();
    assert!(decode_document(&locked.read().unwrap().unwrap())
        .unwrap()
        .encrypted_secrets
        .is_some());
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, BINDING).is_err());
    assert!(LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::new()
        },
    )
    .is_err());
}

#[test]
fn oversized_mutation_fails_before_native_or_file_mutation() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let bytes = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    assert!(access
        .write(
            QUICKSAVE_VAULT_SERVICE,
            "oversized",
            &"x".repeat(crate::encrypted_vault::MAX_PLAINTEXT + 1),
        )
        .is_err());
    assert_eq!(locked.read().unwrap().unwrap(), bytes);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
}

#[test]
fn cooperating_independent_handles_serialize_secret_updates() {
    let fixture = Fixture::new();
    let mut threads = Vec::new();
    for index in 0..8 {
        let path = fixture.path.clone();
        let vault = fixture.vault.clone();
        threads.push(std::thread::spawn(move || {
            let file = StateFile::open(&path).unwrap();
            let locked = file.lock().unwrap();
            let access = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
            access
                .write(
                    QUICKSAVE_VAULT_SERVICE,
                    &format!("concurrent.{index}"),
                    &format!("synthetic-{index}"),
                )
                .unwrap();
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    for index in 0..8 {
        assert!(access
            .read(QUICKSAVE_VAULT_SERVICE, &format!("concurrent.{index}"))
            .unwrap()
            .is_some());
    }
}

#[test]
fn fresh_reads_observe_anchor_denial_even_after_successful_access() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_some());
    fixture.vault.deny_access(true).unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
}

#[test]
fn missing_committed_candidate_never_falls_back_to_previous_slot() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    let mut damaged = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    assert!(damaged
        .encrypted_secrets
        .as_ref()
        .unwrap()
        .candidate
        .is_some());
    damaged.encrypted_secrets.as_mut().unwrap().candidate = None;
    locked.replace(&encode_document(&damaged).unwrap()).unwrap();
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .is_err());
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, BINDING).is_err());
}

#[test]
fn stale_publication_rejection_cannot_undo_committed_revocation() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    let stale = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let mut external = stale.clone();
    external.settings.launch_at_login = true;
    locked
        .replace(&encode_document(&external).unwrap())
        .unwrap();
    assert!(access.replace_document(stale).is_err());
    let reopened = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    assert_eq!(
        reopened
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("inactive")
    );
}

#[test]
fn two_slot_capacity_is_preflighted_before_native_anchor_mutation() {
    let fixture = Fixture::uninitialized();
    let locked = fixture.file.lock().unwrap();
    let large = "x".repeat(crate::encrypted_vault::MAX_PLAINTEXT - 64);
    let access = LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::from([("large".into(), large)]),
        },
    )
    .unwrap();
    let before = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    // The final single envelope fits, but keeping both encrypted hex envelopes
    // plus JSON framing exceeds the unchanged 8 MiB StateFile bound.
    assert!(access
        .write(
            QUICKSAVE_VAULT_SERVICE,
            "large",
            &"y".repeat(crate::encrypted_vault::MAX_PLAINTEXT - 64,)
        )
        .is_err());
    assert_eq!(locked.read().unwrap().unwrap(), before);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
}

#[test]
fn trait_reads_fetch_exactly_one_fresh_anchor_even_for_missing_accounts() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let secrets: &dyn SecretAccess = &access;
    let before = fixture.vault.access_log().unwrap();
    let reads_before = before["reads"].as_array().unwrap().len();
    for account in ["provider.synthetic", "absent", "authority.synthetic"] {
        secrets.read(QUICKSAVE_VAULT_SERVICE, account).unwrap();
    }
    let after = fixture.vault.access_log().unwrap();
    let reads = after["reads"].as_array().unwrap();
    assert_eq!(reads.len(), reads_before + 3);
    for entry in &reads[reads_before..] {
        assert_eq!(entry[0], QUICKSAVE_VAULT_SERVICE);
        assert_eq!(entry[1], ENCRYPTED_VAULT_ACCOUNT);
    }
    assert_eq!(after["writes"], before["writes"]);
}

#[test]
fn anchor_removal_does_not_regenerate_or_fall_back_to_legacy_items() {
    let fixture = Fixture::new();
    fixture
        .vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "provider.synthetic",
            "old-legacy-token-must-never-return",
        )
        .unwrap();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    fixture
        .vault
        .delete(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
        .unwrap();
    let before = fixture.vault.access_log().unwrap();
    let reads_before = before["reads"].as_array().unwrap().len();
    let secrets: &dyn SecretAccess = &access;
    assert!(secrets
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    assert!(secrets
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .is_err());
    assert!(secrets
        .delete(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    let after = fixture.vault.access_log().unwrap();
    assert_eq!(after["writes"], before["writes"]);
    for entry in &after["reads"].as_array().unwrap()[reads_before..] {
        assert_eq!(entry[1], ENCRYPTED_VAULT_ACCOUNT);
    }
}

#[test]
fn normalization_selects_only_the_anchor_for_both_pre_and_post_commit_slots() {
    for commit_anchor in [false, true] {
        let fixture = Fixture::new();
        let locked = fixture.file.lock().unwrap();
        let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
        fixture.vault.fail_writes(!commit_anchor).unwrap();
        let result = access.write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive");
        assert_eq!(result.is_ok(), commit_anchor);
        fixture.vault.fail_writes(false).unwrap();
        let prepared = decode_document(&locked.read().unwrap().unwrap()).unwrap();
        assert!(prepared
            .encrypted_secrets
            .as_ref()
            .unwrap()
            .candidate
            .is_some());
        let before = fixture.vault.access_log().unwrap()["writes"].clone();
        let reopened = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
        reopened.publish_metadata(&prepared).unwrap();
        assert!(decode_document(&locked.read().unwrap().unwrap())
            .unwrap()
            .encrypted_secrets
            .unwrap()
            .candidate
            .is_none());
        assert_eq!(
            reopened
                .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(if commit_anchor {
                "inactive"
            } else {
                "active-old-nonce"
            })
        );
        assert_eq!(fixture.vault.access_log().unwrap()["writes"], before);
    }
}

#[test]
fn ambiguous_initial_anchor_creation_can_reopen_but_cannot_reinitialize() {
    for deny_readback in [false, true] {
        let fixture = Fixture::uninitialized();
        let vault = AmbiguousVault {
            backing: fixture.vault.clone(),
            fail_after_write: AtomicBool::new(!deny_readback),
            deny_read_after_write: AtomicBool::new(deny_readback),
            deny_reads: AtomicBool::new(false),
        };
        let locked = fixture.file.lock().unwrap();
        assert!(LockedSecretAccess::initialize(
            &locked,
            &vault,
            BINDING,
            VaultContents {
                entries: BTreeMap::from([("provider.synthetic".into(), "retained-token".into())]),
            },
        )
        .is_err());
        vault.deny_reads.store(false, Ordering::SeqCst);
        let reopened = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
        assert_eq!(
            reopened
                .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("retained-token")
        );
        assert!(LockedSecretAccess::initialize(
            &locked,
            &vault,
            BINDING,
            VaultContents {
                entries: BTreeMap::new()
            },
        )
        .is_err());
    }
}

struct NonPersistingVault(MemoryVault);

impl CredentialVault for NonPersistingVault {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        self.0.read(service, account)
    }
    fn write(&self, _: &str, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.0.delete(service, account)
    }
}

#[test]
fn success_without_anchor_persistence_fails_readback_and_preserves_old_slot() {
    let fixture = Fixture::new();
    let vault = NonPersistingVault(fixture.vault.clone());
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
    assert!(access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .is_err());
    let reopened = LockedSecretAccess::new(&locked, &vault, BINDING).unwrap();
    assert_eq!(
        reopened
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("active-old-nonce")
    );
}

#[test]
fn native_file_check_failure_at_outer_publication_preserves_revocation() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let mut outer = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    outer.settings.launch_at_login = true;
    access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    // This is an actual native private-directory check failure, not an injected
    // backend success or a claim to cover an after-rename durability failure.
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = access.publish_metadata(&outer);
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(outcome.is_err());
    let reopened = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    assert_eq!(
        reopened
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("inactive")
    );
    assert!(
        !decode_document(&locked.read().unwrap().unwrap())
            .unwrap()
            .settings
            .launch_at_login
    );
}

#[test]
fn snapshot_trait_reads_need_no_state_file_but_fetch_anchor_every_time() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let frozen = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    drop(frozen); // Context owns ciphertext and does not borrow its source frame.
    let before = fixture.vault.access_log().unwrap();
    let first_new_read = before["reads"].as_array().unwrap().len();
    let source = fixture.path.join("state.json");
    let moved = fixture.path.join("synthetic-state-away.json");
    std::fs::rename(&source, &moved).unwrap();
    let secrets: &dyn SecretAccess = &snapshot;
    for _ in 0..3 {
        assert_eq!(
            secrets
                .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("active-old-nonce")
        );
    }
    assert!(secrets
        .read(QUICKSAVE_VAULT_SERVICE, "absent")
        .unwrap()
        .is_none());
    std::fs::rename(&moved, &source).unwrap();
    let after = fixture.vault.access_log().unwrap();
    let reads = after["reads"].as_array().unwrap();
    assert_eq!(reads.len(), first_new_read + 4);
    for entry in &reads[first_new_read..] {
        assert_eq!(entry[1], ENCRYPTED_VAULT_ACCOUNT);
    }
    assert_eq!(after["writes"], before["writes"]);
    assert!(snapshot.cached.borrow().is_some());
    assert!(secrets
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .is_err());
    assert!(secrets
        .delete(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .is_err());
    assert_eq!(
        fixture.vault.access_log().unwrap()["writes"],
        before["writes"]
    );
}

#[test]
fn snapshot_rejects_new_anchor_even_when_both_slots_were_frozen() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let writer = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    fixture.vault.fail_writes(true).unwrap();
    assert!(writer
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .is_err());
    fixture.vault.fail_writes(false).unwrap();
    let frozen = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    assert!(snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .unwrap()
        .is_some());
    // Commit the already-prepared candidate exactly, simulating the native
    // commit point occurring between two verifications in this frozen frame.
    let mut anchor = writer.read_anchor().unwrap();
    let candidate = frozen
        .encrypted_secrets
        .as_ref()
        .unwrap()
        .candidate
        .as_ref()
        .unwrap();
    anchor.revision = candidate.revision;
    anchor.digest = candidate.digest().unwrap();
    writer.write_anchor(&anchor).unwrap();
    let error = snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .unwrap_err();
    assert!(error
        .downcast_ref::<crate::MetadataProjectionChanged>()
        .is_some());
    // Invalidation is sticky; the same frame must not start using its candidate.
    let error = snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .unwrap_err();
    assert!(error
        .downcast_ref::<crate::MetadataProjectionChanged>()
        .is_some());
    assert!(snapshot.cached.borrow().is_none());
}

#[test]
fn snapshot_cache_does_not_bypass_denied_missing_or_mismatched_anchor() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let frozen = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    assert!(snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_some());
    let wrong_workspace =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), [45; 32]).unwrap();
    assert!(wrong_workspace
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    fixture.vault.deny_access(true).unwrap();
    assert!(snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    fixture.vault.deny_access(false).unwrap();
    fixture
        .vault
        .delete(QUICKSAVE_VAULT_SERVICE, ENCRYPTED_VAULT_ACCOUNT)
        .unwrap();
    fixture
        .vault
        .seed(
            QUICKSAVE_VAULT_SERVICE,
            "provider.synthetic",
            "legacy-never-return",
        )
        .unwrap();
    let before = fixture.vault.access_log().unwrap();
    assert!(snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .is_err());
    assert_eq!(
        fixture.vault.access_log().unwrap()["writes"],
        before["writes"]
    );
}

#[test]
fn snapshot_created_before_revocation_rejects_unrepresented_current_anchor() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let frozen = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    let writer = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    writer
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "inactive")
        .unwrap();
    // No previous snapshot read is required for detecting this stale frame.
    let error = snapshot
        .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
        .unwrap_err();
    assert!(error
        .downcast_ref::<crate::MetadataProjectionChanged>()
        .is_some());
    assert!(snapshot.cached.borrow().is_none());
}

#[test]
fn pending_repository_key_is_typed_deferred_in_locked_snapshot_and_create_path() {
    let fixture = Fixture::pending();
    // This receiver's isolated workspace is not the source of the tested access.
    let receiver = crate::WorkspaceStore::open_with_vault(
        &fixture._temporary.path().join("receiver"),
        Arc::new(MemoryVault::default()),
    )
    .unwrap();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let frozen = decode_document(&locked.read().unwrap().unwrap()).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    let before = fixture.vault.access_log().unwrap();
    for secrets in [&access as &dyn SecretAccess, &snapshot as &dyn SecretAccess] {
        for _ in 0..2 {
            let error = secrets
                .read(QUICKSAVE_VAULT_SERVICE, crate::REPOSITORY_KEY_ACCOUNT)
                .unwrap_err();
            assert!(error.downcast_ref::<LegacyCredentialDeferred>().is_some());
        }
        let error = receiver.repository_key(secrets, true).unwrap_err();
        assert!(error.downcast_ref::<LegacyCredentialDeferred>().is_some());
    }
    let after = fixture.vault.access_log().unwrap();
    assert_eq!(after["writes"], before["writes"]);
    assert_eq!(
        after["reads"].as_array().unwrap().len(),
        before["reads"].as_array().unwrap().len() + 6
    );
    for read in &after["reads"].as_array().unwrap()[before["reads"].as_array().unwrap().len()..] {
        assert_eq!(read[1], ENCRYPTED_VAULT_ACCOUNT);
    }
    fixture.vault.deny_access(true).unwrap();
    let error = snapshot
        .read(QUICKSAVE_VAULT_SERVICE, crate::REPOSITORY_KEY_ACCOUNT)
        .unwrap_err();
    assert!(error.downcast_ref::<LegacyCredentialDeferred>().is_none());
}

#[test]
fn pending_grant_and_revocation_are_atomic_tombstones_and_exact_import_preserves_them() {
    let fixture = Fixture::pending();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let original = PendingLegacy::from_contents(&access.load().unwrap().2)
        .unwrap()
        .unwrap();
    access
        .write(QUICKSAVE_VAULT_SERVICE, "authority.synthetic", "new-nonce")
        .unwrap();
    access
        .delete(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap();
    let (_, _, contents) = access.load().unwrap();
    let pending = PendingLegacy::from_contents(&contents).unwrap().unwrap();
    assert_eq!(pending.all_accounts(), original.all_accounts());
    assert_eq!(
        pending.remaining(),
        &[crate::REPOSITORY_KEY_ACCOUNT.to_string()]
    );
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_none());
    let wrong = BTreeMap::from([
        ("authority.synthetic".into(), "old-nonce".into()),
        ("provider.synthetic".into(), "old-token".into()),
        (
            crate::REPOSITORY_KEY_ACCOUNT.into(),
            "retained-master-key".into(),
        ),
    ]);
    let before = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    assert!(access.complete_legacy_import(&wrong).is_err());
    assert_eq!(locked.read().unwrap().unwrap(), before);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
    let revision = access.read_anchor().unwrap().revision;
    access
        .complete_legacy_import(&BTreeMap::from([(
            crate::REPOSITORY_KEY_ACCOUNT.into(),
            "retained-master-key".into(),
        )]))
        .unwrap();
    assert_eq!(access.read_anchor().unwrap().revision, revision + 1);
    assert_eq!(
        fixture.vault.access_log().unwrap()["writes"]
            .as_array()
            .unwrap()
            .len(),
        writes.as_array().unwrap().len() + 1
    );
    assert!(PendingLegacy::from_contents(&access.load().unwrap().2)
        .unwrap()
        .is_none());
    assert_eq!(
        access
            .read(QUICKSAVE_VAULT_SERVICE, "authority.synthetic")
            .unwrap()
            .unwrap()
            .as_str(),
        "new-nonce"
    );
    assert!(access
        .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        .unwrap()
        .is_none());
    assert_eq!(
        access
            .read(QUICKSAVE_VAULT_SERVICE, crate::REPOSITORY_KEY_ACCOUNT)
            .unwrap()
            .unwrap()
            .as_str(),
        "retained-master-key"
    );
    assert!(access.complete_legacy_import(&wrong).is_err());
    assert!(access.complete_legacy_import(&BTreeMap::new()).is_err());
}

#[test]
fn pending_import_payload_errors_and_reserved_writes_do_not_mutate_anchor() {
    let fixture = Fixture::pending();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    let before = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    for payload in [
        BTreeMap::new(),
        BTreeMap::from([("unknown-source".into(), "unknown-value".into())]),
        BTreeMap::from([(PENDING_LEGACY_ACCOUNT.into(), "{}".into())]),
    ] {
        assert!(access.complete_legacy_import(&payload).is_err());
    }
    assert!(access
        .write(QUICKSAVE_VAULT_SERVICE, PENDING_LEGACY_ACCOUNT, "{}")
        .is_err());
    assert!(access
        .delete(QUICKSAVE_VAULT_SERVICE, PENDING_LEGACY_ACCOUNT)
        .is_err());
    assert_eq!(locked.read().unwrap().unwrap(), before);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
}

#[test]
fn pending_completion_and_delete_keep_manifest_until_native_commit() {
    for complete in [false, true] {
        let fixture = Fixture::pending();
        let locked = fixture.file.lock().unwrap();
        let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
        let before = access.load().unwrap().2;
        let pending = PendingLegacy::from_contents(&before).unwrap().unwrap();
        let payload = pending
            .remaining()
            .iter()
            .map(|name| (name.clone(), "old-value".into()))
            .collect();
        fixture.vault.fail_writes(true).unwrap();
        let result = if complete {
            access.complete_legacy_import(&payload)
        } else {
            access.delete(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
        };
        assert!(result.is_err());
        fixture.vault.fail_writes(false).unwrap();
        let restarted = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
        let observed = PendingLegacy::from_contents(&restarted.load().unwrap().2)
            .unwrap()
            .unwrap();
        assert_eq!(observed.remaining(), pending.remaining());
        assert!(restarted
            .read(QUICKSAVE_VAULT_SERVICE, "provider.synthetic")
            .unwrap_err()
            .downcast_ref::<LegacyCredentialDeferred>()
            .is_some());
    }
}

#[test]
fn malformed_authenticated_pending_manifest_fails_before_any_native_write() {
    let fixture = Fixture::new();
    let locked = fixture.file.lock().unwrap();
    let access = LockedSecretAccess::new(&locked, &fixture.vault, BINDING).unwrap();
    // Simulate authenticated malformed content from an incompatible producer,
    // without weakening the production initialization validation.
    access
        .mutate(|contents| {
            contents.entries.insert(
                PENDING_LEGACY_ACCOUNT.into(),
                r#"{"version":1,"allAccounts":["x"],"remaining":["unknown"]}"#.into(),
            );
            Ok(true)
        })
        .unwrap();
    let before = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    assert!(LockedSecretAccess::new(&locked, &fixture.vault, BINDING).is_err());
    assert!(access.read(QUICKSAVE_VAULT_SERVICE, "absent").is_err());
    assert!(access.complete_legacy_import(&BTreeMap::new()).is_err());
    assert!(access.delete(QUICKSAVE_VAULT_SERVICE, "absent").is_err());
    let frozen = decode_document(&before).unwrap();
    let snapshot =
        SnapshotSecretAccess::new(&frozen, Arc::new(fixture.vault.clone()), BINDING).unwrap();
    assert!(snapshot.read(QUICKSAVE_VAULT_SERVICE, "absent").is_err());
    assert_eq!(locked.read().unwrap().unwrap(), before);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
}

#[test]
fn malformed_pending_initialization_fails_before_file_or_native_mutation() {
    let fixture = Fixture::uninitialized();
    let locked = fixture.file.lock().unwrap();
    let before = locked.read().unwrap().unwrap();
    let writes = fixture.vault.access_log().unwrap()["writes"].clone();
    assert!(LockedSecretAccess::initialize(
        &locked,
        &fixture.vault,
        BINDING,
        VaultContents {
            entries: BTreeMap::from([(PENDING_LEGACY_ACCOUNT.into(), "{}".into())]),
        }
    )
    .is_err());
    assert_eq!(locked.read().unwrap().unwrap(), before);
    assert_eq!(fixture.vault.access_log().unwrap()["writes"], writes);
}
