// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic vaults only. Never construct NativeVault or access the OS vault.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counted {
    backing: MemoryVault,
    calls: AtomicUsize,
}
impl CredentialVault for Counted {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.backing.read(service, account)
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.backing.write(service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.backing.delete(service, account)
    }
}
fn fixture() -> (Arc<Counted>, Arc<SessionVaultGate>) {
    let backing = Arc::new(Counted {
        backing: MemoryVault::default(),
        calls: AtomicUsize::new(0),
    });
    let gate = Arc::new(SessionVaultGate::new(backing.clone()));
    (backing, gate)
}

#[test]
fn one_denied_request_stops_concurrent_and_later_native_dialogs() {
    let (backing, gate) = fixture();
    backing.backing.deny_access(true).unwrap();
    let start = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let gate = gate.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                assert!(gate
                    .read(QUICKSAVE_VAULT_SERVICE, &format!("scope-{index}"))
                    .is_err());
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(backing.calls.load(Ordering::SeqCst), 1);
    backing.backing.deny_access(false).unwrap();
    assert!(gate
        .write(QUICKSAVE_VAULT_SERVICE, "scope", "synthetic")
        .is_err());
    assert!(gate.delete(QUICKSAVE_VAULT_SERVICE, "scope").is_err());
    assert_eq!(backing.calls.load(Ordering::SeqCst), 1);
    // A new session explicitly permits a fresh native authorization attempt.
    let next = SessionVaultGate::new(backing.clone());
    assert!(next
        .read(QUICKSAVE_VAULT_SERVICE, "scope")
        .unwrap()
        .is_none());
    assert_eq!(backing.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn successful_access_never_caches_authority_or_hides_revocation() {
    let (backing, gate) = fixture();
    assert!(gate
        .read(QUICKSAVE_VAULT_SERVICE, "authority")
        .unwrap()
        .is_none());
    backing
        .backing
        .seed(QUICKSAVE_VAULT_SERVICE, "authority", "active")
        .unwrap();
    assert_eq!(
        gate.read(QUICKSAVE_VAULT_SERVICE, "authority")
            .unwrap()
            .unwrap()
            .as_str(),
        "active"
    );
    backing
        .backing
        .seed(QUICKSAVE_VAULT_SERVICE, "authority", "revoked")
        .unwrap();
    assert_eq!(
        gate.read(QUICKSAVE_VAULT_SERVICE, "authority")
            .unwrap()
            .unwrap()
            .as_str(),
        "revoked"
    );
    gate.write(QUICKSAVE_VAULT_SERVICE, "authority", "replacement")
        .unwrap();
    assert_eq!(
        gate.read(QUICKSAVE_VAULT_SERVICE, "authority")
            .unwrap()
            .unwrap()
            .as_str(),
        "replacement"
    );
    gate.delete(QUICKSAVE_VAULT_SERVICE, "authority").unwrap();
    assert!(gate
        .read(QUICKSAVE_VAULT_SERVICE, "authority")
        .unwrap()
        .is_none());
}

#[test]
fn failed_write_is_not_retried_and_source_service_writes_remain_forbidden() {
    let (backing, gate) = fixture();
    assert!(gate.write("not-quicksave", "scope", "synthetic").is_err());
    assert_eq!(backing.calls.load(Ordering::SeqCst), 0);
    backing.backing.fail_writes(true).unwrap();
    assert!(gate
        .write(QUICKSAVE_VAULT_SERVICE, "scope", "synthetic")
        .is_err());
    assert!(gate.read(QUICKSAVE_VAULT_SERVICE, "scope").is_err());
    assert_eq!(backing.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn native_interaction_configuration_only_disables_and_propagates_failure() {
    let mut states = Vec::new();
    configure_no_interaction(|state| {
        states.push(state);
        0
    })
    .unwrap();
    assert_eq!(states, vec![0]);
    assert!(configure_no_interaction(|state| {
        assert_eq!(state, 0);
        -1
    })
    .is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn redacted_status_matches_keyrings_actual_security_framework_error_type() {
    // Pure error construction only. No Keychain API, item, service or account.
    let native = security_framework::base::Error::from_code(-25308);
    let failure =
        NativeVaultFailure::from_keyring(keyring::Error::PlatformFailure(Box::new(native)));
    assert_eq!(failure.os_status, Some(-25308));
    assert!(failure.authorization_required());
    assert!(failure.to_string().contains("-25308"));
}

#[test]
fn approved_migration_cannot_change_old_values_delete_items_or_read_foreign_namespaces() {
    let migration = ApprovedMigrationVault;
    assert!(migration
        .write(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT, "synthetic")
        .unwrap_err()
        .to_string()
        .contains("legacy"));
    assert!(migration
        .delete(QUICKSAVE_VAULT_SERVICE, REPOSITORY_KEY_ACCOUNT)
        .is_err());
    assert!(migration.read("foreign-service", "synthetic").is_err());
    assert!(migration.accounts("foreign-service").is_err());
}
