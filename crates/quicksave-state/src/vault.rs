// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{bail, ensure, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
#[path = "vault_gate_tests.rs"]
mod gate_tests;
#[path = "vault_interaction.rs"]
mod interaction;
#[cfg(target_os = "linux")]
#[path = "vault_inventory_linux.rs"]
mod linux_inventory;
#[cfg(all(target_os = "macos", not(test)))]
#[path = "vault_inventory_macos.rs"]
mod macos_inventory;
#[cfg(windows)]
#[path = "vault_inventory_windows.rs"]
mod windows_inventory;

pub const QUICKSAVE_VAULT_SERVICE: &str = "quicksave.desktop-secrets.v1";
pub const REPOSITORY_KEY_ACCOUNT: &str = "QuickSaveRepoMasterKey";
pub const DEVICE_KEY_ACCOUNT: &str = "QuickSaveAutosaveDeviceKey";
pub const MAX_VAULT_VALUE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_VAULT_ACCOUNTS: usize = 4096;

/// Redacted native status only. Never retain a credential, account, native
/// provider error body, or password-bearing backend Debug representation.
#[derive(Clone, Copy, Debug)]
pub struct NativeVaultFailure {
    pub os_status: Option<i32>,
}

impl NativeVaultFailure {
    pub fn authorization_required(&self) -> bool {
        matches!(self.os_status, Some(-25308 | -25293 | -128))
    }

    #[cfg(target_os = "macos")]
    fn from_keyring(error: keyring::Error) -> Self {
        let os_status = match error {
            keyring::Error::PlatformFailure(source) | keyring::Error::NoStorageAccess(source) => {
                source
                    .downcast_ref::<security_framework::base::Error>()
                    .map(|error| error.code())
            }
            _ => None,
        };
        Self { os_status }
    }
}

impl std::fmt::Display for NativeVaultFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.authorization_required() {
            formatter.write_str("Keychain authorization was not granted")?;
        } else {
            formatter.write_str("native credential access failed")?;
        }
        if let Some(status) = self.os_status {
            write!(formatter, " (OS status {status})")?;
        }
        Ok(())
    }
}
impl std::error::Error for NativeVaultFailure {}

#[cfg(all(
    not(test),
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
fn redacted_native_failure(error: keyring::Error) -> anyhow::Error {
    #[cfg(target_os = "macos")]
    return NativeVaultFailure::from_keyring(error).into();
    #[cfg(not(target_os = "macos"))]
    {
        let _ = error;
        NativeVaultFailure { os_status: None }.into()
    }
}

/// Inject both QuickSave storage and read-only legacy lookup. Implementations
/// must never log values. No Debug bound and no secret-bearing error details.
pub trait CredentialVault: Send + Sync {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>>;
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
    /// Complete bounded account inventory for explicit QuickSave migration.
    /// Unsupported implementations must not pretend reachable state refs are
    /// a complete inventory: inactive/recovery authority must be retained too.
    fn accounts(&self, _service: &str) -> Result<Vec<String>> {
        bail!("complete native credential inventory is unsupported")
    }
    /// Pure implementation capability, not a claim of access/unlock.
    fn account_inventory_supported(&self) -> bool {
        false
    }
}

/// Construction does not read any item or touch native account state.
pub struct NativeVault;

/// Serialize native authorization and stop queued/background accesses after a
/// failure. No successful credential or revocation record is cached here.
/// Restart is the explicit retry boundary; cancelling consent must not cause a
/// sequence of further dialogs for every software scope.
pub(crate) struct SessionVaultGate {
    backing: Arc<dyn CredentialVault>,
    blocked: Mutex<bool>,
}

impl SessionVaultGate {
    pub(crate) fn new(backing: Arc<dyn CredentialVault>) -> Self {
        Self {
            backing,
            blocked: Mutex::new(false),
        }
    }

    fn access<T>(&self, operation: impl FnOnce(&dyn CredentialVault) -> Result<T>) -> Result<T> {
        let mut blocked = self
            .blocked
            .lock()
            .map_err(|_| anyhow::anyhow!("native vault authorization gate failed"))?;
        ensure!(!*blocked,
            "native vault access paused after a failed request; restart QuickSave to retry explicitly");
        match operation(self.backing.as_ref()) {
            Ok(value) => Ok(value),
            Err(error) => {
                *blocked = true;
                Err(error)
            }
        }
    }
}

impl CredentialVault for SessionVaultGate {
    fn account_inventory_supported(&self) -> bool {
        self.backing.account_inventory_supported()
    }
    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "only QuickSave inventory is permitted"
        );
        self.access(|vault| vault.accounts(service))
    }
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        self.access(|vault| vault.read(service, account))
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "writes outside QuickSave vault forbidden"
        );
        ensure!(
            value.len() <= MAX_VAULT_VALUE_BYTES,
            "protected credential exceeds size limit"
        );
        self.access(|vault| vault.write(service, account, value))
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "deletes outside QuickSave vault forbidden"
        );
        self.access(|vault| vault.delete(service, account))
    }
}

impl NativeVault {
    #[cfg(all(
        not(test),
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        // Do not include an OS error string that could carry account/value data.
        keyring::Entry::new(service, account).map_err(redacted_native_failure)
    }
}

/// Only called while the process-wide interaction mutex is held.
#[cfg(all(target_os = "macos", not(test)))]
fn set_native_interaction(allowed: bool) -> Result<()> {
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainSetUserInteractionAllowed(state: u8) -> i32;
    }
    if allowed {
        // SAFETY: scalar Boolean, process-local setting; the operation is
        // serialized and a drop guard restores false before releasing the lock.
        ensure!(
            unsafe { SecKeychainSetUserInteractionAllowed(1) } == 0,
            "could not enable explicitly approved native vault authorization"
        );
        Ok(())
    } else {
        configure_no_interaction(|state| unsafe { SecKeychainSetUserInteractionAllowed(state) })
    }
}

#[cfg(not(all(target_os = "macos", not(test))))]
fn set_native_interaction(_allowed: bool) -> Result<()> {
    Ok(())
}

static NATIVE_INTERACTION: interaction::InteractionGate = interaction::InteractionGate::new();

fn native_operation<T>(interactive: bool, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    NATIVE_INTERACTION.run(interactive, set_native_interaction, operation)
}

#[cfg(any(test, target_os = "macos"))]
fn configure_no_interaction(set: impl FnOnce(u8) -> i32) -> Result<()> {
    ensure!(
        set(0) == 0,
        "could not disable interactive native vault requests"
    );
    Ok(())
}

impl CredentialVault for NativeVault {
    fn account_inventory_supported(&self) -> bool {
        cfg!(any(target_os = "macos", target_os = "linux"))
    }
    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        native_operation(false, || Self::accounts_native(service))
    }
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        native_operation(false, || Self::read_native(service, account))
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        native_operation(false, || Self::write_native(service, account, value))
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        native_operation(false, || Self::delete_native(service, account))
    }
}

/// Never exported or used by service startup. Only the native-approved migration
/// entry point constructs this backend; legacy writes/deletion are forbidden.
pub(crate) struct ApprovedMigrationVault;
impl CredentialVault for ApprovedMigrationVault {
    fn account_inventory_supported(&self) -> bool {
        NativeVault.account_inventory_supported()
    }
    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "migration cannot inventory another vault namespace"
        );
        native_operation(true, || NativeVault::accounts_native(service))
    }
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "migration cannot access another vault namespace"
        );
        native_operation(true, || NativeVault::read_native(service, account))
    }
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE
                && account == crate::secret_store::ENCRYPTED_VAULT_ACCOUNT,
            "migration cannot modify a legacy credential"
        );
        native_operation(true, || NativeVault::write_native(service, account, value))
    }
    fn delete(&self, _service: &str, _account: &str) -> Result<()> {
        bail!("migration cannot delete native credentials")
    }
}

impl NativeVault {
    fn accounts_native(service: &str) -> Result<Vec<String>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "only QuickSave inventory is permitted"
        );
        #[cfg(all(target_os = "macos", not(test)))]
        return macos_inventory::accounts(service);
        #[cfg(target_os = "linux")]
        return linux_inventory::accounts(service);
        #[cfg(windows)]
        return windows_inventory::accounts(service);
        #[cfg(not(any(all(target_os = "macos", not(test)), target_os = "linux", windows)))]
        bail!("complete native credential inventory is unsupported on this platform")
    }
    fn read_native(service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            match Self::entry(service, account)?.get_password() {
                Ok(value) => {
                    let value = Zeroizing::new(value);
                    ensure!(
                        value.len() <= MAX_VAULT_VALUE_BYTES,
                        "protected credential exceeds size limit"
                    );
                    Ok(Some(value))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(redacted_native_failure(error)),
            }
        }
        #[cfg(any(
            test,
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            let _ = (service, account);
            bail!("native vault unavailable here; tests must inject MemoryVault")
        }
    }

    fn write_native(service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "writes outside QuickSave vault forbidden"
        );
        ensure!(
            value.len() <= MAX_VAULT_VALUE_BYTES,
            "protected credential exceeds size limit"
        );
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            Self::entry(service, account)?
                .set_password(value)
                .map_err(redacted_native_failure)?;
            let verified = Self::read_native(service, account)?;
            ensure!(
                verified.as_deref().map(|value| value.as_str()) == Some(value),
                "native credential failed read-back verification"
            );
            Ok(())
        }
        #[cfg(any(
            test,
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            let _ = account;
            bail!("native vault unavailable here; tests must inject MemoryVault")
        }
    }

    fn delete_native(service: &str, account: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "deletes outside QuickSave vault forbidden"
        );
        #[cfg(all(
            not(test),
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            match Self::entry(service, account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(redacted_native_failure(error)),
            }
            ensure!(
                Self::read_native(service, account)?.is_none(),
                "credential deletion failed verification"
            );
            Ok(())
        }
        #[cfg(any(
            test,
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            let _ = account;
            bail!("native vault unavailable here; tests must inject MemoryVault")
        }
    }
}

/// Explicit in-memory test/development injection. Never delegates to OS keyring.
#[derive(Clone, Default)]
pub struct MemoryVault {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<(String, String), Zeroizing<String>>,
    reads: Vec<(String, String)>,
    writes: Vec<(String, String)>,
    denied: bool,
    fail_writes: bool,
}

impl Drop for MemoryState {
    fn drop(&mut self) {
        for value in self.values.values_mut() {
            value.zeroize();
        }
    }
}

impl MemoryVault {
    /// Seed a synthetic source vault without recording a runtime write.
    pub fn seed(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            value.len() <= MAX_VAULT_VALUE_BYTES,
            "test vault entry exceeds limit"
        );
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?
            .values
            .insert(
                (service.into(), account.into()),
                Zeroizing::new(value.into()),
            );
        Ok(())
    }

    pub fn access_log(&self) -> Result<serde_json::Value> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?;
        Ok(serde_json::json!({"reads": inner.reads, "writes": inner.writes}))
    }

    pub fn deny_access(&self, denied: bool) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?
            .denied = denied;
        Ok(())
    }

    pub fn fail_writes(&self, fail: bool) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?
            .fail_writes = fail;
        Ok(())
    }
}

impl CredentialVault for MemoryVault {
    fn account_inventory_supported(&self) -> bool {
        true
    }
    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "only QuickSave inventory is permitted"
        );
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?;
        ensure!(!inner.denied, "test vault access denied");
        let accounts = inner
            .values
            .keys()
            .filter(|(owner, _)| owner == service)
            .map(|(_, account)| account.clone())
            .take(MAX_VAULT_ACCOUNTS + 1)
            .collect::<Vec<_>>();
        ensure!(
            accounts.len() <= MAX_VAULT_ACCOUNTS,
            "credential inventory exceeds limit"
        );
        Ok(accounts)
    }
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?;
        ensure!(!inner.denied, "test vault access denied");
        ensure!(inner.reads.len() < 100_000, "test vault access log limit");
        inner.reads.push((service.into(), account.into()));
        Ok(inner.values.get(&(service.into(), account.into())).cloned())
    }

    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "writes outside QuickSave vault forbidden"
        );
        ensure!(
            value.len() <= MAX_VAULT_VALUE_BYTES,
            "protected credential exceeds size limit"
        );
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?;
        ensure!(
            !inner.denied && !inner.fail_writes,
            "test vault write denied"
        );
        ensure!(inner.writes.len() < 100_000, "test vault access log limit");
        inner.writes.push((service.into(), account.into()));
        inner.values.insert(
            (service.into(), account.into()),
            Zeroizing::new(value.into()),
        );
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        ensure!(
            service == QUICKSAVE_VAULT_SERVICE,
            "deletes outside QuickSave vault forbidden"
        );
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("test vault lock poisoned"))?;
        ensure!(
            !inner.denied && !inner.fail_writes,
            "test vault deletion denied"
        );
        ensure!(inner.writes.len() < 100_000, "test vault access log limit");
        inner.writes.push((service.into(), account.into()));
        inner.values.remove(&(service.into(), account.into()));
        Ok(())
    }
}
