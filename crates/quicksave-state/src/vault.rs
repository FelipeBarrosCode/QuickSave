// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{bail, ensure, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

pub const QUICKSAVE_VAULT_SERVICE: &str = "quicksave.desktop-secrets.v1";
pub const REPOSITORY_KEY_ACCOUNT: &str = "QuickSaveRepoMasterKey";
pub const DEVICE_KEY_ACCOUNT: &str = "QuickSaveAutosaveDeviceKey";
pub const MAX_VAULT_VALUE_BYTES: usize = 8 * 1024 * 1024;

/// Inject both QuickSave storage and read-only legacy lookup. Implementations
/// must never log values. No Debug bound and no secret-bearing error details.
pub trait CredentialVault: Send + Sync {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>>;
    fn write(&self, service: &str, account: &str, value: &str) -> Result<()>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
}

/// Construction does not read any item or touch native account state.
pub struct NativeVault;

impl NativeVault {
    #[cfg(all(
        not(test),
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        // Do not include an OS error string that could carry account/value data.
        keyring::Entry::new(service, account)
            .map_err(|_| anyhow::anyhow!("native credential vault is unavailable"))
    }
}

impl CredentialVault for NativeVault {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
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
                Err(_) => bail!("native credential vault access was denied or failed"),
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

    fn write(&self, service: &str, account: &str, value: &str) -> Result<()> {
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
                .map_err(|_| anyhow::anyhow!("native credential vault write failed"))?;
            let verified = self.read(service, account)?;
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

    fn delete(&self, service: &str, account: &str) -> Result<()> {
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
                Err(_) => bail!("native credential vault deletion failed"),
            }
            ensure!(
                self.read(service, account)?.is_none(),
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
