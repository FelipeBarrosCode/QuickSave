// SPDX-License-Identifier: GPL-3.0-only
//! Explicit, read-only inventory of QuickSave's own legacy account ATTRIBUTES.
//! No source account is written/deleted; password data is not requested here.
use super::*;
use core_foundation::{base::TCFType, string::CFString};
use security_framework::{
    item::{ItemClass, ItemSearchOptions, SearchResult},
    os::macos::{
        item::ItemSearchOptionsExt,
        keychain::{SecKeychain, SecPreferencesDomain},
    },
};

pub(super) fn accounts(service: &str) -> Result<Vec<String>> {
    // NativeVault/ApprovedMigrationVault hold the process-wide interaction gate.
    let keychain =
        SecKeychain::default_for_domain(SecPreferencesDomain::User).map_err(|error| {
            NativeVaultFailure {
                os_status: Some(error.code()),
            }
        })?;
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::generic_password())
        .service(service)
        .keychains(&[keychain])
        .load_attributes(true)
        .load_data(false)
        .limit((MAX_VAULT_ACCOUNTS + 1) as i64);
    let results = match search.search() {
        Ok(results) => results,
        Err(error) if error.code() == -25300 => return Ok(Vec::new()),
        Err(error) => {
            return Err(NativeVaultFailure {
                os_status: Some(error.code()),
            }
            .into())
        }
    };
    ensure!(
        results.len() <= MAX_VAULT_ACCOUNTS,
        "credential inventory exceeds limit"
    );
    let mut accounts = std::collections::BTreeSet::new();
    for result in results {
        let SearchResult::Dict(attributes) = result else {
            bail!("native credential inventory returned unsupported attributes");
        };
        ensure!(
            attributes.len() <= 64,
            "native credential attribute limit exceeded"
        );
        let (keys, values) = attributes.get_keys_and_values();
        let mut account = None;
        for (key, value) in keys.iter().zip(values.iter()) {
            // SAFETY: returned dictionary owns each borrowed CF object; types
            // are checked before constructing typed borrowed wrappers.
            unsafe {
                if core_foundation::base::CFGetTypeID(*key) != CFString::type_id() {
                    continue;
                }
                let key = CFString::wrap_under_get_rule((*key).cast());
                if key.char_len() != 4 || key.to_string() != "acct" {
                    continue;
                }
                ensure!(
                    core_foundation::base::CFGetTypeID(*value) == CFString::type_id(),
                    "native credential account has unsupported encoding"
                );
                let value = CFString::wrap_under_get_rule((*value).cast());
                ensure!(
                    value.char_len() > 0 && value.char_len() <= 512,
                    "native credential account exceeds limit"
                );
                let text = value.to_string();
                ensure!(
                    text.len() <= 512 && !text.chars().any(char::is_control),
                    "native credential account is invalid"
                );
                account = Some(text);
            }
        }
        let account =
            account.ok_or_else(|| anyhow::anyhow!("native credential account missing"))?;
        ensure!(
            accounts.insert(account),
            "ambiguous duplicate native credential account"
        );
    }
    Ok(accounts.into_iter().collect())
}
