// SPDX-License-Identifier: GPL-3.0-only
//! Authenticated migration control data, stored inside the encrypted entry map.
use crate::{
    encrypted_vault::{VaultContents, MAX_PLAINTEXT},
    secret_store::ENCRYPTED_VAULT_ACCOUNT,
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const PENDING_LEGACY_ACCOUNT: &str = "__quicksave_legacy_pending_v1";
const MAX_ACCOUNTS: usize = 4096;

/// Absence is not permission to generate a replacement for a deferred secret.
#[derive(Debug)]
pub(crate) struct LegacyCredentialDeferred;

impl std::fmt::Display for LegacyCredentialDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("legacy credential is deferred; explicit credential import is required")
    }
}

impl std::error::Error for LegacyCredentialDeferred {}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingLegacy {
    version: u32,
    #[serde(deserialize_with = "deserialize_accounts")]
    all_accounts: Vec<String>,
    #[serde(deserialize_with = "deserialize_accounts")]
    remaining: Vec<String>,
}

fn deserialize_accounts<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AccountsVisitor;
    impl<'de> serde::de::Visitor<'de> for AccountsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded sorted list of unique legacy account names")
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut accounts: Vec<String> = Vec::new();
            while let Some(account) = sequence.next_element::<String>()? {
                if accounts.len() >= MAX_ACCOUNTS
                    || !valid_account(&account)
                    || accounts.last().is_some_and(|previous| previous >= &account)
                {
                    return Err(serde::de::Error::custom(
                        "invalid pending legacy account list",
                    ));
                }
                accounts.push(account);
            }
            Ok(accounts)
        }
    }
    deserializer.deserialize_seq(AccountsVisitor)
}

fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 512
        && !account.chars().any(char::is_control)
        && account != PENDING_LEGACY_ACCOUNT
        && account != ENCRYPTED_VAULT_ACCOUNT
}

impl PendingLegacy {
    pub(crate) fn new(mut all_accounts: Vec<String>, mut remaining: Vec<String>) -> Result<Self> {
        ensure!(
            all_accounts.len() <= MAX_ACCOUNTS && remaining.len() <= MAX_ACCOUNTS,
            "pending legacy account limit exceeded"
        );
        all_accounts.sort();
        remaining.sort();
        let manifest = Self {
            version: 1,
            all_accounts,
            remaining,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported pending legacy manifest version"
        );
        for accounts in [&self.all_accounts, &self.remaining] {
            ensure!(
                accounts.len() <= MAX_ACCOUNTS,
                "pending legacy account limit exceeded"
            );
            ensure!(
                accounts.windows(2).all(|pair| pair[0] < pair[1]),
                "pending legacy accounts must be sorted and unique"
            );
            for account in accounts {
                ensure!(valid_account(account), "invalid pending legacy account");
            }
        }
        ensure!(
            self.remaining
                .iter()
                .all(|account| self.all_accounts.binary_search(account).is_ok()),
            "pending legacy account is absent from original inventory"
        );
        Ok(())
    }

    pub(crate) fn from_contents(contents: &VaultContents) -> Result<Option<Self>> {
        let Some(encoded) = contents.entries.get(PENDING_LEGACY_ACCOUNT) else {
            return Ok(None);
        };
        ensure!(
            encoded.len() <= MAX_PLAINTEXT,
            "pending legacy manifest exceeds limit"
        );
        let manifest: Self = serde_json::from_str(encoded)
            .map_err(|_| anyhow::anyhow!("invalid pending legacy manifest"))?;
        manifest.validate()?;
        ensure!(
            manifest
                .remaining
                .iter()
                .all(|account| !contents.entries.contains_key(account)),
            "pending legacy account collides with an imported credential"
        );
        Ok(Some(manifest))
    }

    pub(crate) fn install(&self, contents: &mut VaultContents) -> Result<()> {
        self.validate()?;
        ensure!(
            self.remaining
                .iter()
                .all(|account| !contents.entries.contains_key(account)),
            "pending legacy account collides with an imported credential"
        );
        let encoded = Zeroizing::new(serde_json::to_string(self)?);
        ensure!(
            encoded.len() <= MAX_PLAINTEXT,
            "pending legacy manifest exceeds limit"
        );
        if let Some(mut previous) = contents
            .entries
            .insert(PENDING_LEGACY_ACCOUNT.into(), encoded.to_string())
        {
            previous.zeroize();
        }
        Ok(())
    }

    pub(crate) fn remaining(&self) -> &[String] {
        &self.remaining
    }

    pub(crate) fn all_accounts(&self) -> &[String] {
        &self.all_accounts
    }

    pub(crate) fn remove(&mut self, account: &str) -> bool {
        if let Ok(index) = self
            .remaining
            .binary_search_by(|candidate| candidate.as_str().cmp(account))
        {
            self.remaining.remove(index);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn manifest_validation_is_strict_and_bounded() {
        for encoded in [
            "{}",
            r#"{"version":2,"allAccounts":[],"remaining":[]}"#,
            r#"{"version":1,"allAccounts":[],"remaining":["unknown"]}"#,
            r#"{"version":1,"allAccounts":["b","a"],"remaining":[]}"#,
            r#"{"version":1,"allAccounts":["a","a"],"remaining":[]}"#,
            r#"{"version":1,"allAccounts":["a"],"remaining":["a","a"]}"#,
            r#"{"version":1,"allAccounts":["a\nb"],"remaining":[]}"#,
            r#"{"version":1,"allAccounts":[],"remaining":[],"unknown":true}"#,
            r#"{"version":1,"version":1,"allAccounts":[],"remaining":[]}"#,
        ] {
            let contents = VaultContents {
                entries: BTreeMap::from([(PENDING_LEGACY_ACCOUNT.into(), encoded.into())]),
            };
            assert!(PendingLegacy::from_contents(&contents).is_err());
        }
        for account in [
            "",
            PENDING_LEGACY_ACCOUNT,
            ENCRYPTED_VAULT_ACCOUNT,
            "bad\nname",
        ] {
            assert!(PendingLegacy::new(vec![account.into()], vec![]).is_err());
        }
        assert!(PendingLegacy::new(vec!["x".repeat(513)], vec![]).is_err());
        assert!(
            PendingLegacy::new((0..4097).map(|n| format!("account.{n}")).collect(), vec![])
                .is_err()
        );
        assert!(PendingLegacy::new(vec!["a".into(), "a".into()], vec![]).is_err());
    }

    #[test]
    fn original_inventory_survives_removal_and_pending_collisions_fail_closed() {
        let mut manifest =
            PendingLegacy::new(vec!["b".into(), "a".into()], vec!["b".into(), "a".into()]).unwrap();
        assert!(manifest.remove("a"));
        assert!(!manifest.remove("a"));
        assert_eq!(manifest.all_accounts(), &["a".to_string(), "b".to_string()]);
        let mut contents = VaultContents {
            entries: BTreeMap::from([("a".into(), "new-authority".into())]),
        };
        manifest.install(&mut contents).unwrap();
        assert_eq!(
            PendingLegacy::from_contents(&contents)
                .unwrap()
                .unwrap()
                .remaining(),
            &["b".to_string()]
        );
        contents.entries.insert("b".into(), "collision".into());
        assert!(PendingLegacy::from_contents(&contents).is_err());
        assert!(manifest.install(&mut contents).is_err());
    }
}
