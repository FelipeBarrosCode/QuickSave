// SPDX-License-Identifier: GPL-3.0-only
//! AEAD codec only. The external native anchor, not state.json, must supply the
//! expected revision and envelope digest before any decrypted entry is trusted.
use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"QuickSave/state-vault/xchacha20poly1305/v1\0";
pub(crate) const MAX_PLAINTEXT: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultContents {
    #[serde(deserialize_with = "deserialize_entries")]
    pub entries: BTreeMap<String, String>,
}

fn deserialize_entries<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Guard(BTreeMap<String, String>);
    impl Drop for Guard {
        fn drop(&mut self) {
            for value in self.0.values_mut() {
                value.zeroize();
            }
        }
    }
    struct EntriesVisitor;
    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded map of unique encrypted vault accounts")
        }
        fn visit_map<M>(self, mut input: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut entries = Guard(BTreeMap::new());
            let mut total = 0usize;
            while let Some((account, mut value)) = input.next_entry::<String, String>()? {
                let size = total
                    .checked_add(account.len())
                    .and_then(|n| n.checked_add(value.len()));
                if entries.0.len() >= MAX_ENTRIES
                    || entries.0.contains_key(&account)
                    || account.is_empty()
                    || account.len() > 512
                    || account.chars().any(char::is_control)
                    || size.is_none_or(|size| size > MAX_PLAINTEXT)
                {
                    value.zeroize();
                    return Err(serde::de::Error::custom(
                        "invalid or duplicate encrypted vault account",
                    ));
                }
                total = size.unwrap();
                entries.0.insert(account, value);
            }
            Ok(std::mem::take(&mut entries.0))
        }
    }
    deserializer.deserialize_map(EntriesVisitor)
}

impl Drop for VaultContents {
    fn drop(&mut self) {
        for value in self.entries.values_mut() {
            value.zeroize();
        }
    }
}

impl VaultContents {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.entries.len() <= MAX_ENTRIES,
            "encrypted vault entry limit exceeded"
        );
        let mut total = 0usize;
        for (account, value) in &self.entries {
            ensure!(
                !account.is_empty()
                    && account.len() <= 512
                    && !account.chars().any(char::is_control),
                "invalid encrypted vault account"
            );
            ensure!(
                value.len() <= MAX_PLAINTEXT,
                "encrypted vault value exceeds limit"
            );
            total = total
                .checked_add(account.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or_else(|| anyhow::anyhow!("encrypted vault size overflow"))?;
            ensure!(
                total <= MAX_PLAINTEXT,
                "encrypted vault content exceeds limit"
            );
        }
        Ok(())
    }
}

/// Ciphertext is safe to serialize, but never expose it through the webview DTO.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncryptedVault {
    pub version: u32,
    pub algorithm: String,
    pub revision: u64,
    pub nonce: String,
    pub ciphertext: String,
}

impl EncryptedVault {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.algorithm == "xchacha20poly1305",
            "unsupported encrypted vault format"
        );
        ensure!(
            self.revision > 0
                && self.nonce.len() == 48
                && self.ciphertext.len() >= 32
                && self.ciphertext.len() <= 2 * (MAX_PLAINTEXT + 16)
                && self.ciphertext.len().is_multiple_of(2),
            "invalid encrypted vault bounds"
        );
        ensure!(
            self.nonce
                .bytes()
                .chain(self.ciphertext.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid encrypted vault encoding"
        );
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.version.to_le_bytes());
        digest.update(self.revision.to_le_bytes());
        digest.update(self.nonce.as_bytes());
        digest.update(self.ciphertext.as_bytes());
        Ok(digest.finalize().into())
    }

    pub fn seal(
        key: &[u8; 32],
        workspace_binding: &[u8; 32],
        revision: u64,
        contents: &VaultContents,
    ) -> Result<Self> {
        ensure!(revision > 0, "invalid encrypted vault revision");
        contents.validate()?;
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(contents)
                .map_err(|_| anyhow::anyhow!("encrypted vault encoding failed"))?,
        );
        ensure!(
            plaintext.len() <= MAX_PLAINTEXT,
            "encrypted vault encoding exceeds limit"
        );
        let mut nonce = [0u8; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| anyhow::anyhow!("secure vault randomness unavailable"))?;
        let aad = aad(workspace_binding, revision);
        XChaCha20Poly1305::new(key.into())
            .encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut *plaintext)
            .map_err(|_| anyhow::anyhow!("encrypted vault sealing failed"))?;
        Ok(Self {
            version: 1,
            algorithm: "xchacha20poly1305".into(),
            revision,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(plaintext.as_slice()),
        })
    }

    pub fn open(
        &self,
        key: &[u8; 32],
        workspace_binding: &[u8; 32],
        expected_revision: u64,
        expected_digest: &[u8; 32],
    ) -> Result<VaultContents> {
        ensure!(
            self.revision == expected_revision && &self.digest()? == expected_digest,
            "encrypted vault does not match the native anchor"
        );
        let nonce = hex::decode(&self.nonce)
            .map_err(|_| anyhow::anyhow!("encrypted vault nonce invalid"))?;
        let mut plaintext = Zeroizing::new(
            hex::decode(&self.ciphertext)
                .map_err(|_| anyhow::anyhow!("encrypted vault encoding invalid"))?,
        );
        XChaCha20Poly1305::new(key.into())
            .decrypt_in_place(
                XNonce::from_slice(&nonce),
                &aad(workspace_binding, self.revision),
                &mut *plaintext,
            )
            .map_err(|_| anyhow::anyhow!("encrypted vault authentication failed"))?;
        let contents: VaultContents = serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("encrypted vault contents invalid"))?;
        contents.validate()?;
        Ok(contents)
    }
}

fn aad(binding: &[u8; 32], revision: u64) -> Vec<u8> {
    [
        DOMAIN,
        binding.as_slice(),
        revision.to_le_bytes().as_slice(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents() -> VaultContents {
        VaultContents {
            entries: BTreeMap::from([
                (
                    "device-key".into(),
                    "synthetic-secret-never-plaintext".into(),
                ),
                ("authority".into(), "{\"active\":false}".into()),
            ]),
        }
    }

    #[test]
    fn roundtrip_is_randomized_and_serializes_no_plaintext() {
        let first = EncryptedVault::seal(&[7; 32], &[8; 32], 1, &contents()).unwrap();
        let second = EncryptedVault::seal(&[7; 32], &[8; 32], 1, &contents()).unwrap();
        assert_ne!(first.nonce, second.nonce);
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("synthetic-secret"));
        assert!(!encoded.contains("device-key"));
        let decoded: EncryptedVault = serde_json::from_str(&encoded).unwrap();
        let recovered = decoded
            .open(&[7; 32], &[8; 32], 1, &first.digest().unwrap())
            .unwrap();
        assert_eq!(recovered.entries, contents().entries);
    }

    #[test]
    fn wrong_key_workspace_revision_tampering_and_rollback_fail_closed() {
        let first = EncryptedVault::seal(&[7; 32], &[8; 32], 1, &contents()).unwrap();
        let digest = first.digest().unwrap();
        assert!(first.open(&[6; 32], &[8; 32], 1, &digest).is_err());
        assert!(first.open(&[7; 32], &[9; 32], 1, &digest).is_err());
        assert!(first.open(&[7; 32], &[8; 32], 2, &digest).is_err());
        let second = EncryptedVault::seal(&[7; 32], &[8; 32], 2, &contents()).unwrap();
        assert!(first
            .open(&[7; 32], &[8; 32], 2, &second.digest().unwrap())
            .is_err());
        let mut tampered = first.clone();
        tampered.ciphertext.replace_range(
            ..1,
            if &first.ciphertext[..1] == "0" {
                "1"
            } else {
                "0"
            },
        );
        assert!(tampered.open(&[7; 32], &[8; 32], 1, &digest).is_err());
        // Even a forged local digest cannot replace native AEAD authentication.
        assert!(tampered
            .open(&[7; 32], &[8; 32], 1, &tampered.digest().unwrap())
            .is_err());
    }

    #[test]
    fn oversized_and_noncanonical_envelopes_are_rejected_before_decrypt() {
        let mut vault = EncryptedVault::seal(&[7; 32], &[8; 32], 1, &contents()).unwrap();
        vault.algorithm = "plaintext".into();
        assert!(vault.validate().is_err());
        vault.algorithm = "xchacha20poly1305".into();
        vault.nonce = "A".repeat(48);
        assert!(vault.validate().is_err());
        vault.nonce = "0".repeat(48);
        vault.ciphertext = "0".repeat(2 * (MAX_PLAINTEXT + 17));
        assert!(vault.validate().is_err());
    }

    #[test]
    fn duplicate_plaintext_accounts_are_not_silently_overwritten() {
        assert!(serde_json::from_str::<VaultContents>(
            r#"{"entries":{"authority":"active","authority":"revoked"}}"#
        )
        .is_err());
    }
}
