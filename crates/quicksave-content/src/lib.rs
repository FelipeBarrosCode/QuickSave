// SPDX-License-Identifier: GPL-3.0-only
// Derived algorithm provenance and upstream license ambiguity: see PROVENANCE.md.

//! Native-independent, bounded content processing for a new QuickSave repository.
//!
//! Filesystem confinement, stable-file capture and durable publication belong to
//! the caller. This crate only consumes a [`std::io::Read`] or borrowed bytes.
//! Its authenticated envelope is **not** an upstream No Land repository format.

#![forbid(unsafe_code)]

mod chunker;
mod envelope;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use chunker::{
    chunk_reader, FASTCDC_AVG, FASTCDC_MAX, FASTCDC_MIN, MAX_CHUNKS_PER_FILE, MAX_FILE_BYTES,
    SMALL_FILE_THRESHOLD,
};
pub use envelope::{
    open, seal, ENVELOPE_HEADER_LEN, ENVELOPE_ID_LEN, MAX_CIPHERTEXT, MAX_CONTEXT_LEN,
    MAX_PLAINTEXT, MAX_RECORD_PLAINTEXT, NONCE_LEN, RECORD_HEADER_LEN, TAG_LEN,
};

/// Secret repository key, deliberately without `Debug`, `Clone` or serde traits.
///
/// The owned key is wiped by `zeroize` on drop. [`Self::as_bytes`] is an explicit
/// recovery-key export: callers must protect and wipe any copies they create.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RepositoryKey([u8; 32]);

impl RepositoryKey {
    /// Generate a key from the operating system CSPRNG.
    ///
    /// As required by this infallible API, unavailable system entropy panics
    /// rather than falling back to an insecure or deterministic key.
    pub fn generate() -> Self {
        let mut key = Self([0; 32]);
        rand::rngs::OsRng.fill_bytes(&mut key.0);
        key
    }

    /// Import an explicitly supplied recovery key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Explicitly expose key bytes for protected, external recovery-key storage.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable manifest representation; hashes address the uncompressed plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub hash: String,
    pub size: u64,
}

/// BLAKE3 content address in the upstream `blake3:<64 lowercase hex>` spelling.
pub fn hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(
        RepositoryKey: std::fmt::Debug, Clone, Copy, Serialize, serde::de::DeserializeOwned
    );
    static_assertions::assert_impl_all!(RepositoryKey: Zeroize, ZeroizeOnDrop, Send, Sync);

    #[test]
    fn explicit_key_import_export_and_zeroize() {
        let mut key = RepositoryKey::from_bytes([0xa5; 32]);
        assert_eq!(key.as_bytes(), &[0xa5; 32]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0; 32]);
    }

    #[test]
    fn generated_keys_are_not_constant() {
        let first = RepositoryKey::generate();
        let second = RepositoryKey::generate();
        // Do not include key bytes in a failed assertion's diagnostics.
        assert!(first.as_bytes() != &[0; 32]);
        assert!(first.as_bytes() != second.as_bytes());
    }

    #[test]
    fn stable_chunk_json_and_content_address() {
        let chunk = Chunk {
            hash: hash(b"abc"),
            size: 3,
        };
        assert_eq!(
            chunk.hash,
            "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        let json = serde_json::to_string(&chunk).unwrap();
        assert_eq!(json, format!(r#"{{"hash":"{}","size":3}}"#, chunk.hash));
        assert_eq!(serde_json::from_str::<Chunk>(&json).unwrap(), chunk);
        assert_ne!(hash(b"abc"), hash(b"abd"));
    }
}
