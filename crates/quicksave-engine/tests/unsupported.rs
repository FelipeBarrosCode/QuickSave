// SPDX-License-Identifier: GPL-3.0-only
#![cfg(not(any(target_os = "macos", target_os = "linux")))]

#[test]
fn unsupported_durable_mutations_are_not_reported_as_success() {
    let temporary = tempfile::tempdir().unwrap();
    let repository = temporary.path().join("repository");
    let key = quicksave_engine::RepositoryKey::from_bytes([0x5a; 32]);
    assert!(quicksave_engine::initialize_with_key(&repository, &key).is_err());
    assert!(!repository.exists());
}
