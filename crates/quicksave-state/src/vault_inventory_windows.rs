// SPDX-License-Identifier: GPL-3.0-only
//! Fail closed: Windows cannot provide the bounded, service-only legacy scan.
//!
//! Format verified against keyring 3.6.3 `src/windows.rs`,
//! `WinCredential::new_with_target(None, service, user)`: `user.service`.
//! CredEnumerateW accepts only a *prefix* followed by `*`, not a suffix
//! filter. It also allocates the entire result (including secret blobs) before
//! reporting its count, with no caller-supplied allocation/result limit.
//! Consequently neither `*.service` nor an all-credentials scan can satisfy
//! this migration's service confinement and native input bounds. Do not fall
//! back to current-state references: inactive recovery/provider items matter.

pub(super) fn accounts(service: &str) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        service == super::QUICKSAVE_VAULT_SERVICE,
        "only QuickSave inventory is permitted"
    );
    anyhow::bail!(
        "complete bounded QuickSave legacy inventory is unsupported on Windows: \
         Credential Manager has no service-suffix filter or bounded enumeration; \
         legacy credentials were not read or changed"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_without_touching_native_credentials() {
        let error = accounts(super::super::QUICKSAVE_VAULT_SERVICE).unwrap_err();
        assert!(error.to_string().contains("unsupported on Windows"));
        assert!(accounts("foreign.service").is_err());
    }

    #[test]
    fn keyring_default_target_is_account_first_not_service_first() {
        // Construction only; does not call any native credential API.
        let credential = keyring::windows::WinCredential::new_with_target(
            None,
            super::super::QUICKSAVE_VAULT_SERVICE,
            "inactive.recovery",
        )
        .unwrap();
        assert_eq!(
            credential.target_name,
            format!(
                "inactive.recovery.{}",
                super::super::QUICKSAVE_VAULT_SERVICE
            )
        );
    }
}
