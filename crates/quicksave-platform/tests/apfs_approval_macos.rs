// SPDX-License-Identifier: GPL-3.0-only
#![cfg(target_os = "macos")]
//! Real native descriptors on isolated files only; no user SSH/app/vault data.
use anyhow::Result;
use quicksave_platform::SafeRoot;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

#[test]
fn approval_proves_disjointness_without_entering_a_denied_protected_subdirectory() -> Result<()> {
    let base = std::env::temp_dir().canonicalize()?;
    let preferred = base.join("opencode");
    let temp = tempfile::tempdir_in(if preferred.is_dir() { preferred } else { base })?;
    let source = temp.path().join("source");
    let protected = temp.path().join("protected");
    let opaque = protected.join("id_rsa");
    fs::create_dir(&source)?;
    fs::create_dir_all(&opaque)?;
    fs::set_permissions(&opaque, fs::Permissions::from_mode(0o000))?;
    let selected = SafeRoot::open(&source)?;
    let excluded = SafeRoot::open(&protected)?;
    let result = selected.overlaps_for_approval(&excluded);
    let census = selected.overlaps_directory_identities(&excluded);
    fs::remove_dir(&opaque)?;
    assert!(!result?);
    if unsafe { libc::geteuid() } != 0 {
        assert!(
            census.is_err(),
            "control must demonstrate a denied directory census"
        );
    }
    assert!(selected.overlaps_for_approval(&selected)?);
    let child = source.join("child");
    fs::create_dir(&child)?;
    let descendant = SafeRoot::open(&child)?;
    assert!(selected.overlaps_for_approval(&descendant)?);
    assert!(descendant.overlaps_for_approval(&selected)?);
    // Do not infer case sensitivity from the platform or compare lowercased
    // strings as authority; use whichever native identities this volume gives.
    let alternate = temp.path().join("SOURCE/CHILD");
    if alternate.exists() {
        let alias = SafeRoot::open(&alternate)?;
        assert!(selected.overlaps_for_approval(&alias)?);
        assert!(alias.overlaps_for_approval(&selected)?);
    }
    let alias = temp.path().join("alias");
    symlink(&protected, &alias)?;
    assert!(SafeRoot::open(&alias).is_err());
    fs::rename(&source, temp.path().join("retained-source"))?;
    assert!(selected.overlaps_for_approval(&excluded).is_err());
    Ok(())
}
