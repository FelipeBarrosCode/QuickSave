// SPDX-License-Identifier: GPL-3.0-only
//! Approval censuses deliberately do not reuse capture metadata enumeration.
//! A negative answer needs directory topology, not payload readability, link
//! targets, file timestamps, or a claim that the application is stable.

use crate::{
    DirectoryIdentity, DirectoryIdentityInspectionFailure, DirectoryIdentityInspectionSide,
    DirectoryIdentityInspectionStage, MAX_PATH_BYTES, MAX_TREE_ENTRIES, MAX_TREE_PATH_BYTES,
};
use anyhow::{ensure, Context, Result};
use std::{collections::BTreeSet, path::PathBuf};

#[cfg(unix)]
type NativeRoot = crate::unix::Root;
#[cfg(windows)]
type NativeRoot = crate::windows::Root;

// Separate, explicit limits keep the recorded inventory and the native
// before/after child lists bounded even for file-heavy protected repositories.
// File names are counted for work limits but are never retained in this index.
const MAX_DIRECTORIES: usize = 131_072;
const MAX_DIRECTORY_PATH_BYTES: usize = 32 * 1024 * 1024;

/// Private native-location context, transferred to the public typed failure by
/// the approval boundary. No caller reconstructs it from formatted diagnostics.
#[derive(Debug)]
struct CensusLocation {
    relative_path: PathBuf,
}

impl std::fmt::Display for CensusLocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "directory-identity native location {:?}",
            self.relative_path
        )
    }
}

impl std::error::Error for CensusLocation {}

pub(crate) fn with_census_location<T>(result: Result<T>, relative: &[u8]) -> Result<T> {
    if relative.is_empty() {
        return result;
    }
    #[cfg(unix)]
    let relative_path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(relative.to_vec()))
    };
    // The Windows visitor produces UTF-8 from validated native directory names.
    // An unavailable encoding must not be replaced with an invented lossy path.
    #[cfg(windows)]
    let relative_path = match std::str::from_utf8(relative) {
        Ok(relative) => PathBuf::from(relative),
        Err(_) => return result,
    };
    result.with_context(|| CensusLocation { relative_path })
}

pub(crate) fn failure_relative_path(error: &anyhow::Error) -> Option<PathBuf> {
    error
        .downcast_ref::<CensusLocation>()
        .map(|location| location.relative_path.clone())
}

#[derive(Default)]
pub(crate) struct CensusBudget {
    entries: usize,
    name_bytes: usize,
    directories: usize,
    directory_path_bytes: usize,
}

impl CensusBudget {
    pub(crate) fn entry(&mut self, prefix_bytes: usize, name_bytes: usize) -> Result<()> {
        let relative_bytes = prefix_bytes
            .checked_add(usize::from(prefix_bytes != 0))
            .and_then(|length| length.checked_add(name_bytes))
            .context("directory-identity name length overflow")?;
        self.entries = self
            .entries
            .checked_add(1)
            .context("directory-identity entry count overflow")?;
        self.name_bytes = self
            .name_bytes
            .checked_add(relative_bytes)
            .context("directory-identity name budget overflow")?;
        ensure!(
            self.entries <= MAX_TREE_ENTRIES && self.name_bytes <= MAX_TREE_PATH_BYTES,
            "directory-identity census exceeds bounded entry/name work limit"
        );
        Ok(())
    }

    pub(crate) fn directory(&mut self, relative_bytes: usize) -> Result<()> {
        ensure!(
            relative_bytes <= MAX_PATH_BYTES,
            "directory-identity relative path exceeds its bound"
        );
        self.directories = self
            .directories
            .checked_add(1)
            .context("directory-identity directory count overflow")?;
        self.directory_path_bytes = self
            .directory_path_bytes
            .checked_add(relative_bytes)
            .context("directory-identity path budget overflow")?;
        ensure!(
            self.directories < MAX_DIRECTORIES
                && self.directory_path_bytes <= MAX_DIRECTORY_PATH_BYTES,
            "directory-identity census exceeds bounded directory inventory limit"
        );
        Ok(())
    }
}

struct Observation {
    relative: Vec<u8>,
    identity: DirectoryIdentity,
}

struct Inventory {
    directories: Vec<Observation>,
}

impl Inventory {
    fn record(root: &NativeRoot) -> Result<Self> {
        let mut directories = Vec::new();
        root.visit_directory_identities(&mut |relative, identity| {
            ensure!(
                directories.len() < MAX_DIRECTORIES,
                "directory-identity census exceeds bounded directory inventory limit"
            );
            directories.push(Observation {
                relative: relative.to_vec(),
                identity,
            });
            Ok(())
        })?;
        Ok(Self { directories })
    }

    fn verify(&self, root: &NativeRoot) -> Result<()> {
        let mut index = 0;
        root.visit_directory_identities(&mut |relative, identity| {
            let before = self.directories.get(index).with_context(|| {
                format!(
                    "directory added during identity approval at {:?}",
                    String::from_utf8_lossy(relative)
                )
            })?;
            ensure!(
                before.relative == relative && before.identity == identity,
                "directory namespace changed during identity approval: expected {:?}, observed {:?}",
                String::from_utf8_lossy(&before.relative),
                String::from_utf8_lossy(relative)
            );
            index += 1;
            Ok(())
        })?;
        if let Some(missing) = self.directories.get(index) {
            return with_census_location(
                Err(anyhow::anyhow!(
                    "directory removed during identity approval at {:?}",
                    String::from_utf8_lossy(&missing.relative)
                )),
                &missing.relative,
            );
        }
        Ok(())
    }
}

pub(crate) fn directory_identities(
    root: &NativeRoot,
    side: DirectoryIdentityInspectionSide,
) -> Result<BTreeSet<DirectoryIdentity>> {
    let inventory = DirectoryIdentityInspectionFailure::attach(
        Inventory::record(root),
        side,
        DirectoryIdentityInspectionStage::RecordDirectories,
    )?;
    // Verify against the existing inventory rather than allocating a second
    // tree. Native visitors also check each directory's before/open/after edge
    // and its directory children before/after descending.
    DirectoryIdentityInspectionFailure::attach(
        inventory.verify(root),
        side,
        DirectoryIdentityInspectionStage::VerifyDirectories,
    )?;
    Ok(inventory
        .directories
        .into_iter()
        .map(|directory| directory.identity)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_inspection_context_survives_caller_context_and_preserves_native_cause() {
        use DirectoryIdentityInspectionSide::{Protected, Selected};
        use DirectoryIdentityInspectionStage::*;
        for side in [Selected, Protected] {
            for stage in [
                ValidatePinnedRoot,
                RecordDirectories,
                VerifyDirectories,
                RevalidateRootIdentity,
                RevalidatePinnedRoot,
                UnsupportedPlatform,
            ] {
                let original: Result<()> =
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
                let error = DirectoryIdentityInspectionFailure::attach(original, side, stage)
                    .unwrap_err()
                    .context("caller-owned approval label");
                let failure = error
                    .downcast_ref::<DirectoryIdentityInspectionFailure>()
                    .expect("typed context must survive caller context");
                assert_eq!(failure.side, side);
                assert_eq!(failure.stage, stage);
                assert_eq!(failure.relative_path, None);
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        }
    }

    #[test]
    fn census_location_is_typed_and_keeps_native_relative_path_encoding() {
        let mut relative = b"native/".to_vec();
        #[cfg(unix)]
        relative.push(0xff);
        #[cfg(windows)]
        relative.extend_from_slice("directory".as_bytes());
        let original: Result<()> = Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        let error = DirectoryIdentityInspectionFailure::attach(
            with_census_location(original, &relative),
            DirectoryIdentityInspectionSide::Protected,
            DirectoryIdentityInspectionStage::RecordDirectories,
        )
        .unwrap_err()
        .context("caller-owned approval label");
        let failure = error
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .unwrap();
        assert_eq!(failure.side, DirectoryIdentityInspectionSide::Protected);
        assert_eq!(
            failure.stage,
            DirectoryIdentityInspectionStage::RecordDirectories
        );
        let path = failure.relative_path.as_ref().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(path.as_os_str().as_bytes(), relative);
        }
        #[cfg(windows)]
        assert_eq!(path, &PathBuf::from("native/directory"));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn directory_inventory_limits_fail_before_an_unbounded_allocation() {
        let mut count = CensusBudget {
            entries: MAX_TREE_ENTRIES,
            ..CensusBudget::default()
        };
        assert!(count.entry(0, 1).is_err());
        let mut names = CensusBudget {
            name_bytes: MAX_TREE_PATH_BYTES,
            ..CensusBudget::default()
        };
        assert!(names.entry(0, 1).is_err());
        let mut directories = CensusBudget {
            directories: MAX_DIRECTORIES - 1,
            ..CensusBudget::default()
        };
        assert!(directories.directory(1).is_err());
        let mut paths = CensusBudget {
            directory_path_bytes: MAX_DIRECTORY_PATH_BYTES,
            ..CensusBudget::default()
        };
        assert!(paths.directory(1).is_err());
        assert!(CensusBudget::default()
            .directory(MAX_PATH_BYTES + 1)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_and_addition_fail_but_file_churn_does_not() -> Result<()> {
        use std::{fs, os::unix::fs::symlink};
        let base = fs::canonicalize(std::env::temp_dir())?;
        let preferred = base.join("opencode");
        let base = if preferred.is_dir() {
            fs::canonicalize(preferred)?
        } else {
            base
        };
        let temp = tempfile::Builder::new()
            .prefix("quicksave-directory-census-")
            .tempdir_in(base)?;
        let selected = temp.path().join("selected");
        fs::create_dir_all(selected.join("child"))?;
        fs::write(selected.join("payload"), b"before")?;
        let root = NativeRoot::open(&selected)?;
        let before = Inventory::record(&root)?;
        fs::rename(selected.join("payload"), selected.join("old-file"))?;
        fs::write(selected.join("payload"), b"new and longer")?;
        symlink("../../outside", selected.join("escaping-link"))?;
        before.verify(&root)?;
        fs::create_dir(selected.join("added"))?;
        assert!(before.verify(&root).is_err());
        fs::remove_dir(selected.join("added"))?;
        before.verify(&root)?;
        // Preserve the old inode outside the selected root. Paths/counts inside
        // the root stay identical, so only native identity detects replacement.
        fs::rename(selected.join("child"), temp.path().join("detached"))?;
        fs::create_dir(selected.join("child"))?;
        let replacement = DirectoryIdentityInspectionFailure::attach(
            before.verify(&root),
            DirectoryIdentityInspectionSide::Protected,
            DirectoryIdentityInspectionStage::VerifyDirectories,
        )
        .unwrap_err();
        let failure = replacement
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .unwrap();
        assert_eq!(failure.side, DirectoryIdentityInspectionSide::Protected);
        assert_eq!(
            failure.stage,
            DirectoryIdentityInspectionStage::VerifyDirectories
        );
        assert_eq!(
            failure.relative_path.as_deref(),
            Some(std::path::Path::new("child"))
        );
        fs::remove_dir(selected.join("child"))?;
        let missing = DirectoryIdentityInspectionFailure::attach(
            before.verify(&root),
            DirectoryIdentityInspectionSide::Selected,
            DirectoryIdentityInspectionStage::VerifyDirectories,
        )
        .unwrap_err();
        let failure = missing
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .unwrap();
        assert_eq!(failure.side, DirectoryIdentityInspectionSide::Selected);
        assert_eq!(
            failure.stage,
            DirectoryIdentityInspectionStage::VerifyDirectories
        );
        assert_eq!(
            failure.relative_path.as_deref(),
            Some(std::path::Path::new("child"))
        );
        Ok(())
    }
}
