// SPDX-License-Identifier: GPL-3.0-only
#![cfg(any(target_os = "macos", target_os = "linux"))]

use anyhow::{Context, Result};
use quicksave_platform::{
    DirectoryIdentityInspectionFailure, DirectoryIdentityInspectionSide,
    DirectoryIdentityInspectionStage, SafeRoot, MAX_DEPTH,
};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
};

fn isolated() -> tempfile::TempDir {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let preferred = base.join("opencode");
    let base = if preferred.is_dir() {
        fs::canonicalize(preferred).unwrap()
    } else {
        base
    };
    tempfile::Builder::new()
        .prefix("quicksave-directory-approval-")
        .tempdir_in(base)
        .unwrap()
}

fn roots(base: &Path) -> Result<(SafeRoot, SafeRoot)> {
    fs::create_dir_all(base.join("selected/nested"))?;
    fs::create_dir_all(base.join("protected/nested"))?;
    Ok((
        SafeRoot::open(&base.join("selected"))?,
        SafeRoot::open(&base.join("protected"))?,
    ))
}

#[test]
fn escaping_symlinks_are_not_directory_overlap_or_capture_permission() -> Result<()> {
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    symlink(
        "../../protected",
        temp.path().join("selected/nested/relative-escape"),
    )?;
    symlink(
        temp.path().join("protected"),
        temp.path().join("selected/absolute-escape"),
    )?;
    symlink(
        "../../selected",
        temp.path().join("protected/nested/escape"),
    )?;
    assert!(!selected.overlaps_directory_identities(&protected)?);
    assert!(!protected.overlaps_directory_identities(&selected)?);
    // Identity approval is not authorization to resolve or capture links.
    assert!(selected.metadata_entries().is_err());
    assert!(protected.metadata_entries().is_err());
    assert!(selected.entries().is_err());
    let capture_error = selected.overlaps(&protected).unwrap_err();
    assert!(capture_error
        .downcast_ref::<DirectoryIdentityInspectionFailure>()
        .is_none());
    assert!(selected
        .read_file("absolute-escape/not-authorized")
        .is_err());
    Ok(())
}

#[test]
fn denied_payloads_and_special_files_do_not_need_to_be_opened() -> Result<()> {
    use std::ffi::CString;
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    let payload = temp.path().join("protected/nested/payload");
    fs::write(
        &payload,
        b"synthetic secret; never read by identity approval",
    )?;
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o000))?;
    fs::write(temp.path().join("selected/nested/live-payload"), b"old")?;
    let fifo = CString::new(
        temp.path()
            .join("selected/pipe")
            .to_str()
            .context("fixture encoding")?,
    )?;
    anyhow::ensure!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0);
    assert!(!selected.overlaps_directory_identities(&protected)?);
    assert!(!protected.overlaps_directory_identities(&selected)?);
    if unsafe { libc::geteuid() } != 0 {
        assert!(protected.read_file("nested/payload").is_err());
    }
    // The generic capture guard remains strict about the FIFO.
    assert!(selected.overlaps(&protected).is_err());
    Ok(())
}

#[test]
fn same_native_roots_and_real_descendants_still_overlap() -> Result<()> {
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    let same = SafeRoot::open(&temp.path().join("selected"))?;
    let child = SafeRoot::open(&temp.path().join("selected/nested"))?;
    assert!(selected.overlaps_directory_identities(&same)?);
    assert!(selected.overlaps_directory_identities(&child)?);
    assert!(child.overlaps_directory_identities(&selected)?);
    assert!(!selected.overlaps_directory_identities(&protected)?);
    Ok(())
}

#[test]
fn inaccessible_directories_fail_with_the_correct_side_and_relative_directory() -> Result<()> {
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    let blocked = temp.path().join("protected/blocked");
    fs::create_dir(&blocked)?;
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000))?;
    let protected_error = selected.overlaps_directory_identities(&protected).err();
    let selected_error = protected.overlaps_directory_identities(&selected).err();
    // The denied empty fixture is removed by its writable parent, not chmodded
    // or repaired by production code.
    fs::remove_dir(&blocked)?;
    if unsafe { libc::geteuid() } != 0 {
        for (error, side) in [
            (protected_error, DirectoryIdentityInspectionSide::Protected),
            (selected_error, DirectoryIdentityInspectionSide::Selected),
        ] {
            let error = error
                .context("denied directory was skipped")?
                .context("caller-owned approval label");
            let failure = error
                .downcast_ref::<DirectoryIdentityInspectionFailure>()
                .context("identity approval must return typed side")?;
            assert_eq!(failure.side, side);
            assert_eq!(
                failure.stage,
                DirectoryIdentityInspectionStage::RecordDirectories
            );
            assert_eq!(failure.relative_path.as_deref(), Some(Path::new("blocked")));
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .context("native I/O cause must remain downcastable")?
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }
    Ok(())
}

#[test]
fn depth_exhaustion_is_a_side_specific_failure_not_disjointness() -> Result<()> {
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    let mut deep = temp.path().join("selected");
    for _ in 0..=MAX_DEPTH {
        deep.push("d");
        fs::create_dir(&deep)?;
    }
    for (error, side) in [
        (
            selected
                .overlaps_directory_identities(&protected)
                .unwrap_err(),
            DirectoryIdentityInspectionSide::Selected,
        ),
        (
            protected
                .overlaps_directory_identities(&selected)
                .unwrap_err(),
            DirectoryIdentityInspectionSide::Protected,
        ),
    ] {
        let failure = error
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .context("bounded census failure must return typed side")?;
        assert_eq!(failure.side, side);
        assert_eq!(
            failure.stage,
            DirectoryIdentityInspectionStage::RecordDirectories
        );
        assert!(failure.relative_path.is_some());
    }
    Ok(())
}

#[test]
fn root_replacement_never_becomes_a_negative_identity_approval() -> Result<()> {
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    fs::rename(temp.path().join("selected"), temp.path().join("detached"))?;
    fs::create_dir(temp.path().join("selected"))?;
    for (error, side) in [
        (
            selected
                .overlaps_directory_identities(&protected)
                .unwrap_err(),
            DirectoryIdentityInspectionSide::Selected,
        ),
        (
            protected
                .overlaps_directory_identities(&selected)
                .unwrap_err(),
            DirectoryIdentityInspectionSide::Protected,
        ),
    ] {
        let failure = error
            .downcast_ref::<DirectoryIdentityInspectionFailure>()
            .context("root-validation failure must return typed side")?;
        assert_eq!(failure.side, side);
        assert_eq!(
            failure.stage,
            DirectoryIdentityInspectionStage::ValidatePinnedRoot
        );
        assert_eq!(failure.relative_path, None);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn non_unicode_file_and_directory_names_do_not_require_a_payload_index() -> Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let temp = isolated();
    let (selected, protected) = roots(temp.path())?;
    fs::write(
        temp.path()
            .join("selected")
            .join(OsString::from_vec(vec![0xff])),
        b"ignored payload name",
    )?;
    fs::create_dir(
        temp.path()
            .join("protected")
            .join(OsString::from_vec(vec![0xfe])),
    )?;
    assert!(!selected.overlaps_directory_identities(&protected)?);
    assert!(!protected.overlaps_directory_identities(&selected)?);
    assert!(selected.metadata_entries().is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn case_aliases_use_real_directory_ids_when_the_fixture_volume_supports_them() -> Result<()> {
    let temp = isolated();
    fs::create_dir_all(temp.path().join("CaseRoot/Child"))?;
    let alternate = temp.path().join("caseroot/child");
    match fs::metadata(&alternate) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let original = SafeRoot::open(&temp.path().join("CaseRoot"))?;
    let alias_child = SafeRoot::open(&alternate)?;
    assert!(original.overlaps_directory_identities(&alias_child)?);
    assert!(alias_child.overlaps_directory_identities(&original)?);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real bind aliases: explicit CAP_SYS_ADMIN acceptance in a child-only private mount namespace"]
fn shared_descendant_bind_aliases_are_found_beyond_both_root_ancestor_chains() -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf, process::Command};
    const CHILD: &str = "QUICKSAVE_DIRECTORY_ALIAS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "shared_descendant_bind_aliases_are_found_beyond_both_root_ancestor_chains",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()?;
        anyhow::ensure!(
            status.success(),
            "isolated native bind-alias fixture failed"
        );
        return Ok(());
    }
    // Only the subprocess changes mount topology. Never alter the test runner's
    // namespace or require sudo; denied capabilities fail this ignored test.
    anyhow::ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0,
        "isolated mount namespace requires explicit native capability: {}",
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        } == 0,
        "make child namespace non-propagating: {}",
        std::io::Error::last_os_error()
    );
    let temp = isolated();
    fs::create_dir_all(temp.path().join("shared/descendant"))?;
    fs::create_dir_all(temp.path().join("selected/alias"))?;
    fs::create_dir_all(temp.path().join("protected/alias"))?;
    struct Mounts(Vec<PathBuf>);
    impl Drop for Mounts {
        fn drop(&mut self) {
            for target in self.0.iter().rev() {
                let target = CString::new(target.as_os_str().as_bytes()).unwrap();
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
            }
        }
    }
    let mut mounts = Mounts(Vec::new());
    let source = CString::new(temp.path().join("shared").as_os_str().as_bytes())?;
    for leaf in ["selected/alias", "protected/alias"] {
        let target = temp.path().join(leaf);
        let native = CString::new(target.as_os_str().as_bytes())?;
        anyhow::ensure!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    native.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            } == 0,
            "create synthetic bind alias: {}",
            std::io::Error::last_os_error()
        );
        mounts.0.push(target);
    }
    let selected = SafeRoot::open(&temp.path().join("selected"))?;
    let protected = SafeRoot::open(&temp.path().join("protected"))?;
    assert!(!selected.same_root(&protected)?);
    assert!(selected.overlaps_directory_identities(&protected)?);
    assert!(protected.overlaps_directory_identities(&selected)?);
    drop(selected);
    drop(protected);
    drop(mounts);
    Ok(())
}
