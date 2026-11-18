// SPDX-License-Identifier: GPL-3.0-only
#![cfg(any(target_os = "macos", target_os = "linux"))]

use anyhow::Result;
use quicksave_platform::{EntryKind, SafeRoot};
use std::{fs, os::unix::fs::symlink};

fn isolated() -> tempfile::TempDir {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let preferred = base.join("opencode");
    tempfile::Builder::new()
        .prefix("quicksave-links-")
        .tempdir_in(if preferred.is_dir() { preferred } else { base })
        .unwrap()
}

#[test]
fn framework_current_and_binary_links_are_metadata_not_traversal() -> Result<()> {
    let temp = isolated();
    fs::create_dir_all(temp.path().join("Bundle.framework/Versions/A/Resources"))?;
    fs::write(
        temp.path().join("Bundle.framework/Versions/A/Binary"),
        b"binary",
    )?;
    symlink("A", temp.path().join("Bundle.framework/Versions/Current"))?;
    symlink(
        "Versions/Current/Binary",
        temp.path().join("Bundle.framework/Binary"),
    )?;
    symlink(
        "Versions/Current/Resources",
        temp.path().join("Bundle.framework/Resources"),
    )?;
    let root = SafeRoot::open(temp.path())?;
    let entries = root.metadata_entries()?;
    assert_eq!(entries, root.metadata_entries()?);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == EntryKind::Symlink)
            .count(),
        3
    );
    assert!(!entries.iter().any(|e| e.relative_path.contains("Current/")));
    assert!(root.entries().is_err());
    assert!(root.read_file("Bundle.framework/Binary").is_err());
    Ok(())
}

#[test]
fn internal_parent_link_is_preserved_exactly() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("Resources"))?;
    fs::create_dir(temp.path().join("Contents"))?;
    let root = SafeRoot::open(temp.path())?;
    let stamp = root.create_new_relative_symlink("Contents/Resources", "../Resources", None)?;
    assert_eq!(stamp.target, "../Resources");
    root.verify_link("Contents/Resources", &stamp)?;
    assert_eq!(
        fs::read_link(temp.path().join("Contents/Resources"))?.to_str(),
        Some("../Resources")
    );
    Ok(())
}

#[test]
fn dangling_internal_link_does_not_require_target_access() -> Result<()> {
    let temp = isolated();
    symlink("not-created", temp.path().join("link"))?;
    let root = SafeRoot::open(temp.path())?;
    assert_eq!(root.read_link("link")?.target, "not-created");
    assert_eq!(root.metadata_entries()?.len(), 1);
    Ok(())
}

#[test]
fn absolute_target_is_rejected_without_reading_it() -> Result<()> {
    let temp = isolated();
    symlink("/not-accessed", temp.path().join("link"))?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root.metadata_entries().is_err());
    assert!(root.read_link("link").is_err());
    Ok(())
}

#[test]
fn escaping_parent_target_is_rejected() -> Result<()> {
    let temp = isolated();
    symlink("../outside", temp.path().join("link"))?;
    assert!(SafeRoot::open(temp.path())?.metadata_entries().is_err());
    Ok(())
}

#[test]
fn nested_escape_is_rejected_before_creation() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("nested"))?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .create_new_relative_symlink("nested/link", "../../outside", None)
        .is_err());
    assert!(fs::symlink_metadata(temp.path().join("nested/link")).is_err());
    Ok(())
}

#[test]
fn windows_looking_targets_remain_literal_relative_unix_names() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    for (index, target) in [
        r"C:\outside",
        "C:outside",
        r"\??\C:\outside",
        r"\\server\share",
        "file:stream",
        r"\\?\GLOBALROOT\Device",
    ]
    .into_iter()
    .enumerate()
    {
        let path = format!("link-{index}");
        let link = root.create_new_relative_symlink(&path, target, None)?;
        assert_eq!(link.target, target);
        assert_eq!(root.read_link(&path)?, link);
        assert!(
            root.read_file(&path).is_err(),
            "links are never payload-read authority"
        );
    }
    assert_eq!(root.metadata_entries()?.len(), 6);
    Ok(())
}

#[test]
fn nul_empty_and_ambiguous_targets_are_rejected() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    for target in ["", "nul\0text", "a//b", "a/"] {
        assert!(root
            .create_new_relative_symlink("link", target, None)
            .is_err());
    }
    Ok(())
}

#[test]
fn symlink_parent_never_redirects_creation() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("real"))?;
    symlink("real", temp.path().join("alias"))?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .create_new_relative_symlink("alias/link", "../real", None)
        .is_err());
    assert!(!temp.path().join("real/link").exists());
    Ok(())
}

#[test]
fn existing_symlink_is_never_replaced() -> Result<()> {
    let temp = isolated();
    symlink("original", temp.path().join("link"))?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .create_new_relative_symlink("link", "replacement", None)
        .is_err());
    assert_eq!(
        fs::read_link(temp.path().join("link"))?.to_str(),
        Some("original")
    );
    Ok(())
}

#[test]
fn existing_file_and_directory_are_never_replaced() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("file"), b"keep")?;
    fs::create_dir(temp.path().join("directory"))?;
    let root = SafeRoot::open(temp.path())?;
    for name in ["file", "directory"] {
        assert!(root
            .create_new_relative_symlink(name, "target", None)
            .is_err());
    }
    assert_eq!(fs::read(temp.path().join("file"))?, b"keep");
    assert!(temp.path().join("directory").is_dir());
    Ok(())
}

#[test]
fn read_link_never_opens_regular_file_data() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("file"), b"not-link")?;
    assert!(SafeRoot::open(temp.path())?.read_link("file").is_err());
    Ok(())
}

#[test]
fn replacing_link_invalidates_native_link_stamp() -> Result<()> {
    let temp = isolated();
    symlink("first", temp.path().join("link"))?;
    let root = SafeRoot::open(temp.path())?;
    let stamp = root.read_link("link")?;
    fs::remove_file(temp.path().join("link"))?;
    symlink("other", temp.path().join("link"))?;
    assert!(root.verify_link("link", &stamp).is_err());
    Ok(())
}

#[test]
fn replacing_root_invalidates_link_observations() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("root"))?;
    symlink("inside", temp.path().join("root/link"))?;
    let root = SafeRoot::open(&temp.path().join("root"))?;
    fs::rename(temp.path().join("root"), temp.path().join("old"))?;
    fs::create_dir(temp.path().join("root"))?;
    assert!(root.read_link("link").is_err());
    assert!(root.metadata_entries().is_err());
    assert!(root
        .create_new_relative_symlink("new", "inside", None)
        .is_err());
    Ok(())
}

#[test]
fn cycles_are_observed_once_without_following() -> Result<()> {
    let temp = isolated();
    symlink("b", temp.path().join("a"))?;
    symlink("a", temp.path().join("b"))?;
    symlink(".", temp.path().join("self"))?;
    let entries = SafeRoot::open(temp.path())?.metadata_entries()?;
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.kind == EntryKind::Symlink));
    Ok(())
}

#[test]
fn overlap_and_alias_checks_do_not_follow_confined_links() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("left"))?;
    fs::create_dir(temp.path().join("right"))?;
    fs::write(temp.path().join("left/key"), b"key")?;
    symlink("missing", temp.path().join("left/link"))?;
    let left = SafeRoot::open(&temp.path().join("left"))?;
    let right = SafeRoot::open(&temp.path().join("right"))?;
    assert!(!left.overlaps(&right)?);
    let (_, stamp) = left.read_file("key")?;
    assert!(left.contains_file_identity(&stamp)?);
    Ok(())
}
