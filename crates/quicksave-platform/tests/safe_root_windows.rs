// SPDX-License-Identifier: GPL-3.0-only
#![cfg(windows)]

use anyhow::Result;
use quicksave_platform::{ensure_private_directory, SafeRoot};
use std::{
    fs,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
};

#[test]
fn native_handle_reads_and_repeatable_tree_walks() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    fs::create_dir(temp.path().join("directory"))?;
    fs::write(temp.path().join("directory/source"), b"native read")?;
    let root = SafeRoot::open(temp.path())?;
    let entries = root.entries()?;
    assert_eq!(entries, root.entries()?);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect::<Vec<_>>(),
        ["directory", "directory/source"]
    );
    let (mut file, stamp) = root.read_file("directory/source")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"native read");
    root.verify_file("directory/source", &stamp)?;
    Ok(())
}

#[test]
fn unsupported_durable_writes_are_explicit_and_never_run_callback() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    let root = SafeRoot::open(temp.path())?;
    let called = AtomicBool::new(false);
    assert!(root
        .write_new("target", |_| {
            called.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert!(!called.load(Ordering::SeqCst));
    assert!(root.create_dir("directory").is_err());
    assert!(ensure_private_directory(&temp.path().join("private")).is_err());
    assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["durable_create_new"],
        false
    );
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["private_directory_creation"],
        false
    );
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["private_file_verification"],
        false
    );
    Ok(())
}

#[test]
fn native_open_handles_pin_source_names_against_replacement() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    let source = temp.path().join("source");
    fs::write(&source, b"pinned")?;
    let root = SafeRoot::open(temp.path())?;
    let (file, before) = root.read_file("source")?;
    assert!(fs::rename(&source, temp.path().join("moved")).is_err());
    root.verify_file("source", &before)?;
    drop(file);
    fs::rename(&source, temp.path().join("moved"))?;
    fs::write(&source, b"replacement")?;
    assert!(root.verify_file("source", &before).is_err());
    Ok(())
}

#[test]
fn device_names_alternate_streams_and_traversal_are_rejected() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    let root = SafeRoot::open(temp.path())?;
    for name in [
        "CON",
        "NUL.txt",
        "LPT1",
        "COM1",
        "a:stream",
        "../outside",
        r"a\b",
        "trailing.",
        "trailing ",
    ] {
        assert!(root.read_file(name).is_err(), "{name:?}");
    }
    Ok(())
}

#[test]
fn native_directory_overlap_and_file_alias_guards_use_native_ids() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    let left_path = temp.path().join("left");
    let right_path = temp.path().join("right");
    fs::create_dir(&left_path)?;
    fs::create_dir(left_path.join("nested"))?;
    fs::create_dir(&right_path)?;
    fs::write(left_path.join("key"), [0x45; 32])?;
    fs::write(right_path.join("different-file"), [0x45; 32])?;
    let left = SafeRoot::open(&left_path)?;
    let same = SafeRoot::open(&left_path)?;
    let nested = SafeRoot::open(&left_path.join("nested"))?;
    let right = SafeRoot::open(&right_path)?;
    assert!(left.overlaps(&same)?);
    assert!(left.same_root(&same)?);
    assert!(left.overlaps(&nested)?);
    assert!(nested.overlaps(&left)?);
    assert!(!left.same_root(&nested)?);
    assert!(!left.overlaps(&right)?);
    assert!(!right.overlaps(&left)?);
    assert!(!left.same_root(&right)?);
    let (file, stamp) = left.read_file("key")?;
    assert!(left.contains_file_identity(&stamp)?);
    assert!(!right.contains_file_identity(&stamp)?);
    assert!(quicksave_platform::verify_private_file(&file).is_err());
    Ok(())
}
