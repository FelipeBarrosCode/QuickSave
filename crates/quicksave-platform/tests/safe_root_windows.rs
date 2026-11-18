// SPDX-License-Identifier: GPL-3.0-only
#![cfg(windows)]

use anyhow::Result;
use quicksave_platform::{ensure_private_directory, EntryKind, PrivateDirectory, SafeRoot};
use std::{
    fs,
    io::{Read, Write},
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
fn real_native_directory_handles_revalidate_full_ids_and_pin_names() -> Result<()> {
    use std::{
        mem::{size_of, MaybeUninit},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };
    fn native_id(file: &std::fs::File) -> Result<FILE_ID_INFO> {
        let mut info = MaybeUninit::<FILE_ID_INFO>::uninit();
        anyhow::ensure!(
            unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileIdInfo,
                    info.as_mut_ptr().cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            } != 0,
            "query real 128-bit directory identity: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { info.assume_init() })
    }
    let temp = tempfile::Builder::new()
        .prefix("quicksave-directory-")
        .tempdir()?;
    fs::create_dir_all(temp.path().join("parent/child"))?;
    let root = SafeRoot::open(temp.path())?;
    let directory = root.open_directory("parent/child")?;
    let before = native_id(&directory)?;
    let second = native_id(&root.open_directory("parent/child")?)?;
    assert_eq!(before.VolumeSerialNumber, second.VolumeSerialNumber);
    assert_eq!(before.FileId.Identifier, second.FileId.Identifier);
    assert!(fs::rename(
        temp.path().join("parent/child"),
        temp.path().join("parent/replaced")
    )
    .is_err());
    assert!(root.open_directory("").is_err());
    assert!(root.open_directory(".").is_err());
    let root_handle = native_id(&root.clone_root_directory_handle()?)?;
    let approved = root.identity()?;
    assert_eq!(root_handle.VolumeSerialNumber, approved.device);
    assert_eq!(
        root_handle.FileId.Identifier[..8],
        approved.file_id[0].to_le_bytes()
    );
    assert_eq!(
        root_handle.FileId.Identifier[8..],
        approved.file_id[1].to_le_bytes()
    );
    Ok(())
}

#[test]
fn durable_writes_use_a_real_barrier_or_fail_before_the_writer() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir()?;
    let root = SafeRoot::open(temp.path())?;
    let called = AtomicBool::new(false);
    let result = root.write_new("target", |file| {
        called.store(true, Ordering::SeqCst);
        file.write_all(b"durable native bytes")?;
        Ok(())
    });
    match result {
        Ok(()) => {
            assert!(called.load(Ordering::SeqCst));
            assert_eq!(
                fs::read(temp.path().join("target"))?,
                b"durable native bytes"
            );
            let (file, _) = root.read_file("target")?;
            quicksave_platform::verify_private_file(&file)?;
            root.create_dir("directory")?;
            ensure_private_directory(&temp.path().join("private"))?;
        }
        Err(error) => {
            // A non-elevated Windows runner usually cannot open the real volume
            // flush handle. Do not mistake that for an implemented flush.
            assert!(
                format!("{error:#}").contains("volume flush permission required"),
                "{error:#}"
            );
            assert!(!called.load(Ordering::SeqCst));
            assert!(fs::symlink_metadata(temp.path().join("target")).is_err());
            assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        }
    }
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["durable_create_new"],
        true
    );
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["private_directory_creation"],
        true
    );
    assert_eq!(
        quicksave_platform::capabilities()["filesystem"]["private_file_verification"],
        true
    );
    Ok(())
}

#[test]
fn confined_symlinks_are_metadata_and_never_read_through() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-links-")
        .tempdir()?;
    fs::write(temp.path().join("target"), b"do not read through")?;
    let path = temp.path().join("link");
    match std::os::windows::fs::symlink_file("target", &path) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => {
            // Native privilege denial is explicit and no fixture was created.
            assert!(fs::symlink_metadata(path).is_err());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    let root = SafeRoot::open(temp.path())?;
    let link = root.read_link("link")?;
    assert_eq!(link.target, "target");
    assert_eq!(link.target_is_directory, Some(false));
    assert!(root.read_file("link").is_err());
    assert!(root.entries().is_err());
    assert_eq!(
        root.metadata_entries()?
            .iter()
            .filter(|entry| entry.kind == EntryKind::Symlink)
            .count(),
        1
    );
    root.verify_link("link", &link)?;
    fs::remove_file(&path)?;
    std::os::windows::fs::symlink_file("missing", &path)?;
    assert!(root.verify_link("link", &link).is_err());
    Ok(())
}

#[test]
fn native_symlink_ancestors_are_not_traversed() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-reparse-")
        .tempdir()?;
    fs::create_dir(temp.path().join("actual"))?;
    fs::write(temp.path().join("actual/file"), b"unapproved traversal")?;
    match std::os::windows::fs::symlink_dir("actual", temp.path().join("alias")) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let root = SafeRoot::open(temp.path())?;
    assert!(root.read_file("alias/file").is_err());
    assert!(root.create_dir("alias/new").is_err());
    assert!(SafeRoot::open(&temp.path().join("alias")).is_err());
    Ok(())
}

#[test]
#[ignore = "native Windows NTFS/ReFS acceptance: requires actual volume flush permission"]
fn private_state_lock_compare_replace_and_no_overwrite_are_durable() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-config-")
        .tempdir()?;
    let path = temp.path().join("private");
    let private = PrivateDirectory::open(&path)?;
    let lock = private.lock("state.lock")?;
    assert!(private.read("state.json", 1024)?.is_none());
    private.replace("state.json", b"first", None)?;
    let (bytes, before) = private.read("state.json", 1024)?.unwrap();
    assert_eq!(bytes, b"first");
    assert!(private.replace("state.json", b"stale", None).is_err());
    private.replace("state.json", b"second", Some(&before))?;
    assert!(private
        .replace("state.json", b"stale", Some(&before))
        .is_err());
    lock.check()?;
    assert!(fs::rename(path.join("state.lock"), path.join("moved-lock")).is_err());
    let root = SafeRoot::open(&path)?;
    assert!(root
        .write_new("state.json", |_| panic!(
            "existing target cannot run writer"
        ))
        .is_err());
    assert!(root
        .write_new("raced", |file| {
            file.write_all(b"loser")?;
            fs::write(path.join("raced"), b"winner")?;
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(path.join("raced"))?, b"winner");
    private.flush()?;
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
fn ordinary_live_writers_are_not_treated_as_stable_timestamp_proofs() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-writer-")
        .tempdir()?;
    let path = temp.path().join("source");
    fs::write(&path, b"mutable")?;
    let writer = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root.read_file("source").is_err());
    // A metadata-only index is not a content-capture receipt.
    assert_eq!(root.metadata_entries()?.len(), 1);
    drop(writer);
    let (_file, _stamp) = root.read_file("source")?;
    Ok(())
}

#[test]
fn directory_identity_approval_never_opens_an_exclusively_held_payload() -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::Builder::new()
        .prefix("quicksave-directory-approval-")
        .tempdir()?;
    let selected_path = temp.path().join("selected");
    let protected_path = temp.path().join("protected");
    fs::create_dir_all(selected_path.join("nested"))?;
    fs::create_dir_all(protected_path.join("nested"))?;
    fs::write(selected_path.join("payload"), b"synthetic locked payload")?;
    let _exclusive = fs::OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(selected_path.join("payload"))?;
    let selected = SafeRoot::open(&selected_path)?;
    let protected = SafeRoot::open(&protected_path)?;
    assert!(!selected.overlaps_directory_identities(&protected)?);
    assert!(!protected.overlaps_directory_identities(&selected)?);
    assert!(selected.read_file("payload").is_err());
    Ok(())
}

#[test]
fn escaping_native_symlink_does_not_become_directory_overlap_or_capture_permission() -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix("quicksave-directory-links-")
        .tempdir()?;
    let selected_path = temp.path().join("selected");
    let protected_path = temp.path().join("protected");
    fs::create_dir(&selected_path)?;
    fs::create_dir(&protected_path)?;
    match std::os::windows::fs::symlink_dir(&protected_path, selected_path.join("escape")) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let selected = SafeRoot::open(&selected_path)?;
    let protected = SafeRoot::open(&protected_path)?;
    assert!(!selected.overlaps_directory_identities(&protected)?);
    assert!(!protected.overlaps_directory_identities(&selected)?);
    assert!(selected.metadata_entries().is_err());
    assert!(selected.entries().is_err());
    assert!(selected.overlaps(&protected).is_err());
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
    assert!(left.overlaps_directory_identities(&same)?);
    assert!(left.overlaps_directory_identities(&nested)?);
    assert!(nested.overlaps_directory_identities(&left)?);
    assert!(!left.overlaps_directory_identities(&right)?);
    assert!(!right.overlaps_directory_identities(&left)?);
    assert!(!left.same_root(&right)?);
    let (file, stamp) = left.read_file("key")?;
    assert!(left.contains_file_identity(&stamp)?);
    assert!(!right.contains_file_identity(&stamp)?);
    assert!(quicksave_platform::verify_private_file(&file).is_err());
    Ok(())
}
