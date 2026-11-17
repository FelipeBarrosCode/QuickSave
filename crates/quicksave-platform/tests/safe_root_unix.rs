// SPDX-License-Identifier: GPL-3.0-only
#![cfg(any(target_os = "macos", target_os = "linux"))]

use anyhow::{bail, Result};
use quicksave_platform::{
    ensure_private_directory, verify_private_file, FileStamp, SafeRoot, MAX_DEPTH,
};
use std::{
    ffi::{CString, OsString},
    fs::{self, File},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{symlink, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
};

fn isolated() -> tempfile::TempDir {
    // macOS's /var and /tmp aliases are symlinks. The test fixture itself uses
    // the real native ancestor chain, exactly as production SafeRoot requires.
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let preferred = base.join("opencode");
    let base = if preferred.is_dir() {
        fs::canonicalize(preferred).unwrap()
    } else {
        base
    };
    tempfile::Builder::new()
        .prefix("quicksave-platform-")
        .tempdir_in(base)
        .unwrap()
}

fn children(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn stable_read_and_stamp_serde_roundtrip() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("source"), b"stable bytes")?;
    let root = SafeRoot::open(temp.path())?;
    let (mut file, before) = root.read_file("source")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"stable bytes");
    root.verify_file("source", &before)?;
    let decoded: FileStamp = serde_json::from_slice(&serde_json::to_vec(&before)?)?;
    assert_eq!(decoded, before);
    Ok(())
}

#[test]
fn native_source_replacement_is_rejected_even_with_same_length() -> Result<()> {
    let temp = isolated();
    let path = temp.path().join("source");
    fs::write(&path, b"original")?;
    let root = SafeRoot::open(temp.path())?;
    let (mut pinned, before) = root.read_file("source")?;
    fs::rename(&path, temp.path().join("old"))?;
    fs::write(&path, b"replaced")?;
    assert!(root.verify_file("source", &before).is_err());
    let mut bytes = Vec::new();
    pinned.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"original");
    Ok(())
}

#[test]
fn in_place_file_mutation_is_rejected() -> Result<()> {
    let temp = isolated();
    let path = temp.path().join("source");
    fs::write(&path, b"before")?;
    let root = SafeRoot::open(temp.path())?;
    let (_, before) = root.read_file("source")?;
    fs::write(&path, b"changed length")?;
    assert!(root.verify_file("source", &before).is_err());
    Ok(())
}

#[test]
fn root_replacement_invalidates_reads_walks_and_writes() -> Result<()> {
    let temp = isolated();
    let path = temp.path().join("root");
    fs::create_dir(&path)?;
    fs::write(path.join("source"), b"original")?;
    let root = SafeRoot::open(&path)?;
    let (_, before) = root.read_file("source")?;
    let moved = temp.path().join("old-root");
    fs::rename(&path, &moved)?;
    fs::create_dir(&path)?;
    fs::write(path.join("source"), b"replacement")?;
    assert!(root.entries().is_err());
    assert!(root.read_file("source").is_err());
    assert!(root.verify_file("source", &before).is_err());
    assert!(root.contains_file_identity(&before).is_err());
    assert!(root.overlaps(&SafeRoot::open(&path)?).is_err());
    assert!(root.same_root(&SafeRoot::open(&path)?).is_err());
    assert!(root.write_new("target", |_| Ok(())).is_err());
    assert!(root.create_dir("child").is_err());
    assert!(!path.join("target").exists());
    assert!(!moved.join("target").exists());
    Ok(())
}

#[test]
fn replacing_an_ancestor_is_also_rejected() -> Result<()> {
    let temp = isolated();
    let parent = temp.path().join("parent");
    let path = parent.join("root");
    fs::create_dir_all(&path)?;
    let root = SafeRoot::open(&path)?;
    fs::rename(&parent, temp.path().join("old-parent"))?;
    fs::create_dir_all(&path)?;
    assert!(root.entries().is_err());
    assert!(root.write_new("file", |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn symlink_ancestors_and_symlink_entries_never_escape() -> Result<()> {
    let temp = isolated();
    let outside = temp.path().join("outside");
    let source = temp.path().join("source");
    fs::create_dir(&outside)?;
    fs::create_dir(&source)?;
    fs::write(outside.join("secret"), b"not in source")?;
    let alias = temp.path().join("alias");
    symlink(&outside, &alias)?;
    assert!(SafeRoot::open(&alias).is_err());
    fs::create_dir(outside.join("child"))?;
    assert!(SafeRoot::open(&alias.join("child")).is_err());
    let root = SafeRoot::open(&source)?;
    symlink(&outside, source.join("escape"))?;
    assert!(root.read_file("escape/secret").is_err());
    assert!(root.create_dir("escape/created").is_err());
    assert!(root.write_new("escape/created", |_| Ok(())).is_err());
    assert!(root.entries().is_err());
    assert!(!outside.join("created").exists());
    fs::remove_file(source.join("escape"))?;
    symlink(outside.join("secret"), source.join("link"))?;
    assert!(root.read_file("link").is_err());
    assert!(root.entries().is_err());
    assert!(root.write_new("link", |_| Ok(())).is_err());
    assert_eq!(fs::read(outside.join("secret"))?, b"not in source");
    Ok(())
}

#[test]
fn all_traversal_and_invalid_paths_fail_before_callbacks() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    let mut invalid = vec![
        "".to_owned(),
        ".".into(),
        "..".into(),
        "/absolute".into(),
        "../outside".into(),
        "a/../outside".into(),
        "a/./b".into(),
        "a//b".into(),
        "a/".into(),
        r"a\b".into(),
        "C:drive".into(),
        "nul\0byte".into(),
        "x".repeat(256),
        "a/".repeat(MAX_DEPTH) + "b",
        "x".repeat(quicksave_platform::MAX_PATH_BYTES + 1),
    ];
    for path in invalid.drain(..) {
        assert!(root.read_file(&path).is_err(), "{path:?}");
        assert!(root.create_dir(&path).is_err(), "{path:?}");
        let called = AtomicBool::new(false);
        assert!(root
            .write_new(&path, |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        assert!(!called.load(Ordering::SeqCst));
    }
    assert!(children(temp.path()).is_empty());
    Ok(())
}

#[test]
fn fifo_is_rejected_without_blocking_and_non_utf8_is_not_skipped() -> Result<()> {
    let temp = isolated();
    let fifo = temp.path().join("fifo");
    let c_path = CString::new(fifo.to_str().unwrap())?;
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let root = SafeRoot::open(temp.path())?;
    assert!(root.read_file("fifo").is_err());
    assert!(root.entries().is_err());
    fs::remove_file(&fifo)?;
    let invalid_name = temp.path().join(OsString::from_vec(vec![b'f', 0xff]));
    match fs::write(&invalid_name, b"x") {
        Ok(()) => assert!(root.entries().is_err()),
        Err(error) => {
            #[cfg(target_os = "macos")]
            {
                // APFS can reject the fixture at creation time. Accept only
                // native invalid-encoding/input rejection, not other failures.
                assert!(
                    error.raw_os_error() == Some(libc::EILSEQ)
                        || error.kind() == std::io::ErrorKind::InvalidInput,
                    "unexpected non-UTF8 fixture creation failure: {error}"
                );
                assert!(root.entries()?.is_empty());
            }
            #[cfg(target_os = "linux")]
            return Err(error.into());
        }
    }
    assert!(SafeRoot::open(&temp.path().join(OsString::from_vec(vec![0xff]))).is_err());
    Ok(())
}

#[test]
fn walk_is_ordered_and_repeatable_with_directory_sizes_zero() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("z"))?;
    fs::create_dir(temp.path().join("a"))?;
    fs::write(temp.path().join("z/last"), b"xyz")?;
    fs::write(temp.path().join("a/first"), b"1")?;
    fs::write(temp.path().join("middle"), b"12")?;
    let root = SafeRoot::open(temp.path())?;
    let first = root.entries()?;
    assert_eq!(first, root.entries()?);
    assert_eq!(
        first
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect::<Vec<_>>(),
        ["a", "a/first", "middle", "z", "z/last"]
    );
    assert_eq!(
        first.iter().map(|entry| entry.size).collect::<Vec<_>>(),
        [0, 1, 2, 0, 3]
    );
    Ok(())
}

#[test]
fn excessive_tree_depth_fails_not_truncates() -> Result<()> {
    let temp = isolated();
    let mut path = temp.path().to_path_buf();
    for _ in 0..=MAX_DEPTH {
        path.push("d");
        fs::create_dir(&path)?;
    }
    assert!(SafeRoot::open(temp.path())?.entries().is_err());
    Ok(())
}

#[test]
fn transactional_callback_verifies_before_target_publication_and_files_are_private() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    let final_path = temp.path().join("verified");
    root.write_new("verified", |file| {
        file.write_all(b"verified payload")?;
        assert!(!final_path.exists());
        assert!(children(temp.path())
            .iter()
            .all(|name| name.starts_with(".quicksave-stage-")));
        Ok(())
    })?;
    assert_eq!(fs::read(&final_path)?, b"verified payload");
    assert_eq!(
        fs::metadata(&final_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(children(temp.path()), ["verified"]);
    Ok(())
}

#[test]
fn writer_failure_removes_staging_without_publishing() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    fs::write(temp.path().join("preserve"), b"existing")?;
    let result = root.write_new("failed", |file| {
        file.write_all(b"unverified")?;
        bail!("simulated integrity verification failure")
    });
    assert!(result.is_err());
    assert!(!temp.path().join("failed").exists());
    assert_eq!(children(temp.path()), ["preserve"]);
    assert_eq!(fs::read(temp.path().join("preserve"))?, b"existing");
    Ok(())
}

#[test]
fn writer_panic_also_cleans_its_private_staging() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = root.write_new("failed", |file| {
            file.write_all(b"partial")?;
            panic!("intentional test-only writer panic");
        });
    }));
    assert!(result.is_err());
    assert!(children(temp.path()).is_empty());
    Ok(())
}

#[test]
fn existing_targets_are_never_overwritten_or_given_to_callback() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("existing"), b"preserve")?;
    fs::create_dir(temp.path().join("directory"))?;
    let root = SafeRoot::open(temp.path())?;
    for name in ["existing", "directory"] {
        let called = AtomicBool::new(false);
        assert!(root
            .write_new(name, |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        assert!(!called.load(Ordering::SeqCst));
    }
    assert_eq!(fs::read(temp.path().join("existing"))?, b"preserve");
    assert_eq!(children(temp.path()), ["directory", "existing"]);
    Ok(())
}

#[test]
fn target_created_during_callback_wins_without_clobber() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .write_new("race", |file| {
            file.write_all(b"must not overwrite")?;
            fs::write(temp.path().join("race"), b"winner")?;
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(temp.path().join("race"))?, b"winner");
    assert_eq!(children(temp.path()), ["race"]);
    Ok(())
}

#[test]
fn simultaneous_create_new_writers_have_exactly_one_winner() -> Result<()> {
    let temp = isolated();
    let root = Arc::new(SafeRoot::open(temp.path())?);
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [b"writer-a".to_vec(), b"writer-b".to_vec()]
        .into_iter()
        .map(|payload| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                root.write_new("target", |file| {
                    file.write_all(&payload)?;
                    barrier.wait();
                    Ok(())
                })
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    assert!([b"writer-a".as_slice(), b"writer-b".as_slice()]
        .contains(&fs::read(temp.path().join("target"))?.as_slice()));
    assert_eq!(children(temp.path()), ["target"]);
    Ok(())
}

#[test]
fn callback_cannot_swap_native_file_handle_and_publish_unverified_bytes() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("unrelated"), b"preserve")?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .write_new("target", |file| {
            file.write_all(b"stage")?;
            *file = File::open(temp.path().join("unrelated"))?;
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(temp.path().join("unrelated"))?, b"preserve");
    assert_eq!(children(temp.path()), ["unrelated"]);
    Ok(())
}

#[test]
fn replaced_staging_names_are_not_cleaned_up_as_if_they_were_owned() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    let mut replacement = None;
    let result = root.write_new("target", |file| {
        file.write_all(b"private stage")?;
        let name = children(temp.path()).into_iter().next().unwrap();
        let path = temp.path().join(name);
        fs::rename(&path, temp.path().join("displaced-stage"))?;
        fs::create_dir(&path)?;
        fs::write(path.join("preserve"), b"unrelated replacement")?;
        replacement = Some(path);
        bail!("simulated failure after staging-name replacement")
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(replacement.unwrap().join("preserve"))?,
        b"unrelated replacement"
    );
    assert!(!temp.path().join("target").exists());
    // Failure is explicit; the moved stage is not silently scavenged.
    assert!(temp.path().join("displaced-stage/content").exists());
    Ok(())
}

#[test]
fn privacy_mutation_is_rejected_and_staging_is_cleaned() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .write_new("target", |file| {
            file.write_all(b"must stay private")?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            Ok(())
        })
        .is_err());
    assert!(children(temp.path()).is_empty());
    Ok(())
}

#[test]
fn replacing_relative_parent_during_callback_prevents_publication() -> Result<()> {
    let temp = isolated();
    fs::create_dir(temp.path().join("parent"))?;
    let root = SafeRoot::open(temp.path())?;
    assert!(root
        .write_new("parent/target", |file| {
            file.write_all(b"unverified namespace")?;
            fs::rename(temp.path().join("parent"), temp.path().join("old-parent"))?;
            fs::create_dir(temp.path().join("parent"))?;
            fs::write(temp.path().join("parent/preserve"), b"preserve")?;
            Ok(())
        })
        .is_err());
    assert_eq!(children(&temp.path().join("parent")), ["preserve"]);
    assert!(children(&temp.path().join("old-parent")).is_empty());
    Ok(())
}

#[test]
fn directories_are_private_durable_and_existing_real_directories_are_idempotent() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    root.create_dir("private")?;
    root.create_dir("private")?;
    root.create_dir("private/nested")?;
    assert_eq!(
        fs::metadata(temp.path().join("private"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(temp.path().join("private/nested"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(root.create_dir("missing/child").is_err());
    fs::write(temp.path().join("file"), b"x")?;
    assert!(root.create_dir("file").is_err());
    Ok(())
}

#[test]
fn private_directory_helper_creates_components_without_repairing_existing_permissions() -> Result<()>
{
    let temp = isolated();
    let shared = temp.path().join("shared");
    fs::create_dir(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777))?;
    let target = shared.join("QuickSave/Runtime");
    ensure_private_directory(&target)?;
    ensure_private_directory(&target)?;
    for path in [shared.join("QuickSave"), target] {
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
    }
    assert!(ensure_private_directory(&shared).is_err());
    assert_eq!(fs::metadata(&shared)?.permissions().mode() & 0o7777, 0o1777);
    let alias = temp.path().join("alias");
    symlink(&shared, &alias)?;
    assert!(ensure_private_directory(&alias.join("escape")).is_err());
    assert!(!shared.join("escape").exists());
    Ok(())
}

#[test]
fn native_overlap_detects_same_nested_and_disjoint_sibling_roots() -> Result<()> {
    let temp = isolated();
    let source_path = temp.path().join("source");
    let nested_path = source_path.join("nested/deeper");
    let sibling_path = temp.path().join("sibling");
    fs::create_dir_all(&nested_path)?;
    fs::create_dir(&sibling_path)?;
    fs::write(source_path.join("file"), b"source bytes")?;
    fs::write(sibling_path.join("file"), b"unrelated bytes")?;
    let source = SafeRoot::open(&source_path)?;
    let same = SafeRoot::open(&source_path)?;
    let nested = SafeRoot::open(&nested_path)?;
    let sibling = SafeRoot::open(&sibling_path)?;
    assert!(source.overlaps(&same)?);
    assert!(same.overlaps(&source)?);
    assert!(source.same_root(&same)?);
    assert!(same.same_root(&source)?);
    assert!(source.overlaps(&nested)?);
    assert!(nested.overlaps(&source)?);
    assert!(!source.same_root(&nested)?);
    assert!(!nested.same_root(&source)?);
    assert!(!source.overlaps(&sibling)?);
    assert!(!sibling.overlaps(&source)?);
    assert!(!source.same_root(&sibling)?);
    assert!(!nested.overlaps(&sibling)?);
    Ok(())
}

#[test]
fn overlap_scans_reject_symlinks_and_special_files_in_either_tree() -> Result<()> {
    let temp = isolated();
    let left_path = temp.path().join("left");
    let right_path = temp.path().join("right");
    fs::create_dir(&left_path)?;
    fs::create_dir(&right_path)?;
    let left = SafeRoot::open(&left_path)?;
    let right = SafeRoot::open(&right_path)?;
    symlink(&right_path, left_path.join("escape"))?;
    assert!(left.overlaps(&right).is_err());
    assert!(right.overlaps(&left).is_err());
    fs::remove_file(left_path.join("escape"))?;
    let fifo = right_path.join("fifo");
    let name = CString::new(fifo.to_str().unwrap())?;
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(left.overlaps(&right).is_err());
    assert!(right.overlaps(&left).is_err());
    fs::remove_file(fifo)?;
    assert!(!left.overlaps(&right)?);
    Ok(())
}

#[test]
fn disjoint_overlap_scan_obeys_the_tree_depth_bound() -> Result<()> {
    let temp = isolated();
    let deep_path = temp.path().join("deep");
    let clean_path = temp.path().join("clean");
    fs::create_dir(&deep_path)?;
    fs::create_dir(&clean_path)?;
    let mut path = deep_path.clone();
    for _ in 0..=MAX_DEPTH {
        path.push("d");
        fs::create_dir(&path)?;
    }
    let deep = SafeRoot::open(&deep_path)?;
    let clean = SafeRoot::open(&clean_path)?;
    assert!(deep.overlaps(&clean).is_err());
    assert!(clean.overlaps(&deep).is_err());
    Ok(())
}

#[test]
fn file_identity_search_detects_external_key_hard_link_not_identical_bytes() -> Result<()> {
    let temp = isolated();
    let keys_path = temp.path().join("keys");
    let source_path = temp.path().join("capture");
    fs::create_dir(&keys_path)?;
    fs::create_dir(&source_path)?;
    fs::create_dir(source_path.join("nested"))?;
    let key_path = keys_path.join("external-key");
    fs::write(&key_path, [0x41; 32])?;
    fs::write(source_path.join("same-bytes-different-file"), [0x41; 32])?;
    fs::write(source_path.join("different-size"), b"not a key")?;
    let keys = SafeRoot::open(&keys_path)?;
    let source = SafeRoot::open(&source_path)?;
    let (_file, key_stamp) = keys.read_file("external-key")?;
    assert!(keys.contains_file_identity(&key_stamp)?);
    assert!(!source.contains_file_identity(&key_stamp)?);
    fs::hard_link(&key_path, source_path.join("nested/key-alias"))?;
    assert!(source.contains_file_identity(&key_stamp)?);
    // Directory overlap and individual file aliases are distinct checks.
    assert!(!keys.overlaps(&source)?);
    Ok(())
}

#[test]
fn file_identity_search_ignores_timestamps_but_not_device_or_native_id() -> Result<()> {
    let temp = isolated();
    fs::write(temp.path().join("key"), [0x42; 32])?;
    let root = SafeRoot::open(temp.path())?;
    let (_file, before) = root.read_file("key")?;
    File::options()
        .write(true)
        .open(temp.path().join("key"))?
        .set_times(
            fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000)),
        )?;
    assert!(root.verify_file("key", &before).is_err());
    assert!(root.contains_file_identity(&before)?);
    let mut wrong_device = before.clone();
    wrong_device.device ^= 1;
    assert!(!root.contains_file_identity(&wrong_device)?);
    let mut wrong_id = before;
    wrong_id.file_id[0] ^= 1;
    assert!(!root.contains_file_identity(&wrong_id)?);
    Ok(())
}

#[test]
fn file_identity_search_refuses_a_symlink_instead_of_following_or_skipping_it() -> Result<()> {
    let temp = isolated();
    let keys_path = temp.path().join("keys");
    let source_path = temp.path().join("capture");
    fs::create_dir(&keys_path)?;
    fs::create_dir(&source_path)?;
    let key_path = keys_path.join("key");
    fs::write(&key_path, [0x43; 32])?;
    let keys = SafeRoot::open(&keys_path)?;
    let source = SafeRoot::open(&source_path)?;
    let (_file, stamp) = keys.read_file("key")?;
    symlink(&key_path, source_path.join("alias"))?;
    assert!(source.contains_file_identity(&stamp).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn case_alias_overlap_uses_native_identity_when_the_filesystem_supports_it() -> Result<()> {
    let temp = isolated();
    let original = temp.path().join("CaseRoot");
    let alias = temp.path().join("caseroot");
    fs::create_dir(&original)?;
    match fs::metadata(&alias) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    fs::write(original.join("key"), [0x44; 32])?;
    let original = SafeRoot::open(&original)?;
    let alias = SafeRoot::open(&alias)?;
    assert!(original.overlaps(&alias)?);
    assert!(alias.overlaps(&original)?);
    assert!(original.same_root(&alias)?);
    assert!(alias.same_root(&original)?);
    let (_file, stamp) = original.read_file("key")?;
    assert!(alias.contains_file_identity(&stamp)?);
    Ok(())
}

#[test]
fn private_file_verification_rejects_public_modes_hard_links_and_directories() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    root.write_new("key", |file| {
        file.write_all(&[0x46; 32])?;
        Ok(())
    })?;
    let (file, _) = root.read_file("key")?;
    verify_private_file(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    assert!(verify_private_file(&file).is_err());
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    verify_private_file(&file)?;
    fs::hard_link(temp.path().join("key"), temp.path().join("key-alias"))?;
    assert!(verify_private_file(&file).is_err());
    fs::remove_file(temp.path().join("key-alias"))?;
    verify_private_file(&file)?;
    assert!(verify_private_file(&File::open(temp.path())?).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn native_mac_extended_acl_is_rejected_even_when_unix_mode_is_0600() -> Result<()> {
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    root.write_new("key", |file| {
        file.write_all(&[0x47; 32])?;
        Ok(())
    })?;
    let (file, _) = root.read_file("key")?;
    verify_private_file(&file)?;
    macos_acl_fixture::grant_read(&file, false)?;
    assert_eq!(file.metadata()?.permissions().mode() & 0o7777, 0o600);
    assert!(verify_private_file(&file).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_mac_extended_acl_is_rejected_before_the_writer_runs() -> Result<()> {
    let temp = isolated();
    let parent = temp.path().join("private-parent");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    macos_acl_fixture::grant_read(&File::open(&parent)?, true)?;
    assert_eq!(fs::metadata(&parent)?.permissions().mode() & 0o7777, 0o700);
    assert!(ensure_private_directory(&parent).is_err());
    let root = SafeRoot::open(&parent)?;
    let called = AtomicBool::new(false);
    assert!(root
        .write_new("recovery-key", |file| {
            called.store(true, Ordering::SeqCst);
            file.write_all(&[0x48; 32])?;
            Ok(())
        })
        .is_err());
    assert!(!called.load(Ordering::SeqCst));
    assert!(root.entries()?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_posix_acl_is_rejected_even_with_a_zero_group_mask() -> Result<()> {
    use std::os::fd::AsRawFd;
    let temp = isolated();
    let root = SafeRoot::open(temp.path())?;
    root.write_new("key", |file| {
        file.write_all(&[0x49; 32])?;
        Ok(())
    })?;
    let (file, _) = root.read_file("key")?;
    verify_private_file(&file)?;
    // Linux's bounded native POSIX ACL xattr format: version then 8-byte
    // tag/permissions/qualifier entries. The named entry is masked off, so the
    // mode stays 0600 even though an extended ACL is actually present.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, qualifier) in [
        (0x01u16, 6u16, u32::MAX),
        (0x02, 4, unsafe { libc::geteuid() }),
        (0x04, 0, u32::MAX),
        (0x10, 0, u32::MAX),
        (0x20, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&qualifier.to_le_bytes());
    }
    let status = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(file.metadata()?.permissions().mode() & 0o7777, 0o600);
    assert!(verify_private_file(&file).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_linux_default_acl_is_rejected_before_the_writer_runs() -> Result<()> {
    use std::os::fd::AsRawFd;
    let temp = isolated();
    let parent = temp.path().join("private-parent");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    let directory = File::open(&parent)?;
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, permissions) in [(0x01u16, 7u16), (0x04, 0), (0x20, 0)] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    let status = unsafe {
        libc::fsetxattr(
            directory.as_raw_fd(),
            c"system.posix_acl_default".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    assert!(ensure_private_directory(&parent).is_err());
    let root = SafeRoot::open(&parent)?;
    let called = AtomicBool::new(false);
    assert!(root
        .write_new("recovery-key", |_| {
            called.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert!(!called.load(Ordering::SeqCst));
    assert!(root.entries()?.is_empty());
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_acl_fixture {
    use anyhow::{Context, Result};
    use std::{ffi::c_void, fs::File, io, os::fd::AsRawFd, ptr};

    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const ACL_READ_DATA: libc::c_int = 1 << 1;
    const ACL_ENTRY_FILE_INHERIT: libc::c_int = 1 << 5;
    const ACL_ENTRY_DIRECTORY_INHERIT: libc::c_int = 1 << 6;

    unsafe extern "C" {
        fn acl_init(count: libc::c_int) -> *mut c_void;
        fn acl_create_entry(acl: *mut *mut c_void, entry: *mut *mut c_void) -> libc::c_int;
        fn acl_set_tag_type(entry: *mut c_void, tag: libc::c_int) -> libc::c_int;
        fn acl_set_qualifier(entry: *mut c_void, qualifier: *const c_void) -> libc::c_int;
        fn acl_get_permset(entry: *mut c_void, permissions: *mut *mut c_void) -> libc::c_int;
        fn acl_add_perm(permissions: *mut c_void, permission: libc::c_int) -> libc::c_int;
        fn acl_set_permset(entry: *mut c_void, permissions: *mut c_void) -> libc::c_int;
        fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> libc::c_int;
        fn acl_add_flag_np(flags: *mut c_void, flag: libc::c_int) -> libc::c_int;
        fn acl_set_flagset_np(entry: *mut c_void, flags: *mut c_void) -> libc::c_int;
        fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
        fn acl_free(acl: *mut c_void) -> libc::c_int;
        fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
    }

    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe { acl_free(self.0) };
        }
    }

    fn checked(status: libc::c_int) -> Result<()> {
        if status != 0 {
            return Err(io::Error::last_os_error())
                .context("construct isolated native ACL fixture");
        }
        Ok(())
    }

    /// A real current-user allow ACE is sufficient to test the stricter policy
    /// of rejecting every extended ACL, including benign owner-only entries.
    /// No privileges, subprocesses, production keys, or home data are involved.
    pub(super) fn grant_read(file: &File, inherit: bool) -> Result<()> {
        let mut acl = Acl(unsafe { acl_init(1) });
        if acl.0.is_null() {
            return Err(io::Error::last_os_error()).context("allocate native ACL fixture");
        }
        let mut entry = ptr::null_mut();
        checked(unsafe { acl_create_entry(&mut acl.0, &mut entry) })?;
        checked(unsafe { acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) })?;
        let mut uuid = [0u8; 16];
        let status = unsafe { mbr_uid_to_uuid(libc::geteuid(), uuid.as_mut_ptr()) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status))
                .context("resolve current-user ACL UUID");
        }
        checked(unsafe { acl_set_qualifier(entry, uuid.as_ptr().cast()) })?;
        let mut permissions = ptr::null_mut();
        checked(unsafe { acl_get_permset(entry, &mut permissions) })?;
        checked(unsafe { acl_add_perm(permissions, ACL_READ_DATA) })?;
        checked(unsafe { acl_set_permset(entry, permissions) })?;
        if inherit {
            let mut flags = ptr::null_mut();
            checked(unsafe { acl_get_flagset_np(entry, &mut flags) })?;
            checked(unsafe { acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT) })?;
            checked(unsafe { acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT) })?;
            checked(unsafe { acl_set_flagset_np(entry, flags) })?;
        }
        checked(unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) })
    }
}

#[test]
fn directories_are_only_computed_and_capabilities_do_not_claim_packaging_acceptance() -> Result<()>
{
    let directories = quicksave_platform::app_directories()?;
    assert_eq!(directories["application"], "QuickSave");
    assert_eq!(directories["created"], false);
    for key in ["data", "config", "cache", "runtime"] {
        let path = PathBuf::from(directories[key].as_str().unwrap());
        assert!(path.is_absolute());
        assert!(path
            .components()
            .any(|component| component.as_os_str() == "QuickSave"));
    }
    let capabilities = quicksave_platform::capabilities();
    assert_eq!(capabilities["filesystem"]["durable_create_new"], true);
    assert_eq!(
        capabilities["filesystem"]["private_file_verification"],
        true
    );
    assert_eq!(
        capabilities["filesystem"]["application_atomic_snapshots"],
        false
    );
    for platform in ["macos", "windows", "linux"] {
        assert_eq!(capabilities["packaging_acceptance"][platform], false);
    }
    Ok(())
}
