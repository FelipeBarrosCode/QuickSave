// SPDX-License-Identifier: GPL-3.0-only
#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use quicksave_engine::{
    backup, initialize, initialize_with_key, restore, snapshots, RepositoryKey,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    repository: PathBuf,
    source: PathBuf,
    key: RepositoryKey,
}

impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-engine-integration-")
            .tempdir_in(parent)
            .unwrap();
        let repository = temporary.path().join("repository");
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        let key = initialize(&repository).unwrap();
        Self {
            _temporary: temporary,
            repository,
            source,
            key,
        }
    }

    fn destination(&self, name: &str) -> PathBuf {
        let destination = self._temporary.path().join(name);
        fs::create_dir(&destination).unwrap();
        destination
    }
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn collect(root: &Path, path: &Path, output: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    collect(root, root, &mut result);
    result
}

#[test]
fn readonly_source_roundtrip_incremental_and_two_version_history() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.source.join("nested/empty-directory")).unwrap();
    fs::write(fixture.source.join("empty-file"), b"").unwrap();
    fs::write(
        fixture.source.join("nested/save.bin"),
        b"initial save bytes",
    )
    .unwrap();
    fs::write(fixture.source.join("readonly"), b"read only source content").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            fixture.source.join("readonly"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
    }
    let original = files(&fixture.source);
    let first = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert_eq!(first["totalFiles"], 3);
    assert_eq!(first["totalDirectories"], 2);
    assert!(first["newChunks"].as_u64().unwrap() > 0);
    assert!(first["newBytes"].as_u64().unwrap() > 0);
    assert_eq!(first["id"], first["snapshotId"]);
    assert!(first["createdAt"].is_string());
    assert_eq!(files(&fixture.source), original);

    let second = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert_eq!(second["newChunks"], 0);
    assert_eq!(second["newBytes"], 0);
    assert!(second["reusedChunks"].as_u64().unwrap() > 0);
    assert_ne!(first["id"], second["id"]);
    let history = snapshots(&fixture.repository, &fixture.key).unwrap();
    assert_eq!(history.as_array().unwrap().len(), 2);

    let destination = fixture.destination("restored");
    restore(
        &fixture.repository,
        first["id"].as_str().unwrap(),
        &destination,
        &fixture.key,
    )
    .unwrap();
    assert_eq!(files(&destination), original);
    assert!(destination.join("nested/empty-directory").is_dir());
    assert_eq!(files(&fixture.source), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.source.join("readonly"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
    }
}

#[test]
fn changed_files_add_chunks_and_old_version_remains_restorable() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("save"), b"version one").unwrap();
    let first = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    fs::write(
        fixture.source.join("save"),
        b"version two with different bytes",
    )
    .unwrap();
    fs::write(fixture.source.join("new"), b"a new independent file").unwrap();
    let second = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert!(second["newChunks"].as_u64().unwrap() > 0);
    assert_eq!(second["totalFiles"], 2);
    assert_eq!(
        snapshots(&fixture.repository, &fixture.key)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let old_destination = fixture.destination("old");
    restore(
        &fixture.repository,
        first["id"].as_str().unwrap(),
        &old_destination,
        &fixture.key,
    )
    .unwrap();
    assert_eq!(
        fs::read(old_destination.join("save")).unwrap(),
        b"version one"
    );
    assert!(!old_destination.join("new").exists());
    let new_destination = fixture.destination("new");
    restore(
        &fixture.repository,
        second["id"].as_str().unwrap(),
        &new_destination,
        &fixture.key,
    )
    .unwrap();
    assert_eq!(files(&new_destination), files(&fixture.source));
}

#[test]
fn wrong_key_fails_before_repository_or_destination_mutation() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("save"), b"data").unwrap();
    let capture = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    let before = files(&fixture.repository);
    let wrong = RepositoryKey::from_bytes([0x51; 32]);
    let destination = fixture.destination("destination");
    assert!(backup(&fixture.repository, &fixture.source, &wrong).is_err());
    assert!(snapshots(&fixture.repository, &wrong).is_err());
    assert!(restore(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &destination,
        &wrong
    )
    .is_err());
    assert_eq!(files(&fixture.repository), before);
    assert!(fs::read_dir(destination).unwrap().next().is_none());
}

#[test]
fn nonempty_destination_is_never_touched_even_when_bytes_match() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("save"), b"snapshot bytes").unwrap();
    let capture = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    let destination = fixture.destination("nonempty");
    fs::write(destination.join("save"), b"existing user bytes").unwrap();
    let before = files(&destination);
    assert!(restore(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &destination,
        &fixture.key
    )
    .is_err());
    assert_eq!(files(&destination), before);
}

#[test]
fn corruption_and_missing_chunks_fail_preflight_without_output() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("first"), b"first file bytes").unwrap();
    fs::write(fixture.source.join("second"), b"second file bytes").unwrap();
    let capture = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    let object = fs::read_dir(fixture.repository.join("quicksave/objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = fs::read(&object).unwrap();
    let mut corrupt = original.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x80;
    fs::write(&object, &corrupt).unwrap();
    let destination = fixture.destination("corrupt");
    assert!(restore(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &destination,
        &fixture.key
    )
    .is_err());
    assert!(fs::read_dir(&destination).unwrap().next().is_none());
    assert!(backup(&fixture.repository, &fixture.source, &fixture.key).is_err());
    assert_eq!(fs::read(&object).unwrap(), corrupt);
    fs::remove_file(&object).unwrap();
    assert!(restore(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &destination,
        &fixture.key
    )
    .is_err());
    assert!(fs::read_dir(destination).unwrap().next().is_none());
}

#[test]
fn overlaps_duplicate_roots_and_traversal_ids_fail_closed() {
    let fixture = Fixture::new();
    assert!(backup(&fixture.repository, &fixture.repository, &fixture.key).is_err());
    assert!(backup(&fixture.repository, fixture._temporary.path(), &fixture.key).is_err());
    let nested = fixture.repository.join("quicksave/inside");
    fs::create_dir(&nested).unwrap();
    assert!(backup(&fixture.repository, &nested, &fixture.key).is_err());
    let capture = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert!(restore(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &nested,
        &fixture.key
    )
    .is_err());
    let destination = fixture.destination("destination");
    for id in ["../outside", "/absolute", "a/b", "", "LATEST"] {
        assert!(restore(&fixture.repository, id, &destination, &fixture.key).is_err());
    }
    assert!(fs::read_dir(destination).unwrap().next().is_none());
}

#[test]
fn empty_tree_and_empty_file_roundtrip() {
    let fixture = Fixture::new();
    let empty = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert_eq!(empty["totalFiles"], 0);
    assert_eq!(empty["newChunks"], 0);
    let destination = fixture.destination("empty-tree");
    restore(
        &fixture.repository,
        empty["id"].as_str().unwrap(),
        &destination,
        &fixture.key,
    )
    .unwrap();
    assert!(fs::read_dir(destination).unwrap().next().is_none());
    fs::write(fixture.source.join("empty"), b"").unwrap();
    let single = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert_eq!(single["newChunks"], 0);
    assert_eq!(single["logicalBytes"], 0);
    let destination = fixture.destination("empty-file");
    restore(
        &fixture.repository,
        single["id"].as_str().unwrap(),
        &destination,
        &fixture.key,
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("empty")).unwrap(), b"");
}

#[test]
fn external_key_initialization_and_no_land_refusal_do_not_store_keys() {
    let fixture = Fixture::new();
    let repository = fixture._temporary.path().join("explicit-key-repository");
    let key = RepositoryKey::from_bytes([0xa9; 32]);
    let initialized = initialize_with_key(&repository, &key).unwrap();
    assert_eq!(initialized["keyStoredInRepository"], false);
    assert!(snapshots(&repository, &key)
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    for bytes in files(&repository).values() {
        assert!(!bytes.windows(32).any(|window| window == key.as_bytes()));
    }
    assert!(initialize_with_key(&repository, &key).is_err());
    let foreign = fixture._temporary.path().join("old-repository");
    quicksave_platform::ensure_private_directory(&foreign).unwrap();
    fs::write(foreign.join("bundle.manifest.json"), b"No Land metadata").unwrap();
    let before = files(&foreign);
    assert!(initialize(&foreign).is_err());
    assert_eq!(files(&foreign), before);
    assert!(snapshots(&foreign, &key).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_roots_entries_and_repository_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let outside = fixture._temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"unapproved bytes").unwrap();
    symlink(&outside, fixture.source.join("link")).unwrap();
    assert!(backup(&fixture.repository, &fixture.source, &fixture.key).is_err());
    fs::remove_file(fixture.source.join("link")).unwrap();
    let source_alias = fixture._temporary.path().join("source-alias");
    symlink(&fixture.source, &source_alias).unwrap();
    assert!(backup(&fixture.repository, &source_alias, &fixture.key).is_err());
    let parent_alias = fixture._temporary.path().join("parent-alias");
    symlink(&outside, &parent_alias).unwrap();
    assert!(initialize(&parent_alias.join("repository")).is_err());
    assert!(!outside.join("repository").exists());
    assert_eq!(
        fs::read(outside.join("secret")).unwrap(),
        b"unapproved bytes"
    );
}

#[cfg(unix)]
#[test]
fn repository_is_private_and_nonprivate_existing_roots_are_not_chmodded() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    assert_eq!(
        fs::metadata(&fixture.repository)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let public = fixture._temporary.path().join("public");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(initialize(&public).is_err());
    assert_eq!(
        fs::metadata(&public).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(fs::read_dir(public).unwrap().next().is_none());
}

#[test]
fn large_file_fastcdc_incremental_append_reuses_existing_chunks() {
    use std::io::Write;
    let fixture = Fixture::new();
    let mut state = 0x1234_5678_90ab_cdef_u64;
    let bytes: Vec<_> = (0..18 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    let path = fixture.source.join("large");
    fs::write(&path, &bytes).unwrap();
    let first = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert!(first["newChunks"].as_u64().unwrap() >= 3);
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&vec![0x9d; 64 * 1024])
        .unwrap();
    let second = backup(&fixture.repository, &fixture.source, &fixture.key).unwrap();
    assert!(second["reusedChunks"].as_u64().unwrap() > 0);
    assert!(second["newChunks"].as_u64().unwrap() > 0);
    let destination = fixture.destination("old-large");
    restore(
        &fixture.repository,
        first["id"].as_str().unwrap(),
        &destination,
        &fixture.key,
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("large")).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn source_directory_can_be_readonly_and_is_not_changed() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fs::write(fixture.source.join("save"), b"readonly source bytes").unwrap();
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o500)).unwrap();
    let result = backup(&fixture.repository, &fixture.source, &fixture.key);
    let mode = fs::metadata(&fixture.source).unwrap().permissions().mode() & 0o777;
    // Restore permission only on this test's own temporary root for cleanup.
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o700)).unwrap();
    result.unwrap();
    assert_eq!(mode, 0o500);
    assert_eq!(
        fs::read(fixture.source.join("save")).unwrap(),
        b"readonly source bytes"
    );
}
