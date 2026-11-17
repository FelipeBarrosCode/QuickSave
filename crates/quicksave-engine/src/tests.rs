// SPDX-License-Identifier: GPL-3.0-only

use std::{fs, path::PathBuf};

use anyhow::Result;
use quicksave_content::{hash, seal, RepositoryKey};

use crate::{
    backup, capture::backup_with_validation_hook, format::*, initialize, repository::Repository,
    restore, snapshots,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    repository: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    key: RepositoryKey,
}

impl Fixture {
    fn new() -> Self {
        // macOS's conventional /var temp spelling is a symlink. Tests approve
        // the real temporary parent explicitly, never a production directory.
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-engine-unit-")
            .tempdir_in(base)
            .unwrap();
        let repository = temporary.path().join("repository");
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let key = initialize(&repository).unwrap();
        Self {
            _temporary: temporary,
            repository,
            source,
            destination,
            key,
        }
    }

    fn capture(&self) -> serde_json::Value {
        backup(&self.repository, &self.source, &self.key).unwrap()
    }

    fn count_commits(&self) -> usize {
        snapshots(&self.repository, &self.key)
            .unwrap()
            .as_array()
            .unwrap()
            .len()
    }

    fn rewrite_commit(&self, commit: &Commit) {
        let plain = serialize_bounded(commit, MAX_COMMIT_BYTES).unwrap();
        let encrypted = seal(
            &self.key,
            &context(
                &commit.repository_id,
                "snapshot-commit",
                &commit.snapshot_id,
            ),
            &plain,
        )
        .unwrap();
        // Deliberate test-only attacker/corruption injection into isolated data.
        fs::write(
            self.repository
                .join(commit_path(&commit.snapshot_id).unwrap()),
            encrypted,
        )
        .unwrap();
    }
}

#[test]
fn same_length_source_modification_prevents_commit() {
    let fixture = Fixture::new();
    let path = fixture.source.join("file");
    fs::write(&path, b"before").unwrap();
    let result =
        backup_with_validation_hook(&fixture.repository, &fixture.source, &fixture.key, || {
            fs::write(&path, b"after!").unwrap();
            Ok(())
        });
    assert!(result.is_err());
    assert_eq!(fixture.count_commits(), 0);
    assert_eq!(fs::read(&path).unwrap(), b"after!");
}

#[test]
fn tree_addition_prevents_commit_and_keeps_source() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("original"), b"original").unwrap();
    let result =
        backup_with_validation_hook(&fixture.repository, &fixture.source, &fixture.key, || {
            fs::write(fixture.source.join("added"), b"added").unwrap();
            Ok(())
        });
    assert!(result.is_err());
    assert_eq!(fixture.count_commits(), 0);
    assert_eq!(
        fs::read(fixture.source.join("original")).unwrap(),
        b"original"
    );
    assert_eq!(fs::read(fixture.source.join("added")).unwrap(), b"added");
}

#[test]
fn tree_removal_prevents_commit() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.source.join("empty")).unwrap();
    let result =
        backup_with_validation_hook(&fixture.repository, &fixture.source, &fixture.key, || {
            fs::remove_dir(fixture.source.join("empty")).unwrap();
            Ok(())
        });
    assert!(result.is_err());
    assert_eq!(fixture.count_commits(), 0);
}

#[test]
fn replacement_by_same_length_file_prevents_commit() {
    let fixture = Fixture::new();
    let path = fixture.source.join("file");
    fs::write(&path, b"same").unwrap();
    let result =
        backup_with_validation_hook(&fixture.repository, &fixture.source, &fixture.key, || {
            fs::rename(&path, fixture.source.join("old")).unwrap();
            fs::write(&path, b"same").unwrap();
            fs::remove_file(fixture.source.join("old")).unwrap();
            Ok(())
        });
    assert!(result.is_err());
    assert_eq!(fixture.count_commits(), 0);
}

#[test]
fn writer_lock_excludes_second_writer_without_blocking_history() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file"), b"data").unwrap();
    fixture.capture();
    let repository = Repository::open(&fixture.repository, &fixture.key).unwrap();
    let _lock = repository.lock_writer().unwrap();
    let error = backup(&fixture.repository, &fixture.source, &fixture.key)
        .unwrap_err()
        .to_string();
    assert!(error.contains("active writer"));
    assert_eq!(fixture.count_commits(), 1);
}

#[test]
fn authenticated_path_traversal_is_rejected_before_any_output() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file"), b"data").unwrap();
    let capture = fixture.capture();
    let id = capture["snapshotId"].as_str().unwrap();
    let repository = Repository::open(&fixture.repository, &fixture.key).unwrap();
    let mut commit = repository.load_commit(id).unwrap();
    match &mut commit.nodes[0] {
        Node::File { path, .. } => *path = "../escaped".to_owned(),
        _ => panic!("expected file"),
    }
    fixture.rewrite_commit(&commit);
    assert!(restore(&fixture.repository, id, &fixture.destination, &fixture.key).is_err());
    assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none());
    assert!(!fixture
        .destination
        .parent()
        .unwrap()
        .join("escaped")
        .exists());
}

#[test]
fn case_collision_and_parent_file_collision_are_rejected() {
    let file = |path: &str| Node::File {
        path: path.to_owned(),
        index: hash(b"index"),
        hash: hash(b""),
        size: 0,
    };
    assert!(validate_nodes(&[file("SAVE"), file("save")]).is_err());
    assert!(validate_nodes(&[file("file"), file("file/child")]).is_err());
    assert!(validate_nodes(&[
        Node::Directory {
            path: "Dir".to_owned()
        },
        file("dir/child")
    ])
    .is_err());
    assert!(validate_nodes(&[file("same"), file("same")]).is_err());
}

#[test]
fn unicode_casefold_and_normalization_aliases_are_rejected() {
    let directory = |path: &str| Node::Directory {
        path: path.to_owned(),
    };
    assert!(validate_nodes(&[directory("Straße"), directory("STRASSE")]).is_err());
    assert!(validate_nodes(&[directory("I"), directory("ı")]).is_err());
    assert!(validate_nodes(&[directory("café"), directory("cafe\u{301}")]).is_err());
    assert!(validate_nodes(&[directory("Ａ"), directory("A")]).is_err());
}

#[test]
fn invalid_portable_paths_are_rejected() {
    for path in [
        "",
        "/absolute",
        "../outside",
        "a/../outside",
        "a//b",
        "./a",
        "a/",
        "C:/outside",
        r"a\outside",
        "a\0b",
        "nul",
        "CON.txt",
        "lpt1.log",
        "LPT¹.txt",
        "CONIN$",
        "name.",
        "name ",
        "a:b",
        "wild*",
    ] {
        assert!(validate_relative(path).is_err(), "accepted {path:?}");
    }
    assert!(validate_relative(&"a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
    assert!(validate_relative(&vec!["a"; MAX_PATH_DEPTH + 1].join("/")).is_err());
    assert!(validate_relative("ordinary/Unicode-数据.txt").is_ok());
}

#[test]
fn metadata_bounds_are_not_raised_or_bypassed() {
    assert_eq!(MAX_METADATA_BYTES, 512 * 1024 * 1024);
    const { assert!(MAX_COMMIT_BYTES <= MAX_METADATA_BYTES) };
    const { assert!(MAX_INDEX_BYTES <= MAX_METADATA_BYTES) };
    assert!(serialize_bounded(&"too long", 2).is_err());
    assert!(serialize_bounded(&"", MAX_METADATA_BYTES + 1).is_err());
    assert_eq!(serialize_bounded(&"ok", 4).unwrap(), b"\"ok\"");
}

#[test]
fn published_limits_match_engine_guards_not_platform_walk_limits() {
    let limits = crate::limits();
    assert_eq!(limits["maxTreeEntries"], 250_000);
    assert_eq!(limits["maxTreePathBytes"], 32 * 1024 * 1024);
    assert_eq!(limits["maxCommitBytes"], 64 * 1024 * 1024);
    assert_eq!(limits["maxIndexBytes"], MAX_INDEX_BYTES);
    assert_eq!(limits["maxChunkBytes"], MAX_CHUNK_BYTES);
    assert_eq!(limits["maxFileBytes"], MAX_FILE_BYTES);
    assert_eq!(limits["maxChunksPerFile"], MAX_CHUNKS_PER_FILE);
    assert_eq!(limits["captureConsistency"], CONSISTENCY);
    assert_eq!(MAX_METADATA_BYTES, 512 * 1024 * 1024);
}

#[test]
fn synthetic_186735_file_commit_roundtrip_fits_unchanged_metadata_guard() {
    const FILE_COUNT: usize = 186_735;
    const PATH_LENGTH: usize = 80;
    let repository_id = "11111111-1111-4111-8111-111111111111";
    let snapshot_id = "22222222-2222-4222-8222-222222222222";
    let empty_hash = hash(b"");
    let index = FileIndex {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: repository_id.to_owned(),
        hash: empty_hash.clone(),
        size: 0,
        chunks: Vec::new(),
    };
    let index_id = hash(&serialize_bounded(&index, MAX_INDEX_BYTES).unwrap());
    let padding = "p".repeat(56);
    let nodes: Vec<_> = (0..FILE_COUNT)
        .map(|number| {
            let path = format!("save-profile-{number:06}-{padding}.bin");
            assert_eq!(path.len(), PATH_LENGTH);
            Node::File {
                path,
                index: index_id.clone(),
                hash: empty_hash.clone(),
                size: 0,
            }
        })
        .collect();
    assert!(nodes.windows(2).all(|pair| pair[0].path() < pair[1].path()));
    const { assert!(FILE_COUNT * PATH_LENGTH <= MAX_TREE_PATH_BYTES) };
    let commit = Commit {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: repository_id.to_owned(),
        snapshot_id: snapshot_id.to_owned(),
        created_at: "2026-11-17T00:00:00.000Z".to_owned(),
        capture_consistency: CONSISTENCY.to_owned(),
        summary: Summary {
            total_files: FILE_COUNT as u64,
            ..Summary::default()
        },
        nodes,
    };
    validate_commit(&commit, repository_id, snapshot_id).unwrap();
    let mut encoded = serialize_bounded(&commit, MAX_COMMIT_BYTES).unwrap();
    assert!(encoded.len() < 64 * 1024 * 1024);
    assert_eq!(MAX_METADATA_BYTES, 512 * 1024 * 1024);
    // Keep one owned tree at a time: do not clone the 186,735-file manifest.
    drop(commit);
    let decoded: Commit = serde_json::from_slice(&encoded).unwrap();
    validate_commit(&decoded, repository_id, snapshot_id).unwrap();
    assert_eq!(decoded.nodes.len(), FILE_COUNT);
    assert_eq!(
        decoded
            .nodes
            .iter()
            .filter(|node| !node.is_directory())
            .count(),
        FILE_COUNT
    );
    assert_eq!(decoded.summary.total_files, FILE_COUNT as u64);
    drop(decoded);

    // Exercise the raised count guard with real bounded JSON, still without
    // another manifest copy or any physical files. Duplicate directory names
    // are intentional: decoding itself must hit the sequence-count guard
    // before the later semantic duplicate-path pass can run.
    assert!(encoded.ends_with(b"]}"));
    encoded.truncate(encoded.len() - 2);
    let extra = b",{\"kind\":\"directory\",\"path\":\"overflow\"}";
    for _ in FILE_COUNT..=MAX_TREE_ENTRIES {
        encoded.extend_from_slice(extra);
    }
    encoded.extend_from_slice(b"]}");
    assert!(encoded.len() < MAX_COMMIT_BYTES);
    let error = serde_json::from_slice::<Commit>(&encoded).err().unwrap();
    assert!(
        error.to_string().contains("sequence count limit exceeded"),
        "unexpected count-guard error: {error}"
    );
}

#[test]
fn verify_repository_authenticates_identity_without_history_or_source_inspection() {
    let fixture = Fixture::new();
    let initialized = crate::verify_repository(&fixture.repository, &fixture.key).unwrap();
    assert_eq!(initialized["id"], initialized["repositoryId"]);
    assert_eq!(initialized["format"], FORMAT);
    assert_eq!(initialized["version"], VERSION);
    // The identity-only check must not scan or parse an unrelated broken
    // history entry (and has no source/destination parameter to grant).
    let id = uuid::Uuid::new_v4().to_string();
    fs::write(
        fixture.repository.join(commit_path(&id).unwrap()),
        b"not authenticated history",
    )
    .unwrap();
    assert!(snapshots(&fixture.repository, &fixture.key).is_err());
    assert!(crate::verify_repository(&fixture.repository, &fixture.key).is_ok());
    assert!(
        crate::verify_repository(&fixture.repository, &RepositoryKey::from_bytes([0x17; 32]))
            .is_err()
    );
}

#[test]
fn deserialize_counts_and_paths_are_limited_before_retaining_payloads() {
    let mut index = FileIndex {
        format: FORMAT.to_owned(),
        version: VERSION,
        repository_id: uuid::Uuid::new_v4().to_string(),
        hash: hash(b""),
        size: 0,
        chunks: vec![
            ChunkRef {
                hash: hash(b"x"),
                size: 1,
            };
            MAX_CHUNKS_PER_FILE + 1
        ],
    };
    let encoded = serde_json::to_vec(&index).unwrap();
    assert!(serde_json::from_slice::<FileIndex>(&encoded).is_err());
    index.chunks.clear();
    assert!(serde_json::from_slice::<FileIndex>(&serde_json::to_vec(&index).unwrap()).is_ok());

    let oversized = serde_json::json!({
        "kind": "directory",
        "path": "a".repeat(MAX_COMPONENT_BYTES + 1)
    });
    assert!(serde_json::from_value::<Node>(oversized).is_err());
    let extra_payload = r#"{"kind":"directory","path":"valid","unknown":[{"many":"values"}]}"#;
    assert!(serde_json::from_str::<Node>(extra_payload).is_err());
}

#[test]
fn full_file_hash_is_checked_before_restore_writes() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file"), b"data").unwrap();
    let capture = fixture.capture();
    let id = capture["snapshotId"].as_str().unwrap();
    let repository = Repository::open(&fixture.repository, &fixture.key).unwrap();
    let mut commit = repository.load_commit(id).unwrap();
    let Node::File {
        index: index_id,
        hash: file_hash,
        ..
    } = &mut commit.nodes[0]
    else {
        panic!("expected file")
    };
    let mut index = repository.load_index(index_id).unwrap();
    index.hash = hash(b"other");
    *file_hash = index.hash.clone();
    let plain = serialize_bounded(&index, MAX_INDEX_BYTES).unwrap();
    *index_id = hash(&plain);
    repository
        .store_immutable(
            &index_path(index_id).unwrap(),
            "file-index",
            index_id,
            &plain,
            MAX_INDEX_BYTES,
        )
        .unwrap();
    fixture.rewrite_commit(&commit);
    assert!(restore(&fixture.repository, id, &fixture.destination, &fixture.key).is_err());
    assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none());
}

#[test]
fn copying_object_between_repository_contexts_does_not_authenticate() {
    let first = Fixture::new();
    let second = Fixture::new();
    // Use the same key deliberately: repository ID is still independently bound.
    let third_path = second._temporary.path().join("same-key-repository");
    crate::initialize_with_key(&third_path, &first.key).unwrap();
    fs::write(first.source.join("file"), b"data").unwrap();
    first.capture();
    let first_object = fs::read_dir(first.repository.join(OBJECTS))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let object_name = first_object.file_name().unwrap();
    fs::copy(&first_object, third_path.join(OBJECTS).join(object_name)).unwrap();
    fs::write(second.source.join("file"), b"data").unwrap();
    assert!(backup(&third_path, &second.source, &first.key).is_err());
}

#[test]
fn repository_identity_id_is_authenticated() {
    let fixture = Fixture::new();
    let identity_path = fixture.repository.join(IDENTITY_PATH);
    let mut identity: Identity =
        serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
    identity.repository_id = uuid::Uuid::new_v4().to_string();
    fs::write(&identity_path, serde_json::to_vec(&identity).unwrap()).unwrap();
    assert!(snapshots(&fixture.repository, &fixture.key).is_err());
}

#[test]
fn history_ignores_uncommitted_objects_but_not_corrupt_final_commits() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file"), b"data").unwrap();
    let capture = fixture.capture();
    fs::write(
        fixture.repository.join(COMMITS).join("unfinished.tmp"),
        b"not a commit",
    )
    .unwrap();
    assert_eq!(fixture.count_commits(), 1);
    fs::write(
        fixture
            .repository
            .join(commit_path(capture["id"].as_str().unwrap()).unwrap()),
        b"corrupt final commit",
    )
    .unwrap();
    assert!(snapshots(&fixture.repository, &fixture.key).is_err());
}

#[test]
fn native_lock_file_symlink_is_not_followed() -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let lock = fixture.repository.join(LOCK_PATH);
        fs::remove_file(&lock)?;
        let external = fixture._temporary.path().join("external");
        fs::write(&external, LOCK_BYTES)?;
        symlink(&external, &lock)?;
        assert!(backup(&fixture.repository, &fixture.source, &fixture.key).is_err());
        assert_eq!(fs::read(external)?, LOCK_BYTES);
    }
    Ok(())
}

#[test]
fn late_restore_corruption_retains_completed_new_entries_and_removes_failed_stage() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("a-good"), b"good").unwrap();
    fs::write(fixture.source.join("z-bad"), b"bad").unwrap();
    let capture = fixture.capture();
    let id = capture["id"].as_str().unwrap();
    let repository = Repository::open(&fixture.repository, &fixture.key).unwrap();
    let commit = repository.load_commit(id).unwrap();
    let Node::File { index, .. } = commit.nodes.last().unwrap() else {
        panic!("expected file")
    };
    let index = repository.load_index(index).unwrap();
    let bad_object = fixture
        .repository
        .join(object_path(&index.chunks[0].hash).unwrap());
    let error = crate::restore::restore_with_write_hook(
        &fixture.repository,
        id,
        &fixture.destination,
        &fixture.key,
        || {
            fs::write(&bad_object, b"changed after preflight")?;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("retained for inspection"));
    assert_eq!(
        fs::read(fixture.destination.join("a-good")).unwrap(),
        b"good"
    );
    assert!(!fixture.destination.join("z-bad").exists());
    assert_eq!(fs::read_dir(&fixture.destination).unwrap().count(), 1);
}

#[test]
fn destination_race_does_not_clobber_or_remove_an_external_entry() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("file"), b"snapshot bytes").unwrap();
    fs::create_dir(fixture.source.join("new-empty-directory")).unwrap();
    let capture = fixture.capture();
    let error = crate::restore::restore_with_write_hook(
        &fixture.repository,
        capture["id"].as_str().unwrap(),
        &fixture.destination,
        &fixture.key,
        || {
            fs::write(fixture.destination.join("file"), b"concurrent user bytes")?;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("retained for inspection"));
    assert_eq!(
        fs::read(fixture.destination.join("file")).unwrap(),
        b"concurrent user bytes"
    );
    assert!(fixture.destination.join("new-empty-directory").is_dir());
}

#[test]
#[ignore = "invoked only by the isolated cross-process lock test"]
fn writer_lock_child_process() {
    let Some(directory) = std::env::var_os("QUICKSAVE_ENGINE_TEST_LOCK_ROOT") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let key = RepositoryKey::from_bytes([0x63; 32]);
    let error = backup(
        &directory.join("repository"),
        &directory.join("source"),
        &key,
    )
    .unwrap_err();
    assert!(error.to_string().contains("active writer"));
}

#[test]
fn writer_lock_is_cross_process() {
    use std::process::{Command, Stdio};
    let fixture = Fixture::new();
    let path = fixture._temporary.path().join("process-lock");
    let repository_path = path.join("repository");
    fs::create_dir(&path).unwrap();
    fs::create_dir(path.join("source")).unwrap();
    let key = RepositoryKey::from_bytes([0x63; 32]);
    crate::initialize_with_key(&repository_path, &key).unwrap();
    let repository = Repository::open(&repository_path, &key).unwrap();
    let _guard = repository.lock_writer().unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::writer_lock_child_process")
        .arg("--ignored")
        .env("QUICKSAVE_ENGINE_TEST_LOCK_ROOT", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "child must observe the parent's active lock"
    );
}
