// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::{self, Write},
    marker::PhantomData,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{json, Value};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

pub(crate) const FORMAT: &str = "QuickSave.Local.Encrypted";
pub(crate) const VERSION: u32 = 1;
pub(crate) const CONSISTENCY: &str = "validated-stable-file-capture-not-application-atomic";
pub(crate) const IDENTITY_PATH: &str = "quicksave.repository.json";
pub(crate) const NAMESPACE: &str = "quicksave";
pub(crate) const LOCK_PATH: &str = "quicksave/writer.lock";
pub(crate) const LOCK_BYTES: &[u8] = b"QuickSave.Local.Encrypted/v1 immutable writer lock\n";
pub(crate) const OBJECTS: &str = "quicksave/objects";
pub(crate) const INDEXES: &str = "quicksave/indexes";
pub(crate) const COMMITS: &str = "quicksave/commits";

// The original 512 MiB global metadata guard is not increased. This format uses
// smaller independent records, and never embeds all files' chunk indexes in a
// single snapshot document.
pub(crate) const MAX_METADATA_BYTES: usize = 512 * 1024 * 1024;
pub(crate) const MAX_COMMIT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_IDENTITY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HISTORY_RESPONSE_BYTES: usize = 64 * 1024 - 1;
pub(crate) const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_OVERHEAD: usize = 1024 * 1024;
pub(crate) const MAX_TREE_ENTRIES: usize = 250_000;
pub(crate) const MAX_TREE_PATH_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_CHUNKS_PER_FILE: usize = quicksave_content::MAX_CHUNKS_PER_FILE;
pub(crate) const MAX_FILE_BYTES: u64 = quicksave_content::MAX_FILE_BYTES;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
pub(crate) const MAX_PATH_DEPTH: usize = 64;
pub(crate) const MAX_COMPONENT_BYTES: usize = 255;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    #[serde(deserialize_with = "deserialize_short_string")]
    pub format: String,
    pub version: u32,
    #[serde(deserialize_with = "deserialize_uuid")]
    pub repository_id: String,
    pub key_check: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyCheck {
    #[serde(deserialize_with = "deserialize_short_string")]
    pub format: String,
    pub version: u32,
    #[serde(deserialize_with = "deserialize_uuid")]
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    pub purpose: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChunkRef {
    #[serde(deserialize_with = "deserialize_hash")]
    pub hash: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileIndex {
    #[serde(deserialize_with = "deserialize_short_string")]
    pub format: String,
    pub version: u32,
    #[serde(deserialize_with = "deserialize_uuid")]
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_hash")]
    pub hash: String,
    pub size: u64,
    #[serde(deserialize_with = "deserialize_chunks")]
    pub chunks: Vec<ChunkRef>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Node {
    Directory {
        path: String,
    },
    File {
        path: String,
        index: String,
        hash: String,
        size: u64,
    },
}

// A streaming visitor is deliberate: serde's usual internally-tagged enum
// decoder first buffers arbitrary Content values to discover the tag. That
// could allocate a huge unknown array before path/count validation.
impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        enum Field {
            Kind,
            Path,
            Index,
            Hash,
            Size,
        }
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                struct FieldVisitor;
                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a QuickSave tree entry field")
                    }
                    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Field, E> {
                        match value {
                            "kind" => Ok(Field::Kind),
                            "path" => Ok(Field::Path),
                            "index" => Ok(Field::Index),
                            "hash" => Ok(Field::Hash),
                            "size" => Ok(Field::Size),
                            _ => Err(E::custom("unknown snapshot tree entry field")),
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct NodeVisitor;
        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = Node;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded QuickSave file/directory entry")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Node, A::Error> {
                let mut kind = None;
                let mut path = None;
                let mut index = None;
                let mut hash = None;
                let mut size = None;
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Kind => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            let value = map.next_value_seed(StringSeed {
                                validate: |value| {
                                    ensure!(
                                        value == "file" || value == "directory",
                                        "unsupported snapshot node kind"
                                    );
                                    Ok(())
                                },
                            })?;
                            kind = Some(value);
                        }
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value_seed(StringSeed {
                                validate: validate_relative,
                            })?);
                        }
                        Field::Index => {
                            if index.is_some() {
                                return Err(de::Error::duplicate_field("index"));
                            }
                            index = Some(map.next_value_seed(StringSeed {
                                validate: validate_hash,
                            })?);
                        }
                        Field::Hash => {
                            if hash.is_some() {
                                return Err(de::Error::duplicate_field("hash"));
                            }
                            hash = Some(map.next_value_seed(StringSeed {
                                validate: validate_hash,
                            })?);
                        }
                        Field::Size => {
                            if size.is_some() {
                                return Err(de::Error::duplicate_field("size"));
                            }
                            let value: u64 = map.next_value()?;
                            if value > MAX_FILE_BYTES {
                                return Err(de::Error::custom("file exceeds capture size limit"));
                            }
                            size = Some(value);
                        }
                    }
                }
                let kind = kind.ok_or_else(|| de::Error::missing_field("kind"))?;
                let path = path.ok_or_else(|| de::Error::missing_field("path"))?;
                if kind == "directory" {
                    if index.is_some() || hash.is_some() || size.is_some() {
                        return Err(de::Error::custom("directory contains file-only metadata"));
                    }
                    Ok(Node::Directory { path })
                } else {
                    Ok(Node::File {
                        path,
                        index: index.ok_or_else(|| de::Error::missing_field("index"))?,
                        hash: hash.ok_or_else(|| de::Error::missing_field("hash"))?,
                        size: size.ok_or_else(|| de::Error::missing_field("size"))?,
                    })
                }
            }
        }
        deserializer.deserialize_map(NodeVisitor)
    }
}

impl Node {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::File { path, .. } => path,
        }
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    pub total_files: u64,
    pub total_directories: u64,
    pub logical_bytes: u64,
    pub new_chunks: u64,
    pub reused_chunks: u64,
    /// Ciphertext bytes of newly published chunk objects; metadata is excluded.
    pub new_bytes: u64,
    pub new_logical_chunk_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Commit {
    #[serde(deserialize_with = "deserialize_short_string")]
    pub format: String,
    pub version: u32,
    #[serde(deserialize_with = "deserialize_uuid")]
    pub repository_id: String,
    #[serde(deserialize_with = "deserialize_uuid")]
    pub snapshot_id: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    pub created_at: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    pub capture_consistency: String,
    pub summary: Summary,
    #[serde(deserialize_with = "deserialize_nodes")]
    pub nodes: Vec<Node>,
}

impl Commit {
    pub fn summary_json(&self) -> Value {
        json!({
            "id": self.snapshot_id,
            "snapshotId": self.snapshot_id,
            "repositoryId": self.repository_id,
            "createdAt": self.created_at,
            "totalFiles": self.summary.total_files,
            "totalDirectories": self.summary.total_directories,
            "logicalBytes": self.summary.logical_bytes,
            "newChunks": self.summary.new_chunks,
            "reusedChunks": self.summary.reused_chunks,
            "newBytes": self.summary.new_bytes,
            "newBytesIncludes": "encrypted chunk objects only; metadata excluded",
            "newLogicalChunkBytes": self.summary.new_logical_chunk_bytes,
            "captureConsistency": self.capture_consistency,
            "state": "committed",
            "formatVersion": VERSION,
        })
    }
}

pub(crate) fn context(repository_id: &str, kind: &str, id: &str) -> Vec<u8> {
    // Each component is either a fixed domain or strictly validated ASCII ID.
    format!("QuickSave.Local.Encrypted/v1\0{repository_id}\0{kind}\0{id}").into_bytes()
}

pub(crate) fn validate_uuid(id: &str) -> Result<()> {
    ensure!(id.len() == 36, "identifier must be a canonical UUID");
    let parsed = uuid::Uuid::parse_str(id).context("invalid QuickSave identifier")?;
    ensure!(
        parsed.to_string() == id && !parsed.is_nil(),
        "identifier must be a non-nil canonical lowercase UUID"
    );
    Ok(())
}

pub(crate) fn validate_hash(hash: &str) -> Result<()> {
    let hex = hash.strip_prefix("blake3:").unwrap_or("");
    ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid BLAKE3 content identifier"
    );
    Ok(())
}

pub(crate) fn object_path(hash: &str) -> Result<String> {
    validate_hash(hash)?;
    Ok(format!("{OBJECTS}/{}.qsobj", &hash[7..]))
}

pub(crate) fn index_path(hash: &str) -> Result<String> {
    validate_hash(hash)?;
    Ok(format!("{INDEXES}/{}.qsidx", &hash[7..]))
}

pub(crate) fn commit_path(id: &str) -> Result<String> {
    validate_uuid(id)?;
    Ok(format!("{COMMITS}/{id}.qscommit"))
}

/// Reject nonportable aliases instead of relying on the host's case behavior.
pub(crate) fn validate_relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "empty or oversized relative path"
    );
    ensure!(
        !path.starts_with('/') && !path.contains('\\'),
        "absolute paths and backslashes are unsupported"
    );
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        ensure!(depth <= MAX_PATH_DEPTH, "path exceeds maximum depth");
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= MAX_COMPONENT_BYTES,
            "invalid relative path component"
        );
        ensure!(
            !component.ends_with('.') && !component.ends_with(' '),
            "ambiguous trailing dot or space in path"
        );
        ensure!(
            !component
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, ':' | '<' | '>' | '"' | '|' | '?' | '*')),
            "unsupported or ambiguous path character"
        );
        let normalized = portable_key(component);
        let device = normalized
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let numbered_device = device
            .strip_prefix("COM")
            .or_else(|| device.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'));
        ensure!(
            !matches!(
                device.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) && !numbered_device,
            "reserved device name in path"
        );
    }
    Ok(())
}

pub(crate) fn validate_nodes(nodes: &[Node]) -> Result<(u64, u64, u64)> {
    ensure!(nodes.len() <= MAX_TREE_ENTRIES, "tree entry limit exceeded");
    let mut paths = BTreeMap::new();
    let mut folded = HashSet::new();
    let mut files = 0_u64;
    let mut directories = 0_u64;
    let mut bytes = 0_u64;
    let mut path_bytes = 0_usize;
    let mut folded_bytes = 0_usize;
    for node in nodes {
        let path = node.path();
        validate_relative(path).with_context(|| format!("invalid snapshot path {path:?}"))?;
        path_bytes = path_bytes
            .checked_add(path.len())
            .context("tree path length overflow")?;
        ensure!(
            path_bytes <= MAX_TREE_PATH_BYTES,
            "tree exceeds bounded total path length"
        );
        ensure!(
            paths.insert(path, node.is_directory()).is_none(),
            "duplicate snapshot path"
        );
        let folded_path = portable_key(path);
        folded_bytes = folded_bytes
            .checked_add(folded_path.len())
            .context("folded path length overflow")?;
        ensure!(
            folded_path.len() <= MAX_PATH_BYTES && folded_bytes <= MAX_TREE_PATH_BYTES,
            "normalized tree paths exceed bounded path length"
        );
        ensure!(
            folded.insert(folded_path),
            "case-colliding or Unicode-normalization-colliding snapshot paths"
        );
        match node {
            Node::Directory { .. } => directories += 1,
            Node::File {
                index, hash, size, ..
            } => {
                validate_hash(index)?;
                validate_hash(hash)?;
                ensure!(*size <= MAX_FILE_BYTES, "file exceeds capture size limit");
                files += 1;
                bytes = bytes
                    .checked_add(*size)
                    .context("logical byte count overflow")?;
            }
        }
    }
    // Every parent must be explicitly represented as a directory. This also
    // catches file/descendant collisions on case-sensitive hosts.
    for node in nodes {
        let mut parent = node.path();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            ensure!(
                paths.get(prefix) == Some(&true),
                "missing directory or file/descendant collision"
            );
            parent = prefix;
        }
    }
    Ok((files, directories, bytes))
}

pub(crate) fn validate_commit(commit: &Commit, repository_id: &str, id: &str) -> Result<()> {
    ensure!(
        commit.format == FORMAT
            && commit.version == VERSION
            && commit.repository_id == repository_id
            && commit.snapshot_id == id,
        "snapshot identity or QuickSave format mismatch"
    );
    validate_uuid(id)?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&commit.created_at)
        .context("invalid snapshot creation timestamp")?;
    ensure!(
        timestamp
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            == commit.created_at,
        "snapshot creation timestamp must be canonical UTC milliseconds"
    );
    ensure!(
        commit.capture_consistency == CONSISTENCY,
        "unsupported snapshot consistency declaration"
    );
    let (files, directories, bytes) = validate_nodes(&commit.nodes)?;
    ensure!(
        files == commit.summary.total_files
            && directories == commit.summary.total_directories
            && bytes == commit.summary.logical_bytes,
        "snapshot totals do not match its validated tree"
    );
    let summary = &commit.summary;
    let chunks = summary
        .new_chunks
        .checked_add(summary.reused_chunks)
        .context("snapshot chunk count overflow")?;
    ensure!(
        summary.new_logical_chunk_bytes <= bytes
            && chunks <= files * MAX_CHUNKS_PER_FILE as u64
            && (summary.new_chunks == 0) == (summary.new_bytes == 0)
            && (summary.new_chunks == 0) == (summary.new_logical_chunk_bytes == 0),
        "snapshot incremental totals are inconsistent"
    );
    Ok(())
}

pub(crate) fn validate_index(index: &FileIndex, repository_id: &str) -> Result<()> {
    ensure!(
        index.format == FORMAT && index.version == VERSION && index.repository_id == repository_id,
        "file index identity or QuickSave format mismatch"
    );
    validate_hash(&index.hash)?;
    ensure!(
        index.size <= MAX_FILE_BYTES && index.chunks.len() <= MAX_CHUNKS_PER_FILE,
        "file index exceeds bounded capture limits"
    );
    let mut sum = 0_u64;
    for chunk in &index.chunks {
        validate_hash(&chunk.hash)?;
        ensure!(
            chunk.size > 0 && chunk.size <= MAX_CHUNK_BYTES as u64,
            "invalid chunk length"
        );
        sum = sum
            .checked_add(chunk.size)
            .context("chunk length overflow")?;
    }
    ensure!(
        sum == index.size,
        "file index has inconsistent chunk lengths"
    );
    ensure!(
        index.size != 0 || index.chunks.is_empty(),
        "empty files must have no chunk objects"
    );
    Ok(())
}

pub(crate) fn absolute_root(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty(), "root path must not be empty");
    ensure!(
        path.to_str()
            .is_some_and(|text| text.len() <= 32_768 && !text.contains('\0')),
        "root must be a bounded UTF-8 path without NUL"
    );
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("cannot resolve current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => bail!("parent components in root paths are unsupported"),
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    ensure!(normalized.is_absolute(), "root must be absolute");
    ensure!(
        normalized.file_name().is_some(),
        "filesystem roots are not valid operation roots"
    );
    Ok(normalized)
}

pub(crate) fn reject_overlap(left: &Path, right: &Path) -> Result<()> {
    // SafeRoot rejects symlink ancestors; lexical normalization therefore does
    // not follow aliases through unapproved links. Case folding also prevents a
    // case-insensitive filesystem from accepting a spelling-only overlap.
    let folded = |path: &Path| -> Result<Vec<String>> {
        path.components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .map(portable_key)
                    .context("non-UTF8 root paths are unsupported")
            })
            .collect()
    };
    let left = folded(left)?;
    let right = folded(right)?;
    ensure!(
        !left.starts_with(&right) && !right.starts_with(&left),
        "repository and source/destination roots must not overlap or be duplicates"
    );
    Ok(())
}

fn portable_key(value: &str) -> String {
    if value.is_ascii() {
        return value.to_ascii_uppercase();
    }
    // Full folding handles aliases such as ß/SS. A final uppercase mapping also
    // conservatively catches ordinal-uppercase host aliases such as I/dotless-ı.
    value
        .nfkc()
        .case_fold()
        .flat_map(char::to_uppercase)
        .nfc()
        .collect()
}

/// serde_json can lend unescaped strings from the bounded input buffer. Check
/// their lengths/content before allocating an owned manifest string. Escaped
/// JSON still requires serde_json's bounded-record scratch buffer first.
fn validated_string<'de, D: Deserializer<'de>>(
    deserializer: D,
    validate: fn(&str) -> Result<()>,
) -> std::result::Result<String, D::Error> {
    struct StringVisitor {
        validate: fn(&str) -> Result<()>,
    }
    impl<'de> Visitor<'de> for StringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded, validated QuickSave string")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<String, E> {
            (self.validate)(value).map_err(E::custom)?;
            Ok(value.to_owned())
        }

        fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<String, E> {
            (self.validate)(&value).map_err(E::custom)?;
            Ok(value)
        }
    }
    deserializer.deserialize_str(StringVisitor { validate })
}

fn deserialize_short_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    validated_string(deserializer, |value| {
        ensure!(value.len() <= 128, "metadata header string exceeds limit");
        Ok(())
    })
}

fn deserialize_hash<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    validated_string(deserializer, validate_hash)
}

fn deserialize_uuid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    validated_string(deserializer, validate_uuid)
}

struct StringSeed {
    validate: fn(&str) -> Result<()>,
}

impl<'de> DeserializeSeed<'de> for StringSeed {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<String, D::Error> {
        validated_string(deserializer, self.validate)
    }
}

/// Reject a sequence's next element before deserializing/allocating it once
/// the count limit is reached. Never trust a deserializer's size hint.
struct ElementSeed<T> {
    allow: bool,
    marker: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ElementSeed<T> {
    type Value = T;

    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<T, D::Error> {
        if !self.allow {
            return Err(de::Error::custom("metadata sequence count limit exceeded"));
        }
        T::deserialize(deserializer)
    }
}

fn bounded_vec<'de, D, T, const LIMIT: usize>(
    deserializer: D,
    item_bytes: fn(&T) -> usize,
    byte_limit: usize,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const LIMIT: usize> {
        item_bytes: fn(&T) -> usize,
        byte_limit: usize,
    }
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for BoundedVisitor<T, LIMIT> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence of at most {LIMIT} entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > LIMIT) {
                return Err(de::Error::custom(
                    "metadata sequence size hint exceeds limit",
                ));
            }
            let mut output = Vec::new();
            let mut bytes = 0_usize;
            while let Some(item) = sequence.next_element_seed(ElementSeed::<T> {
                allow: output.len() < LIMIT,
                marker: PhantomData,
            })? {
                bytes = bytes
                    .checked_add((self.item_bytes)(&item))
                    .filter(|sum| *sum <= self.byte_limit)
                    .ok_or_else(|| de::Error::custom("metadata sequence byte limit exceeded"))?;
                if output.len() == output.capacity() {
                    output
                        .try_reserve((LIMIT - output.len()).min(256))
                        .map_err(de::Error::custom)?;
                }
                output.push(item);
            }
            Ok(output)
        }
    }
    deserializer.deserialize_seq(BoundedVisitor::<T, LIMIT> {
        item_bytes,
        byte_limit,
    })
}

fn deserialize_nodes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Node>, D::Error> {
    bounded_vec::<D, Node, MAX_TREE_ENTRIES>(
        deserializer,
        |node| node.path().len(),
        MAX_TREE_PATH_BYTES,
    )
}

fn deserialize_chunks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<ChunkRef>, D::Error> {
    bounded_vec::<D, ChunkRef, MAX_CHUNKS_PER_FILE>(
        deserializer,
        |_| std::mem::size_of::<ChunkRef>() + 71,
        MAX_INDEX_BYTES,
    )
}

struct CountWriter {
    count: usize,
    limit: usize,
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .filter(|count| *count <= self.limit)
            .ok_or_else(|| io::Error::other("metadata record size limit exceeded"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    ensure!(limit <= MAX_METADATA_BYTES, "invalid metadata size guard");
    let mut counter = CountWriter { count: 0, limit };
    serde_json::to_writer(&mut counter, value).context("metadata exceeds bounded record size")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(counter.count)
        .context("metadata allocation failed")?;
    serde_json::to_writer(&mut bytes, value)?;
    ensure!(bytes.len() <= limit, "metadata record size limit exceeded");
    Ok(bytes)
}
