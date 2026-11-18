// SPDX-License-Identifier: GPL-3.0-only
//! Pure validation of authenticated Windows source metadata. These source IDs
//! are provenance, never grants to mutate a destination. Destination observations
//! always come from held handles and the current-user native ACL adapter.
use std::collections::BTreeMap;

use noland_state_core::{LogicalRoot, Result, StateError};
use serde::Deserialize;
use serde_json::Value;

use super::{NativeEntryKind, MAX_ENTRIES};

mod root_scope;
pub(super) use root_scope::{RootMetadata, WindowsRootMetadata};

pub(super) fn link_hints(environment: &Value) -> Result<BTreeMap<(&str, &str), bool>> {
    let Some(value) = environment.get("windowsSymlinkMetadata") else {
        return Ok(BTreeMap::new());
    };
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= MAX_ENTRIES)
        .ok_or_else(|| {
            StateError::Integrity("invalid/beyond-bound windowsSymlinkMetadata rows".into())
        })?;
    let mut hints = BTreeMap::new();
    for row in rows {
        let object = row
            .as_object()
            .filter(|object| {
                object.len() == 3
                    && ["logicalRoot", "relativePath", "targetIsDirectory"]
                        .iter()
                        .all(|key| object.contains_key(*key))
            })
            .ok_or_else(|| {
                StateError::Integrity("unknown/missing Windows link hint fields".into())
            })?;
        let logical = object["logicalRoot"]
            .as_str()
            .filter(|token| {
                token.len() <= 4096
                    && LogicalRoot::parse(token).is_some_and(|root| root.as_token() == *token)
            })
            .ok_or_else(|| StateError::Integrity("noncanonical Windows link root token".into()))?;
        let path = object["relativePath"]
            .as_str()
            .ok_or_else(|| StateError::Integrity("Windows link hint path is missing".into()))?;
        super::validate_relative(path)?;
        let directory = object["targetIsDirectory"].as_bool().ok_or_else(|| {
            StateError::Integrity("Windows link kind must be an actual boolean".into())
        })?;
        if hints.insert((logical, path), directory).is_some() {
            return Err(StateError::Integrity(
                "duplicate exact Windows link type hint".into(),
            ));
        }
    }
    Ok(hints)
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourcePlatform {
    Windows,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceIdentity {
    device: u64,
    file_id: [u64; 2],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceMetadata {
    platform: SourcePlatform,
    identity: SourceIdentity,
    kind: NativeEntryKind,
    size: u64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
    link_count: u32,
    reparse_tag: u32,
}

impl SourceMetadata {
    fn same_state(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.kind == other.kind
            && self.size == other.size
            && self.creation_time == other.creation_time
            && self.last_write_time == other.last_write_time
            && self.change_time == other.change_time
            && self.attributes == other.attributes
            && self.link_count == other.link_count
            && self.reparse_tag == other.reparse_tag
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceStamp {
    device: u64,
    file_id: [u64; 2],
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u32,
    changed_seconds: i64,
    changed_nanoseconds: u32,
}

fn stamp_time(seconds: i64, nanos: u32) -> Result<i64> {
    if nanos >= 1_000_000_000 || nanos % 100 != 0 {
        return Err(StateError::Integrity(
            "unrepresentable Windows root timestamp precision".into(),
        ));
    }
    i64::try_from(seconds as i128 * 1_000_000_000 + nanos as i128)
        .map_err(|_| StateError::Integrity("Windows root timestamp range overflow".into()))
}

fn filetime_nanos(ticks: i64) -> Result<i64> {
    if ticks <= 0 {
        return Err(StateError::Integrity(
            "unsupported Windows root FILETIME".into(),
        ));
    }
    i64::try_from((ticks as i128 - 116_444_736_000_000_000i128) * 100)
        .map_err(|_| StateError::Integrity("Windows root FILETIME range overflow".into()))
}

pub(super) fn captured_root_mtime(capture: &Value) -> Result<i64> {
    if capture["kind"] != "directory"
        || ["mode", "owner", "group"]
            .iter()
            .any(|key| capture.get(*key).is_some_and(|value| !value.is_null()))
    {
        return Err(StateError::Integrity(
            "legacy/unknown POSIX root ownership cannot bind Windows metadata".into(),
        ));
    }
    // Deserialization borrows the existing JSON; no second whole document or
    // source inventory is cloned. Missing/unknown native fields fail closed.
    let metadata = SourceMetadata::deserialize(&capture["metadata"])?;
    let stamp = SourceStamp::deserialize(&capture["stamp"])?;
    let modified = stamp_time(stamp.modified_seconds, stamp.modified_nanoseconds)?;
    let changed = stamp_time(stamp.changed_seconds, stamp.changed_nanoseconds)?;
    let _actual_platform = metadata.platform;
    if metadata.kind != NativeEntryKind::Directory
        || metadata.identity.file_id == [0; 2]
        || metadata.identity.device != stamp.device
        || metadata.identity.file_id != stamp.file_id
        || metadata.size != stamp.size
        || metadata.link_count == 0
        || metadata.attributes & (0x10 | 0x40 | 0x400) != 0x10
        || metadata.reparse_tag != 0
        || metadata.creation_time <= 0
        || metadata.last_access_time <= 0
        || filetime_nanos(metadata.last_write_time)? != modified
        || filetime_nanos(metadata.change_time)? != changed
    {
        return Err(StateError::Integrity(
            "Windows captured root lacks matching exact native type/128-bit ID/times".into(),
        ));
    }
    Ok(modified)
}

/// Prior manual-leaf deletion evidence must contain actual Windows file
/// metadata too. Neither a logical ID nor two matching null fields is a stat.
pub(super) fn captured_file_mtime(metadata: &Value, stamp: &Value) -> Result<i64> {
    let metadata = SourceMetadata::deserialize(metadata)?;
    let stamp = SourceStamp::deserialize(stamp)?;
    let modified = stamp_time(stamp.modified_seconds, stamp.modified_nanoseconds)?;
    let changed = stamp_time(stamp.changed_seconds, stamp.changed_nanoseconds)?;
    if metadata.kind != NativeEntryKind::File
        || metadata.identity.file_id == [0; 2]
        || metadata.identity.device != stamp.device
        || metadata.identity.file_id != stamp.file_id
        || metadata.size != stamp.size
        || metadata.link_count == 0
        || metadata.attributes & (0x10 | 0x40 | 0x400) != 0
        || metadata.reparse_tag != 0
        || metadata.creation_time <= 0
        || metadata.last_access_time <= 0
        || filetime_nanos(metadata.last_write_time)? != modified
        || filetime_nanos(metadata.change_time)? != changed
    {
        return Err(StateError::Integrity(
            "manual deleted leaf lacks actual matching Windows file metadata/128-bit identity"
                .into(),
        ));
    }
    Ok(modified)
}

/// Bounded FILE_STREAM_INFORMATION from a held native handle. This parser is
/// pure so malformed/alternate stream records can be tested without Windows.
pub(crate) fn validate_stream_records(bytes: &[u8], regular_file_size: Option<u64>) -> Result<()> {
    if bytes.len() > 64 * 1024 {
        return Err(StateError::Integrity(
            "native stream-information budget exceeded".into(),
        ));
    }
    let invalid = || {
        StateError::UnsafePath(
            "alternate, malformed or unknown native data stream is unsupported".into(),
        )
    };
    let mut offset = 0usize;
    let mut streams = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 24 {
            return Err(invalid());
        }
        let next = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let size = i64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if length != 14 || offset + 24 + length > bytes.len() || size < 0 || streams != 0 {
            return Err(invalid());
        }
        let name = bytes[offset + 24..offset + 24 + length]
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]));
        if !name.eq("::$DATA".encode_utf16())
            || regular_file_size.map_or(size != 0, |expected| size as u64 != expected)
        {
            return Err(invalid());
        }
        streams += 1;
        if next == 0 {
            if bytes.len() - (offset + 24 + length) >= 8 {
                return Err(invalid());
            }
            break;
        }
        if next % 8 != 0 || next < 24 + length || next >= bytes.len() - offset {
            return Err(invalid());
        }
        offset += next;
    }
    if regular_file_size.is_some() && streams != 1 {
        return Err(invalid());
    }
    Ok(())
}

/// Observe the symlink object only. Original absolute link targets may be moved
/// back by authenticated identity without following them. New links still use
/// the stricter confined-relative source API and exact captured directory hint.
pub(crate) fn symlink_reparse_data(bytes: &[u8]) -> Result<(String, [u8; 32])> {
    let invalid = || StateError::UnsafePath("malformed/unknown native symlink reparse data".into());
    if bytes.len() < 20 || bytes.len() > 16 * 1024 {
        return Err(invalid());
    }
    let tag = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let length = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
    let extent = 8usize.checked_add(length).ok_or_else(invalid)?;
    let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    if tag != 0xa000000c || length < 12 || extent > bytes.len() || flags & !1 != 0 {
        return Err(invalid());
    }
    let slice = |offset: usize, count: usize| -> Result<&[u8]> {
        if offset % 2 != 0 || count % 2 != 0 {
            return Err(invalid());
        }
        let start = 20usize.checked_add(offset).ok_or_else(invalid)?;
        let end = start
            .checked_add(count)
            .filter(|end| *end <= extent)
            .ok_or_else(invalid)?;
        bytes.get(start..end).ok_or_else(invalid)
    };
    let offset = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
    let print_offset = u16::from_le_bytes(bytes[12..14].try_into().unwrap()) as usize;
    let print_count = u16::from_le_bytes(bytes[14..16].try_into().unwrap()) as usize;
    slice(print_offset, print_count)?;
    let target = slice(offset, count)?;
    if target.is_empty() {
        return Err(invalid());
    }
    let words = target
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect::<Vec<_>>();
    let target = String::from_utf16(&words).map_err(|_| invalid())?;
    if target.contains('\0') {
        return Err(invalid());
    }
    Ok((
        target.replace('\\', "/"),
        *blake3::hash(&bytes[..extent]).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn link_hints_are_exact_and_never_inferred_from_selected_target_files() {
        let environment = json!({"windowsSymlinkMetadata":[
            {"logicalRoot":"$DOCUMENTS","relativePath":"Game/link","targetIsDirectory":true}
        ]});
        let hints = link_hints(&environment).unwrap();
        assert_eq!(hints.get(&("$DOCUMENTS", "Game/link")), Some(&true));
        assert!(!hints.contains_key(&("$DOCUMENTS", "Other/link")));
        for rows in [
            json!([{"logicalRoot":"$DOCUMENTS","relativePath":"Game/link"}]),
            json!([{"logicalRoot":"$DOCUMENTS","relativePath":"Game/link","targetIsDirectory":1}]),
            json!([{"logicalRoot":"$DOCUMENTS","relativePath":"../link","targetIsDirectory":false}]),
            json!([{"logicalRoot":"$DOCUMENTS","relativePath":"Game/link","targetIsDirectory":true,"guess":true}]),
            json!([
                environment["windowsSymlinkMetadata"][0],
                environment["windowsSymlinkMetadata"][0]
            ]),
        ] {
            assert!(link_hints(&json!({"windowsSymlinkMetadata":rows})).is_err());
        }
        assert!(link_hints(&json!({})).unwrap().is_empty());
    }

    fn root_capture() -> Value {
        json!({
            "kind":"directory",
            "stamp":{"device":9,"file_id":[7,23],"size":0,
                "modified_seconds":1,"modified_nanoseconds":200,
                "changed_seconds":2,"changed_nanoseconds":300},
            "metadata":{"platform":"windows","identity":{"device":9,"fileId":[7,23]},
                "kind":"directory","size":0,"creationTime":116_444_736_000_000_001i64,
                "lastAccessTime":116_444_736_000_000_001i64,
                "lastWriteTime":116_444_736_010_000_002i64,
                "changeTime":116_444_736_020_000_003i64,
                "attributes":16,"linkCount":1,"reparseTag":0}
        })
    }

    #[test]
    fn root_metadata_requires_actual_matching_native_frame_and_no_fake_unix_owner() {
        let valid = root_capture();
        assert_eq!(captured_root_mtime(&valid).unwrap(), 1_000_000_200);
        for pointer in [
            "/metadata/identity/fileId/1",
            "/metadata/attributes",
            "/metadata/reparseTag",
            "/metadata/changeTime",
            "/stamp/modified_nanoseconds",
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).unwrap() = json!(1);
            assert!(captured_root_mtime(&invalid).is_err(), "{pointer}");
        }
        let mut legacy = valid.clone();
        legacy["owner"] = json!(0);
        assert!(captured_root_mtime(&legacy).is_err());
        legacy = valid.clone();
        legacy["metadata"] = Value::Null;
        assert!(captured_root_mtime(&legacy).is_err());
        legacy = valid;
        legacy["metadata"]["invented"] = json!(true);
        assert!(captured_root_mtime(&legacy).is_err());
    }

    #[test]
    fn native_stream_records_reject_ads_torn_offsets_unknown_names_and_size_changes() {
        let mut unnamed = vec![0u8; 40];
        unnamed[4..8].copy_from_slice(&14u32.to_le_bytes());
        unnamed[8..16].copy_from_slice(&7i64.to_le_bytes());
        for (index, word) in "::$DATA".encode_utf16().enumerate() {
            unnamed[24 + index * 2..26 + index * 2].copy_from_slice(&word.to_le_bytes());
        }
        validate_stream_records(&unnamed, Some(7)).unwrap();
        validate_stream_records(&[], None).unwrap();
        assert!(validate_stream_records(&[], Some(0)).is_err());
        assert!(validate_stream_records(&unnamed, Some(8)).is_err());
        assert!(validate_stream_records(&unnamed, None).is_err());
        assert!(validate_stream_records(&unnamed[..30], Some(7)).is_err());
        let mut ads = unnamed.clone();
        ads[26..28].copy_from_slice(&(b'x' as u16).to_le_bytes());
        assert!(validate_stream_records(&ads, Some(7)).is_err());
        let mut multiple = unnamed.clone();
        multiple[0..4].copy_from_slice(&40u32.to_le_bytes());
        multiple.extend_from_slice(&unnamed);
        assert!(validate_stream_records(&multiple, Some(7)).is_err());
        unnamed[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_stream_records(&unnamed, Some(7)).is_err());
    }

    #[test]
    fn original_absolute_links_are_opaque_bound_objects_not_new_link_authority() {
        let target = r"\??\C:\outside\original"
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut data = vec![0u8; 20 + target.len() * 2];
        data[..4].copy_from_slice(&0xa000000cu32.to_le_bytes());
        let length = (data.len() - 8) as u16;
        data[4..6].copy_from_slice(&length.to_le_bytes());
        data[10..12].copy_from_slice(&((target.len() * 2) as u16).to_le_bytes());
        for (index, word) in target.iter().enumerate() {
            data[20 + index * 2..22 + index * 2].copy_from_slice(&word.to_le_bytes());
        }
        let (opaque, digest) = symlink_reparse_data(&data).unwrap();
        assert_eq!(opaque, "/??/C:/outside/original");
        assert!(
            noland_state_core::validate_relative_symlink_target_within_root("link", &opaque)
                .is_err()
        );
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert_ne!(symlink_reparse_data(&data).unwrap().1, digest);
        data[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(symlink_reparse_data(&data).is_err());
    }
}
