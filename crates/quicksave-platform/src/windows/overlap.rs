// SPDX-License-Identifier: GPL-3.0-only
//! Native directory-identity approval, separate from payload/link capture.
//! Known symbolic links are ignored without reading reparse target data.
//! Junctions/unknown directory reparse tags fail: they are not disjointness.

use super::*;
use crate::overlap::{with_census_location, CensusBudget};

#[derive(PartialEq, Eq)]
struct Child {
    name: String,
    id: [u64; 2],
}

impl Root {
    pub(crate) fn visit_directory_identities(
        &self,
        visit: &mut impl FnMut(&[u8], DirectoryIdentity) -> Result<()>,
    ) -> Result<()> {
        let mut relative = String::new();
        let result = walk(
            self,
            &mut Vec::new(),
            &mut relative,
            &mut CensusBudget::default(),
            &mut CensusBudget::default(),
            visit,
        );
        self.check()?;
        with_census_location(result, relative.as_bytes())
    }
}

fn current_directory<'a>(root: &'a Root, parents: &'a [Directory]) -> &'a File {
    parents
        .last()
        .map(|directory| &directory.file)
        .unwrap_or_else(|| root.file())
}

fn walk(
    root: &Root,
    parents: &mut Vec<Directory>,
    relative: &mut String,
    discovery: &mut CensusBudget,
    confirmation: &mut CensusBudget,
    visit: &mut impl FnMut(&[u8], DirectoryIdentity) -> Result<()>,
) -> Result<()> {
    root.check_parents(parents)
        .with_context(|| format!("directory {relative:?}"))?;
    let own = identity(&metadata(current_directory(root, parents), true)?);
    visit(
        relative.as_bytes(),
        DirectoryIdentity {
            device: own.volume,
            file_id: own.id,
        },
    )?;
    let children = directory_children(current_directory(root, parents), relative, discovery)
        .with_context(|| format!("enumerate directory {relative:?}"))?;
    for child in &children {
        ensure!(
            parents.len() < MAX_DEPTH,
            "directory-identity census exceeds depth limit at {relative:?}"
        );
        let length = relative.len();
        if length != 0 {
            relative.push('/');
        }
        relative.push_str(&child.name);
        root.check_parents(parents)?;
        let before = open_child(current_directory(root, parents), &child.name, true)
            .with_context(|| format!("open read-only no-reparse directory {relative:?}"))?;
        let before_identity = identity(&metadata(&before, true)?);
        ensure!(
            before_identity.volume == own.volume && before_identity.id == child.id,
            "directory enumeration/open identity changed at {relative:?}"
        );
        ensure!(
            before_identity != root.ancestors.last().unwrap().identity
                && parents
                    .iter()
                    .all(|ancestor| ancestor.identity != before_identity),
            "directory alias cycle during identity approval at {relative:?}"
        );
        // Open a second native handle to verify the namespace edge, rather than
        // deriving a 128-bit ID from legacy Rust Metadata or trusting a name.
        let file = open_child(current_directory(root, parents), &child.name, true)?;
        ensure!(
            identity(&metadata(&file, true)?) == before_identity,
            "directory changed while opening at {relative:?}"
        );
        let after = open_child(current_directory(root, parents), &child.name, true)?;
        ensure!(
            identity(&metadata(&after, true)?) == before_identity,
            "directory namespace changed while opening at {relative:?}"
        );
        parents.push(Directory {
            file,
            identity: before_identity,
            name: Some(child.name.clone()),
        });
        walk(root, parents, relative, discovery, confirmation, visit)?;
        root.check_parents(parents)?;
        parents.pop();
        relative.truncate(length);
    }
    root.check_parents(parents)?;
    let after = directory_children(current_directory(root, parents), relative, confirmation)
        .with_context(|| format!("recheck directory children {relative:?}"))?;
    ensure!(
        after == children,
        "directory children changed during identity approval at {relative:?}"
    );
    root.check_parents(parents)?;
    Ok(())
}

fn directory_children(
    directory: &File,
    prefix: &str,
    budget: &mut CensusBudget,
) -> Result<Vec<Child>> {
    // Independent native enumeration cursor; do not change another consumer's
    // directory offset or fall back to an unanchored std::fs::read_dir path.
    let enumeration = open_dot(directory)?;
    ensure!(
        identity(&metadata(&enumeration, true)?) == identity(&metadata(directory, true)?),
        "directory stream identity changed"
    );
    let mut children = Vec::new();
    let mut first = true;
    loop {
        let mut storage = [0u64; 8192];
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtQueryDirectoryFile(
                enumeration.as_raw_handle(),
                ptr::null_mut(),
                None,
                ptr::null(),
                &mut io_status,
                storage.as_mut_ptr().cast(),
                size_of_val(&storage) as u32,
                FileIdExtdDirectoryInformation,
                false,
                ptr::null(),
                first,
            )
        };
        first = false;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        nt_result(status)?;
        let valid = io_status.Information;
        ensure!(
            valid > 0 && valid <= size_of_val(&storage),
            "invalid native directory-identity byte count"
        );
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), valid) };
        parse_records(bytes, prefix, budget, &mut children)?;
    }
    children.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    ensure!(
        children.windows(2).all(|pair| pair[0].name != pair[1].name),
        "duplicate native directory name during identity approval"
    );
    Ok(children)
}

fn parse_records(
    bytes: &[u8],
    prefix: &str,
    budget: &mut CensusBudget,
    children: &mut Vec<Child>,
) -> Result<()> {
    let mut offset = 0usize;
    let header = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    loop {
        let header_end = offset
            .checked_add(header)
            .context("directory-identity native offset overflow")?;
        ensure!(
            header_end <= bytes.len(),
            "truncated native directory-identity header"
        );
        // Only copy fields inside the returned byte count. A short filename
        // need not include Rust's trailing struct padding or FileName[0].
        let mut record = MaybeUninit::<FILE_ID_EXTD_DIR_INFORMATION>::zeroed();
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr().add(offset),
                record.as_mut_ptr().cast::<u8>(),
                header,
            );
        }
        let record = unsafe { record.assume_init() };
        let length = record.FileNameLength as usize;
        ensure!(
            length > 0 && length.is_multiple_of(2) && length <= 510,
            "invalid native directory-identity name byte count"
        );
        let name_end = header_end
            .checked_add(length)
            .context("directory-identity native name overflow")?;
        ensure!(
            name_end <= bytes.len(),
            "native directory-identity name exceeds returned byte count"
        );
        let native_name = &bytes[header_end..name_end];
        let dot = native_name == [b'.', 0] || native_name == [b'.', 0, b'.', 0];
        if !dot {
            // Count ignored names as work, but never decode/store them or open a
            // payload handle. Invalid UTF-16 on a file is not an alias directory.
            budget.entry(prefix.len(), length)?;
            if record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                if record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    ensure!(
                        record.ReparsePointTag == links::SYMLINK_TAG,
                        "unsupported directory alias/reparse tag {:#x} under {prefix:?}",
                        record.ReparsePointTag
                    );
                } else {
                    ensure!(
                        record.FileAttributes & FILE_ATTRIBUTE_DEVICE == 0,
                        "unsupported native device directory under {prefix:?}"
                    );
                    let encoded: Vec<u16> = native_name
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect();
                    let name = String::from_utf16(&encoded)
                        .context("non-Unicode native directory name")?;
                    validate_windows_component(&name)?;
                    let id = id_parts(record.FileId.Identifier);
                    ensure!(
                        id != [0, 0],
                        "native directory-identity record lacks a full file ID"
                    );
                    budget
                        .directory(prefix.len() + usize::from(!prefix.is_empty()) + name.len())?;
                    children.push(Child { name, id });
                }
            }
        }
        if record.NextEntryOffset == 0 {
            break;
        }
        let next = record.NextEntryOffset as usize;
        let next_offset = offset
            .checked_add(next)
            .context("directory-identity native record offset overflow")?;
        ensure!(
            next >= header + length && next.is_multiple_of(8) && next_offset < bytes.len(),
            "invalid native directory-identity record offset"
        );
        offset = next_offset;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &[u16], attributes: u32, tag: u32, id: [u64; 2]) -> Vec<u8> {
        let header = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        let mut bytes = vec![0u8; header + name.len() * 2];
        let length = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
        bytes[length..length + 4].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        let flags = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes);
        bytes[flags..flags + 4].copy_from_slice(&attributes.to_le_bytes());
        let reparse = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, ReparsePointTag);
        bytes[reparse..reparse + 4].copy_from_slice(&tag.to_le_bytes());
        let file_id = offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId);
        bytes[file_id..file_id + 8].copy_from_slice(&id[0].to_le_bytes());
        bytes[file_id + 8..file_id + 16].copy_from_slice(&id[1].to_le_bytes());
        for (pair, unit) in bytes[header..].chunks_exact_mut(2).zip(name) {
            pair.copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn directory_record_parser_preserves_both_id_halves_and_byte_bounds() -> Result<()> {
        let id = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let bytes = record(&[b'd' as u16], FILE_ATTRIBUTE_DIRECTORY, 0, id);
        let mut children = Vec::new();
        parse_records(&bytes, "", &mut CensusBudget::default(), &mut children)?;
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].id, id);
        for end in 0..bytes.len() {
            assert!(parse_records(
                &bytes[..end],
                "",
                &mut CensusBudget::default(),
                &mut Vec::new()
            )
            .is_err());
        }
        let mut invalid_next = bytes.clone();
        invalid_next[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_records(
            &invalid_next,
            "",
            &mut CensusBudget::default(),
            &mut Vec::new()
        )
        .is_err());
        let missing_id = record(&[b'd' as u16], FILE_ATTRIBUTE_DIRECTORY, 0, [0, 0]);
        assert!(parse_records(
            &missing_id,
            "",
            &mut CensusBudget::default(),
            &mut Vec::new()
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn files_and_known_links_are_skipped_but_junctions_never_mean_disjoint() -> Result<()> {
        let mut children = Vec::new();
        // Unpaired surrogate payload filename: this purpose must not need it.
        let file = record(&[0xd800], FILE_ATTRIBUTE_REPARSE_POINT, 0xdead_beef, [0, 0]);
        parse_records(&file, "", &mut CensusBudget::default(), &mut children)?;
        let symlink = record(
            &[b'l' as u16],
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            links::SYMLINK_TAG,
            [1, 2],
        );
        parse_records(&symlink, "", &mut CensusBudget::default(), &mut children)?;
        assert!(children.is_empty());
        let junction = record(
            &[b'j' as u16],
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            0xa000_0003,
            [1, 2],
        );
        assert!(parse_records(&junction, "", &mut CensusBudget::default(), &mut children).is_err());
        Ok(())
    }
}
