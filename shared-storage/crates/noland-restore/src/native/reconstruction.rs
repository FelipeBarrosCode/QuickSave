// SPDX-License-Identifier: GPL-3.0-only
//! Read-only, bounded post-reconstruction assessment. Never executes an app,
//! signs code, follows an original source path, or hashes an executable again.
//! Plist event bounds follow QuickSave's original parsers/macos.rs pattern.
use std::io::{Read, Seek, SeekFrom};

use noland_state_core::{
    native_layout::{NativeLayoutRole, NativeLayoutSourceKind, NativeRootLayout},
    Result, StateError,
};
use serde::Serialize;

use super::{filesystem, NativeEntryKind, NativeRestoreEntry, NativeTransaction};

const MAX_PLIST: usize = 1024 * 1024;
const MAX_EVENTS: usize = 16384;
const MAX_COMMANDS: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRestoreReadiness {
    FilesOnly,
    ReconstructionUnverified,
}

impl NativeRestoreReadiness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FilesOnly => "files_only",
            Self::ReconstructionUnverified => "reconstruction_unverified",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeReconstructionReport {
    pub version: u32,
    pub readiness: NativeRestoreReadiness,
    pub layout_reconstructed: bool,
    pub entire_manifest: bool,
    pub source_full_scope: bool,
    pub platform_compatible: bool,
    pub runnable: bool,
    pub root_mapping_fingerprint: String,
    /// Actual bounded metadata reads, separate from assembly-verifier readback.
    pub metadata_read_bytes: u64,
    pub applications: Vec<NativeApplicationAssessment>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NativeApplicationAssessment {
    pub destination_relative: String,
    pub captured_entries: usize,
    pub bundle_metadata_validated: bool,
    pub executable_capture_hash_verified: bool,
    pub executable_format: String,
    pub embedded_signature_metadata_validated: bool,
    pub declared_dependencies: usize,
    pub native_signature_verified: bool,
    pub dependency_graph_verified: bool,
    pub diagnostics: Vec<String>,
}

impl NativeTransaction {
    pub(super) fn assess_reconstruction(&self) -> Result<NativeReconstructionReport> {
        let preview = self.control.preview();
        let compatible = preview
            .root_layout
            .as_ref()
            .is_some_and(|layout| layout.platform.is_current());
        let eligible = preview.reconstruction_eligible();
        let mut report = NativeReconstructionReport {
            version: 1,
            readiness: NativeRestoreReadiness::FilesOnly,
            layout_reconstructed: false,
            entire_manifest: preview.entire_manifest,
            source_full_scope: preview.source_full_scope,
            platform_compatible: compatible,
            runnable: false,
            root_mapping_fingerprint: preview.root_mapping_digest()?,
            metadata_read_bytes: 0,
            applications: vec![],
            diagnostics: vec![],
        };
        let Some(layout) = &preview.root_layout else {
            report
                .diagnostics
                .push("legacy_manifest_has_no_authenticated_native_layout".into());
            return Ok(report);
        };
        report.layout_reconstructed = !preview.entries.is_empty()
            || preview
                .root_entries
                .iter()
                .any(|entry| !entry.is_scaffold_root());
        if !report.layout_reconstructed && !preview.tombstones.is_empty() {
            report
                .diagnostics
                .push("deletion_only_revision_not_an_empty_application".into());
        }
        if preview
            .root_entries
            .iter()
            .any(NativeRestoreEntry::is_scaffold_root)
        {
            report
                .diagnostics
                .push("source_parent_metadata_not_captured_destination_scaffold_only".into());
        }
        if !preview.entire_manifest {
            report
                .diagnostics
                .push("selected_files_not_a_complete_application".into());
        }
        if !preview.source_full_scope {
            report
                .diagnostics
                .push("source_application_coverage_not_proven".into());
        }
        if !compatible {
            report
                .diagnostics
                .push("source_and_destination_platforms_differ".into());
        }
        for root in &layout.roots {
            if root.role != NativeLayoutRole::Installation {
                continue;
            }
            let mut assessment = NativeApplicationAssessment {
                destination_relative: self
                    .root
                    .relative_path(&preview.root_mappings[&root.logical_root])?,
                captured_entries: preview
                    .entries
                    .iter()
                    .filter(|entry| entry.logical_root == root.logical_root)
                    .count(),
                ..Default::default()
            };
            if root.source_kind == NativeLayoutSourceKind::Directory
                && root.leaf_name.to_ascii_lowercase().ends_with(".app")
                && layout.platform == noland_state_core::native_layout::NativeLayoutPlatform::Macos
            {
                self.assess_macos_bundle(root, &mut assessment, &mut report.metadata_read_bytes)?;
            } else {
                assessment
                    .diagnostics
                    .push("native_installation_format_assessment_required".into());
            }
            report.applications.push(assessment);
        }
        if eligible && !report.applications.is_empty() {
            report.readiness = NativeRestoreReadiness::ReconstructionUnverified;
        }
        // Byte/metadata reconstruction is NOT OS launch acceptance. Embedded
        // signature metadata is not signature validity, and a dylib name is not
        // a verified dependency graph. Never mint Runnable from these facts.
        report
            .diagnostics
            .push("native_signature_and_dependency_acceptance_required_before_runnable".into());
        Ok(report)
    }

    fn entry_for(&self, root: &NativeRootLayout, path: &str) -> Option<&NativeRestoreEntry> {
        let entries = &self.control.preview.entries;
        entries
            .binary_search_by(|entry| {
                entry
                    .logical_root
                    .as_str()
                    .cmp(&root.logical_root)
                    .then(entry.relative_path.as_str().cmp(path))
            })
            .ok()
            .map(|index| &entries[index])
    }

    fn open_verified_entry(&self, entry: &NativeRestoreEntry) -> Result<std::fs::File> {
        let current = self.root.observe(&entry.destination_relative)?;
        let expected = self
            .publications
            .get(&entry.destination_relative)
            .and_then(|publication| publication.output.clone())
            .or(self.control.expected(entry)?);
        if entry.kind != NativeEntryKind::File
            || expected.as_ref() != Some(&current)
            || current.size != entry.size
            || !entry.file_hash.strip_prefix("blake3:").is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(StateError::Conflict(
                "native application metadata lost its verified pipeline receipt".into(),
            ));
        }
        let file = self.root.open_regular(&entry.destination_relative)?;
        if filesystem::handle_id(&file)? != current.id {
            return Err(StateError::Conflict(
                "native application file handle changed".into(),
            ));
        }
        Ok(file)
    }

    fn read_metadata(
        &self,
        entry: &NativeRestoreEntry,
        offset: u64,
        limit: usize,
        read_bytes: &mut u64,
    ) -> Result<Vec<u8>> {
        let mut file = self.open_verified_entry(entry)?;
        let before = noland_snapshot::SourceMetadata::from_file(&file)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limit as u64)
            .read_to_end(&mut bytes)?;
        *read_bytes = read_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            StateError::Integrity("native metadata read accounting overflow".into())
        })?;
        if !noland_snapshot::same_file_identity(
            &noland_snapshot::SourceMetadata::from_file(&file)?,
            &before,
        ) || self.root.observe(&entry.destination_relative)?.id != filesystem::handle_id(&file)?
        {
            return Err(StateError::Conflict(
                "native application metadata changed while reading".into(),
            ));
        }
        // Recheck the full observation, including ctime, against the authentic
        // publication/reuse receipt, not just the path/ID from the first open.
        self.open_verified_entry(entry)?;
        Ok(bytes)
    }

    fn assess_macos_bundle(
        &self,
        root: &NativeRootLayout,
        result: &mut NativeApplicationAssessment,
        read_bytes: &mut u64,
    ) -> Result<()> {
        let Some(info) = self.entry_for(root, "Contents/Info.plist") else {
            result
                .diagnostics
                .push("captured_bundle_has_no_info_plist".into());
            return Ok(());
        };
        if info.kind != NativeEntryKind::File || info.size > MAX_PLIST as u64 {
            result
                .diagnostics
                .push("bundle_info_plist_type_or_size_unsupported".into());
            return Ok(());
        }
        let bytes = self.read_metadata(info, 0, MAX_PLIST + 1, read_bytes)?;
        let Some((identifier, executable)) = bundle_identity(&bytes) else {
            result
                .diagnostics
                .push("bundle_info_plist_invalid_or_incomplete".into());
            return Ok(());
        };
        if noland_state_core::native_layout::validate_native_layout_leaf(&executable).is_err()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            result
                .diagnostics
                .push("bundle_executable_or_identifier_is_not_confined".into());
            return Ok(());
        }
        result.bundle_metadata_validated = true;
        let path = format!("Contents/MacOS/{executable}");
        let Some(executable) = self.entry_for(root, &path) else {
            result
                .diagnostics
                .push("bundle_executable_not_in_authenticated_selection".into());
            return Ok(());
        };
        if executable.kind != NativeEntryKind::File {
            result
                .diagnostics
                .push("bundle_executable_is_not_a_regular_captured_file".into());
            return Ok(());
        }
        self.open_verified_entry(executable)?;
        result.executable_capture_hash_verified = true;
        let header = self.read_metadata(executable, 0, 64, read_bytes)?;
        if header.starts_with(b"#!") {
            result.executable_format = "script_not_native_launch_verified".into();
            result
                .diagnostics
                .push("script_bundle_is_reconstructed_not_native_launch_verified".into());
            return Ok(());
        }
        if header.len() < 32 || header[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
            result.executable_format = "unknown_or_unassessed_executable".into();
            result
                .diagnostics
                .push("native_executable_format_assessment_required".into());
            return Ok(());
        }
        result.executable_format = "macho_64".into();
        let cpu = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let file_type = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let count = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
        let current_cpu = match std::env::consts::ARCH {
            "aarch64" => 0x0100000c,
            "x86_64" => 0x01000007,
            _ => 0,
        };
        if cpu != current_cpu
            || file_type != 2
            || count > 2048
            || size > MAX_COMMANDS
            || 32u64
                .checked_add(size as u64)
                .is_none_or(|end| end > executable.size)
        {
            result
                .diagnostics
                .push("macho_architecture_type_or_command_bounds_not_accepted".into());
            return Ok(());
        }
        let commands = self.read_metadata(executable, 32, size, read_bytes)?;
        let Some((dependencies, signature)) = load_commands(&commands, count, executable.size)
        else {
            result
                .diagnostics
                .push("macho_load_commands_invalid".into());
            return Ok(());
        };
        result.declared_dependencies = dependencies;
        if let Some((offset, size)) = signature {
            let header = self.read_metadata(executable, offset, 12, read_bytes)?;
            if header.len() == 12 && header[..4] == [0xfa, 0xde, 0x0c, 0xc0] {
                let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as u64;
                let count = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
                if length <= size && (1..=128).contains(&count) && 12 + count as u64 * 8 <= length {
                    let slots =
                        self.read_metadata(executable, offset + 12, count * 8, read_bytes)?;
                    let slots_valid = slots.len() == count * 8
                        && slots.chunks_exact(8).all(|slot| {
                            let start = u32::from_be_bytes(slot[4..8].try_into().unwrap()) as u64;
                            start >= 12 + count as u64 * 8 && start + 8 <= length
                        });
                    if slots_valid {
                        for slot in slots.chunks_exact(8) {
                            let kind = u32::from_be_bytes(slot[..4].try_into().unwrap());
                            if kind != 0 {
                                continue;
                            }
                            let start = u32::from_be_bytes(slot[4..8].try_into().unwrap()) as u64;
                            let directory =
                                self.read_metadata(executable, offset + start, 8, read_bytes)?;
                            if directory.len() == 8 && directory[..4] == [0xfa, 0xde, 0x0c, 0x02] {
                                let declared =
                                    u32::from_be_bytes(directory[4..8].try_into().unwrap()) as u64;
                                result.embedded_signature_metadata_validated =
                                    declared >= 44 && start + declared <= length;
                            }
                        }
                    }
                }
            }
        }
        result
            .diagnostics
            .push("embedded_signature_metadata_is_not_native_signature_validity".into());
        Ok(())
    }
}

fn bundle_identity(bytes: &[u8]) -> Option<(String, String)> {
    use plist::stream::{Event, Reader};
    let mut events = Vec::new();
    let mut depth = 0usize;
    let mut expanded = 0usize;
    let mut declared = 0u64;
    let mut top_keys = std::collections::BTreeSet::new();
    let mut key_expected = true;
    for event in Reader::new(std::io::Cursor::new(bytes)) {
        if events.len() >= MAX_EVENTS {
            return None;
        }
        let event = event.ok()?;
        if events.is_empty() && !matches!(event, Event::StartDictionary(_)) {
            return None;
        }
        if !events.is_empty() && depth == 0 {
            return None;
        }
        if depth == 1 {
            match &event {
                Event::EndCollection if !key_expected => return None,
                Event::String(key) if key_expected => {
                    if !top_keys.insert(key.to_string()) {
                        return None;
                    }
                    key_expected = false;
                }
                Event::EndCollection => {}
                _ if key_expected => return None,
                _ => key_expected = true,
            }
        }
        match &event {
            Event::StartArray(size) | Event::StartDictionary(size) => {
                depth += 1;
                declared = declared.checked_add(size.unwrap_or(0).saturating_mul(2))?;
                if depth > 32 || declared > MAX_EVENTS as u64 {
                    return None;
                }
            }
            Event::EndCollection => {
                depth = depth.checked_sub(1)?;
            }
            Event::String(value) => {
                expanded = expanded.checked_add(value.len())?;
            }
            Event::Data(value) => {
                expanded = expanded.checked_add(value.len())?;
            }
            _ => {}
        }
        if expanded > 4 * MAX_PLIST {
            return None;
        }
        events.push(event);
    }
    if depth != 0 || events.is_empty() {
        return None;
    }
    let value = plist::Value::from_events(events.into_iter().map(Ok)).ok()?;
    let dictionary = value.as_dictionary()?;
    let id = dictionary.get("CFBundleIdentifier")?.as_string()?;
    let executable = dictionary.get("CFBundleExecutable")?.as_string()?;
    if id.is_empty()
        || id.len() > 255
        || id.split('.').any(str::is_empty)
        || executable.is_empty()
        || executable.len() > 255
    {
        return None;
    }
    if dictionary
        .get("CFBundlePackageType")
        .is_some_and(|value| value.as_string() != Some("APPL"))
    {
        return None;
    }
    Some((id.to_owned(), executable.to_owned()))
}

fn load_commands(
    bytes: &[u8],
    count: usize,
    file_size: u64,
) -> Option<(usize, Option<(u64, u64)>)> {
    let mut offset = 0usize;
    let mut dependencies = 0usize;
    let mut signature = None;
    for _ in 0..count {
        let header = bytes.get(offset..offset.checked_add(8)?)?;
        let command = u32::from_le_bytes(header[..4].try_into().ok()?);
        let size = u32::from_le_bytes(header[4..].try_into().ok()?) as usize;
        if size < 8 || size % 8 != 0 {
            return None;
        }
        let end = offset.checked_add(size)?;
        let data = bytes.get(offset..end)?;
        if command == 0x1d {
            if size != 16 || signature.is_some() {
                return None;
            }
            let start = u32::from_le_bytes(data[8..12].try_into().ok()?) as u64;
            let length = u32::from_le_bytes(data[12..16].try_into().ok()?) as u64;
            if start.checked_add(length)? > file_size || length < 12 {
                return None;
            }
            signature = Some((start, length));
        }
        if matches!(command, 0xc | 0x80000018 | 0x8000001f | 0x80000023) {
            if size < 24 {
                return None;
            }
            let start = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
            if start < 24 || start >= size {
                return None;
            }
            let text = &data[start..];
            let end = text.iter().position(|byte| *byte == 0)?;
            if end == 0
                || end > 4096
                || std::str::from_utf8(&text[..end])
                    .ok()?
                    .chars()
                    .any(char::is_control)
            {
                return None;
            }
            dependencies += 1;
        }
        offset = end;
    }
    (offset == bytes.len()).then_some((dependencies, signature))
}
