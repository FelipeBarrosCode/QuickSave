// SPDX-License-Identifier: GPL-3.0-only
//! MAC-chained write-ahead intents. A plain checksum is never recovery authority.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use noland_snapshot::SourcePath;
use noland_state_core::{Result, StateError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::filesystem;
use super::{
    NativeEntryObservation, NativeObjectId, NativeRestoreControl, MAX_NATIVE_RESTORE_METADATA,
};

const HEADER: &str = "restore-native.v1.json";
const LOG: &str = "restore-native.v1.log";
const MAX_RECORD: usize = 256 * 1024;
#[cfg(unix)]
const DOMAIN: &[u8] = b"QuickSave authenticated native restore v1\0";
#[cfg(windows)]
const DOMAIN: &[u8] = b"QuickSave authenticated native Windows restore v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OwnershipRole {
    Directory,
    RollbackDirectory,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    pub destination: String,
    pub partial: Option<String>,
    pub output: Option<NativeEntryObservation>,
    pub original: Option<NativeEntryObservation>,
    pub backup: Option<String>,
    pub durable: bool,
    pub backup_durable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RollbackCapture {
    pub artifact: String,
    pub observation: NativeEntryObservation,
    pub file_hash: String,
    pub copied_bytes: u64,
    pub cow_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryMetadataRollback {
    pub destination: String,
    pub original: NativeEntryObservation,
    pub existed: bool,
    pub requested_mode: Option<u32>,
    pub requested_mtime_ns: Option<i64>,
    pub requested_uid: Option<u32>,
    pub requested_gid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Event {
    Owned {
        path: String,
        observation: NativeEntryObservation,
        role: OwnershipRole,
    },
    Publish(Publication),
    CapturedOriginal {
        destination: String,
        capture: RollbackCapture,
    },
    DirectoryMetadata(DirectoryMetadataRollback),
    DirectoryMetadataRestored {
        destination: String,
        observation: NativeEntryObservation,
    },
    Published {
        destination: String,
        observation: NativeEntryObservation,
    },
    BackupStored {
        destination: String,
        observation: NativeEntryObservation,
    },
    Restored {
        destination: String,
        observation: NativeEntryObservation,
    },
    Committed,
    RolledBack,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    restore_id: Uuid,
    job_id: Uuid,
    scope_digest: String,
    destination: PathBuf,
    destination_identity: NativeObjectId,
    expected_payload: String,
    workspace_identity: NativeObjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_mapping_digest: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    header: Header,
    mac: [u8; 32],
}

pub(super) struct NativeJournal {
    pub restore_id: Uuid,
    workspace: PathBuf,
    workspace_identity: NativeObjectId,
    log_identity: NativeObjectId,
    control: Arc<NativeRestoreControl>,
    scope_digest: String,
    previous: [u8; 32],
    sequence: u64,
    log_bytes: usize,
    file: File,
    pending: Vec<u8>,
    poisoned: bool,
    pub flushes: u64,
    pub records: u64,
    header_identity: NativeObjectId,
    header_snapshot: noland_snapshot::SourceMetadata,
    log_snapshot: noland_snapshot::SourceMetadata,
    repaired_tail: bool,
}

fn header_message(header: &Header) -> Result<Vec<u8>> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(b"scope\0");
    serde_json::to_writer(&mut message, header)?;
    Ok(message)
}

fn record_message(
    restore_id: Uuid,
    scope: &str,
    sequence: u64,
    previous: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + scope.len() + payload.len() + 72);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(b"intent\0");
    message.extend_from_slice(restore_id.as_bytes());
    message.extend_from_slice(scope.as_bytes());
    message.extend_from_slice(&sequence.to_le_bytes());
    message.extend_from_slice(previous);
    message.extend_from_slice(payload);
    message
}

fn equal_mac(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Journal readers must coexist with the restore-owned append handle. Unlike
/// stable source/executable readers, they do not deny that writer on Windows.
/// The MAC chain, private ACL, full native ID and before/after stamps are still
/// required; this reader is never publication or deletion authority.
fn open_receipt_reader(path: &Path) -> Result<File> {
    #[cfg(unix)]
    return SourcePath::new(path)?.open_regular();
    #[cfg(windows)]
    {
        let file = crate::windows::open_path_metadata(path, 1)?;
        if noland_snapshot::native_metadata::WindowsMetadata::from_file(&file)?.kind
            != noland_snapshot::native_metadata::NativeEntryKind::File
        {
            return Err(StateError::UnsafePath(
                "native recovery receipt is not a regular file".into(),
            ));
        }
        crate::windows::security(&file)?;
        Ok(file)
    }
}

pub(super) fn is_native_workspace(workspace: &Path) -> bool {
    // symlink_metadata sees a dangling/replaced marker too; it must never fall
    // through to an unjournaled legacy workspace sweep.
    fs::symlink_metadata(workspace.join(HEADER)).is_ok()
        || fs::symlink_metadata(workspace.join(LOG)).is_ok()
}

impl NativeJournal {
    pub fn create(
        workspace: &Path,
        restore_id: Uuid,
        control: Arc<NativeRestoreControl>,
    ) -> Result<Self> {
        let source = SourcePath::new(workspace)?;
        let directory = source.open_directory()?;
        #[cfg(windows)]
        noland_snapshot::native_metadata::verify_private_directory(&directory)?;
        let workspace_identity = filesystem::handle_id(&directory)?;
        if workspace
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| Uuid::parse_str(name).ok())
            != Some(restore_id)
        {
            return Err(StateError::UnsafePath(
                "native restore workspace does not match the attempt ID".into(),
            ));
        }
        let scope_digest = control.preview.digest()?;
        let header = Header {
            version: super::NATIVE_CONTROL_VERSION,
            restore_id,
            job_id: control.preview.job_id,
            scope_digest: scope_digest.clone(),
            destination: control.preview.destination.clone(),
            destination_identity: control.preview.destination_identity,
            expected_payload: control.preview.expected_payload.clone(),
            workspace_identity,
            root_mapping_digest: Some(control.preview.root_mapping_digest()?),
        };
        let envelope = Envelope {
            mac: control.authority.mac(&header_message(&header)?)?,
            header,
        };
        let mut header_file =
            SourcePath::child(&directory, HEADER.into())?.open_partial_private(true)?;
        serde_json::to_writer(&mut header_file, &envelope)?;
        header_file.sync_all()?;
        let header_identity = filesystem::handle_id(&header_file)?;
        let header_snapshot = noland_snapshot::SourceMetadata::from_file(&header_file)?;
        let file = SourcePath::child(&directory, LOG.into())?.open_partial_private(true)?;
        let log_identity = filesystem::handle_id(&file)?;
        file.sync_all()?;
        let log_snapshot = noland_snapshot::SourceMetadata::from_file(&file)?;
        noland_snapshot::native_metadata::flush_directory(&directory)?;
        if !noland_snapshot::same_file_identity(
            &source.metadata()?,
            &noland_snapshot::SourceMetadata::from_file(&directory)?,
        ) {
            return Err(StateError::Conflict(
                "native restore workspace identity changed".into(),
            ));
        }
        if let Some(parent) = workspace.parent() {
            noland_snapshot::native_metadata::flush_directory(
                &SourcePath::new(parent)?.open_directory()?,
            )?;
        }
        Ok(Self {
            restore_id,
            workspace: workspace.into(),
            workspace_identity,
            log_identity,
            control,
            scope_digest,
            previous: envelope.mac,
            sequence: 0,
            log_bytes: 0,
            file,
            pending: Vec::new(),
            poisoned: false,
            flushes: 0,
            records: 0,
            header_identity,
            header_snapshot,
            log_snapshot,
            repaired_tail: false,
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn workspace_identity(&self) -> NativeObjectId {
        self.workspace_identity
    }

    pub fn receipt_files(&self) -> [(&'static str, NativeObjectId); 2] {
        [(HEADER, self.header_identity), (LOG, self.log_identity)]
    }

    pub fn verify_receipt_snapshot(&self) -> Result<()> {
        if self.poisoned || !self.pending.is_empty() || self.repaired_tail {
            return Err(StateError::Integrity(
                "native completion receipt has unflushed, failed or repaired journal data".into(),
            ));
        }
        self.check_workspace()?;
        let header = open_receipt_reader(&self.workspace.join(HEADER))?;
        let log = open_receipt_reader(&self.workspace.join(LOG))?;
        noland_snapshot::native_metadata::verify_private_file(&header)?;
        noland_snapshot::native_metadata::verify_private_file(&log)?;
        if filesystem::handle_id(&header)? != self.header_identity
            || !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&header)?,
                &self.header_snapshot,
            )
            || !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&log)?,
                &self.log_snapshot,
            )
            || log.metadata()?.len() != self.log_bytes as u64
        {
            return Err(StateError::Conflict(
                "authenticated native receipt files changed during completion verification".into(),
            ));
        }
        Ok(())
    }

    fn check_workspace(&self) -> Result<()> {
        let directory = SourcePath::new(&self.workspace)?.open_directory()?;
        if filesystem::handle_id(&directory)? != self.workspace_identity {
            return Err(StateError::Conflict(
                "native recovery workspace was replaced".into(),
            ));
        }
        let current = open_receipt_reader(&self.workspace.join(LOG))?;
        if filesystem::handle_id(&current)? != self.log_identity
            || filesystem::handle_id(&self.file)? != self.log_identity
        {
            return Err(StateError::Conflict(
                "native recovery intent file was replaced".into(),
            ));
        }
        Ok(())
    }

    pub fn append(&mut self, event: &Event) -> Result<()> {
        if self.poisoned {
            return Err(StateError::Storage(
                "native recovery journal write failed; retaining all artifacts".into(),
            ));
        }
        let payload = serde_json::to_vec(event)?;
        if payload.len() > MAX_RECORD
            || self.log_bytes.saturating_add(payload.len() + 36) > MAX_NATIVE_RESTORE_METADATA
        {
            return Err(StateError::Invalid(
                "native recovery journal exceeds its bounded metadata budget".into(),
            ));
        }
        let sequence = self.sequence.checked_add(1).ok_or_else(|| {
            StateError::Integrity("native recovery intent sequence overflow".into())
        })?;
        let mac = self.control.authority.mac(&record_message(
            self.restore_id,
            &self.scope_digest,
            sequence,
            &self.previous,
            &payload,
        ))?;
        if self.pending.len().saturating_add(payload.len() + 36) > MAX_RECORD {
            self.flush()?;
        }
        self.pending
            .extend_from_slice(&(payload.len() as u32).to_le_bytes());
        self.pending.extend_from_slice(&payload);
        self.pending.extend_from_slice(&mac);
        self.log_bytes += payload.len() + 36;
        self.previous = mac;
        self.sequence = sequence;
        self.records += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.check_workspace()?;
        if self.poisoned {
            return Err(StateError::Storage(
                "native recovery journal write failed; artifacts retained".into(),
            ));
        }
        if self.pending.is_empty() {
            return Ok(());
        }
        if let Err(error) = self
            .file
            .write_all(&self.pending)
            .and_then(|()| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(error.into());
        }
        self.pending.clear();
        self.log_snapshot = noland_snapshot::SourceMetadata::from_file(&self.file)?;
        self.flushes += 1;
        Ok(())
    }

    pub fn open_scope(workspace: &Path, control: Arc<NativeRestoreControl>) -> Result<Self> {
        Self::read_impl(workspace, control, false, true, |_| Ok(()))
    }

    pub fn replay(
        workspace: &Path,
        control: Arc<NativeRestoreControl>,
        on_event: impl FnMut(Event) -> Result<()>,
    ) -> Result<Self> {
        Self::read_impl(workspace, control, true, false, on_event)
    }

    pub fn replay_readonly(
        workspace: &Path,
        control: Arc<NativeRestoreControl>,
        on_event: impl FnMut(Event) -> Result<()>,
    ) -> Result<Self> {
        Self::read_impl(workspace, control, true, true, on_event)
    }

    fn read_impl(
        workspace: &Path,
        control: Arc<NativeRestoreControl>,
        replay_log: bool,
        readonly: bool,
        mut on_event: impl FnMut(Event) -> Result<()>,
    ) -> Result<Self> {
        let directory = SourcePath::new(workspace)?.open_directory()?;
        let workspace_identity = filesystem::handle_id(&directory)?;
        #[cfg(windows)]
        noland_snapshot::native_metadata::verify_private_directory(&directory)?;
        let mut header_file = open_receipt_reader(&workspace.join(HEADER))?;
        noland_snapshot::native_metadata::verify_private_file(&header_file)?;
        let header_identity = filesystem::handle_id(&header_file)?;
        let header_snapshot = noland_snapshot::SourceMetadata::from_file(&header_file)?;
        let mut header_bytes = Vec::new();
        Read::by_ref(&mut header_file)
            .take((MAX_RECORD + 1) as u64)
            .read_to_end(&mut header_bytes)?;
        if header_bytes.len() > MAX_RECORD {
            return Err(StateError::Integrity(
                "native recovery scope header exceeds its bound".into(),
            ));
        }
        let envelope: Envelope = serde_json::from_slice(&header_bytes)?;
        if !noland_snapshot::same_file_identity(
            &noland_snapshot::SourceMetadata::from_file(&header_file)?,
            &header_snapshot,
        ) {
            return Err(StateError::Conflict(
                "native receipt header changed while reading".into(),
            ));
        }
        let expected_mac = control.authority.mac(&header_message(&envelope.header)?)?;
        if !equal_mac(&envelope.mac, &expected_mac) {
            return Err(StateError::Integrity(
                "native recovery scope MAC authentication failed".into(),
            ));
        }
        let header = envelope.header;
        if header.version != super::NATIVE_CONTROL_VERSION
            || header.workspace_identity != workspace_identity
            || header.job_id != control.preview.job_id
            || header.destination != control.preview.destination
            || header.destination_identity != control.preview.destination_identity
            || header.scope_digest != control.preview.digest()?
            || header.expected_payload != control.preview.expected_payload
            || header.root_mapping_digest.as_ref().is_some_and(|digest| {
                control.preview.root_mapping_digest().ok().as_ref() != Some(digest)
            })
            || workspace
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Uuid::parse_str(name).ok())
                != Some(header.restore_id)
        {
            return Err(StateError::Integrity(
                "native recovery journal belongs to another frozen job/destination/selection"
                    .into(),
            ));
        }
        let log_source = SourcePath::new(&workspace.join(LOG))?;
        let mut reader = open_receipt_reader(&workspace.join(LOG))?;
        noland_snapshot::native_metadata::verify_private_file(&reader)?;
        let log_identity = filesystem::handle_id(&reader)?;
        let read_snapshot = noland_snapshot::SourceMetadata::from_file(&reader)?;
        if read_snapshot.len() > MAX_NATIVE_RESTORE_METADATA as u64 {
            return Err(StateError::Integrity(
                "native recovery intent log exceeds 512 MiB".into(),
            ));
        }
        let mut previous = envelope.mac;
        let mut sequence = 0u64;
        let mut log_bytes = 0usize;
        let mut torn_tail = false;
        while replay_log {
            let mut length = [0u8; 4];
            let count = reader.read(&mut length)?;
            if count == 0 {
                break;
            }
            if count != 4 {
                torn_tail = true;
                break;
            }
            let length = u32::from_le_bytes(length) as usize;
            if length > MAX_RECORD
                || length == 0
                || log_bytes.saturating_add(length + 36) > MAX_NATIVE_RESTORE_METADATA
            {
                return Err(StateError::Integrity(
                    "native recovery intent record has an invalid length".into(),
                ));
            }
            let mut payload = vec![0u8; length];
            let mut mac = [0u8; 32];
            if let Err(error) = reader
                .read_exact(&mut payload)
                .and_then(|()| reader.read_exact(&mut mac))
            {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    torn_tail = true;
                    break;
                }
                return Err(error.into());
            }
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| StateError::Integrity("native recovery sequence overflow".into()))?;
            let expected = control.authority.mac(&record_message(
                header.restore_id,
                &header.scope_digest,
                sequence,
                &previous,
                &payload,
            ))?;
            if !equal_mac(&mac, &expected) {
                return Err(StateError::Integrity(
                    "native recovery intent MAC authentication failed".into(),
                ));
            }
            // Fold verified records immediately. Do not retain a second copy of
            // a potentially hundreds-of-MiB journal beside the ownership maps.
            on_event(serde_json::from_slice(&payload)?)?;
            previous = mac;
            log_bytes += length + 36;
        }
        if readonly && torn_tail {
            return Err(StateError::Integrity(
                "native completion cannot accept an incomplete journal tail".into(),
            ));
        }
        if !noland_snapshot::same_file_identity(
            &noland_snapshot::SourceMetadata::from_file(&reader)?,
            &read_snapshot,
        ) || !noland_snapshot::same_file_identity(&log_source.metadata()?, &read_snapshot)
        {
            return Err(StateError::Conflict(
                "native receipt log changed during authenticated replay".into(),
            ));
        }
        let mut file = if readonly {
            open_receipt_reader(&workspace.join(LOG))?
        } else {
            log_source.open_partial_private(false)?
        };
        if filesystem::handle_id(&file)? != log_identity
            || !noland_snapshot::same_file_identity(
                &noland_snapshot::SourceMetadata::from_file(&file)?,
                &read_snapshot,
            )
        {
            return Err(StateError::Conflict(
                "native recovery journal was replaced after authenticated replay".into(),
            ));
        }
        // A torn append was never acknowledged and could not authorize a
        // mutation. Truncate only this authenticated held journal handle before
        // appending recovery records; never rewrite a replaced pathname.
        if torn_tail {
            if filesystem::handle_id(&file)? != log_identity {
                return Err(StateError::Conflict(
                    "native recovery journal changed while reading".into(),
                ));
            }
            file.set_len(log_bytes as u64)?;
            file.sync_all()?;
        }
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::End(0))?;
        let log_snapshot = noland_snapshot::SourceMetadata::from_file(&file)?;
        let journal = Self {
            restore_id: header.restore_id,
            workspace: workspace.into(),
            workspace_identity,
            log_identity,
            control,
            scope_digest: header.scope_digest,
            previous,
            sequence,
            log_bytes,
            file,
            pending: Vec::new(),
            poisoned: false,
            flushes: 0,
            records: sequence,
            header_identity,
            header_snapshot,
            log_snapshot,
            repaired_tail: torn_tail,
        };
        journal.check_workspace()?;
        Ok(journal)
    }
}
